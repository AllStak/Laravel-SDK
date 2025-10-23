<?php

namespace AllStak\Tracing;

use AllStak\AllStakClient;
use AllStak\Helpers\SecurityHelper;  // Adjust import
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use AllStak\Tracing\SpanContext;

class DBSpanRecorder
{
    private AllStakClient $client;
    private SecurityHelper $securityHelper;
    private static bool $isRecording = false; // Recursion guard

    public function __construct(AllStakClient $client, SecurityHelper $securityHelper)
    {
        $this->client = $client;
        $this->securityHelper = $securityHelper;
    }

    public function record(QueryExecuted $query)
    {
        // CRITICAL: Prevent infinite recursion
        if (self::$isRecording) {
            return; // Skip if already recording
        }

        // Check if this is a cache/session query from AllStak itself
        $sql = strtolower($query->sql);
        if (str_contains($sql, 'cache') ||
            str_contains($sql, 'sessions') ||
            str_contains($sql, 'rate_limit')) {
            return; // Skip internal Laravel queries
        }

        try {
            self::$isRecording = true; // Set guard

            error_log('DBSpanRecorder::record called - sql_preview: ' . substr($query->sql, 0, 100));  // Preview only

            $traceId = SpanContext::getTraceId();

            // FIXED: Mask SQL and bindings before sending
            $maskedQueryText = $this->securityHelper->maskQueryText($query->sql);  // Masks inline literals (e.g., 'email@example.com')
            $maskedBindings = $this->securityHelper->maskDbParameters($query->bindings);  // Masks params (e.g., emails, keys)

            $this->client->sendDbQuery(
                queryText: $maskedQueryText,
                bindings: $maskedBindings,  // Now masked array
                duration: $query->time,
                connectionName: $query->connectionName,
                traceId: $traceId,
                success: true
            );

            // Log masking summary
            error_log('DB Query Sent with Masking - trace_id: ' . $traceId . ', masked_bindings_count: ' . count($maskedBindings) . ', has_masking: ' . (count(array_filter($maskedBindings, fn($b) => strpos((string)$b, '*') !== false)) > 0 ? 'true' : 'false'));

        } finally {
            self::$isRecording = false; // Always reset guard
        }
    }

    /**
     * Handle failed DB queries (QueryException) – call from app/Exceptions/Handler.php
     * Captures errors like column not found, with masking.
     */
    public function recordFailedQuery(QueryException $exception)
    {
        if (self::$isRecording) {
            return;
        }

        try {
            self::$isRecording = true;
            $traceId = SpanContext::getTraceId();

            // Mask SQL and bindings for failures
            $maskedQueryText = $this->securityHelper->maskQueryText($exception->getSql() ?? '');
            $maskedBindings = $this->securityHelper->maskDbParameters($exception->getBindings() ?? []);

            // Extract error details from QueryException
            $errorCode = $exception->getCode();
            $errorMessage = $exception->getMessage();

            // Get stack trace (limit to first 10 lines for size/security)
            $stackTrace = $this->getStackTraceSummary($exception);

            // ✅ Call sendDbQuery with error parameters
            $this->client->sendDbQuery(
                queryText: $maskedQueryText,
                bindings: $maskedBindings,
                duration: 0, // Failed, no execution time
                connectionName: $exception->getConnectionName() ?? (function_exists('config') ? config('database.default') : 'default'),
                traceId: $traceId,
                success: false,
                errorCode: (string)$errorCode,
                errorMessage: $this->securityHelper->maskExceptionMessage($errorMessage, $exception),
                stackTrace: $stackTrace
            );

            error_log('Failed DB Query Recorded - trace_id: ' . $traceId . ', error_code: ' . $errorCode . ', masked: true');

        } catch (\Exception $e) {
            error_log('Failed to record failed query - error: ' . $e->getMessage());
        } finally {
            self::$isRecording = false;
        }
    }

    /**
     * Get a summary of stack trace (limited for security/size)
     */
    private function getStackTraceSummary(\Exception $exception, int $limit = 10): string
    {
        $trace = $exception->getTrace();
        $summary = [];

        foreach (array_slice($trace, 0, $limit) as $index => $frame) {
            $file = $frame['file'] ?? 'unknown';
            $line = $frame['line'] ?? 0;
            $function = $frame['function'] ?? 'unknown';
            $class = $frame['class'] ?? '';

            $summary[] = "#{$index} {$class}{$function}() at {$file}:{$line}";
        }

        return implode("\n", $summary);
    }

}
