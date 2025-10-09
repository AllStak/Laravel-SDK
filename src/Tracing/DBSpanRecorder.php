<?php

namespace AllStak\Tracing;

use AllStak\AllStakClient;
use AllStak\Helpers\SecurityHelper;  // Adjust import
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use AllStak\Tracing\SpanContext;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\DB;

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

            Log::debug('DBSpanRecorder::record called', ['sql_preview' => substr($query->sql, 0, 100)]);  // Preview only

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
            Log::debug('DB Query Sent with Masking', [
                'trace_id' => $traceId,
                'masked_bindings_count' => count($maskedBindings),
                'has_masking' => count(array_filter($maskedBindings, fn($b) => strpos((string)$b, '*') !== false)) > 0
            ]);

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
        if (self::$isRecording) return;

        try {
            self::$isRecording = true;

            $traceId = SpanContext::getTraceId();

            // FIXED: Mask SQL and bindings for failures
            $maskedQueryText = $this->securityHelper->maskQueryText($exception->getSql() ?? '');
            $maskedBindings = $this->securityHelper->maskDbParameters($exception->getBindings() ?? []);

            $this->client->sendDbQuery(
                queryText: $maskedQueryText,
                bindings: $maskedBindings,
                duration: 0,  // Failed, no time
                connectionName: $exception->getConnectionName() ?? config('database.default'),
                traceId: $traceId,
                success: false,
                errorCode: $exception->getCode(),
                errorMessage: $this->securityHelper->maskExceptionMessage($exception->getMessage(), $exception)  // From previous
            );

            Log::warning('Failed DB Query Recorded', [
                'trace_id' => $traceId,
                'error_code' => $exception->getCode(),
                'masked' => true
            ]);

        } finally {
            self::$isRecording = false;
        }
    }
}
