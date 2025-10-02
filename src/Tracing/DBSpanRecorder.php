<?php

namespace AllStak\Tracing;

use Illuminate\Database\Events\QueryExecuted;
use AllStak\AllStakClient;

class DBSpanRecorder
{
    protected $client;
    protected static $isRecording = false;

    public function __construct(AllStakClient $client)
    {
        $this->client = $client;
    }

    public function record(QueryExecuted $query)
    {
        // Prevent recursive recording
        if (self::$isRecording) {
            return;
        }

        // Skip internal Laravel queries
        if ($this->shouldSkipQuery($query->sql)) {
            return;
        }

        // Check if we have a valid trace context
        $traceId = SpanContext::getTraceId();
        if (!$traceId) {
            // No active trace context, skip this query
            \Log::debug('No active trace context, skipping DB span', ['sql' => $query->sql]);
            return;
        }

        self::$isRecording = true;

        try {
            $span = [
                'id' => bin2hex(random_bytes(8)),
                'trace_id' => $traceId,
                'parent_span_id' => SpanContext::getParentSpanId(),
                'name' => 'db.query',
                'start_time' => microtime(true) - ($query->time / 1000),
                'end_time' => microtime(true),
                'attributes' => [
                    'sql' => $query->sql,
                    'bindings' => json_encode($query->bindings),
                    'time_ms' => $query->time,
                    'connection' => $query->connectionName,
                ],
                'status' => 'ok',
            ];

            // Add breadcrumb for this db query
            $this->client->addBreadcrumb(
                'db',
                'Database query executed',
                [
                    'sql' => $query->sql,
                    'bindings' => $query->bindings,
                    'time_ms' => $query->time,
                    'connection' => $query->connectionName,
                ],
                'info'
            );

            $this->client->sendDbSpan($span);
        } finally {
            self::$isRecording = false;
        }
    }

    /**
     * Determine if a query should be skipped from tracing
     */
    protected function shouldSkipQuery(string $sql): bool
    {
        $sql = strtolower(trim($sql));

        // Skip internal Laravel tables
        $skipTables = [
            'cache',
            'sessions',
            'migrations',
            'jobs',
            'failed_jobs',
            'password_resets',
            'password_reset_tokens',
        ];

        foreach ($skipTables as $table) {
            // Check for various SQL patterns
            if (strpos($sql, "from \"{$table}\"") !== false ||
                strpos($sql, "from `{$table}`") !== false ||
                strpos($sql, "into \"{$table}\"") !== false ||
                strpos($sql, "into `{$table}`") !== false ||
                strpos($sql, "update \"{$table}\"") !== false ||
                strpos($sql, "update `{$table}`") !== false ||
                strpos($sql, "delete from \"{$table}\"") !== false ||
                strpos($sql, "delete from `{$table}`") !== false) {
                return true;
            }
        }

        return false;
    }
}
