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

        // Skip cache queries to reduce noise and prevent issues
        if ($this->shouldSkipQuery($query->sql)) {
            return;
        }

        self::$isRecording = true;

        try {
            $span = [
                'id' => bin2hex(random_bytes(8)),
                'trace_id' => SpanContext::getTraceId(),
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

        // Skip cache table queries
        $cachePatterns = [
            'select * from "cache"',
            'select * from `cache`',
            'insert into "cache"',
            'insert into `cache`',
            'update "cache"',
            'update `cache`',
            'delete from "cache"',
            'delete from `cache`',
        ];

        foreach ($cachePatterns as $pattern) {
            if (strpos($sql, $pattern) === 0) {
                return true;
            }
        }

        // Skip internal Laravel queries (optional - adjust as needed)
        $internalPatterns = [
            'migrations',
            'sessions',
            'jobs',
            'failed_jobs',
        ];

        foreach ($internalPatterns as $table) {
            if (strpos($sql, "from \"{$table}\"") !== false ||
                strpos($sql, "from `{$table}`") !== false) {
                return true;
            }
        }

        return false;
    }
}
