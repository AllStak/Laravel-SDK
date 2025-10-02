<?php

namespace AllStak\Tracing;

use AllStak\AllStakClient;
use Illuminate\Database\Events\QueryExecuted;

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
            // 🔧 FIX 1: Calculate actual query start time
            $startTime = microtime(true) - ($query->time / 1000);
            $endTime = microtime(true);

            // 🔧 FIX 2: Detect slow queries and mark as error
            $isSlowQuery = $query->time > config('allstak.slow_query_threshold', 1000);
            $status = $isSlowQuery ? 'error' : 'ok';

            $span = [
                'id' => bin2hex(random_bytes(8)),
                'trace_id' => $traceId,
                'parent_span_id' => SpanContext::getParentSpanId(),
                'name' => 'db.query',
                'start_time' => $startTime,
                'end_time' => $endTime,
                'attributes' => [
                    'sql' => $query->sql,
                    'bindings' => json_encode($query->bindings),
                    'time_ms' => $query->time,
                    'connection' => $query->connectionName,
                    // 🔧 FIX 3: Add database type and name
                    'db.system' => config("database.connections.{$query->connectionName}.driver", 'unknown'),
                    'db.name' => config("database.connections.{$query->connectionName}.database", 'unknown'),
                    // 🔧 FIX 4: Add slow query indicator
                    'is_slow_query' => $isSlowQuery,
                ],
                'status' => $status,
                // 🔧 FIX 5: Add error message for slow queries
                'error' => $isSlowQuery ? "Slow query detected: {$query->time}ms" : null,
            ];

            // 🔧 FIX 6: Add breadcrumb with proper level
            $breadcrumbLevel = $isSlowQuery ? 'warning' : 'info';
            $this->client->addBreadcrumb(
                'db',
                'Database query executed',
                [
                    'sql' => $query->sql,
                    'bindings' => $query->bindings,
                    'time_ms' => $query->time,
                    'connection' => $query->connectionName,
                    'is_slow' => $isSlowQuery,
                ],
                $breadcrumbLevel
            );

            $this->client->sendDbSpan($span);
        } catch (\Exception $e) {
            // 🔧 FIX 7: Better error handling
            \Log::error('Failed to record DB span', [
                'error' => $e->getMessage(),
                'sql' => $query->sql,
                'trace_id' => $traceId,
            ]);
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

        // 🔧 FIX 8: Use config for ignored tables
        $skipTables = config('allstak.ignored_db_tables', [
            'cache',
            'sessions',
            'migrations',
            'jobs',
            'failed_jobs',
            'password_resets',
            'password_reset_tokens',
            'telescope_entries',
            'telescope_entries_tags',
            'telescope_monitoring',
        ]);

        foreach ($skipTables as $table) {
            // 🔧 FIX 9: More comprehensive pattern matching
            $patterns = [
                "from \"{$table}\"",
                "from `{$table}`",
                "from {$table} ",
                "into \"{$table}\"",
                "into `{$table}`",
                "into {$table} ",
                "update \"{$table}\"",
                "update `{$table}`",
                "update {$table} ",
                "delete from \"{$table}\"",
                "delete from `{$table}`",
                "delete from {$table} ",
                "insert into \"{$table}\"",
                "insert into `{$table}`",
                "insert into {$table} ",
            ];

            foreach ($patterns as $pattern) {
                if (strpos($sql, $pattern) !== false) {
                    return true;
                }
            }
        }

        // 🔧 FIX 10: Skip SELECT 1 health check queries
        if (preg_match('/^select\s+1(\s|$)/i', $sql)) {
            return true;
        }

        return false;
    }
}
