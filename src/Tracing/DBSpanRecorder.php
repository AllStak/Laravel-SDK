<?php

namespace AllStak\Tracing;

use AllStak\AllStakClient;
use AllStak\Helpers\SecurityHelper;
use AllStak\Tracing\SpanContext;
use Illuminate\Database\Events\QueryExecuted;

class DBSpanRecorder
{
    protected $client;
    protected $securityHelper;
    protected static $isRecording = false;

    // Buffer to track recent queries for N+1 detection
    protected static $recentQueries = [];

    // N+1 detection parameters
    protected $nPlusOneWindowSeconds = 1.0; // time window to track queries (seconds)
    protected $nPlusOneThreshold = 3;       // number of similar queries to flag

    public function __construct(AllStakClient $client)
    {
        $this->client = $client;
        $this->securityHelper = new SecurityHelper();
    }

    public function record(QueryExecuted $query)
    {
        if (self::$isRecording) {
            return;
        }

        if ($this->shouldSkipQuery($query->sql)) {
            return;
        }

        $traceId = SpanContext::getTraceId();

        if (!$traceId) {
            \Log::debug('No active trace context, skipping DB span', ['sql' => $query->sql]);
            return;
        }

        self::$isRecording = true;

        try {
            $startTime = microtime(true) - ($query->time / 1000);
            $endTime = microtime(true);

            $maskedBindings = $this->maskBindings($query->bindings);
            $sanitizedSQL = $this->sanitizeSQL($query->sql);

            $isSlowQuery = $query->time > config('allstak.slow_query_threshold', 1000);
            $status = $isSlowQuery ? 'error' : 'ok';

            $span = [
                'id' => bin2hex(random_bytes(8)),
                'trace_id' => $traceId,
                'parent_span_id' => SpanContext::getParentId(),
                'name' => 'db.query',
                'start_time' => $startTime,
                'end_time' => $endTime,
                'attributes' => [
                    'sql' => $sanitizedSQL,
                    'bindings' => json_encode($maskedBindings),
                    'time_ms' => $query->time,
                    'connection' => $query->connectionName,
                    'db.system' => config("database.connections.{$query->connectionName}.driver", 'unknown'),
                    'db.name' => config("database.connections.{$query->connectionName}.database", 'unknown'),
                    'is_slow_query' => $isSlowQuery,
                ],
                'status' => $status,
                'error' => $isSlowQuery ? "Slow query detected: {$query->time}ms" : null,
            ];

            $this->detectNPlusOne($sanitizedSQL);

            $this->client->addBreadcrumb(
                'db',
                'Database query executed',
                [
                    'sql' => $sanitizedSQL,
                    'bindings' => $maskedBindings,
                    'time_ms' => $query->time,
                    'connection' => $query->connectionName,
                    'is_slow_query' => $isSlowQuery,
                ],
                $isSlowQuery ? 'warning' : 'info'
            );

            $this->client->sendDbSpan($span);
        } catch (\Exception $ex) {
            \Log::error('Failed to record DB span', [
                'error' => $ex->getMessage(),
                'sql' => $query->sql,
                'trace' => $ex->getTraceAsString(),
            ]);
        }

        self::$isRecording = false;
    }

    protected function maskBindings(array $bindings)
    {
        $filtered = [];
        foreach ($bindings as $key => $value) {
            if ($this->securityHelper->isSensitiveKey($key) || $this->securityHelper->isSensitiveValue($value)) {
                $filtered[$key] = '*****';
            } else {
                $filtered[$key] = $value;
            }
        }
        return $filtered;
    }

    protected function sanitizeSQL(string $sql)
    {
        return preg_replace('/\'[^\']*\'/', '?', $sql);
    }

    protected function detectNPlusOne(string $query)
    {
        $now = microtime(true);

        self::$recentQueries = array_filter(self::$recentQueries, function ($entry) use ($now) {
            return ($now - $entry['timestamp']) <= $this->nPlusOneWindowSeconds;
        });

        $normalized = $this->normalizeQuery($query);

        $count = 0;
        foreach (self::$recentQueries as $entry) {
            if ($entry['normalized'] === $normalized) {
                $count++;
            }
        }

        self::$recentQueries[] = ['normalized' => $normalized, 'timestamp' => $now];

        if ($count + 1 >= $this->nPlusOneThreshold) {
            $this->client->addBreadcrumb(
                'performance',
                'N+1 query detected',
                ['query' => $normalized, 'count' => $count + 1],
                'warning'
            );
        }
    }

    protected function normalizeQuery(string $query)
    {
        $query = strtolower(trim($query));
        $query = preg_replace('/\'[^\']*\'/', '?', $query);
        $query = preg_replace('/[0-9]+/', '?', $query);

        return $query;
    }

    protected function shouldSkipQuery(string $sql)
    {
        $sql = strtolower(trim($sql));
        $skipTables = config('database.ignore_tables', [
            'cache',
            'sessions',
            'migrations',
            'jobs',
            'failed_jobs',
            'password_resets',
            'telescope_entries',
            'telescope_entries_tags',
            'telescope_monitoring'
        ]);

        foreach ($skipTables as $table) {
            $patterns = [
                "from {$table}",
                "into {$table}",
                "update {$table}",
                "delete from {$table}",
                "insert into {$table}"
            ];

            foreach ($patterns as $pattern) {
                if (strpos($sql, $pattern) !== false) {
                    return true;
                }
            }
        }

        if (preg_match('/^select\s+1$/i', $sql)) {
            return true;
        }

        return false;
    }
}
