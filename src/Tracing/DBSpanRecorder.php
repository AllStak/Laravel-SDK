<?php

namespace AllStak\Tracing;

use AllStak\AllStakClient;
use Illuminate\Database\Events\QueryExecuted;
use AllStak\Tracing\SpanContext;
use Illuminate\Support\Facades\Log;

class DBSpanRecorder
{
    private AllStakClient $client;
    private static bool $isRecording = false; // Add recursion guard

    public function __construct(AllStakClient $client)
    {
        $this->client = $client;
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

            Log::debug('DBSpanRecorder::record called', ['sql' => $query->sql]);
            $traceId = SpanContext::getTraceId();

            $this->client->sendDbQuery(
                queryText: $query->sql,
                bindings: $query->bindings,
                duration: $query->time,
                connectionName: $query->connectionName,
                traceId: $traceId,
                success: true
            );
        } finally {
            self::$isRecording = false; // Always reset guard
        }
    }
}
