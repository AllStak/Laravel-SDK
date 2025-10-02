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
        if (self::$isRecording) {
            return;
        }

        self::$isRecording = true;

        try {
            \Log::debug('DBSpanRecorder::record called', ['sql' => $query->sql]);

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
}
