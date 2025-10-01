<?php


namespace Techsea\AllStak\Tracing;

use Illuminate\Database\Events\QueryExecuted;
use Techsea\AllStak\AllStakClient;

class DBSpanRecorder
{
    protected $client;

    public function __construct(AllStakClient $client)
    {
        $this->client = $client;
    }

    public function record(QueryExecuted $query)
    {
        \Log::debug('DBSpanRecorder::record called', ['sql' => $query->sql]);

        $span = [
            'id' => bin2hex(random_bytes(8)),
            'trace_id' => SpanContext::getTraceId(),
            'parent_span_id' => SpanContext::getParentSpanId(),
            'name' => 'db.query',
            'start_time' => microtime(true) - ($query->time / 1000), // estimate start
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
    }

}
