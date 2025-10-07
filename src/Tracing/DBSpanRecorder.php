<?php

namespace AllStak\Laravel\Tracing;
use Illuminate\Database\Events\QueryExecuted;
use AllStak\AllStakClient;
use AllStak\Tracing\SpanContext;

class DBSpanRecorder
{
    private AllStakClient $client;

    public function __construct(AllStakClient $client)
    {
        $this->client = $client;
    }

    public function record(QueryExecuted $query)
    {
        \Log::debug('DBSpanRecorder::record called', ['sql' => $query->sql]);

        $traceId = SpanContext::getTraceId();

        $this->client->sendDbQuery(
            queryText: $query->sql,
            bindings: $query->bindings,
            duration: $query->time,
            connectionName: $query->connectionName,
            traceId: $traceId,
            success: true
        );
    }
}
