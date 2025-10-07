<?php

namespace AllStak\Tracing;

use AllStak\AllStakClient;
use AllStak\Tracing\SpanContext;
use Illuminate\Database\Events\QueryExecuted;

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
