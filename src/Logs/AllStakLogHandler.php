<?php

namespace AllStak\Logs;

// Add LogHandler.php
use AllStak\AllStakClient;
use AllStak\Tracing\SpanContext;
use Monolog\Handler\AbstractProcessingHandler;

class AllStakLogHandler extends AbstractProcessingHandler
{
    protected function write(array $record): void
    {
        app(AllStakClient::class)->captureLog([
            'level' => $record['level_name'],
            'message' => $record['message'],
            'context' => $record['context'],
            'trace_id' => SpanContext::getTraceId(),
        ]);
    }
}
