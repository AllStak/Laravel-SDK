<?php

namespace AllStak\Logging;

use AllStak\AllStakClient;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\LogRecord;

class AllStakLogHandler extends AbstractProcessingHandler
{
    private AllStakClient $allStakClient;

    public function __construct(AllStakClient $allStakClient, $level = \Monolog\Logger::DEBUG, bool $bubble = true)
    {
        parent::__construct($level, $bubble);
        $this->allStakClient = $allStakClient;
    }

    /**
     * Writes the record down to the log of the implementing handler
     */
    protected function write(LogRecord $record): void
    {
        $context = $record->context;
        
        // Extract trace ID if present
        $traceId = $context['trace_id'] ?? null;
        if (isset($context['trace_id'])) {
            unset($context['trace_id']);
        }

        // Map Monolog levels to AllStak levels
        $level = strtolower($record->level->getName());
        
        try {
            // Use the public log method directly instead of reflection
            $this->allStakClient->log($level, $record->message, $context, $traceId);
        } catch (\Exception $e) {
            error_log('AllStak logging failed: ' . $e->getMessage());
        }
    }
}
