<?php

namespace AllStak\Logging;

use AllStak\AllStakClient;

class AllStakLogHandler
{
    private AllStakClient $allStakClient;
    private string $level;

    public function __construct(AllStakClient $allStakClient, string $level = 'debug')
    {
        $this->allStakClient = $allStakClient;
        $this->level = $level;
    }

    /**
     * Handle the log record
     */
    public function handle(array $record): bool
    {
        // Check if we should handle this level
        if (!$this->shouldHandle($record['level_name'] ?? 'info')) {
            return false;
        }

        // Extract context and extra data
        $context = array_merge($record['context'] ?? [], $record['extra'] ?? []);
        
        // Get trace ID from context if available
        $traceId = $context['trace_id'] ?? null;
        unset($context['trace_id']); // Remove from context to avoid duplication

        // Convert level to lowercase
        $level = strtolower($record['level_name'] ?? 'info');

        // Send to AllStak backend
        return $this->allStakClient->log(
            $level,
            $record['message'] ?? '',
            $context,
            $traceId
        );
    }

    private function shouldHandle(string $levelName): bool
    {
        $levels = ['debug' => 0, 'info' => 1, 'warning' => 2, 'error' => 3];
        $recordLevel = $levels[strtolower($levelName)] ?? 1;
        $handlerLevel = $levels[strtolower($this->level)] ?? 0;
        
        return $recordLevel >= $handlerLevel;
    }
}