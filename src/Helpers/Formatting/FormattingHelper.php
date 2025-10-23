<?php

namespace AllStak\Helpers\Formatting;

use DateTimeInterface;
use Throwable;

class FormattingHelper
{
    /**
     * Format a timestamp to ISO 8601 format
     *
     * @param DateTimeInterface $dt
     * @return string
     */
    public function formatTimestamp(DateTimeInterface $dt): string
    {
        return $dt->format('Y-m-d\TH:i:s');
    }
    
    /**
     * Format stack trace into a structured array
     *
     * @param Throwable $exception
     * @return array
     */
    public function formatStackTrace(Throwable $exception): array
    {
        $stackTrace = [];
        foreach ($exception->getTrace() as $index => $frame) {
            $stackTrace["frame_$index"] = [
                'file'     => $frame['file'] ?? '',
                'line'     => $frame['line'] ?? '',
                'function' => $frame['function'] ?? '',
                'class'    => $frame['class'] ?? '',
                'type'     => $frame['type'] ?? '',
            ];
        }
        return $stackTrace;
    }
    
    /**
     * Create runtime context information
     *
     * @return array
     */
    public function createContexts(): array
    {
        return [
            'runtime' => [
                'name'    => 'PHP',
                'version' => PHP_VERSION,
            ],
            'system'  => [
                'os'    => PHP_OS,
                'uname' => php_uname(),
            ],
            'process' => [
                'pid' => getmypid(),
            ],
        ];
    }
    
    /**
     * Get current memory usage
     *
     * @return int
     */
    public function getMemoryUsage(): int
    {
        return memory_get_usage(true);
    }
}