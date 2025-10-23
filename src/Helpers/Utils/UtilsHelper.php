<?php

namespace AllStak\Helpers\Utils;

use Throwable;

class UtilsHelper
{
    /**
     * Generate a unique trace ID
     *
     * @return string
     */
    public function generateTraceId(): string
    {
        return bin2hex(random_bytes(16));
    }
    
    /**
     * Get code context lines around a specific line in a file
     *
     * @param string $file
     * @param int $line
     * @param int $context
     * @return array
     */
    public function getCodeContextLines(string $file, int $line, int $context): array
    {
        if (!is_readable($file)) {
            return [];
        }

        $lines = @file($file, FILE_IGNORE_NEW_LINES);
        if (!$lines) {
            return [];
        }

        $start = max($line - $context - 1, 0);
        $end = min($line + $context - 1, count($lines) - 1);

        $snippet = [];
        for ($i = $start; $i <= $end; $i++) {
            $snippet[$i + 1] = $lines[$i];
        }
        return $snippet;
    }
    
    /**
     * Determine error severity based on exception type
     *
     * @param Throwable $exception
     * @return string
     */
    public function determineErrorSeverity(Throwable $exception): string
    {
        $exceptionClass = get_class($exception);
        
        if (strpos($exceptionClass, 'Fatal') !== false) {
            return 'critical';
        }
        
        if (strpos($exceptionClass, 'Warning') !== false) {
            return 'warning';
        }
        
        return 'error';
    }
    
    /**
     * Determine error category based on exception type
     *
     * @param Throwable $exception
     * @return string
     */
    public function determineErrorCategory(Throwable $exception): string
    {
        $exceptionClass = get_class($exception);
        
        if (strpos($exceptionClass, 'Database') !== false || strpos($exceptionClass, 'SQL') !== false) {
            return 'database';
        }
        
        if (strpos($exceptionClass, 'Http') !== false || strpos($exceptionClass, 'Request') !== false) {
            return 'http';
        }
        
        if (strpos($exceptionClass, 'Validation') !== false) {
            return 'validation';
        }
        
        return 'application';
    }
}