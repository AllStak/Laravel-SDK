<?php

namespace AllStak\Helpers\Logging;

use Illuminate\Support\Facades\Log;
use Throwable;

class LoggingHelper
{
    /**
     * Log a warning message with context
     *
     * @param string $message
     * @param array $context
     * @return void
     */
    public function warning(string $message, array $context = []): void
    {
        Log::warning($message, $context);
    }

    /**
     * Log a debug message with context
     *
     * @param string $message
     * @param array $context
     * @return void
     */
    public function debug(string $message, array $context = []): void
    {
        Log::debug($message, $context);
    }

    /**
     * Log an error message with context
     *
     * @param string $message
     * @param array $context
     * @return void
     */
    public function error(string $message, array $context = []): void
    {
        Log::error($message, $context);
    }

    /**
     * Log an exception with context
     *
     * @param Throwable $exception
     * @param array $context
     * @return void
     */
    public function exception(Throwable $exception, array $context = []): void
    {
        Log::error($exception->getMessage(), array_merge([
            'exception' => get_class($exception),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'trace' => $exception->getTraceAsString(),
        ], $context));
    }
}