<?php

namespace AllStak\Logging;

use AllStak\AllStakClient;

class AllStakLogChannel
{
    /**
     * Create a custom logger instance for AllStak
     */
    public function __invoke(array $config)
    {
        // Get AllStak client configuration
        $apiKey = $config['api_key'] ?? null;
        $environment = $config['environment'] ?? 'production';
        $serviceName = $config['service_name'] ?? 'laravel-app';
        
        // Create AllStak client
        $allStakClient = new AllStakClient($apiKey, $environment, true, $serviceName);
        
        // Return a logger that implements the PSR-3 LoggerInterface
        return new AllStakLogger($allStakClient);
    }
}

class AllStakLogger
{
    private AllStakClient $allStakClient;

    public function __construct(AllStakClient $allStakClient)
    {
        $this->allStakClient = $allStakClient;
    }

    public function emergency($message, array $context = []): void
    {
        $this->writeLog('error', $message, $context);
    }

    public function alert($message, array $context = []): void
    {
        $this->writeLog('error', $message, $context);
    }

    public function critical($message, array $context = []): void
    {
        $this->writeLog('error', $message, $context);
    }

    public function error($message, array $context = []): void
    {
        $this->writeLog('error', $message, $context);
    }

    public function warning($message, array $context = []): void
    {
        $this->writeLog('warning', $message, $context);
    }

    public function notice($message, array $context = []): void
    {
        $this->writeLog('info', $message, $context);
    }

    public function info($message, array $context = []): void
    {
        $this->writeLog('info', $message, $context);
    }

    public function debug($message, array $context = []): void
    {
        $this->writeLog('debug', $message, $context);
    }

    public function log($level, $message, array $context = []): void
    {
        $this->writeLog($level, $message, $context);
    }

    private function writeLog(string $level, $message, array $context = []): void
    {
        // Get trace ID from context if available
        $traceId = $context['trace_id'] ?? null;
        if (isset($context['trace_id'])) {
            unset($context['trace_id']);
        }

        // Convert message to string
        $messageStr = is_string($message) ? $message : (string) $message;

        // Use reflection to access the private log method
        try {
            $reflection = new \ReflectionClass($this->allStakClient);
            $logMethod = $reflection->getMethod('log');
            $logMethod->setAccessible(true);
            $logMethod->invoke($this->allStakClient, strtolower($level), $messageStr, $context, $traceId);
        } catch (\Exception $e) {
            // Fallback - silently fail to prevent breaking the application
            error_log('AllStak logging failed: ' . $e->getMessage());
        }
    }
}