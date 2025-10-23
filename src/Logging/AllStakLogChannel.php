<?php

namespace AllStak\Logging;

use AllStak\AllStakClient;
use Monolog\Logger;

class AllStakLogChannel
{
    /**
     * Create a custom Monolog logger instance for AllStak
     *
     * @param array $config
     * @return \Monolog\Logger
     */
    public function __invoke(array $config)
    {
        // Get AllStak client configuration
        $apiKey = $config['api_key'] ?? null;
        $environment = $config['environment'] ?? 'production';
        $serviceName = $config['service_name'] ?? 'laravel-app';
        
        // Create AllStak client
        $allStakClient = new AllStakClient($apiKey, $environment, true, $serviceName);
        
        // Create Monolog Logger with custom handler
        $logger = new Logger('allstak');
        $logger->pushHandler(new AllStakLogHandler($allStakClient));
        
        return $logger;
    }
}
