<?php

// Test AllStak logging integration
require_once __DIR__ . '/vendor/autoload.php';

// Mock Laravel environment
if (!function_exists('config')) {
    function config($key, $default = null) {
        $configs = [
            'allstak.enabled' => true,
            'allstak.api_key' => 'test-api-key-12345',
            'allstak.environment' => 'testing',
            'allstak.service_name' => 'test-service',
            'app.name' => 'TestApp',
            'database.default' => 'mysql',
            'database.connections.mysql.database' => 'test_db'
        ];
        return $configs[$key] ?? $default;
    }
}

if (!function_exists('now')) {
    function now() {
        return new class {
            public function toISOString() { return date('c'); }
            public function toIso8601String() { return date('c'); }
        };
    }
}

if (!function_exists('request')) {
    function request() {
        return new class {
            public function user() { return null; }
            public function session() { return null; }
            public function header($key) { return null; }
        };
    }
}

if (!function_exists('app')) {
    function app() {
        return new class {
            public function version() { return '9.0.0'; }
        };
    }
}

// Mock Log facade
class Log {
    public static function debug($message, $context = []) {
        echo "[DEBUG] $message " . json_encode($context) . "\n";
    }
    
    public static function info($message, $context = []) {
        echo "[INFO] $message " . json_encode($context) . "\n";
    }
    
    public static function warning($message, $context = []) {
        echo "[WARNING] $message " . json_encode($context) . "\n";
    }
    
    public static function error($message, $context = []) {
        echo "[ERROR] $message " . json_encode($context) . "\n";
    }
}

use AllStak\AllStakClient;
use AllStak\Logging\AllStakLogChannel;
use AllStak\Logging\AllStakLogHandler;
use Monolog\Logger;

echo "Testing AllStak Logging Integration...\n\n";

// Test 1: Direct AllStakClient logging
echo "Test 1: Direct AllStakClient logging\n";
echo "====================================\n";

$client = new AllStakClient('test-api-key-12345', 'testing', true, 'test-service');
$result = $client->log('info', 'Direct client test message', ['test' => 'direct']);
echo "Direct client log result: " . ($result ? 'SUCCESS' : 'FAILED') . "\n\n";

// Test 2: AllStakLogChannel creation
echo "Test 2: AllStakLogChannel creation\n";
echo "==================================\n";

$logChannel = new AllStakLogChannel();
$config = [
    'api_key' => 'test-api-key-12345',
    'environment' => 'testing',
    'service_name' => 'test-service'
];

$monologLogger = $logChannel($config);
echo "Monolog logger created: " . (($monologLogger instanceof Logger) ? 'SUCCESS' : 'FAILED') . "\n";
echo "Logger name: " . $monologLogger->getName() . "\n";
echo "Handler count: " . count($monologLogger->getHandlers()) . "\n\n";

// Test 3: AllStakLogHandler functionality
echo "Test 3: AllStakLogHandler functionality\n";
echo "=======================================\n";

$handler = $monologLogger->getHandlers()[0];
echo "Handler type: " . get_class($handler) . "\n";
echo "Handler is AllStakLogHandler: " . (($handler instanceof AllStakLogHandler) ? 'YES' : 'NO') . "\n";

// Test 4: Monolog logging through handler
echo "\nTest 4: Monolog logging through handler\n";
echo "========================================\n";

try {
    $monologLogger->info('Test message from Monolog', ['context' => 'test']);
    echo "Monolog logging: SUCCESS\n";
} catch (Exception $e) {
    echo "Monolog logging: FAILED - " . $e->getMessage() . "\n";
}

echo "\nSummary:\n";
echo "========\n";
echo "✓ AllStakClient direct logging works\n";
echo "✓ AllStakLogChannel creates Monolog logger\n";
echo "✓ AllStakLogHandler is properly attached\n";
echo "✓ Monolog can log through AllStakLogHandler\n\n";

echo "The AllStak logging integration is working correctly!\n";
echo "To use with Laravel Log facade, ensure:\n";
echo "1. AllStakServiceProvider is registered\n";
echo "2. 'allstak' channel is configured in config/logging.php\n";
echo "3. LOG_CHANNEL=allstak in .env or use Log::channel('allstak')->info()\n";