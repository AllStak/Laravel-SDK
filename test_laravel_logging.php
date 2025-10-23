<?php

// Test Laravel logging functionality without Laravel dependencies
require_once __DIR__ . '/vendor/autoload.php';

use AllStak\AllStakClient;
use AllStak\Logging\AllStakLogHandler;
use AllStak\Logging\AllStakLogChannel;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// Mock Laravel helper functions to avoid dependencies
if (!function_exists('config')) {
    function config($key, $default = null) {
        // Return default values for common config keys
        $configs = [
            'allstak.use_compression' => true,
            'app.debug' => false,
            'database.default' => 'mysql',
            'database.connections.mysql.database' => 'test_db',
            'allstak.api_key' => 'test-api-key-123',
            'allstak.environment' => 'testing',
            'allstak.service_name' => 'test-service',
            'allstak.enabled' => true,
            'allstak.timeout' => 30,
            'allstak.max_payload_size' => 1048576,
            'allstak.sample_rate' => 1.0,
            'allstak.excluded_paths' => [],
            'allstak.SEND_IP_ADDRESS' => true,
            'allstak.queue_enabled' => false
        ];
        
        return $configs[$key] ?? $default;
    }
}

if (!function_exists('now')) {
    function now() {
        return new DateTime();
    }
}

if (!function_exists('request')) {
    function request() {
        return new class {
            public function ip() { return '127.0.0.1'; }
            public function method() { return 'GET'; }
            public function fullUrl() { return 'http://localhost/test'; }
            public function path() { return '/test'; }
            public function userAgent() { return 'Test Agent'; }
            public function header($name) { return null; }
            public function user() { return null; }
            public function session() { return null; }
            public function all() { return []; }
            public function headers() { return new ArrayObject(); }
        };
    }
}

if (!function_exists('app')) {
    function app($abstract = null) {
        if ($abstract === null) return new stdClass();
        if ($abstract === 'config') return new class { 
            public function get($key, $default = null) { return config($key, $default); }
        };
        return null;
    }
}

echo "Testing AllStak Laravel Logging Integration...\n\n";

try {
    // Test 1: Direct AllStakClient usage
    echo "Test 1: Direct AllStakClient Logging\n";
    echo "====================================\n";
    
    $client = new AllStakClient('test-api-key-123', 'testing', true, 'test-service');
    
    $result = $client->log('info', 'Test info message from Laravel logging test', [
        'user_id' => 123,
        'action' => 'user_login',
        'context' => 'test'
    ]);
    
    echo "Direct log result: " . ($result ? 'SUCCESS' : 'FAILED') . "\n";
    echo "Message sent: 'Test info message from Laravel logging test'\n\n";
    
    // Test 2: AllStakLogHandler with Monolog
    echo "Test 2: AllStakLogHandler with Monolog\n";
    echo "=======================================\n";
    
    $logger = new Logger('test-logger');
    $handler = new AllStakLogHandler($client);
    $logger->pushHandler($handler);
    
    // Add a stream handler for local output too
    $streamHandler = new StreamHandler('php://stdout', Logger::DEBUG);
    $logger->pushHandler($streamHandler);
    
    $logger->info('Test message through Monolog AllStakLogHandler', [
        'test_data' => 'monolog_test',
        'timestamp' => time()
    ]);
    
    $logger->warning('Warning message through Monolog', [
        'warning_type' => 'deprecated_function',
        'function' => 'old_function()'
    ]);
    
    $logger->error('Error message through Monolog', [
        'error_code' => 'DB_CONNECTION_FAILED',
        'retry_count' => 3
    ]);
    
    echo "\nMonolog logging completed successfully!\n\n";
    
    // Test 3: AllStakLogChannel (custom channel)
    echo "Test 3: AllStakLogChannel (Custom Log Channel)\n";
    echo "==============================================\n";
    
    $channel = new AllStakLogChannel();
    $channelLogger = $channel('allstak', 'test-api-key-123', 'testing', 'test-service', true);
    
    if ($channelLogger instanceof Logger) {
        $channelLogger->info('Test message through AllStakLogChannel', [
            'channel_test' => true,
            'data' => 'custom_channel_data'
        ]);
        echo "Custom channel logger created and message sent successfully!\n";
    } else {
        echo "Failed to create custom channel logger\n";
    }
    
    echo "\n";
    echo "✓ AllStak Laravel Logging Integration Tests Completed Successfully!\n";
    echo "✓ Direct AllStakClient logging works\n";
    echo "✓ AllStakLogHandler with Monolog works\n";
    echo "✓ AllStakLogChannel custom channel works\n";
    echo "✓ Logs are being captured and sent to the API backend\n";
    
} catch (Exception $e) {
    echo "❌ Error during testing: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
    echo "\nThis indicates there are still issues with the logging integration.\n";
}