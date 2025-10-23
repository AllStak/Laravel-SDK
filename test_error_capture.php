<?php

// Mock Laravel functions for testing BEFORE requiring autoload
if (!function_exists('config')) {
    function config($key, $default = null) {
        $configs = [
            'allstak.api_key' => 'test-api-key',
            'allstak.environment' => 'test',
            'allstak.enabled' => true,
            'allstak.sample_rate' => 1.0,
            'allstak.timeout' => 30,
            'allstak.max_payload_size' => 1024000,
            'allstak.use_compression' => true,
            'allstak.compression_level' => 6,
            'database.connections.mysql.database' => 'test_db',
            'database.default' => 'mysql'
        ];
        return $configs[$key] ?? $default;
    }
}

if (!function_exists('now')) {
    function now() {
        return new class {
            public function toIso8601String() {
                return date('c');
            }
        };
    }
}

if (!function_exists('app')) {
    function app() {
        return new class {
            public function version() {
                return '9.0.0';
            }
        };
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
            public function header($key) { return null; }
            public function all() { return []; }
            public function user() { return null; }
            public function headers() {
                return new class {
                    public function all() { return []; }
                };
            }
        };
    }
}

require_once __DIR__ . '/vendor/autoload.php';

use AllStak\AllStakClient;
use AllStak\Helpers\Security\SecurityHelper;
use AllStak\Helpers\Utils\ErrorHelper;
use AllStak\Helpers\Http\PayloadHelper;
use AllStak\Helpers\ClientHelper;
use AllStak\Helpers\Utils\TracingHelper;
use AllStak\Helpers\Utils\RateLimitingHelper;
use AllStak\Transport\AsyncHttpTransport;

// Mock Log facade
class Log {
    public static function debug($message, $context = []) {
        echo "[DEBUG] $message\n";
        if (!empty($context)) {
            echo "Context: " . json_encode($context, JSON_PRETTY_PRINT) . "\n";
        }
    }
    
    public static function error($message, $context = []) {
        echo "[ERROR] $message\n";
        if (!empty($context)) {
            echo "Context: " . json_encode($context, JSON_PRETTY_PRINT) . "\n";
        }
    }
    
    public static function warning($message, $context = []) {
        echo "[WARNING] $message\n";
        if (!empty($context)) {
            echo "Context: " . json_encode($context, JSON_PRETTY_PRINT) . "\n";
        }
    }
}

// Mock Cache facade
class Cache {
    private static $cache = [];
    
    public static function get($key, $default = null) {
        return self::$cache[$key] ?? $default;
    }
    
    public static function put($key, $value, $ttl = null) {
        self::$cache[$key] = $value;
    }
    
    public static function forget($key) {
        unset(self::$cache[$key]);
    }
}

// Set up facade root to prevent facade errors
if (class_exists('Illuminate\Support\Facades\Facade')) {
    $app = new class {
        private $bindings = [];
        
        public function bind($abstract, $concrete) {
            $this->bindings[$abstract] = $concrete;
        }
        
        public function make($abstract) {
            return $this->bindings[$abstract] ?? null;
        }
    };
    
    \Illuminate\Support\Facades\Facade::setFacadeApplication($app);
}

// Test error capturing
echo "Testing AllStak Error Capturing...\n\n";

try {
    // Create AllStak client
    $client = new AllStakClient('test-api-key-12345', 'test', true, 'test-service');
    
    // Test 1: Basic exception capture
    echo "Test 1: Basic Exception Capture\n";
    echo "================================\n";
    
    try {
        throw new Exception("Test exception with sensitive data: password=secret123");
    } catch (Exception $e) {
        $result = $client->captureException($e);
        echo "Exception captured: " . ($result ? "SUCCESS" : "FAILED") . "\n\n";
    }
    
    // Test 2: Database exception simulation
    echo "Test 2: Database Exception Simulation\n";
    echo "=====================================\n";
    
    $dbException = new class extends Exception {
        public function getSql() {
            return "SELECT * FROM users WHERE password = 'secret123'";
        }
        
        public function getBindings() {
            return ['password' => 'secret123', 'email' => 'test@example.com'];
        }
    };
    
    try {
        throw $dbException;
    } catch (Exception $e) {
        $result = $client->captureException($e);
        echo "Database exception captured: " . ($result ? "SUCCESS" : "FAILED") . "\n\n";
    }
    
    // Test 3: HTTP exception simulation
    echo "Test 3: HTTP Exception Simulation\n";
    echo "=================================\n";
    
    $httpException = new class extends Exception {
        public function getStatusCode() {
            return 404;
        }
    };
    
    try {
        throw $httpException;
    } catch (Exception $e) {
        $result = $client->captureException($e);
        echo "HTTP exception captured: " . ($result ? "SUCCESS" : "FAILED") . "\n\n";
    }
    
    // Test 4: Request capture
    echo "Test 4: Request Capture\n";
    echo "======================\n";
    
    $result = $client->captureRequest();
    echo "Request captured: " . ($result ? "SUCCESS" : "FAILED") . "\n\n";
    
    // Test 5: Logging functionality
    echo "Test 5: Logging Functionality\n";
    echo "=============================\n";
    
    $client->log('info', 'Test log message with trace_id', ['user_id' => 123], 'test-trace-123');
    echo "Log message sent\n\n";
    
    echo "All tests completed!\n";
    
} catch (Exception $e) {
    echo "Test failed with error: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}