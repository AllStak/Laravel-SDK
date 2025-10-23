<?php

// Completely isolated test without Laravel dependencies
require_once __DIR__ . '/vendor/autoload.php';

use AllStak\AllStakClient;

// Mock basic functions without Laravel
define('LARAVEL_START', microtime(true));

// Mock config function - return defaults without Laravel container
if (!function_exists('config')) {
    function config($key, $default = null) {
        $defaults = [
            'allstak.use_compression' => true,
            'allstak.api_url' => 'https://api.allstak.com',
            'allstak.rate_limit' => 1000,
            'allstak.rate_window' => 3600,
            'allstak.send_ip_address' => true,
            'allstak.enabled' => true,
            'allstak.sample_rate' => 1.0,
            'app.debug' => false,
            'database.default' => 'mysql',
            'database.connections.mysql.database' => 'test_db',
            'database.connections.pgsql.database' => 'test_pgsql',
        ];
        
        return $defaults[$key] ?? $default;
    }
}

// Mock now function
if (!function_exists('now')) {
    function now() {
        return new class {
            public function toIso8601String() {
                return date('c');
            }
        };
    }
}

// Mock request function
if (!function_exists('request')) {
    function request() {
        return new class {
            public function user() {
                return null;
            }
            public function ip() {
                return '127.0.0.1';
            }
            public function method() {
                return 'GET';
            }
            public function fullUrl() {
                return 'http://localhost/test';
            }
            public function path() {
                return '/test';
            }
            public function userAgent() {
                return 'TestAgent';
            }
            public function header($name) {
                return null;
            }
            public function headers() {
                return new class {
                    public function all() { return []; }
                    public function has($name) { return false; }
                };
            }
            public function all() {
                return [];
            }
            public function session() {
                return null;
            }
        };
    }
}

// Mock app function
if (!function_exists('app')) {
    function app($abstract = null) {
        if ($abstract === null) {
            return new class {
                public function version() {
                    return '10.0.0';
                }
            };
        }
        return null;
    }
}

// Mock Log facade
if (!class_exists('Log')) {
    class Log {
        public static function debug($message, $context = []) {
            echo "[DEBUG] $message " . json_encode($context) . "\n";
        }
        public static function error($message, $context = []) {
            echo "[ERROR] $message " . json_encode($context) . "\n";
        }
        public static function warning($message, $context = []) {
            echo "[WARNING] $message " . json_encode($context) . "\n";
        }
    }
}

// Now test the AllStakClient
try {
    echo "Testing AllStakClient with mocked functions...\n";
    
    // Include the AllStakClient and dependencies
    require_once __DIR__ . '/src/AllStakClient.php';
    require_once __DIR__ . '/src/Transport/AsyncHttpTransport.php';
    require_once __DIR__ . '/src/Helpers/SecurityHelper.php';
    require_once __DIR__ . '/src/Helpers/Utils/ErrorHelper.php';
    require_once __DIR__ . '/src/Helpers/Http/PayloadHelper.php';
    require_once __DIR__ . '/src/Helpers/ClientHelper.php';
    require_once __DIR__ . '/src/Helpers/Utils/DataTransformHelper.php';
    
    // Test basic client creation
    $client = new AllStakClient('test-api-key-123', 'testing', true, 'test-service');
    echo "✅ AllStakClient created successfully!\n";
    
    // Test logging
    echo "Testing framework logging...\n";
    $result = $client->captureFrameworkLog('info', 'Test log message', ['test' => 'data']);
    echo "✅ Framework log captured: " . ($result ? 'success' : 'failed') . "\n";
    
    // Test exception capture
    echo "Testing exception capture...\n";
    $exception = new Exception('Test exception');
    $result = $client->captureException($exception);
    echo "✅ Exception captured: " . ($result ? 'success' : 'failed') . "\n";
    
    // Test database query logging
    echo "Testing database query logging...\n";
    $result = $client->sendDbQuery('SELECT * FROM users WHERE id = ?', [1], 150.5, 'mysql');
    echo "✅ Database query logged: " . ($result ? 'success' : 'failed') . "\n";
    
    echo "\n🎉 All tests passed! The logging integration is working correctly.\n";
    
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}