<?php

// Laravel route test for AllStak logging
// Add this to your routes/web.php file

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;

Route::get('/test-allstak-logging', function () {
    try {
        // Test 1: Default log channel (should work if LOG_CHANNEL=allstak)
        Log::info("Test message from default channel", [
            'test_type' => 'default_channel',
            'timestamp' => now()->toISOString()
        ]);
        
        // Test 2: Specific AllStak channel
        Log::channel('allstak')->info("Test message from AllStak channel", [
            'test_type' => 'allstak_channel',
            'timestamp' => now()->toISOString()
        ]);
        
        // Test 3: Different log levels
        Log::channel('allstak')->debug("Debug message", ['level' => 'debug']);
        Log::channel('allstak')->warning("Warning message", ['level' => 'warning']);
        Log::channel('allstak')->error("Error message", ['level' => 'error']);
        
        // Test 4: Direct AllStak client (for comparison)
        $client = app(\AllStak\AllStakClient::class);
        $directResult = $client->captureFrameworkLog('info', 'Direct AllStak client test', [
            'test_type' => 'direct_client',
            'timestamp' => now()->toISOString()
        ]);
        
        return response()->json([
            'message' => 'AllStak logging tests completed',
            'tests' => [
                'default_channel' => 'executed',
                'allstak_channel' => 'executed', 
                'log_levels' => 'executed',
                'direct_client' => $directResult ? 'success' : 'failed'
            ],
            'instructions' => [
                'Check your AllStak dashboard for the log entries',
                'Verify that all log levels appear correctly',
                'Compare direct client vs channel logging'
            ],
            'timestamp' => now()
        ]);
        
    } catch (\Exception $e) {
        return response()->json([
            'error' => 'Logging test failed',
            'message' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ], 500);
    }
});

// Configuration check route
Route::get('/test-allstak-config', function () {
    return response()->json([
        'config' => [
            'allstak_enabled' => config('allstak.enabled', 'not_set'),
            'allstak_api_key' => config('allstak.api_key') ? 'set' : 'not_set',
            'log_channel' => config('logging.default'),
            'allstak_channel_exists' => array_key_exists('allstak', config('logging.channels', [])),
        ],
        'env_vars' => [
            'LOG_CHANNEL' => env('LOG_CHANNEL'),
            'ALLSTAK_API_KEY' => env('ALLSTAK_API_KEY') ? 'set' : 'not_set',
            'ALLSTAK_ENV' => env('ALLSTAK_ENV'),
            'ALLSTAK_SERVICE_NAME' => env('ALLSTAK_SERVICE_NAME'),
        ],
        'service_provider' => [
            'allstak_client_bound' => app()->bound(\AllStak\AllStakClient::class),
            'log_manager_available' => app()->bound('log'),
        ]
    ]);
});