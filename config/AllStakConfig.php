<?php

/**
 * AllStak Laravel SDK v2.0 Configuration
 *
 * Complete observability for your Laravel application.
 *
 * @see https://docs.allstak.io for full documentation
 */

return [
    // Authentication
    'api_key' => env('ALLSTAK_API_KEY', ''),
    'project_id' => env('ALLSTAK_PROJECT_ID', ''),
    'environment' => env('ALLSTAK_ENV', env('APP_ENV', 'production')),
    'endpoint' => 'http://localhost:8080/api/v2/ingest',

    // Automatic features
    'capture_http' => env('ALLSTAK_CAPTURE_HTTP', true),
    'capture_errors' => env('ALLSTAK_CAPTURE_ERRORS', true),
    'capture_logs' => env('ALLSTAK_CAPTURE_LOGS', true),
    'capture_database' => env('ALLSTAK_CAPTURE_DATABASE', true),

    // Performance
    'sample_rate' => env('ALLSTAK_SAMPLE_RATE', 1.0), // 0.0 to 1.0
    'batch_size' => env('ALLSTAK_BATCH_SIZE', 100),
    'flush_interval' => env('ALLSTAK_FLUSH_INTERVAL', 5000), // milliseconds

    // Privacy
    'send_client_ip' => env('ALLSTAK_SEND_CLIENT_IP', true),
    'anonymize_ip' => env('ALLSTAK_ANONYMIZE_IP', false),
    'scrub_headers' => env('ALLSTAK_SCRUB_HEADERS', 'Authorization,Cookie'),

    // Context
    'tags' => [
        'version' => env('APP_VERSION', '1.0.0'),
        'service_name' => env('ALLSTAK_SERVICE_NAME', env('APP_NAME', 'laravel-app')),
    ],

    // Advanced
    'enabled' => env('ALLSTAK_ENABLED', true),
    'timeout' => env('ALLSTAK_TIMEOUT', 5),
    'excluded_paths' => env('ALLSTAK_EXCLUDED_PATHS', '/health,/metrics'),
];
