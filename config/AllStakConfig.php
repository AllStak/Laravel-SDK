<?php

return [
    'api_key' => env('ALLSTAK_API_KEY', ''),
    'environment' => env('ALLSTAK_ENV', env('APP_ENV', 'production')),
    'SEND_IP_ADDRESS' => env('ALLSTAK_SEND_IP_ADDRESS', true),

    // Sampling configuration
    'sampling_rate' => env('ALLSTAK_SAMPLING_RATE', 0.1), // 10% by default

    // Enable/disable features
    'enable_db_tracing' => env('ALLSTAK_DB_TRACING', true),
    'enable_http_tracing' => env('ALLSTAK_HTTP_TRACING', true),

    // Performance thresholds
    'slow_request_threshold' => env('ALLSTAK_SLOW_REQUEST_MS', 1000),
    'release' => env('ALLSTAK_RELEASE', env('APP_VERSION')),
    'git_commit' => env('GIT_COMMIT_SHA'),

    // Paths to exclude from tracing
    'excluded_paths' => [
        '/health',
        '/healthcheck',
        '/ping',
    ],
];
