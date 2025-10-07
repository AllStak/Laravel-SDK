<?php

return [
    'api_key' => env('ALLSTAK_API_KEY', ''),
    'environment' => env('ALLSTAK_ENV', app()->environment()),
    'SEND_IP_ADDRESS' => env('ALLSTAK_SEND_IP_ADDRESS', true),

    'enabled' => env('ALLSTAK_ENABLED', true), // Allow disabling in dev
    'queue_enabled' => env('ALLSTAK_QUEUE_ENABLED', false), // Async sending
    'sample_rate' => env('ALLSTAK_SAMPLE_RATE', 1.0), // Sampling for high traffic
    'timeout' => env('ALLSTAK_TIMEOUT', 5), // Request timeout
    'max_payload_size' => env('ALLSTAK_MAX_PAYLOAD_SIZE', 10000), // Bytes
    'excluded_paths' => env('ALLSTAK_EXCLUDED_PATHS', '/health,/metrics'), // Skip certain routes
];
