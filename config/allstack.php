<?php

return [
    'services' => [
        'allstack' => [
            'api_key' => env('ALLSTACK_API_KEY'),
            'environment' => env('ALLSTACK_ENVIRONMENT', 'production'),
        ],
    ],
];