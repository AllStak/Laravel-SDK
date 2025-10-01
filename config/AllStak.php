<?php

return [
    /*
    |--------------------------------------------------------------------------
    | AllStak API Key
    |--------------------------------------------------------------------------
    |
    | This is your AllStack API key which will be used to authenticate
    | your requests to the AllStack service.
    |
    */
    'api_key' => env('ALLSTAK_API_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Environment
    |--------------------------------------------------------------------------
    |
    | This is the environment your application is running in. This helps
    | to separate logs from different environments.
    |
    */
    'environment' => env('ALLSTAC_ENVIRONMENT', app()->environment()),
];