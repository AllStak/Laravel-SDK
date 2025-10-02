<?php

namespace AllStak\Tracing;

// Add HTTPClientSpanRecorder.php
use AllStak\AllStakClient;
use Illuminate\Support\Facades\Http;

Http::macro('traced', function () {
    return Http::withMiddleware(function ($request, $next) {
        $span = app(AllStakClient::class)->startSpan('http.client', 'HTTP Request');
        $response = $next($request);
        app(AllStakClient::class)->finishSpan($span);
        return $response;
    });
});
