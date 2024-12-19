<?php

namespace Techsea\AllStack\Middleware;

use Closure;
use Illuminate\Http\Request;
use Techsea\AllStack\AllStackClient;
use Illuminate\Support\Facades\Log;

class AllStackMiddleware
{
    private $allstack;
    private $excludePaths = [
        '_debugbar',
        '_ignition',
        'horizon',
        'nova',
        'telescope'
    ];

    public function __construct(AllStackClient $allstack)
    {
        $this->allstack = $allstack;
    }

    public function handle(Request $request, Closure $next)
    {
        // Skip tracking for excluded paths
        foreach ($this->excludePaths as $path) {
            if ($request->is($path.'*')) {
                return $next($request);
            }
        }

        try {
            // Add performance tracking
            $startTime = microtime(true);
            
            // Add request identifier
            $requestId = uniqid('req_', true);
            $this->allstack->setTag('request_id', $requestId);
            
            // Process the request
            $response = $next($request);
            
            // Calculate request duration
            $duration = microtime(true) - $startTime;
            $this->allstack->setTag('duration', number_format($duration * 1000, 2).'ms');
            
            // Add response status
            if (method_exists($response, 'status')) {
                $this->allstack->setTag('status_code', (string)$response->status());
            }

            // Capture the request asynchronously
            dispatch(function() use ($request) {
                $this->allstack->captureRequest($request);
            })->afterResponse();

            return $response;

        } catch (\Throwable $e) {
            Log::error('AllStack middleware error: ' . $e->getMessage());
            return $next($request);
        }
    }
}