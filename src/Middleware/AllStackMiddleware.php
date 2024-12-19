<?php

namespace Techsea\AllStack\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
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
        'telescope',
        'health',
        'api/health',
    ];

    private $excludeExtensions = [
        'css',
        'js',
        'ico',
        'png',
        'jpg',
        'jpeg',
        'gif',
        'svg',
        'woff',
        'woff2',
        'ttf',
        'eot'
    ];

    public function __construct(AllStackClient $allstack)
    {
        $this->allstack = $allstack;
    }

    public function handle(Request $request, Closure $next)
    {
        // Skip if it's an excluded path or asset
        if ($this->shouldSkip($request)) {
            return $next($request);
        }

        try {
            // Process the request first
            $response = $next($request);

            // Then capture everything in one go
            $this->captureRequestData($request, $response);

            return $response;

        } catch (\Throwable $e) {
            Log::error('AllStack middleware error: ' . $e->getMessage(), [
                'exception' => $e
            ]);
            
            // Don't break the application if our monitoring fails
            return $next($request);
        }
    }

    private function captureRequestData(Request $request, $response): void
    {
        try {
            // Capture the request immediately instead of dispatching
            $result = $this->allstack->captureRequest($request);
            
            if (!$result) {
                Log::warning('Failed to capture request in AllStack');
            }
        } catch (\Throwable $e) {
            Log::error('Error capturing request in AllStack: ' . $e->getMessage(), [
                'exception' => $e
            ]);
        }
    }

    private function shouldSkip(Request $request): bool
    {
        // Skip excluded paths
        foreach ($this->excludePaths as $path) {
            if ($request->is($path.'*')) {
                return true;
            }
        }

        // Skip asset files
        $extension = strtolower(pathinfo($request->path(), PATHINFO_EXTENSION));
        if (in_array($extension, $this->excludeExtensions)) {
            return true;
        }

        // Skip if it's an OPTIONS request
        if ($request->isMethod('OPTIONS')) {
            return true;
        }

        // Skip if it's a health check
        if ($request->is('health*') || $request->is('*/health*')) {
            return true;
        }

        return false;
    }
}