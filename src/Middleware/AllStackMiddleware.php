<?php

namespace Techsea\AllStack\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Techsea\AllStack\AllStackClient;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

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

        // Generate unique request ID
        $requestId = $this->generateRequestId();
        $startTime = microtime(true);

        try {
            // Add basic request information
            $this->allstack
                ->setTag('request_id', $requestId)
                ->setTag('route', $request->route()?->getName() ?? 'unnamed')
                ->setTag('method', $request->method())
                ->setTag('url', $request->fullUrl());

            // Process the request
            $response = $next($request);

            // Add response information
            $duration = (microtime(true) - $startTime) * 1000;
            $statusCode = $response->status();

            $this->allstack
                ->setTag('duration', number_format($duration, 2).'ms')
                ->setTag('status_code', (string)$statusCode)
                ->setTag('content_type', $response->headers->get('Content-Type', 'unknown'));

            // Add performance metrics
            if (function_exists('memory_get_peak_usage')) {
                $this->allstack->setTag('memory_peak', 
                    $this->formatBytes(memory_get_peak_usage(true))
                );
            }

            // Capture slow requests specifically
            if ($duration > 1000) { // 1 second threshold
                $this->allstack->setTag('performance_alert', 'slow_request');
            }

            // Capture client information
            if ($request->hasHeader('User-Agent')) {
                $this->allstack->setTag('user_agent', $request->header('User-Agent'));
            }
            
            // Add session information if available
            if ($request->hasSession()) {
                $this->allstack->setTag('session_id', $request->session()->getId());
            }

            // Capture the request asynchronously
            dispatch(function() use ($request, $response) {
                try {
                    // Add response size for non-streaming responses
                    if (!$response->headers->has('Transfer-Encoding')) {
                        $this->allstack->setTag('response_size', 
                            $this->formatBytes(strlen($response->getContent()))
                        );
                    }
                    
                    $this->allstack->captureRequest($request);
                } catch (\Throwable $e) {
                    Log::error('Failed to capture request in AllStack: ' . $e->getMessage());
                }
            })->afterResponse();

            return $response;

        } catch (\Throwable $e) {
            Log::error('AllStack middleware error: ' . $e->getMessage(), [
                'request_id' => $requestId,
                'exception' => $e
            ]);
            
            // Don't break the application if our monitoring fails
            return $next($request);
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

    private function generateRequestId(): string
    {
        return sprintf(
            'req_%s_%s',
            date('Ymd_His'),
            substr(md5(uniqid()), 0, 8)
        );
    }

    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        
        return sprintf(
            '%.2f %s',
            $bytes / pow(1024, $pow),
            $units[$pow]
        );
    }
}