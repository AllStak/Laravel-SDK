<?php

namespace Techsea\AllStak\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Techsea\AllStak\AllStakClient;

class AllStakMiddleware
{
    protected $allstack;

    protected $excludePaths = [
        '_debugbar*',
        '_ignition*',
        'horizon*',
        'nova*',
        'telescope*',
        'health*',
        'api/health*',
    ];

    protected $excludeExtensions = [
        'css', 'js', 'ico', 'png', 'jpg', 'jpeg', 'gif', 'svg',
        'woff', 'woff2', 'ttf', 'eot', 'map', 'txt'
    ];

    public function __construct(AllStakClient $allstack)
    {
        $this->allstack = $allstack;
    }

    public function handle($request, Closure $next)
    {
        if ($this->shouldSkip($request)) {
            return $next($request);
        }

        try {
            $response = $next($request);
            $this->allstack->captureRequest($request);
            return $response;
        } catch (\Throwable $e) {
            // Let the exception bubble up.
            throw $e;
        }
    }

    protected function shouldSkip($request)
    {
        // Skip preflight (OPTIONS) requests.
        if (method_exists($request, 'isMethod') && $request->isMethod('OPTIONS')) {
            return true;
        }

        // Skip excluded paths.
        foreach ($this->excludePaths as $path) {
            if (method_exists($request, 'is') && $request->is($path)) {
                return false;
            }
        }

        // Skip static assets.
        $path = $request->getPathInfo();
        $extension = pathinfo($path, PATHINFO_EXTENSION);
        if (in_array(strtolower($extension), $this->excludeExtensions)) {
            return true;
        }

        return false;
    }
}
