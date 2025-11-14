<?php

namespace AllStak\Middleware;

use AllStak\AllStakClient;
use AllStak\Tracing\SpanContext;
use Closure;
use Illuminate\Http\Request;

class AllStakMiddleware
{
    private AllStakClient $client;

    public function __construct(AllStakClient $client)
    {
        $this->client = $client;
    }

    public function handle(Request $request, Closure $next)
    {
        // Check if path should be excluded
        $excludedPaths = explode(',', config('allstak.excluded_paths', ''));
        foreach ($excludedPaths as $path) {
            if ($request->is(trim($path))) {
                return $next($request);
            }
        }

        // Generate or extract trace ID from headers
        $traceId = $request->header('X-Trace-ID') ??
                   $request->header('traceparent') ??
                   $this->client->generateTraceId();

        $spanId = $this->client->generateSpanId();

        // Set trace context
        SpanContext::setTraceId($traceId);
        $request->headers->set('X-Trace-ID', $traceId);

        $startTime = microtime(true);

        try {
            $response = $next($request);

            $duration = microtime(true) - $startTime;

            // Capture successful request
            $this->client->captureRequest($request, $response, $duration, $traceId, $spanId);

            // Add trace ID to response headers
            if (method_exists($response, 'header')) {
                $response->header('X-Trace-ID', $traceId);
            }

            return $response;
        } catch (\Throwable $e) {
            $duration = microtime(true) - $startTime;

            // Capture error
            $this->client->captureError($e, $request, [
                'traceId' => $traceId,
                'spanId' => $spanId,
                'handled' => false,
                'mechanism' => 'middleware',
            ]);

            throw $e;
        } finally {
            SpanContext::clear();
        }
    }
}

