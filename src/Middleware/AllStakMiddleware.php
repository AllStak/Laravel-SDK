<?php

namespace AllStak\Tracing\Middleware;

use AllStak\Tracing\AllStakClient;
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
        // Generate or get trace ID
        $traceId = $request->header('X-Trace-ID') ?? $this->client->generateTraceId();
        SpanContext::setTraceId($traceId);

        // Add trace ID to response headers
        $request->headers->set('X-Trace-ID', $traceId);

        $startTime = microtime(true);

        try {
            $response = $next($request);

            $duration = microtime(true) - $startTime;

            // Log successful request
            $this->client->captureRequest($request, $response, $duration, $traceId);

            // Add trace ID to response
            if (method_exists($response, 'header')) {
                $response->header('X-Trace-ID', $traceId);
            }

            return $response;
        } catch (\Throwable $exception) {
            $duration = microtime(true) - $startTime;

            // Log error with same trace ID
            $this->client->captureException($exception, $request, $traceId);

            throw $exception;
        } finally {
            SpanContext::clear();
        }
    }
}
