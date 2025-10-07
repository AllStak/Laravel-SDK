<?php

namespace AllStak\Middleware;

use AllStak\AllStakClient;
use AllStak\Tracing\SpanContext;
use Closure;
use Illuminate\Http\Request;

class AllStakTracingMiddleware
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

        // Add trace ID to request headers
        $request->headers->set('X-Trace-ID', $traceId);

        // FIXED: Use startSpan correctly - it only accepts name and optional parentSpanId
        $span = $this->client->startSpan('http.request', null);

        // Add attributes to the span
        $span->setAttribute('method', $request->method());
        $span->setAttribute('url', $request->fullUrl());
        $span->setAttribute('ip', $request->ip());
        $span->setAttribute('user_agent', $request->userAgent());

        try {
            $response = $next($request);

            $span->setAttribute('status_code', $response->getStatusCode());
            $span->setStatus('ok');

            // Add trace ID to response
            if (method_exists($response, 'header')) {
                $response->header('X-Trace-ID', $traceId);
            }

            return $response;
        } catch (\Throwable $e) {
            $span->setStatus('error');
            $span->recordException($e);
            $this->client->captureException($e, $request, $traceId);
            throw $e;
        } finally {
            // FIXED: Use endSpan to send the Span object
            $span->end();
            $this->client->endSpan($span);
            SpanContext::clear();
        }
    }
}
