<?php
namespace AllStak\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use AllStak\AllStakClient;
use AllStak\Tracing\SpanContext;

class AllStakTracingMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $client = app(AllStakClient::class);
        // Generate unique trace and span IDs
        $traceId = bin2hex(random_bytes(16));
        $spanId = bin2hex(random_bytes(8));
        SpanContext::setTraceId($traceId);
        SpanContext::setParentSpanId($spanId);

        // Start the root span for the HTTP request
        $span = $client->startSpan('http.request', $traceId, null, $spanId);
        $span->setAttribute('method', $request->method());
        $span->setAttribute('url', $request->fullUrl());
        $span->setAttribute('ip', $request->ip());
        $span->setAttribute('user_agent', $request->userAgent());

        try {
            $response = $next($request);
            $span->setAttribute('status_code', $response->getStatusCode());
            $span->setStatus('ok');
            return $response;
        } catch (\Throwable $e) {
            $span->setStatus('error');
            $span->recordException($e);
            $client->captureException($e);
            throw $e;
        } finally {
            $span->end();
            $client->sendSpan($span);
            SpanContext::clear(); // Clean up after the request
        }
    }
}
