<?php

namespace AllStak\Middleware;

use Closure;
use Illuminate\Http\Request;
use AllStak\AllStakClient;
use AllStak\Tracing\SpanContext;

class AllStakTracingMiddleware
{
    protected $client;

    public function __construct(AllStakClient $client)
    {
        $this->client = $client;
    }

    public function handle(Request $request, Closure $next)
    {
        // Generate trace and span IDs
        $traceId = bin2hex(random_bytes(16));
        $spanId = bin2hex(random_bytes(8));

        // Set context
        SpanContext::setTraceId($traceId);
        SpanContext::setParentSpanId(null);

        // Start transaction (not just a span)
        $transaction = $this->client->startTransaction(
            $request->method() . ' ' . $request->path(),
            'http.request',
            [
                'http.method' => $request->method(),
                'http.url' => $request->fullUrl(),
                'http.ip' => $request->ip(),
                'http.user_agent' => $request->userAgent(),
            ]
        );

        try {
            $response = $next($request);

            // Add status code to transaction
            $transaction['attributes']['http.status_code'] = $response->getStatusCode();

            // Determine status
            $status = $response->getStatusCode() >= 200 && $response->getStatusCode() < 400 ? 'ok' : 'error';

            $this->client->finishTransaction($transaction, $status);

            return $response;
        } catch (\Throwable $e) {
            // Capture exception
            $this->client->captureException($e);

            // Finish transaction with error
            $this->client->finishTransaction($transaction, 'error', [
                'exception' => get_class($e),
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            throw $e;
        } finally {
            // Clean up context
            SpanContext::clear();
        }
    }
}
