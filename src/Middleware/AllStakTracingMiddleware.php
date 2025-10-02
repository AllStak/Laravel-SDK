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
        $traceId = bin2hex(random_bytes(16));
        $spanId = bin2hex(random_bytes(8));

        SpanContext::setTraceId($traceId);
        SpanContext::setParentSpanId(null);

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

            $transaction['attributes']['http.status_code'] = $response->getStatusCode();
            $status = $response->getStatusCode() >= 200 && $response->getStatusCode() < 400 ? 'ok' : 'error';

            $this->client->finishTransaction($transaction, $status);

            return $response;
        } catch (\Throwable $e) {
            $this->client->captureException($e);
            $this->client->finishTransaction($transaction, 'error', [
                'exception' => get_class($e),
                'message' => $e->getMessage(),
            ]);
            throw $e;
        }
    }

    /**
     * Perform any final actions for the request lifecycle.
     */
    public function terminate($request, $response)
    {
        // Clear context after Laravel's terminate phase
        SpanContext::clear();
    }
}
