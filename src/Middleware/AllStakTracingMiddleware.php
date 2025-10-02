<?php

namespace AllStak\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
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
        // Check if tracing is enabled for this request
        if (!$this->shouldTrace($request)) {
            return $next($request);
        }

        // Support distributed tracing - check for existing trace context
        $traceId = $this->extractTraceId($request) ?? bin2hex(random_bytes(16));
        $parentSpanId = $this->extractParentSpanId($request);
        $spanId = bin2hex(random_bytes(8));

        SpanContext::setTraceId($traceId);
        SpanContext::setParentSpanId($parentSpanId);

        // Add breadcrumb for request start
        $this->client->addBreadcrumb(
            'http',
            'Request started',
            [
                'method' => $request->method(),
                'url' => $request->fullUrl(),
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ],
            'info'
        );

        // Create transaction with enriched attributes
        $transaction = $this->client->startTransaction(
            $this->getTransactionName($request),
            'http.request',
            $this->buildAttributes($request)
        );

        // Add span events for request processing milestones
        $requestStart = microtime(true);

        try {
            $response = $next($request);

            // Calculate response generation time
            $processingTime = microtime(true) - $requestStart;

            // Add breadcrumb for response
            $this->client->addBreadcrumb(
                'http',
                'Response sent',
                [
                    'status_code' => $response->getStatusCode(),
                    'content_type' => $response->headers->get('Content-Type'),
                ],
                'info'
            );

            // Add response attributes
            $transaction['attributes'] = array_merge(
                $transaction['attributes'],
                $this->buildResponseAttributes($response, $processingTime)
            );

            // Add custom business metrics if available
            $this->addBusinessMetrics($transaction, $request, $response);

            // Determine status based on response
            $status = $this->determineStatus($response);

            // Add span events
            if (isset($transaction['events'])) {
                $transaction['events'] = array_merge($transaction['events'], [
                    [
                        'name' => 'request.completed',
                        'timestamp' => microtime(true),
                        'attributes' => [
                            'processing_time_ms' => round($processingTime * 1000, 2),
                        ],
                    ],
                ]);
            }

            $this->client->finishTransaction($transaction, $status);

            // Add trace headers to response for client-side tracing
            $this->addTraceHeadersToResponse($response, $traceId, $spanId);

            return $response;
        } catch (\Throwable $e) {
            // Add breadcrumb for exception
            $this->client->addBreadcrumb(
                'exception',
                'Exception thrown',
                [
                    'exception_class' => get_class($e),
                    'message' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                ],
                'error'
            );

            // Capture exception with full context
            $this->client->captureException($e);

            // Add exception details to transaction
            $transaction['attributes']['exception.type'] = get_class($e);
            $transaction['attributes']['exception.message'] = $e->getMessage();
            $transaction['attributes']['exception.file'] = $e->getFile();
            $transaction['attributes']['exception.line'] = $e->getLine();

            $this->client->finishTransaction($transaction, 'error', [
                'exception' => get_class($e),
                'message' => $e->getMessage(),
                'stacktrace' => $e->getTraceAsString(),
            ]);

            throw $e;
        }
    }

    /**
     * Determine if this request should be traced (sampling logic)
     */
    protected function shouldTrace(Request $request): bool
    {
        // Always trace in local/development
        if (app()->environment('local', 'development')) {
            return true;
        }

        // Skip health check endpoints
        if ($this->isHealthCheckEndpoint($request)) {
            return false;
        }

        // Skip static assets
        if ($this->isStaticAsset($request)) {
            return false;
        }

        // Get sampling rate from config (default 10%)
        $samplingRate = Config::get('allstak.sampling_rate', 0.1);

        // Always trace errors (implement via error detection if needed)
        // For now, use probabilistic sampling
        return mt_rand(1, 100) <= ($samplingRate * 100);
    }

    /**
     * Check if request is for health check endpoint
     */
    protected function isHealthCheckEndpoint(Request $request): bool
    {
        $healthCheckPaths = [
            '/health',
            '/healthcheck',
            '/health-check',
            '/ping',
            '/status',
            '/readiness',
            '/liveness',
        ];

        return in_array($request->path(), $healthCheckPaths);
    }

    /**
     * Check if request is for static asset
     */
    protected function isStaticAsset(Request $request): bool
    {
        $extensions = ['css', 'js', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot'];
        $path = $request->path();

        foreach ($extensions as $ext) {
            if (str_ends_with($path, '.' . $ext)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract trace ID from incoming request headers (for distributed tracing)
     */
    protected function extractTraceId(Request $request): ?string
    {
        // Support multiple trace header formats
        $traceHeaders = [
            'x-trace-id',           // Custom
            'traceparent',          // W3C Trace Context
            'x-b3-traceid',         // Zipkin B3
            'x-amzn-trace-id',      // AWS X-Ray
        ];

        foreach ($traceHeaders as $header) {
            $value = $request->header($header);
            if ($value) {
                // Parse W3C traceparent format: 00-traceid-spanid-flags
                if ($header === 'traceparent') {
                    $parts = explode('-', $value);
                    if (count($parts) >= 2) {
                        return $parts[1];
                    }
                }
                return $value;
            }
        }

        return null;
    }

    /**
     * Extract parent span ID from incoming request headers
     */
    protected function extractParentSpanId(Request $request): ?string
    {
        // W3C traceparent format: 00-traceid-spanid-flags
        $traceparent = $request->header('traceparent');
        if ($traceparent) {
            $parts = explode('-', $traceparent);
            if (count($parts) >= 3) {
                return $parts[2];
            }
        }

        return $request->header('x-parent-span-id');
    }

    /**
     * Get meaningful transaction name
     */
    protected function getTransactionName(Request $request): string
    {
        // Use route name if available
        $route = $request->route();
        if ($route && $route->getName()) {
            return $route->getName();
        }

        // Use route action
        if ($route && $route->getActionName()) {
            $action = $route->getActionName();
            if ($action !== 'Closure') {
                return $action;
            }
        }

        // Fallback to HTTP method + path pattern
        $path = $route ? $route->uri() : $request->path();
        return $request->method() . ' ' . $path;
    }

    /**
     * Build comprehensive request attributes
     */
    protected function buildAttributes(Request $request): array
    {
        $attributes = [
            // HTTP attributes (OpenTelemetry semantic conventions)
            'http.method' => $request->method(),
            'http.url' => $request->fullUrl(),
            'http.target' => $request->getRequestUri(),
            'http.scheme' => $request->getScheme(),
            'http.route' => $request->route() ? $request->route()->uri() : null,
            'http.user_agent' => $request->userAgent(),

            // Network attributes
            'net.host.name' => $request->getHost(),
            'net.host.port' => $request->getPort(),
            'net.peer.ip' => $request->ip(),

            // Server attributes
            'server.address' => $request->getHost(),
            'server.port' => $request->getPort(),

            // Client attributes
            'client.address' => $request->ip(),
        ];

        // Add user context if authenticated
        if (Auth::check()) {
            $user = Auth::user();
            $attributes['user.id'] = $user->id;
            $attributes['user.email'] = $user->email ?? null;
            $attributes['user.name'] = $user->name ?? null;
        }

        // Add request ID if available
        if ($request->hasHeader('x-request-id')) {
            $attributes['request.id'] = $request->header('x-request-id');
        }

        // Add query parameters count
        if ($request->query->count() > 0) {
            $attributes['http.query_params_count'] = $request->query->count();
        }

        // Add content length if present
        if ($request->hasHeader('content-length')) {
            $attributes['http.request.body.size'] = (int) $request->header('content-length');
        }

        // Add content type
        if ($request->hasHeader('content-type')) {
            $attributes['http.request.content_type'] = $request->header('content-type');
        }

        return $attributes;
    }

    /**
     * Build response attributes
     */
    protected function buildResponseAttributes($response, float $processingTime): array
    {
        $attributes = [
            'http.status_code' => $response->getStatusCode(),
            'http.response_time_ms' => round($processingTime * 1000, 2),
        ];

        // Add response content type
        if ($response->headers->has('content-type')) {
            $attributes['http.response.content_type'] = $response->headers->get('content-type');
        }

        // Add response size
        $content = $response->getContent();
        if ($content !== false) {
            $attributes['http.response.body.size'] = strlen($content);
        }

        return $attributes;
    }

    /**
     * Add custom business metrics
     */
    protected function addBusinessMetrics(array &$transaction, Request $request, $response): void
    {
        // Add custom tags/attributes based on your business logic
        // Examples:

        // API version
        if ($request->header('api-version')) {
            $transaction['attributes']['api.version'] = $request->header('api-version');
        }

        // Customer/tenant ID
        if ($request->header('x-tenant-id')) {
            $transaction['attributes']['tenant.id'] = $request->header('x-tenant-id');
        }

        // Feature flags (if using feature flags)
        // $transaction['attributes']['feature.flags'] = json_encode(FeatureFlags::getActive());
    }

    /**
     * Determine transaction status
     */
    protected function determineStatus($response): string
    {
        $statusCode = $response->getStatusCode();

        if ($statusCode >= 500) {
            return 'error';
        } elseif ($statusCode >= 400) {
            return 'error';
        } elseif ($statusCode >= 200 && $statusCode < 400) {
            return 'ok';
        }

        return 'unknown';
    }

    /**
     * Add trace headers to response for distributed tracing
     */
    protected function addTraceHeadersToResponse($response, string $traceId, string $spanId): void
    {
        // Add custom trace headers
        $response->headers->set('X-Trace-Id', $traceId);
        $response->headers->set('X-Span-Id', $spanId);

        // Add W3C Trace Context header
        $traceparent = sprintf('00-%s-%s-01', $traceId, $spanId);
        $response->headers->set('Traceparent', $traceparent);

        // For frontend integration (similar to Sentry meta tags)
        if ($response->headers->get('content-type') === 'text/html') {
            // You can inject meta tags here if needed
        }
    }

    /**
     * Perform any final actions for the request lifecycle
     */
    public function terminate($request, $response)
    {
        // Clear context after Laravel's terminate phase
        SpanContext::clear();
    }
}
