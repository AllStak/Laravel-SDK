<?php

namespace AllStak;

use AllStak\Helpers\ClientHelper;
use AllStak\Helpers\SecurityHelper;
use AllStak\Tracing\Span;
use AllStak\Tracing\SpanContext;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Cache\RateLimiter;
use Symfony\Component\HttpClient\HttpClient;
use Throwable;

class AllStakClient
{
//    private const API_URL = 'https://api.allstak.com/v1';
    private const API_URL = 'http://localhost:8080/api/sdk/v2';
    private const MAX_ATTEMPTS = 100;
    private const SDK_VERSION = '2.0.0';
    private ?RateLimiter $rateLimiter = null;
    private string $apiKey;
    private string $environment;
    private bool $sendIpAddress;
    private $httpClient;
    private SecurityHelper $securityHelper;
    private ClientHelper $clientHelper;
    private string $serviceName;
    private array $activeSpans = [];

    public function __construct(
        string $apiKey,
        string $environment = 'production',
        bool $sendIpAddress = true,
        string $serviceName = 'laravel-app'
    ) {
        $this->apiKey = $apiKey;
        $this->environment = $environment;
        $this->sendIpAddress = $sendIpAddress;
        $this->serviceName = $serviceName;

        $this->httpClient = HttpClient::create([
            'timeout' => 5,
            'headers' => [
                'x-api-key' => $this->apiKey,
                'Accept' => 'application/json',
            ],
        ]);

        $this->securityHelper = new SecurityHelper();
        $this->clientHelper = new ClientHelper($this->securityHelper);
    }

    private function getRateLimiter(): RateLimiter
    {
        if ($this->rateLimiter === null) {
            $this->rateLimiter = app(RateLimiter::class);
        }
        return $this->rateLimiter;
    }

    /**
     * Generate a unique trace ID for the current request
     */
    public function generateTraceId(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Capture exception and send to error_logs + http_errors tables
     */
    public function captureException(Throwable $exception, ?Request $request = null, ?string $traceId = null): bool
    {
        if ($this->shouldThrottle()) {
            Log::warning('allstak rate limit exceeded');
            return false;
        }

        try {
            $traceId = $traceId ?? $this->generateTraceId();
            $request = $request ?? request();

            $errorSeverity = $this->clientHelper->determineErrorSeverity($exception);
            $errorCategory = $this->clientHelper->determineErrorCategory($exception);

            $codeContextLines = $this->clientHelper->getCodeContextLines(
                $exception->getFile(),
                $exception->getLine(),
                5
            );
            $maskedCodeContext = $this->securityHelper->maskCodeLines($codeContextLines);

            // Main error_logs payload
            $payload = [
                'trace_id' => $traceId,
                'timestamp' => now()->toIso8601String(),
                'error_type' => $this->mapErrorType($errorCategory),
                'error_code' => $this->generateErrorCode($exception),
                'error_message' => $exception->getMessage() ?: 'Unknown Exception',
                'error_class' => get_class($exception),
                'severity' => $errorSeverity,
                'status' => 'new',
                'stack_trace' => $exception->getTraceAsString(),
                'source' => 'SDK',
                'service_name' => $this->serviceName,
                'environment' => $this->environment,
                'ip' => $this->sendIpAddress ? $request->ip() : $this->securityHelper->maskIp($request->ip()),
                'user_id' => $request->user()?->id ?? null,
                'sdk_version' => self::SDK_VERSION,
                'tags' => $this->extractTags($exception),

                // Additional context
                'additional_data' => [
                    'file' => $exception->getFile(),
                    'line' => $exception->getLine(),
                    'hostname' => gethostname(),
                    'code_context' => $maskedCodeContext,
                    'memory_usage' => $this->clientHelper->getMemoryUsage(),
                ],

                // HTTP error details (if applicable)
                'http_error' => $this->isHttpException($exception) ? [
                    'http_method' => $request->method(),
                    'http_url' => $this->securityHelper->sanitizeUrl($request->fullUrl()),
                    'http_path' => $request->path(),
                    'http_status_code' => $this->getHttpStatusCode($exception),
                    'http_duration' => null, // Should be set from middleware
                    'user_agent' => $request->userAgent() ?? 'unknown',
                    'referer' => $request->header('referer'),
                    'request_headers' => json_encode($this->clientHelper->transformHeaders($request->headers->all())),
                    'request_body' => json_encode($this->clientHelper->transformRequestBody($request->all())),
                    'response_headers' => null,
                    'response_body' => null,
                    'is_client_error' => $this->isClientError($exception),
                    'is_server_error' => $this->isServerError($exception),
                ] : null,

                // Database error details (if applicable)
                'database_error' => $this->isDatabaseException($exception) ? [
                    'query_text' => $this->extractQueryFromException($exception),
                    'database_name' => config('database.connections.' . config('database.default') . '.database'),
                    'constraint_violated' => $this->extractConstraintViolation($exception),
                ] : null,

                // Application error details (if applicable)
                'application_error' => [
                    'file_path' => $exception->getFile(),
                    'line_number' => $exception->getLine(),
                    'function_name' => $this->extractFunctionName($exception),
                    'class_name' => $this->extractClassName($exception),
                    'exception_type' => get_class($exception),
                    'is_handled' => true,
                ],
            ];

            Log::debug('allstak Exception Payload', ['payload' => $payload]);

            $this->httpClient->request('POST', self::API_URL . '/errors', [
                'json' => $payload,
            ]);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send error to allstak: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Capture HTTP request and send to http_logs table
     */
    public function captureRequest(
        Request $request,
        $response,
        float $duration,
        ?string $traceId = null
    ): bool {
        if ($this->shouldThrottle()) {
            Log::warning('allstak rate limit exceeded');
            return false;
        }

        try {
            $traceId = $traceId ?? $this->generateTraceId();
            $statusCode = method_exists($response, 'getStatusCode') ? $response->getStatusCode() : 200;

            $payload = [
                'trace_id' => $traceId,
                'timestamp' => now()->toIso8601String(),
                'ip' => $this->sendIpAddress ? $request->ip() : $this->securityHelper->maskIp($request->ip()),
                'http_method' => $request->method(),
                'http_url' => $this->securityHelper->sanitizeUrl($request->fullUrl()),
                'http_path' => $request->path(),
                'http_status_code' => $statusCode,
                'http_duration' => (int)($duration * 1000), // Convert to milliseconds
                'user_agent' => $request->userAgent() ?? 'unknown',
                'referer' => $request->header('referer'),
                'request_headers' => json_encode($this->clientHelper->transformHeaders($request->headers->all())),
                'request_body' => json_encode($this->clientHelper->transformRequestBody($request->all())),
                'response_headers' => method_exists($response, 'headers') ? json_encode($response->headers->all()) : null,
                'response_body' => $this->getResponseBody($response),
                'response_size' => $this->getResponseSize($response),
                'service_name' => $this->serviceName,
                'environment' => $this->environment,
                'user_id' => $request->user()?->id ?? null,
                'session_id' => $request->session()?->getId(),
                'is_success' => $statusCode >= 200 && $statusCode < 400,
                'is_cached' => $request->headers->has('X-Cache-Hit'),
            ];

            Log::debug('allstak HTTP Request Payload', ['payload' => $payload]);

            $this->httpClient->request('POST', self::API_URL . '/http-logs', [
                'json' => $payload,
            ]);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send request to allstak: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Send database query log to db_query_logs table
     */
    public function sendDbQuery(
        string $queryText,
        array $bindings,
        float $duration,
        string $connectionName,
        ?string $traceId = null,
        bool $success = true
    ): bool {
        if ($this->shouldThrottle()) {
            Log::warning('allstak rate limit exceeded');
            return false;
        }

        try {
            $traceId = $traceId ?? $this->generateTraceId();

            $payload = [
                'trace_id' => $traceId,
                'timestamp' => now()->toIso8601String(),
                'query_text' => $queryText,
                'query_hash' => md5($queryText),
                'query_type' => $this->extractQueryType($queryText),
                'database_name' => config("database.connections.{$connectionName}.database"),
                'table_name' => $this->extractTableName($queryText),
                'execution_time' => (int)$duration, // milliseconds
                'rows_affected' => null, // Should be provided from query result
                'rows_examined' => null,
                'query_plan' => null,
                'parameters' => json_encode($bindings),
                'service_name' => $this->serviceName,
                'environment' => $this->environment,
                'user_id' => request()->user()?->id ?? null,
                'connection_id' => $connectionName,
                'is_success' => $success,
                'is_slow' => $duration > 1000, // Slow if > 1 second
                'is_cached' => false,
                'cache_hit' => false,
            ];

            Log::debug('allstak DB Query Payload', ['payload' => $payload]);

            $this->httpClient->request('POST', self::API_URL . '/db-queries', [
                'json' => $payload,
            ]);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send DB query to allstak: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * NEW: Capture framework logs to framework_logs table
     */
    public function captureFrameworkLog(
        string $level,
        string $message,
        array $context = [],
        ?string $traceId = null
    ): bool {
        if ($this->shouldThrottle()) {
            Log::warning('allstak rate limit exceeded');
            return false;
        }

        try {
            $traceId = $traceId ?? SpanContext::getTraceId() ?? $this->generateTraceId();
            $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5);
            $caller = $backtrace[1] ?? [];

            $payload = [
                'trace_id' => $traceId,
                'timestamp' => now()->toIso8601String(),
                'log_level' => strtoupper($level),
                'logger_name' => $context['logger'] ?? 'default',
                'message' => $message,
                'context' => json_encode($context),
                'exception_type' => $context['exception'] ? get_class($context['exception']) : null,
                'exception_message' => $context['exception']?->getMessage(),
                'stack_trace' => $context['exception']?->getTraceAsString(),
                'file_path' => $caller['file'] ?? null,
                'line_number' => $caller['line'] ?? null,
                'function_name' => $caller['function'] ?? null,
                'class_name' => $caller['class'] ?? null,
                'framework_name' => 'laravel',
                'framework_version' => app()->version(),
                'service_name' => $this->serviceName,
                'environment' => $this->environment,
                'user_id' => request()->user()?->id ?? null,
                'session_id' => request()->session()?->getId(),
                'request_id' => request()->header('X-Request-ID'),
                'process_id' => getmypid(),
                'hostname' => gethostname(),
            ];

            Log::debug('allstak Framework Log Payload', ['payload' => $payload]);

            $this->httpClient->request('POST', self::API_URL . '/framework-logs', [
                'json' => $payload,
            ]);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send framework log to allstak: ' . $e->getMessage());
            return false;
        }
    }

    // Helper methods

    private function mapErrorType(string $category): string
    {
        return match($category) {
            'DATABASE_ERROR' => 'DatabaseError',
            'NETWORK_ERROR' => 'HttpError',
            'SECURITY_ERROR' => 'ApplicationError',
            'PERFORMANCE_ERROR' => 'ApplicationError',
            default => 'ApplicationError',
        };
    }

    private function generateErrorCode(Throwable $exception): string
    {
        return 'E' . substr(md5(get_class($exception)), 0, 6);
    }

    private function extractTags(Throwable $exception): array
    {
        $tags = [];
        $message = strtolower($exception->getMessage());

        if (str_contains($message, 'payment')) $tags[] = 'payment';
        if (str_contains($message, 'auth')) $tags[] = 'authentication';
        if (str_contains($message, 'database')) $tags[] = 'database';
        if (str_contains($message, 'validation')) $tags[] = 'validation';

        return $tags;
    }

    private function isHttpException(Throwable $exception): bool
    {
        return $exception instanceof \Symfony\Component\HttpKernel\Exception\HttpException;
    }

    private function getHttpStatusCode(Throwable $exception): int
    {
        if (method_exists($exception, 'getStatusCode')) {
            return $exception->getStatusCode();
        }
        return 500;
    }

    private function isClientError(Throwable $exception): bool
    {
        $code = $this->getHttpStatusCode($exception);
        return $code >= 400 && $code < 500;
    }

    private function isServerError(Throwable $exception): bool
    {
        $code = $this->getHttpStatusCode($exception);
        return $code >= 500;
    }

    private function isDatabaseException(Throwable $exception): bool
    {
        return $exception instanceof \PDOException ||
               $exception instanceof \Illuminate\Database\QueryException;
    }

    private function extractQueryFromException(Throwable $exception): ?string
    {
        if (method_exists($exception, 'getSql')) {
            return $exception->getSql();
        }
        return null;
    }

    private function extractConstraintViolation(Throwable $exception): ?string
    {
        $message = $exception->getMessage();
        if (preg_match('/Integrity constraint violation: (.+?)\\n/', $message, $matches)) {
            return $matches[1];
        }
        return null;
    }

    private function extractFunctionName(Throwable $exception): ?string
    {
        $trace = $exception->getTrace();
        return $trace[0]['function'] ?? null;
    }

    private function extractClassName(Throwable $exception): ?string
    {
        $trace = $exception->getTrace();
        return $trace[0]['class'] ?? null;
    }

    private function extractQueryType(string $query): string
    {
        $query = trim(strtoupper($query));
        if (str_starts_with($query, 'SELECT')) return 'SELECT';
        if (str_starts_with($query, 'INSERT')) return 'INSERT';
        if (str_starts_with($query, 'UPDATE')) return 'UPDATE';
        if (str_starts_with($query, 'DELETE')) return 'DELETE';
        return 'OTHER';
    }

    private function extractTableName(string $query): ?string
    {
        // Simple regex to extract table name
        if (preg_match('/(?:FROM|INTO|UPDATE|TABLE)\s+`?(\w+)`?/i', $query, $matches)) {
            return $matches[1];
        }
        return null;
    }

    // Add these properties at the top of the class

    /**
     * Start a new span for distributed tracing
     */
    public function startSpan(string $name, ?string $parentSpanId = null): Span
    {
        $traceId = SpanContext::getTraceId() ?? $this->generateTraceId();

        // Create and return a Span object
        $span = new Span($name, $traceId, $parentSpanId);

        // Store it for later
        $this->activeSpans[$span->id] = $span;

        return $span;
    }
    /**
     * End a span and send to API
     */
    public function endSpan(Span $span): bool
    {
        $span->end(); // Call the Span's end method

        try {
            $payload = [
                'trace_id' => $span->traceId,
                'span_id' => $span->id,
                'parent_span_id' => $span->parentSpanId,
                'name' => $span->name,
                'start_time' => $span->startTime,
                'end_time' => $span->endTime,
                'duration' => ($span->endTime - $span->startTime) * 1000, // ms
                'status' => $span->status ?? 'ok',
                'attributes' => $span->attributes,
                'service_name' => $this->serviceName,
                'environment' => $this->environment,
            ];

            if ($span->error) {
                $payload['error'] = $span->error;
            }

            $this->httpClient->request('POST', self::API_URL . '/spans', [
                'json' => $payload,
            ]);

            unset($this->activeSpans[$span->id]);
            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send span: ' . $e->getMessage());
            return false;
        }
    }
    /**
     * Add attributes to a span
     */
    public function addSpanAttribute(string $spanId, string $key, $value): void
    {
        if (isset($this->activeSpans[$spanId])) {
            $this->activeSpans[$spanId]['attributes'][$key] = $value;
        }
    }


    private function getResponseBody($response): ?string
    {
        if (method_exists($response, 'getContent')) {
            $content = $response->getContent();
            return strlen($content) > 10000 ? substr($content, 0, 10000) . '...' : $content;
        }
        return null;
    }

    private function getResponseSize($response): ?int
    {
        if (method_exists($response, 'getContent')) {
            return strlen($response->getContent());
        }
        return null;
    }

    private function shouldThrottle(): bool
    {
        try {
            return !$this->getRateLimiter()->attempt(
                'allstak-api',
                self::MAX_ATTEMPTS,
                fn() => true
            );
        } catch (\Exception $e) {
            Log::warning('AllStak rate limiter failed: ' . $e->getMessage());
            return false;
        }
    }
}
