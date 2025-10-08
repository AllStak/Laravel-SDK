<?php

namespace AllStak;

use AllStak\Helpers\ClientHelper;
use AllStak\Helpers\SecurityHelper;
use AllStak\Tracing\Span;
use AllStak\Tracing\SpanContext;
use AllStak\Transport\AsyncHttpTransport;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\app;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;
use Illuminate\Contracts\Cache\Repository;

class AllStakClient
{
    private const API_URL = 'http://localhost:8080/api/sdk/v2';
    private const MAX_ATTEMPTS = 100;
    private const DECAY_SECONDS = 60; // 1 minute window
    const SDK_VERSION = "2.0.0";

    private string $apiKey;
    private string $environment;
    private bool $sendIpAddress;
    private ?HttpClientInterface $httpClient = null;
    private SecurityHelper $securityHelper;
    private ClientHelper $clientHelper;
    private string $serviceName;
    private array $activeSpans = [];
    private ?AsyncHttpTransport $transport = null;
    private bool $enabled = true;
    private string $rateLimitKey;

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
        $this->rateLimitKey = 'allstak:' . md5($apiKey); // Unique per API key

        // Validate API key and enable SDK
        if (empty($apiKey) || strlen($apiKey) < 10) {
            Log::warning('AllStak SDK disabled: Invalid or empty API key');
            $this->enabled = false;
            return;
        }

        // Create HTTP client for transport
        $this->httpClient = HttpClient::create([
            'timeout' => 5,
            'max_duration' => 10,
        ]);

        // Initialize async transport (only if enabled)
        if ($this->enabled) {
            $this->transport = new AsyncHttpTransport(
                $this->httpClient,
                $this->apiKey,
                config('allstak.use_compression', true)
            );
        }

        $this->securityHelper = new SecurityHelper();
        $this->clientHelper = new ClientHelper($this->securityHelper);
    }

    /**
     * Check if SDK is enabled and rate limit allows
     */
    private function isAllowed(): bool
    {
        if (!$this->enabled) {
            return false;
        }
        return !$this->shouldThrottle();
    }

    /**
     * Simple cache-based rate limiting (replaces broken RateLimiter facade usage)
     */
    private function shouldThrottle(): bool
    {
        try {
            $attempts = Cache::get($this->rateLimitKey, 0);

            if ($attempts >= self::MAX_ATTEMPTS) {
                Log::debug('AllStak rate limit exceeded', ['attempts' => $attempts]);
                return true;
            }

            // Increment attempts
            Cache::put($this->rateLimitKey, $attempts + 1, self::DECAY_SECONDS);

            Log::debug('AllStak rate limit check', ['attempts' => $attempts + 1]);
            return false;
        } catch (\Exception $e) {
            Log::warning('AllStak rate limiting failed, proceeding without limit', [
                'error' => $e->getMessage()
            ]);
            return false; // Fail open to avoid blocking
        }
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
        if (!$this->isAllowed()) {
            Log::warning('AllStak rate limit exceeded or SDK disabled');
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
                'sdk_language' => 'php',
                'sdk_platform' => 'laravel',
                'php_version' => PHP_VERSION,
                'laravel_version' => app()->version(),
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

            Log::debug('AllStak Exception Payload', ['payload' => $payload]);

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/errors', $payload);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send error to AllStak: ' . $e->getMessage());
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
        if (!$this->isAllowed()) {
            Log::warning('AllStak rate limit exceeded or SDK disabled');
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
                'sdk_version' => self::SDK_VERSION,
                'sdk_language' => 'php',
                'sdk_platform' => 'laravel',
                'php_version' => PHP_VERSION,
                'laravel_version' => app()->version(),
            ];

            Log::debug('AllStak HTTP Request Payload', ['payload' => $payload]);

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/http-logs', $payload);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send request to AllStak: ' . $e->getMessage());
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
        if (!$this->isAllowed()) {
            Log::warning('AllStak rate limit exceeded or SDK disabled');
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
                'sdk_version' => self::SDK_VERSION,
                'sdk_language' => 'php',
                'sdk_platform' => 'laravel',
                'php_version' => PHP_VERSION,
                'laravel_version' => app()->version(),
            ];

            Log::debug('AllStak DB Query Payload', ['payload' => $payload]);

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/db-queries', $payload);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send DB query to AllStak: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Capture framework logs to framework_logs table
     */
    public function captureFrameworkLog(
        string $level,
        string $message,
        array $context = [],
        ?string $traceId = null
    ): bool {
        if (!$this->isAllowed()) {
            Log::warning('AllStak rate limit exceeded or SDK disabled');
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
                'sdk_version' => self::SDK_VERSION,
                'sdk_language' => 'php',
                'sdk_platform' => 'laravel',
                'php_version' => PHP_VERSION,
                'laravel_version' => app()->version(),
            ];

            Log::debug('AllStak Framework Log Payload', ['payload' => $payload]);

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/framework-logs', $payload);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send framework log to AllStak: ' . $e->getMessage());
            return false;
        }
    }

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
        if (!$this->isAllowed()) {
            Log::warning('AllStak rate limit exceeded or SDK disabled for span');
            return false;
        }

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
                'sdk_version' => self::SDK_VERSION,
                'sdk_language' => 'php',
                'sdk_platform' => 'laravel',
                'php_version' => PHP_VERSION,
                'laravel_version' => app()->version(),
            ];

            if ($span->error) {
                $payload['error'] = $span->error;
            }

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/spans', $payload);

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
            $this->activeSpans[$spanId]->attributes[$key] = $value;
        }
    }

    /**
     * Add a span directly (for backward compatibility with QuerySpanLogger)
     */
    public function addSpan(string $name, float $startTime, float $endTime, array $attributes = []): bool
    {
        if (!$this->isAllowed()) {
            Log::warning('AllStak rate limit exceeded or SDK disabled for span');
            return false;
        }

        try {
            $traceId = SpanContext::getTraceId() ?? $this->generateTraceId();

            $payload = [
                'trace_id' => $traceId,
                'span_id' => bin2hex(random_bytes(8)),
                'parent_span_id' => null,
                'name' => $name,
                'start_time' => $startTime,
                'end_time' => $endTime,
                'duration' => ($endTime - $startTime) * 1000, // Convert to milliseconds
                'status' => 'ok',
                'attributes' => $attributes,
                'service_name' => $this->serviceName,
                'environment' => $this->environment,
                'sdk_version' => self::SDK_VERSION,
                'sdk_language' => 'php',
                'sdk_platform' => 'laravel',
                'php_version' => PHP_VERSION,
                'laravel_version' => app()->version(),
            ];

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/spans', $payload);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send span to AllStak: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Manually flush pending events (useful for CLI scripts)
     */
    public function flush(int $timeout = 2): void
    {
        if ($this->enabled && $this->transport) {
            $this->transport->flush($timeout);
        }
    }

    // Helper methods (unchanged)

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

    /**
     * Destructor ensures pending requests are flushed
     */
    public function __destruct()
    {
        $this->flush();
    }
}
