<?php

namespace AllStak;

use AllStak\Helpers\ClientHelper;
use AllStak\Helpers\Security\SecurityHelper;
use AllStak\Helpers\Utils\RateLimitingHelper;
use AllStak\Helpers\Utils\TracingHelper;
use AllStak\Helpers\Utils\ErrorHelper;
use AllStak\Helpers\Utils\DataTransformHelper;
use AllStak\Helpers\Http\PayloadHelper;
use AllStak\Tracing\Span;
use AllStak\Tracing\SpanContext;
use AllStak\Transport\AsyncHttpTransport;
use Illuminate\Http\Request;
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
    const SDK_VERSION = "2.0.0";

    private string $apiKey;
    private string $environment;
    private bool $sendIpAddress;
    private ?HttpClientInterface $httpClient = null;
    private SecurityHelper $securityHelper;
    private ClientHelper $clientHelper;
    private string $serviceName;
    private ?AsyncHttpTransport $transport = null;
    private bool $enabled = true;
    private RateLimitingHelper $rateLimitingHelper;
    private TracingHelper $tracingHelper;
    private ErrorHelper $errorHelper;
    private DataTransformHelper $dataTransformHelper;
    private PayloadHelper $payloadHelper;

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

        // Initialize helper objects first (always needed)
        $this->securityHelper = new SecurityHelper();
        $this->clientHelper = new ClientHelper($this->securityHelper);
        $this->rateLimitingHelper = new RateLimitingHelper($apiKey);
        $this->tracingHelper = new TracingHelper();
        $this->errorHelper = new ErrorHelper();
        $this->dataTransformHelper = new DataTransformHelper();
        $this->payloadHelper = new PayloadHelper($this->securityHelper);

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
    }

    /**
     * Check if SDK is enabled and rate limit allows
     */
    private function isAllowed(): bool
    {
        if (!$this->enabled) {
            return false;
        }
        return !$this->rateLimitingHelper->shouldThrottle();
    }

    /**
     * Generate a unique trace ID for the current request
     */
    public function generateTraceId(): string
    {
        return $this->tracingHelper->generateTraceId();
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
            $maskedCodeContext = $this->securityHelper->maskCodeLines($codeContextLines);  // Likely array
            $rawMessage = $exception->getMessage() ?: 'Unknown Exception';
            $securityHelper = $this->securityHelper;  // Assume injected
            $maskedMessage = $securityHelper->maskExceptionMessage($rawMessage, $exception);  // New helper below
            // FIXED: json_encode array fields that DTO expects as String (e.g., code_context, tags if nested)
            $maskedCodeContextJson = json_encode($maskedCodeContext);  // Now a JSON string
            $tags = $this->errorHelper->extractTags($exception);

            // Main error_logs payload
            $payload = [
                'trace_id' => $traceId,
                'timestamp' => now()->toIso8601String(),
                'error_type' => $this->errorHelper->mapErrorType($errorCategory),
                'error_code' => $this->errorHelper->generateErrorCode($exception),
                'error_message' => $this->payloadHelper->sanitizeString($maskedMessage),  // Now masked + sanitized
                'error_class' => get_class($exception),
                'severity' => $errorSeverity,
                'status' => 'new',
                'stack_trace' => $this->payloadHelper->sanitizeString($exception->getTraceAsString()),  // From earlier sanitization
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
                'tags' => $tags,  // FIXED: Encode if array (DTO: List<String> will parse JSON array)

                // Additional context - FIXED: code_context as JSON string
                'additional_data' => [
                    'file' => $this->payloadHelper->sanitizeString($exception->getFile()),
                    'line' => $exception->getLine(),
                    'hostname' => gethostname(),
                    'code_context' => $maskedCodeContextJson,  // Now string: "[\"masked line1\", ...]"
                    'memory_usage' => $this->clientHelper->getMemoryUsage(),
                ],

                // HTTP error details (already has json_encode for headers/body - good)
                'http_error' => $this->errorHelper->isHttpException($exception) ? [
                    'http_method' => $request->method(),
                    'http_url' => $this->securityHelper->sanitizeUrl($request->fullUrl()),
                    'http_path' => $request->path(),
                    'http_status_code' => $this->errorHelper->getHttpStatusCode($exception),
                    'http_duration' => null,
                    'user_agent' => $request->userAgent() ?? 'unknown',
                    'referer' => $request->header('referer'),
                    'request_headers' => json_encode($this->clientHelper->transformHeaders($request->headers->all())),
                    'request_body' => json_encode($this->clientHelper->transformRequestBody($request->all())),
                    'response_headers' => null,  // If array later, json_encode
                    'response_body' => null,  // If content, truncate + json_encode if object
                    'is_client_error' => $this->errorHelper->isClientError($exception),
                    'is_server_error' => $this->errorHelper->isServerError($exception),
                ] : null,

                // Database error (strings only - good)
                'database_error' => $this->errorHelper->isDatabaseException($exception) ? [
                    'query_text' => $this->securityHelper->maskQueryText($exception->getSql() ?? ''),  // Masked SQL
                    'database_name' => config('database.connections.' . config('database.default') . '.database'),
                    'constraint_violated' => $this->errorHelper->extractConstraintViolation($exception),
                    // Add masked bindings as JSON (for backend parsing)
                    'masked_parameters' => json_encode($this->securityHelper->maskDbParameters($exception->getBindings() ?? [])),
                ] : null,

                // Application error (strings/ints - good)
                'application_error' => [
                    'file_path' => $this->payloadHelper->sanitizeString($exception->getFile()),
                    'line_number' => $exception->getLine(),
                    'function_name' => $this->payloadHelper->sanitizeString($this->errorHelper->extractFunctionName($exception)),
                    'class_name' => $this->payloadHelper->sanitizeString($this->errorHelper->extractClassName($exception)),
                    'exception_type' => get_class($exception),
                    'is_handled' => true,
                ],
            ];

            // FIXED: Sanitize/encode full payload before sending
            Log::debug('AllStak Exception Payload prepared', [
                'trace_id' => $traceId,
                'error_message_preview' => substr($payload['error_message'], 0, 100) . '...',
                'db_query_preview' => isset($payload['database_error']) ? substr($payload['database_error']['query_text'], 0, 100) . '...' : 'N/A'
            ]);
            $payload = $this->payloadHelper->sanitizePayload($payload);
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
                'response_body' => $this->dataTransformHelper->getResponseBody($response),
                'response_size' => $this->dataTransformHelper->getResponseSize($response),
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
        bool $success = true,
        ?string $errorCode = null,        // ✅ NEW: Error code for failed queries
        ?string $errorMessage = null,     // ✅ NEW: Error message for failed queries
        ?string $stackTrace = null        // ✅ NEW: Stack trace for debugging
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
                'query_type' => $this->dataTransformHelper->extractQueryType($queryText),
                'database_name' => config("database.connections.{$connectionName}.database"),
                'table_name' => $this->dataTransformHelper->extractTableName($queryText),
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

            // ✅ Add error-specific fields when query fails
            if (!$success) {
                $payload['error_code'] = $errorCode ?? 'UNKNOWN';
                $payload['error_message'] = $errorMessage ?? 'Database query failed';
                $payload['error_type'] = 'DATABASE_ERROR';

                // Only include stack trace if provided (for security/size reasons)
                if ($stackTrace) {
                    $payload['stack_trace'] = $stackTrace;
                }

                Log::debug('AllStak DB Query Failed', [
                    'trace_id' => $traceId,
                    'error_code' => $errorCode,
                    'error_message' => substr($errorMessage ?? '', 0, 100) // Log preview
                ]);
            }

            Log::debug('AllStak DB Query Payload', [
                'trace_id' => $traceId,
                'success' => $success,
                'query_type' => $payload['query_type']
            ]);

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

    /**
     * Destructor ensures pending requests are flushed
     */
    public function __destruct()
    {
        $this->flush();
    }
}

    /**
     * Send a log message to AllStak backend
     */
    public function log(string $level, string $message, array $context = [], ?string $traceId = null): bool
    {
        if (!$this->isAllowed()) {
            return false;
        }

        try {
            $traceId = $traceId ?? $this->generateTraceId();

            $payload = [
                'trace_id' => $traceId,
                'level' => strtolower($level),
                'message' => $this->payloadHelper->sanitizeString($message),
                'context' => $this->payloadHelper->sanitizePayload($context),
                'timestamp' => now()->toISOString(),
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

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/logs', $payload);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send log to AllStak: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Log debug message
     */
    public function logDebug(string $message, array $context = [], ?string $traceId = null): bool
    {
        return $this->log('debug', $message, $context, $traceId);
    }

    /**
     * Log info message
     */
    public function logInfo(string $message, array $context = [], ?string $traceId = null): bool
    {
        return $this->log('info', $message, $context, $traceId);
    }

    /**
     * Log warning message
     */
    public function logWarning(string $message, array $context = [], ?string $traceId = null): bool
    {
        return $this->log('warning', $message, $context, $traceId);
    }

    /**
     * Log error message
     */
    public function logError(string $message, array $context = [], ?string $traceId = null): bool
    {
        return $this->log('error', $message, $context, $traceId);
    }
}
