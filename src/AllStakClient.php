<?php

namespace AllStak;

use AllStak\Helpers\ClientHelper;
use AllStak\Helpers\Utils\ErrorHelper;
use AllStak\Helpers\Http\PayloadHelper;
use AllStak\Helpers\Security\SecurityHelper;
use AllStak\Helpers\Utils\TracingHelper;
use AllStak\Helpers\Utils\DataTransformHelper;
use AllStak\Transport\AsyncHttpTransport;
use AllStak\Tracing\Span;
use AllStak\Tracing\SpanContext;
use Throwable;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Component\HttpClient\HttpClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\app;
use Psr\Log\LoggerInterface;
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
    // Rate limiting removed - logs always sent
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
        // Rate limiting removed - logs always sent
        $this->tracingHelper = new TracingHelper();
        $this->errorHelper = new ErrorHelper();
        $this->dataTransformHelper = new DataTransformHelper();
        $this->payloadHelper = new PayloadHelper($this->securityHelper);

        // Validate API key and enable SDK
        if (empty($apiKey) || strlen($apiKey) < 10) {
            $this->safeLog('warning', 'AllStak SDK disabled: Invalid or empty API key');
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
            // Check if config service is bound (Laravel environment with config service available)
            $useCompression = false; // Disable compression to prevent JSON parsing issues
            if (function_exists('app') && is_callable(['app', 'bound']) && app()->bound('config')) {
                $useCompression = config('allstak.use_compression', false);
            }
            
            $this->transport = new AsyncHttpTransport(
                $this->httpClient,
                $this->apiKey,
                $useCompression
            );
        }
    }

    /**
     * Safely log messages without Laravel facades
     */
    private function safeLog(string $level, string $message, array $context = []): void
    {
        $logMessage = "AllStak [{$level}]: {$message} " . json_encode($context);
        error_log($logMessage);
    }

    /**
     * Check if SDK is enabled (rate limiting removed - always send logs)
     */
    private function isAllowed(): bool
    {
        if (!$this->enabled) {
            $this->safeLog('debug', 'AllStak SDK is disabled');
            return false;
        }
        
        // Rate limiting removed - always allow logs to be sent
        return true;
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
            error_log('AllStak captureException blocked - SDK disabled or rate limited');
            return false;
        }

        try {
            $traceId = $traceId ?? $this->generateTraceId();
            // Safely get request - avoid calling \request() in CLI context
            if ($request === null) {
                try {
                    if (function_exists('request') && \request() !== null) {
                        $request = \request();
                    }
                } catch (\Exception $e) {
                    // Not in HTTP context, leave request as null
                }
            }

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
                'timestamp' => (new \DateTime())->format('c'),
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
                'ip' => $request ? ($this->sendIpAddress ? $request->ip() : $this->securityHelper->maskIp($request->ip())) : 'unknown',
                'user_id' => $request ? ($request->user()?->id ?? null) : null,
                'sdk_version' => self::SDK_VERSION,
                'sdk_language' => 'php',
                'sdk_platform' => 'laravel',
                'php_version' => PHP_VERSION,
                'laravel_version' => (function_exists('app') && is_callable(['app', 'bound']) && app()->bound('config')) ? \app()->version() : 'cli',
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
                'http_error' => $this->errorHelper->isHttpException($exception) && $request ? [
                    'http_method' => method_exists($request, 'method') ? $request->method() : 'unknown',
                    'http_url' => method_exists($request, 'fullUrl') ? $this->securityHelper->sanitizeUrl($request->fullUrl()) : 'unknown',
                    'http_path' => method_exists($request, 'path') ? $request->path() : 'unknown',
                    'http_status_code' => $this->errorHelper->getHttpStatusCode($exception),
                    'http_duration' => null,
                    'user_agent' => method_exists($request, 'userAgent') ? ($request->userAgent() ?? 'unknown') : 'unknown',
                    'referer' => method_exists($request, 'header') ? $request->header('referer') : null,
                    'request_headers' => method_exists($request, 'headers') && property_exists($request, 'headers') && $request->headers !== null ? json_encode($this->clientHelper->transformHeaders($request->headers->all())) : '[]',
                    'request_body' => method_exists($request, 'all') ? json_encode($this->clientHelper->transformRequestBody($request->all())) : '[]',
                    'response_headers' => null,  // If array later, json_encode
                    'response_body' => null,  // If content, truncate + json_encode if object
                    'is_client_error' => $this->errorHelper->isClientError($exception),
                    'is_server_error' => $this->errorHelper->isServerError($exception),
                ] : null,

                // Database error (strings only - good)
                'database_error' => $this->errorHelper->isDatabaseException($exception) ? [
                    'query_text' => $this->securityHelper->maskQueryText($this->errorHelper->extractQueryFromException($exception) ?? ''),  // Masked SQL
                    'database_name' => (function_exists('app') && is_callable(['app', 'bound']) && app()->bound('config')) ? 
                        config('database.connections.' . config('database.default', 'mysql') . '.database') : 'unknown',
                    'constraint_violated' => $this->errorHelper->extractConstraintViolation($exception),
                    // Add masked bindings as JSON (for backend parsing) - only if method exists
                    'masked_parameters' => json_encode($this->securityHelper->maskDbParameters(
                        method_exists($exception, 'getBindings') ? $exception->getBindings() : []
                    )),
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
            $this->safeLog('debug', 'AllStak Exception Payload prepared', [
                'trace_id' => $traceId,
                'error_message_preview' => substr($payload['error_message'], 0, 100) . '...',
                'db_query_preview' => isset($payload['database_error']) ? substr($payload['database_error']['query_text'], 0, 100) . '...' : 'N/A'
            ]);
            
            $payload = $this->payloadHelper->sanitizePayload($payload);
            
            if ($this->transport) {
                $this->transport->send(self::API_URL . '/errors', $payload);
                $this->safeLog('debug', 'AllStak Exception sent successfully', ['trace_id' => $traceId]);
            } else {
                $this->safeLog('error', 'AllStak transport not initialized');
                return false;
            }

            return true;
        } catch (\Exception $e) {
            $this->safeLog('error', 'Failed to send error to AllStak: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Capture HTTP request and send to http_logs table
     */
    public function captureRequest(
        $request,
        $response,
        float $duration,
        ?string $traceId = null
    ): bool {
        if (!$this->isAllowed()) {
            $this->safeLog('warning', 'AllStak rate limit exceeded or SDK disabled');
            return false;
        }

        try {
            $traceId = $traceId ?? $this->generateTraceId();
            $statusCode = method_exists($response, 'getStatusCode') ? $response->getStatusCode() : 200;

            $payload = [
                'trace_id' => $traceId,
                'timestamp' => (new \DateTime())->format('c'),
                'ip' => method_exists($request, 'ip') ? ($this->sendIpAddress ? $request->ip() : $this->securityHelper->maskIp($request->ip())) : 'unknown',
                'http_method' => method_exists($request, 'method') ? $request->method() : 'unknown',
                'http_url' => method_exists($request, 'fullUrl') ? $this->securityHelper->sanitizeUrl($request->fullUrl()) : 'unknown',
                'http_path' => method_exists($request, 'path') ? $request->path() : 'unknown',
                'http_status_code' => $statusCode,
                'http_duration' => (int)($duration * 1000), // Convert to milliseconds
                'user_agent' => method_exists($request, 'userAgent') ? ($request->userAgent() ?? 'unknown') : 'unknown',
                'referer' => method_exists($request, 'header') ? $request->header('referer') : null,
                'request_headers' => method_exists($request, 'headers') && property_exists($request, 'headers') && $request->headers !== null ? json_encode($this->clientHelper->transformHeaders($request->headers->all())) : '[]',
                'request_body' => method_exists($request, 'all') ? json_encode($this->clientHelper->transformRequestBody($request->all())) : '[]',
                'response_headers' => method_exists($response, 'headers') && property_exists($response, 'headers') && $response->headers !== null ? json_encode($response->headers->all()) : null,
                'response_body' => $this->dataTransformHelper->getResponseBody($response),
                'response_size' => $this->dataTransformHelper->getResponseSize($response),
                'service_name' => $this->serviceName,
                'environment' => $this->environment,
                'user_id' => method_exists($request, 'user') ? ($request->user()?->id ?? null) : null,
                'session_id' => method_exists($request, 'session') ? ($request->session()?->getId()) : null,
                'is_success' => $statusCode >= 200 && $statusCode < 400,
                'is_cached' => method_exists($request, 'headers') && property_exists($request, 'headers') && $request->headers !== null && is_object($request->headers) && method_exists($request->headers, 'has') ? $request->headers->has('X-Cache-Hit') : false,
                'sdk_version' => self::SDK_VERSION,
                'sdk_language' => 'php',
                'sdk_platform' => 'laravel',
                'php_version' => PHP_VERSION,
                'laravel_version' => (function_exists('app') && is_callable(['app', 'bound']) && app()->bound('config')) ? \app()->version() : 'cli',
            ];

            $this->safeLog('debug', 'AllStak HTTP Request Payload', ['payload' => $payload]);

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/http-logs', $payload);

            return true;
        } catch (\Exception $e) {
            $this->safeLog('error', 'Failed to send request to AllStak: ' . $e->getMessage());
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
            $this->safeLog('warning', 'AllStak rate limit exceeded or SDK disabled');
            return false;
        }

        try {
            $traceId = $traceId ?? $this->generateTraceId();

            // Safely get request data - check if we're in HTTP context
            $userId = null;
            
            try {
                if (function_exists('request') && \request() !== null) {
                    $request = \request();
                    $userId = $request->user()?->id ?? null;
                }
            } catch (\Exception $e) {
                // Not in HTTP context, leave request data as null
            }

            $payload = [
                'trace_id' => $traceId,
                'timestamp' => (new \DateTime())->format('c'),
                'query_text' => $queryText,
                'query_hash' => md5($queryText),
                'query_type' => $this->dataTransformHelper->extractQueryType($queryText),
                'database_name' => (function_exists('app') && app()->bound('config')) ? config("database.connections.{$connectionName}.database") : $connectionName,
                'table_name' => $this->dataTransformHelper->extractTableName($queryText),
                'execution_time' => (int)$duration, // milliseconds
                'rows_affected' => null, // Should be provided from query result
                'rows_examined' => null,
                'query_plan' => null,
                'parameters' => json_encode($bindings),
                'service_name' => $this->serviceName,
                'environment' => $this->environment,
                'user_id' => $userId,
                'connection_id' => $connectionName,
                'is_success' => $success,
                'is_slow' => $duration > 1000, // Slow if > 1 second
                'is_cached' => false,
                'cache_hit' => false,
                'sdk_version' => self::SDK_VERSION,
                'sdk_language' => 'php',
                'sdk_platform' => 'laravel',
                'php_version' => PHP_VERSION,
                'laravel_version' => (function_exists('app') && app()->bound('config')) ? \app()->version() : 'cli',
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

                $this->safeLog('debug', 'AllStak DB Query Failed', [
                    'trace_id' => $traceId,
                    'error_code' => $errorCode,
                    'error_message' => substr($errorMessage ?? '', 0, 100) // Log preview
                ]);
            }

            $this->safeLog('debug', 'AllStak DB Query Payload', [
                'trace_id' => $traceId,
                'success' => $success,
                'query_type' => $payload['query_type']
            ]);

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/db-queries', $payload);

            return true;
        } catch (\Exception $e) {
            $this->safeLog('error', 'Failed to send DB query to AllStak: ' . $e->getMessage());
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
            $this->safeLog('warning', 'AllStak rate limit exceeded or SDK disabled');
            return false;
        }

        try {
            $traceId = $traceId ?? SpanContext::getTraceId() ?? $this->generateTraceId();
            $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5);
            $caller = $backtrace[1] ?? [];

            $payload = [
                'trace_id' => $traceId,
                'timestamp' => (new \DateTime())->format('c'),
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
                'framework_version' => (function_exists('app') && app()->bound('config')) ? \app()->version() : 'cli',
                'service_name' => $this->serviceName,
                'environment' => $this->environment,
            ];

            // Safely get request data - check if we're in HTTP context
            $userId = null;
            $sessionId = null;
            $requestId = null;
            
            try {
                if (function_exists('request') && \request() !== null) {
                    $request = \request();
                    $userId = $request->user() ? $request->user()->id : null;
                    $session = $request->session();
                    $sessionId = $session ? $session->getId() : null;
                    $requestId = $request->header('X-Request-ID');
                }
            } catch (\Exception $e) {
                // Not in HTTP context, leave request data as null
            }

            $payload['user_id'] = $userId;
            $payload['session_id'] = $sessionId;
            $payload['request_id'] = $requestId;
            $payload['process_id'] = getmypid();
            $payload['hostname'] = gethostname();
            $payload['sdk_version'] = self::SDK_VERSION;
            $payload['sdk_language'] = 'php';
            $payload['sdk_platform'] = 'laravel';
            $payload['php_version'] = PHP_VERSION;
            $payload['laravel_version'] = (function_exists('app') && app()->bound('config')) ? \app()->version() : 'cli';

            // Use error_log if Laravel facades are not available
            if (class_exists('\Illuminate\Support\Facades\Log')) {
                $this->safeLog('debug', 'AllStak Framework Log Payload', ['payload' => $payload]);
            } else {
                error_log('AllStak Framework Log Payload sent - trace_id: ' . $payload['trace_id']);
            }

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/framework-logs', $payload);

            return true;
        } catch (\Exception $e) {
            // Use error_log if Laravel facades are not available
            if (class_exists('\Illuminate\Support\Facades\Log')) {
                $this->safeLog('error', 'Failed to send framework log to AllStak: ' . $e->getMessage());
            } else {
                error_log('Failed to send framework log to AllStak: ' . $e->getMessage());
            }
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
        if (!$this->enabled) {
            $this->safeLog('warning', 'AllStak SDK disabled for span');
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
                'laravel_version' => (function_exists('app') && app()->bound('config')) ? \app()->version() : 'cli',
            ];

            if ($span->error) {
                $payload['error'] = $span->error;
            }

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/spans', $payload);

            unset($this->activeSpans[$span->id]);
            return true;
        } catch (\Exception $e) {
            $this->safeLog('error', 'Failed to send span: ' . $e->getMessage());
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
        if (!$this->enabled) {
            $this->safeLog('warning', 'AllStak SDK disabled for span');
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
                'laravel_version' => (function_exists('app') && app()->bound('config')) ? \app()->version() : 'cli',
            ];

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/spans', $payload);

            return true;
        } catch (\Exception $e) {
            $this->safeLog('error', 'Failed to send span to AllStak: ' . $e->getMessage());
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

            // Safely get request data - check if we're in HTTP context
            $request = null;
            $userId = null;
            $sessionId = null;
            $requestId = null;
            
            try {
                if (function_exists('request') && \request() !== null) {
                    $request = \request();
                    $userId = $request->user() ? $request->user()->id : null;
                    $session = $request->session();
                    $sessionId = $session ? $session->getId() : null;
                    $requestId = $request->header('X-Request-ID');
                }
            } catch (\Exception $e) {
                // Not in HTTP context, leave request data as null
            }

            // Debug: Check if helpers are available
            if (!isset($this->payloadHelper)) {
                $this->safeLog('error', 'PayloadHelper not initialized');
                return false;
            }

            $this->safeLog('debug', 'AllStak log method - preparing payload');

            $payload = [
                'trace_id' => $traceId,
                'level' => strtolower($level),
                'message' => $this->payloadHelper->sanitizeString($message),
                'context' => $this->payloadHelper->sanitizePayload($context),
                'timestamp' => (new \DateTime())->format('c'),
                'service_name' => $this->serviceName,
                'environment' => $this->environment,
                'user_id' => $userId,
                'session_id' => $sessionId,
                'request_id' => $requestId,
                'process_id' => getmypid(),
                'hostname' => gethostname(),
                'sdk_version' => self::SDK_VERSION,
                'sdk_language' => 'php',
                'sdk_platform' => 'laravel',
                'php_version' => PHP_VERSION,
                'laravel_version' => (function_exists('app') && app()->bound('config')) ? \app()->version() : 'cli',
            ];

            $this->safeLog('debug', 'AllStak log method - payload prepared');

            // Debug: Check if transport is available
            if (!isset($this->transport)) {
                $this->safeLog('error', 'Transport not initialized');
                return false;
            }

            $this->safeLog('debug', 'AllStak log method - sending to transport');

            // Use async transport (non-blocking)
            $this->transport->send(self::API_URL . '/logs', $payload);

            $this->safeLog('debug', 'AllStak log method - transport send completed');

            return true;
        } catch (\Exception $e) {
            $this->safeLog('error', 'Failed to send log to AllStak: ' . $e->getMessage());
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
