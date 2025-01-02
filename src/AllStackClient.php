<?php

namespace Techsea\AllStack;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;
use Illuminate\Cache\RateLimiter;
use Throwable;
use Illuminate\Http\Request;

class AllStackClient
{
    private const API_URL = 'https://allstack-api.techsea.sa/api/client';
    private const MAX_ATTEMPTS = 100; // per minute

    private string $apiKey;
    private string $environment;
    private Client $httpClient;
    private RateLimiter $rateLimiter;

    public function __construct(string $apiKey, string $environment = 'production')
    {
        $this->apiKey = $apiKey;
        $this->environment = $environment;
        $this->httpClient = new Client([
            'timeout'         => 5,
            'connect_timeout' => 5,
            'http_errors'     => true
        ]);
        $this->rateLimiter = app(RateLimiter::class);
    }

    /**
     * Capture exceptions and send them as "error" events.
     */
    public function captureException(Throwable $exception): bool
    {
        if ($this->shouldThrottle()) {
            Log::warning('AllStack rate limit exceeded');
            return false;
        }

        try {
            // 1. Determine severity & level
            $errorSeverity = $this->determineErrorSeverity($exception);
            $errorLevel    = $this->determineErrorLevel('error', $errorSeverity);

            // 2. Build final payload
            $payload = [
                'errorMessage'   => $exception->getMessage() ?: 'Unknown Exception',
                'errorType'      => get_class($exception),
                'errorLevel'     => $errorLevel,
                'environment'    => $this->environment,
                'ip'             => $this->getIpAddress(),
                'userAgent'      => 'Laravel',
                'url'            => '',
                'timestamp'      => $this->formatTimestamp(now()),
                'additionalData' => [
                    'file'     => $exception->getFile(),
                    'line'     => $exception->getLine(),
                    'trace'    => $exception->getTraceAsString(),
                    'hostname' => gethostname(),
                    // NEW: Capture code snippet
                    'codeContext' => $this->getCodeContext(
                        $exception->getFile(), 
                        $exception->getLine(), 
                        5 // number of lines of context on each side
                    ), 
                ],
                'stackTrace'    => (object) $this->formatStackTrace($exception),
                'contexts'      => $this->createContexts(),

                // new field
                'errorCategory' => $this->determineErrorCategory($exception),
                // new field for cause
                'errorCause'    => $this->determineErrorCause($exception),

                // Example optional fields (match your Java DTO)
                'release'       => env('RELEASE', '1.0.0'),
                'component'     => env('COMPONENT', 'my-component'),
                'transactionId' => '',
                'fingerprint'   => '',
                'rootCause'     => '',
                'category'      => '',
                'memoryUsage'   => $this->getMemoryUsage(),
                'cpuUsage'      => null,
                'responseTime'  => 0,
                'tags'          => [],
                'errorSeverity' => $errorSeverity,
            ];

            Log::debug('AllStack Exception Payload', ['payload' => $payload]);

            // 3. Validate & send
            if (!$this->validatePayload($payload)) {
                return false;
            }

            return $this->sendWithRetry('/exception', $payload);
        } catch (\Exception $e) {
            Log::error('Failed to send error to AllStack: ' . $e->getMessage());
            return false;
        }
    }


    private function getCodeContext(string $file, int $line, int $context = 5): array
    {
        // If file can't be read (e.g., restricted perms), return empty context
        if (!is_readable($file)) {
            return [];
        }

        // Read all lines from file
        $lines = @file($file, FILE_IGNORE_NEW_LINES);

        if (!$lines) {
            return [];
        }

        // Indices in the array are zero-based; PHP lines are 1-based
        $start = max($line - $context - 1, 0);
        $end   = min($line + $context - 1, count($lines) - 1);

        $snippet = [];

        for ($i = $start; $i <= $end; $i++) {
            // Store line number and content. You can highlight the error line if you want.
            $snippet[$i + 1] = $lines[$i];
        }

        return $snippet;
    }

    /**
     * Capture HTTP requests and send them as "request" events.
     */
    public function captureRequest(Request $request, float $responseTime = 0): bool
    {
        if ($this->shouldThrottle()) {
            Log::warning('AllStack rate limit exceeded');
            return false;
        }

        try {
            // For requests, let's treat them as "low severity" "warning" events.
            $errorSeverity = 'low';
            $errorLevel    = 'WARNING';

            $payload = [
                'errorMessage'   => 'HTTP Request Captured',
                'errorType'      => 'HTTPRequest',
                'errorLevel'     => $errorLevel,
                'environment'    => $this->environment,
                'ip'             => $request->ip(),
                'userAgent'      => $request->userAgent() ?? 'unknown',
                'url'            => $request->fullUrl(),
                'timestamp'      => $this->formatTimestamp(now()),
                'additionalData' => [
                    'headers'     => $this->transformHeaders($request->headers->all()),
                    'queryParams' => $this->transformQueryParams($request->query()),
                    'body'        => $this->transformRequestBody($request->all()),
                    'method'      => $request->method(),
                    'host'        => $request->getHost(),
                    'protocol'    => $request->getScheme(),
                    'hostname'    => gethostname(),
                    'port'        => (string) $request->getPort(),
                ],
                'stackTrace'    => new \stdClass(),
                'contexts'      => $this->createContexts(),

                // We default requests to 'APPLICATION_ERROR' or similar
                'errorCategory' => 'APPLICATION_ERROR',
                // For requests, we might default 'USER' or do logic if certain status codes = user error
                'errorCause'    => 'USER',

                // Optional fields
                'release'       => env('RELEASE', '1.0.0'),
                'component'     => env('COMPONENT', 'my-component'),
                'transactionId' => '',
                'fingerprint'   => '',
                'rootCause'     => '',
                'category'      => '',
                'memoryUsage'   => $this->getMemoryUsage(),
                'cpuUsage'      => null,
                'responseTime'  => $responseTime,
                'tags'          => [],
                'errorSeverity' => $errorSeverity,
            ];

            Log::debug('AllStack Request Payload', ['payload' => $payload]);

            if (!$this->validatePayload($payload)) {
                return false;
            }

            return $this->sendWithRetry('/http-request-transactions', $payload);
        } catch (\Exception $e) {
            Log::error('Failed to send request to AllStack: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * -------------------------------
     * Helper methods & transformations
     * -------------------------------
     */

    /**
     * New method to decide if the error is caused by the user or by the system.
     */
    private function determineErrorCause(Throwable $exception): string
    {
        // Example heuristics, tailor to your logic
        $msg = strtolower($exception->getMessage());
        // If the message mentions invalid input, we consider it user-caused.
        if (str_contains($msg, 'validation') || str_contains($msg, 'input')) {
            return 'USER';
        }
        // If it mentions DB connection, server crash, etc., we consider it system-caused.
        if (str_contains($msg, 'db') || str_contains($msg, 'server') || str_contains($msg, 'connection')) {
            return 'SYSTEM';
        }

        // Fallback
        return 'SYSTEM';
    }

    /**
     * We add a method to figure out which of the Java enum categories might match this PHP Throwable.
     * APPLICATION_ERROR, NETWORK_ERROR, DATABASE_ERROR,
     * SECURITY_ERROR, PERFORMANCE_ERROR, UNKNOWN_ERROR
     */
    private function determineErrorCategory(Throwable $exception): string
    {
        $message = strtolower($exception->getMessage());

        // Very naive heuristics, adjust as needed:
        if (str_contains($message, 'sql') || str_contains($message, 'db') || str_contains($message, 'database')) {
            return 'DATABASE_ERROR';
        }
        if (str_contains($message, 'network') || str_contains($message, 'timeout') || str_contains($message, 'socket')) {
            return 'NETWORK_ERROR';
        }
        if (str_contains($message, 'security') || str_contains($message, 'unauthorized') || str_contains($message, 'forbidden')) {
            return 'SECURITY_ERROR';
        }
        if (str_contains($message, 'performance') || str_contains($message, 'slow')) {
            return 'PERFORMANCE_ERROR';
        }
        if (str_contains($message, 'app') || str_contains($message, 'logic') || str_contains($message, 'handler')) {
            return 'APPLICATION_ERROR';
        }

        return 'UNKNOWN_ERROR';
    }

    /**
     * Very simplified approach to "severity" mapping (like in Node SDK).
     */
    private function determineErrorSeverity(Throwable $exception): string
    {
        if ($exception instanceof \TypeError || $exception instanceof \ErrorException) {
            return 'high';
        }
        if (stripos($exception->getMessage(), 'syntax') !== false) {
            return 'critical';
        }
        if (stripos($exception->getMessage(), 'timeout') !== false ||
            stripos($exception->getMessage(), 'network') !== false) {
            return 'medium';
        }
        return 'low';
    }

    /**
     * Determine the "errorLevel" (INFO, WARNING, ERROR, CRITICAL).
     */
    private function determineErrorLevel(string $type, string $severity): string
    {
        if ($type === 'error') {
            return $severity === 'critical' ? 'CRITICAL' : 'ERROR';
        }
        return $severity === 'critical' ? 'CRITICAL' : 'WARNING';
    }

    /**
     * Format a stack trace as an array of frames (similar to Node approach).
     */
    private function formatStackTrace(Throwable $exception): array
    {
        $stackTrace = [];
        $trace      = $exception->getTrace();

        foreach ($trace as $index => $frame) {
            $frameKey = sprintf("frame_%d", $index);
            $stackTrace[$frameKey] = [
                'file'     => $frame['file']     ?? '',
                'line'     => $frame['line']     ?? '',
                'function' => $frame['function'] ?? '',
                'class'    => $frame['class']    ?? '',
                'type'     => $frame['type']     ?? '',
            ];
        }

        return $stackTrace;
    }

    /**
     * Minimal "contexts" to mimic Node’s "runtime/system/process" concept.
     */
    private function createContexts(): array
    {
        return [
            'runtime' => [
                'name'    => 'PHP',
                'version' => PHP_VERSION
            ],
            'system' => [
                'os'    => PHP_OS,
                'uname' => php_uname(),
            ],
            'process' => [
                'pid' => getmypid(),
            ],
        ];
    }

    private function getMemoryUsage(): int
    {
        return memory_get_usage(true);
    }

    private function formatTimestamp(\DateTimeInterface $dt): string
    {
        return $dt->format('Y-m-d\TH:i:s');
    }

    private function getIpAddress(): string
    {
        return gethostbyname(gethostname());
    }

    private function transformHeaders(array $headers): array
    {
        $transformed = [];
        
        foreach ($headers as $key => $values) {
            if (is_array($values)) {
                $transformed[strtolower($key)] = implode(', ', $values);
            } else {
                $transformed[strtolower($key)] = $values;
            }
        }
        
        Log::debug('Transformed headers', ['headers' => $transformed]);
        return $transformed;
    }

    private function transformQueryParams(array $params): array
    {
        $transformed = [];
        
        foreach ($params as $key => $value) {
            if (is_array($value)) {
                $transformed[$key] = implode(',', $value);
            } else {
                if ($value === 'true') {
                    $transformed[$key] = true;
                } elseif ($value === 'false') {
                    $transformed[$key] = false;
                } elseif (is_numeric($value)) {
                    $transformed[$key] = $value * 1;
                } else {
                    $transformed[$key] = $value;
                }
            }
        }
        
        Log::debug('Transformed query params', ['params' => $transformed]);
        return $transformed;
    }

    private function transformRequestBody(array $data): array
    {
        $transformed = [];
        $sensitiveFields = ['password', 'token', 'secret', 'credit_card'];
        
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $transformed[$key] = $this->transformRequestBody($value);
            } else {
                foreach ($sensitiveFields as $field) {
                    if (stripos($key, $field) !== false) {
                        $value = '[REDACTED]';
                        break;
                    }
                }
                if ($value === 'true') {
                    $transformed[$key] = true;
                } elseif ($value === 'false') {
                    $transformed[$key] = false;
                } elseif (is_numeric($value)) {
                    $transformed[$key] = $value * 1;
                } else {
                    $transformed[$key] = $value;
                }
            }
        }
        
        return $transformed;
    }

    private function validatePayload(array $payload): bool
    {
        if (isset($payload['errorMessage']) && isset($payload['errorType'])) {
            $requiredFields = ['errorMessage', 'errorType', 'errorLevel', 'environment', 'timestamp'];
        } elseif (isset($payload['errorMessage']) && $payload['errorType'] === 'HTTPRequest') {
            $requiredFields = ['errorMessage', 'errorType', 'environment', 'timestamp', 'url'];
        } else {
            Log::warning('Unknown payload type', ['payload' => $payload]);
            return false;
        }

        foreach ($requiredFields as $field) {
            if ($payload[$field] === null || $payload[$field] === '') {
                Log::warning("Missing required field: {$field}", ['payload' => $payload]);
                return false;
            }
        }

        return true;
    }

    private function shouldThrottle(): bool
    {
        return !$this->rateLimiter->attempt(
            'allstack-api',
            self::MAX_ATTEMPTS,
            function () {
                return true;
            }
        );
    }

    private function sendWithRetry(string $endpoint, array $payload, int $maxRetries = 3): bool
    {
        $attempt = 0;

        Log::debug('Sending payload to AllStack', [
            'endpoint' => $endpoint,
            'payload'  => $payload,
            'attempt'  => $attempt + 1
        ]);

        while ($attempt < $maxRetries) {
            try {
                $response = $this->httpClient->post(self::API_URL . $endpoint, [
                    'headers' => $this->getHeaders(),
                    'json'    => $payload,
                ]);

                Log::info('Successfully sent to AllStack', [
                    'endpoint' => $endpoint,
                    'status'   => $response->getStatusCode()
                ]);
                return true;
            } catch (\Exception $e) {
                $attempt++;
                Log::error('Failed to send to AllStack', [
                    'endpoint' => $endpoint,
                    'attempt'  => $attempt,
                    'error'    => $e->getMessage()
                ]);

                if ($attempt === $maxRetries) {
                    Log::error("Failed after {$maxRetries} attempts: " . $e->getMessage());
                    return false;
                }
                sleep(1);
            }
        }

        return false;
    }

    private function getHeaders(): array
    {
        return [
            'x-api-key'    => "{$this->apiKey}",
            'Content-Type' => 'application/json',
            'Accept'       => 'application/json',
        ];
    }
}
