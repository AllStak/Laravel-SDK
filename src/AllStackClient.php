<?php

namespace Techsea\AllStack;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;
use Illuminate\Cache\RateLimiter;
use Throwable;
use Illuminate\Http\Request;

class AllStackClient
{
    private const API_URL = 'http://localhost:8080/api/client';
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
                'errorMessage' => $exception->getMessage() ?: 'Unknown Exception',
                'errorType'    => get_class($exception),
                'errorLevel'   => $errorLevel,
                'environment'  => $this->environment,
                'ip'           => $this->getIpAddress(),
                'userAgent'    => 'Laravel', // or anything you prefer
                'url'          => '',        // No URL for a plain exception (unless you have it)
                'timestamp'    => $this->formatTimestamp(now()),
                
                // Additional structured data
                'additionalData' => [
                    'file'     => $exception->getFile(),
                    'line'     => $exception->getLine(),
                    'trace'    => $exception->getTraceAsString(),
                    'hostname' => gethostname(),
                    // You can add more debug info or system metrics below
                ],
                'stackTrace' => (object) $this->formatStackTrace($exception),
                
                // Optional contexts or dynamic details
                'contexts' => $this->createContexts(),

                // Example optional fields (match your Java DTO)
                'release'       => env('RELEASE', '1.0.0'),
                'component'     => env('COMPONENT', 'my-component'),
                'transactionId' => '',
                'fingerprint'   => '',
                'rootCause'     => '',
                'category'      => '',
                'memoryUsage'   => $this->getMemoryUsage(),
                'cpuUsage'      => null, // Not trivial in PHP
                'responseTime'  => 0,
                'tags'          => [],   // Possibly fill from config or pass in
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

            // Build final payload that matches your Node/Java style
            $payload = [
                'errorMessage' => 'HTTP Request Captured',
                'errorType'    => 'HTTPRequest',
                'errorLevel'   => $errorLevel,
                'environment'  => $this->environment,
                'ip'           => $request->ip(),
                'userAgent'    => $request->userAgent() ?? 'unknown',
                'url'          => $request->fullUrl(),
                'timestamp'    => $this->formatTimestamp(now()),

                // Combine request details + system metrics in additionalData
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
                'stackTrace' => new \stdClass(), // Typically empty for request logging
                'contexts'   => $this->createContexts(),

                // Example optional fields
                'release'       => env('RELEASE', '1.0.0'),
                'component'     => env('COMPONENT', 'my-component'),
                'transactionId' => '',
                'fingerprint'   => '',
                'rootCause'     => '',
                'category'      => '',
                'memoryUsage'   => $this->getMemoryUsage(),
                'cpuUsage'      => null, // Not trivial in PHP
                'responseTime'  => $responseTime,
                'tags'          => [],   // Possibly fill from config
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
     * ---------------------------------------
     * Below are helper methods & transformations
     * ---------------------------------------
     */

    /**
     * Very simplified approach to "severity" mapping (like in Node SDK).
     */
    private function determineErrorSeverity(Throwable $exception): string
    {
        // Simple example mapping
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
        // Node logic: if type=error & severity=critical => CRITICAL else ERROR
        // if type=warning & severity=critical => CRITICAL else WARNING
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
                'os'   => PHP_OS,  // e.g., 'Linux'
                'uname' => php_uname(),
            ],
            'process' => [
                'pid' => getmypid(),
                // Add anything else relevant to your environment
            ],
        ];
    }

    /**
     * Approximate memory usage in bytes (for the current PHP process).
     * We skip CPU usage because PHP has no simple built-in for system-level CPU usage.
     */
    private function getMemoryUsage(): int
    {
        return memory_get_usage(true);
    }

    /**
     * Formats timestamp to match your Java LocalDateTime parsing (ISO-like).
     * E.g., "2024-12-21T21:54:16"
     */
    private function formatTimestamp(\DateTimeInterface $dt): string
    {
        return $dt->format('Y-m-d\TH:i:s');
    }

    /**
     * Attempt to get a "real" IP address (fallback is the hostname IP).
     */
    private function getIpAddress(): string
    {
        // If you are in a CLI context, there's no real IP, so fallback to gethostname().
        return gethostbyname(gethostname());
    }

    /**
     * Transform request headers into a flatter structure (already in your code).
     */
    private function transformHeaders(array $headers): array
    {
        $transformed = [];
        
        foreach ($headers as $key => $values) {
            // Convert array of values to comma-separated string
            if (is_array($values)) {
                $transformed[strtolower($key)] = implode(', ', $values);
            } else {
                $transformed[strtolower($key)] = $values;
            }
        }
        
        Log::debug('Transformed headers', ['headers' => $transformed]);
        return $transformed;
    }

    /**
     * Transform query params to typed values (already in your code).
     */
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

    /**
     * Transform request body, redacting sensitive fields (already in your code).
     */
    private function transformRequestBody(array $data): array
    {
        $transformed = [];
        $sensitiveFields = ['password', 'token', 'secret', 'credit_card'];
        
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $transformed[$key] = $this->transformRequestBody($value);
            } else {
                // Check for sensitive fields
                foreach ($sensitiveFields as $field) {
                    if (stripos($key, $field) !== false) {
                        $value = '[REDACTED]';
                        break;
                    }
                }
                // Convert types
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

    /**
     * Basic validation to ensure required fields are present.
     * Adjust as you see fit.
     */
    private function validatePayload(array $payload): bool
    {
        // Distinguish between "request" or "exception" type based on certain fields
        if (isset($payload['errorMessage']) && isset($payload['errorType'])) {
            // Exception or generic event
            $requiredFields = ['errorMessage', 'errorType', 'errorLevel', 'environment', 'timestamp'];
        } elseif (isset($payload['errorMessage']) && $payload['errorType'] === 'HTTPRequest') {
            // We decided to name it "HTTPRequest" for request events
            $requiredFields = ['errorMessage', 'errorType', 'environment', 'timestamp', 'url'];
        } else {
            Log::warning('Unknown payload type', ['payload' => $payload]);
            return false;
        }

        foreach ($requiredFields as $field) {
            if (empty($payload[$field]) && $payload[$field] !== 0) {
                Log::warning("Missing required field: {$field}", ['payload' => $payload]);
                return false;
            }
        }

        return true;
    }

    /**
     * Prevent spamming the API beyond a certain rate.
     */
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

    /**
     * Send data with simple retry logic (similar to Node’s exponential backoff).
     */
    private function sendWithRetry(string $endpoint, array $payload, int $maxRetries = 3): bool
    {
        $attempt = 0;

        // Log the final payload for debugging
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
                sleep(1); // Wait 1 second before retrying
            }
        }

        return false;
    }

    /**
     * Basic headers required by your API.
     */
    private function getHeaders(): array
    {
        return [
            'x-api-key'    => "{$this->apiKey}",
            'Content-Type' => 'application/json',
            'Accept'       => 'application/json',
        ];
    }
}
