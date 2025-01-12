<?php

namespace Techsea\AllStack;

use Illuminate\Support\Facades\Log;
use Illuminate\Cache\RateLimiter;
use Throwable;
use Illuminate\Http\Request;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class AllStackClient
{
    private const API_URL = 'https://allstack-api.techsea.sa/api/client';
    private const MAX_ATTEMPTS = 100; // per minute

    private string $apiKey;
    private string $environment;
    private HttpClientInterface $httpClient;
    private RateLimiter $rateLimiter;

    /**
     * Toggle data anonymization (IP, UA, etc.). Default to true for GDPR.
     */
    private bool $anonymizeData = true;

    /**
     * --------------------------------------
     * NEW: Pattern-based detection for secrets
     * --------------------------------------
     * You can expand or refine this list of regex patterns
     * to capture typical API keys, tokens, etc.
     *
     * Example patterns:
     * - `[A-Za-z0-9_=-]{20,}`: a naive pattern for 20+ base64-ish strings
     * - `AKIA[0-9A-Z]{16}`: an AWS Access Key example
     * - `[0-9a-fA-F]{32,}`: a naive hex token of length >= 32
     */
    private array $secretPatterns = [
        '/AKIA[0-9A-Z]{16}/',        // Example: AWS Access Key (very naive)
        '/[A-Za-z0-9_\-=]{20,}/',    // Generic "long token" with base64 chars or underscores
        '/[0-9a-fA-F]{32,}/',        // Hex strings of length >= 32
    ];

    public function __construct(string $apiKey, string $environment = 'production')
    {
        $this->apiKey       = $apiKey;
        $this->environment  = $environment;
        $this->httpClient   = HttpClient::create([
            'timeout' => 5,
            'headers' => [
                'x-api-key' => $this->apiKey,
                'Accept'    => 'application/json',
            ],
        ]);
        $this->rateLimiter  = app(RateLimiter::class);
    }

    /**
     * Example: Capture an Exception
     */
    public function captureException(Throwable $exception): bool
    {
        // OPTIONAL: Check if user consented to data processing (GDPR)
        if (!$this->userHasConsented()) {
            Log::info('Skipping error capture due to no user consent');
            return false;
        }

        if ($this->shouldThrottle()) {
            Log::warning('AllStack rate limit exceeded');
            return false;
        }

        try {
            // 1. Determine severity & level
            $errorSeverity = $this->determineErrorSeverity($exception);
            $errorLevel    = $this->determineErrorLevel('error', $errorSeverity);

            // 2. Build the payload
            $payload = [
                'errorMessage'   => $exception->getMessage() ?: 'Unknown Exception',
                'errorType'      => get_class($exception),
                'errorLevel'     => $errorLevel,
                'environment'    => $this->environment,
                'ip'             => $this->anonymizeData
                    ? $this->anonymizeIp($this->getIpAddress())
                    : $this->getIpAddress(),
                'userAgent'      => 'Laravel',
                'url'            => '',
                'timestamp'      => $this->formatTimestamp(now()),
                'additionalData' => [
                    'file'        => $exception->getFile(),
                    'line'        => $exception->getLine(),
                    'trace'       => $exception->getTraceAsString(),
                    'hostname'    => gethostname(),
                    'codeContext' => $this->getCodeContext(
                        $exception->getFile(),
                        $exception->getLine(),
                        5
                    ),
                ],
                'stackTrace'    => (object) $this->formatStackTrace($exception),
                'contexts'      => $this->createContexts(),
                'errorCategory' => $this->determineErrorCategory($exception),
                'errorCause'    => $this->determineErrorCause($exception),

                // Some optional fields
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

            $this->httpClient->request('POST', self::API_URL . '/exception', [
                'json' => $payload,
            ]);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send error to AllStack: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Capture an HTTP request
     */
    public function captureRequest(Request $request, float $responseTime = 0): bool
    {
        // OPTIONAL: Check if user consented to data processing (GDPR)
        if (!$this->userHasConsented()) {
            Log::info('Skipping request capture due to no user consent');
            return false;
        }

        if ($this->shouldThrottle()) {
            Log::warning('AllStack rate limit exceeded');
            return false;
        }

        try {
            // Let's treat requests as low severity warnings
            $errorSeverity = 'low';
            $errorLevel    = 'WARNING';

            $ipAddress     = $this->anonymizeData
                ? $this->anonymizeIp($request->ip())
                : $request->ip();

            // Build the payload
            $payload = [
                'errorMessage'   => 'HTTP Request Captured',
                'errorType'      => 'HTTPRequest',
                'errorLevel'     => $errorLevel,
                'environment'    => $this->environment,
                'ip'             => $ipAddress,
                'userAgent'      => $this->anonymizeData
                    ? $this->filterUserAgent($request->userAgent())
                    : ($request->userAgent() ?? 'unknown'),
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
                'errorCategory' => 'APPLICATION_ERROR',
                'errorCause'    => 'USER',

                // Optional
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

            $this->httpClient->request('POST', self::API_URL . '/http-request-transactions', [
                'json' => $payload,
            ]);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send request to AllStack: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * ==========================================
     * TRANSFORMATION METHODS (HEADERS/BODY/QUERY)
     * WITH PATTERN-BASED REDACTION
     * ==========================================
     */

    /**
     * We define a single method that applies
     * multiple checks (field-based + pattern-based).
     */
    private function sanitizeValue(string $key, mixed $value): mixed
    {
        // 1) If it's not a string, we won't do pattern matching
        //    but we still might want to check for arrays below.
        if (!is_string($value)) {
            return $value;
        }

        // 2) If the key is obviously sensitive (like 'password', 'token', etc.), redact immediately.
        if ($this->isFieldSensitive($key)) {
            return '[REDACTED]';
        }

        // 3) Check for typical PII (email, phone) or known sensitive pattern
        if ($this->isPotentiallySensitive($value)) {
            return '[REDACTED]';
        }

        // 4) Otherwise, return value as is
        return $value;
    }

    /**
     * Transform headers: remove or mask known sensitive headers
     * plus run pattern checks.
     */
    private function transformHeaders(array $headers): array
    {
        $transformed = [];
        $sensitiveHeaders = [
            'authorization',
            'cookie',
            'set-cookie'
            // add more if needed
        ];

        foreach ($headers as $key => $values) {
            $lowerKey = strtolower($key);

            // If header name is sensitive, redact entirely
            if (in_array($lowerKey, $sensitiveHeaders, true)) {
                $transformed[$lowerKey] = '[REDACTED]';
                continue;
            }

            // Otherwise, check each value for patterns
            if (is_array($values)) {
                $masked = [];
                foreach ($values as $val) {
                    $masked[] = is_string($val)
                        ? $this->applySecretPatterns($val)
                        : $val;
                }
                $transformed[$lowerKey] = implode(', ', $masked);
            } else {
                $transformed[$lowerKey] = $this->applySecretPatterns($values);
            }
        }

        Log::debug('Transformed headers with pattern-based redaction', ['headers' => $transformed]);
        return $transformed;
    }

    /**
     * Transform query params: recursively sanitize each value
     */
    private function transformQueryParams(array $params): array
    {
        $transformed = [];
        foreach ($params as $key => $value) {
            if (is_array($value)) {
                $transformed[$key] = $this->transformQueryParams($value);
                continue;
            }

            // Convert booleans and numbers
            if ($value === 'true') {
                $value = true;
            } elseif ($value === 'false') {
                $value = false;
            } elseif (is_numeric($value)) {
                $value = $value * 1;
            }

            // Apply combined field+pattern checks
            $transformed[$key] = $this->sanitizeValue($key, $value);
        }

        Log::debug('Transformed query params with pattern-based redaction', ['params' => $transformed]);
        return $transformed;
    }

    /**
     * Transform request body: recursively sanitize each field
     */
    private function transformRequestBody(array $data): array
    {
        $transformed = [];
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $transformed[$key] = $this->transformRequestBody($value);
                continue;
            }

            if ($value === 'true') {
                $value = true;
            } elseif ($value === 'false') {
                $value = false;
            } elseif (is_numeric($value)) {
                $value = $value * 1;
            }

            $transformed[$key] = $this->sanitizeValue($key, (string)$value);
        }

        return $transformed;
    }

    /**
     * ==========================================
     * PATTERN-BASED SENSITIVE DETECTION
     * ==========================================
     */

    /**
     * Actually apply the patterns in $this->secretPatterns
     * to the given string, returning "[REDACTED]" if a match is found.
     */
    private function applySecretPatterns(string $value): string
    {
        foreach ($this->secretPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return '[REDACTED]';
            }
        }
        return $value;
    }

    /**
     * We can define "isPotentiallySensitive" more broadly:
     * - Checks for email or phone
     * - Checks the secret patterns
     */
    private function isPotentiallySensitive(string $value): bool
    {
        // Check for email
        if (filter_var($value, FILTER_VALIDATE_EMAIL)) {
            return true;
        }

        // Check for phone number (naive)
        if (preg_match('/^\+?\d{7,15}$/', $value)) {
            return true;
        }

        // Check for known secret patterns (API keys, tokens)
        foreach ($this->secretPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the field name is known to be sensitive
     * e.g. password, token, secret, credit_card, etc.
     */
    private function isFieldSensitive(string $fieldName): bool
    {
        $sensitiveFields = [
            'password', 'pwd', 'token', 'secret', 'credit_card',
            'card_number', 'api_key', 'apikey', 'secret_key',
            'authorization' // if it shows up in body
        ];

        foreach ($sensitiveFields as $field) {
            if (stripos($fieldName, $field) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * ==========================================
     * Other existing helper methods
     * ==========================================
     */

    private function anonymizeIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            $parts[count($parts) - 1] = 'x';
            return implode('.', $parts);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);
            $parts = array_slice($parts, 0, 4);
            return implode(':', $parts).'::xxxx';
        }

        return $ip;
    }

    private function filterUserAgent(?string $userAgent): string
    {
        if (!$userAgent) {
            return 'unknown';
        }
        return preg_replace('/\d+/', 'XXX', $userAgent);
    }

    private function userHasConsented(): bool
    {
        // For demonstration, we return true by default.
        // Real-world: Check user preference or a config setting.
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

    private function getCodeContext(string $file, int $line, int $context = 5): array
    {
        if (!is_readable($file)) {
            return [];
        }

        $lines = @file($file, FILE_IGNORE_NEW_LINES);
        if (!$lines) {
            return [];
        }

        $start = max($line - $context - 1, 0);
        $end   = min($line + $context - 1, count($lines) - 1);

        $snippet = [];
        for ($i = $start; $i <= $end; $i++) {
            $snippet[$i + 1] = $lines[$i];
        }
        return $snippet;
    }

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

    private function determineErrorLevel(string $type, string $severity): string
    {
        if ($type === 'error') {
            return $severity === 'critical' ? 'CRITICAL' : 'ERROR';
        }
        return $severity === 'critical' ? 'CRITICAL' : 'WARNING';
    }

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

    private function determineErrorCause(Throwable $exception): string
    {
        $msg = strtolower($exception->getMessage());
        if (str_contains($msg, 'validation') || str_contains($msg, 'input')) {
            return 'USER';
        }
        if (str_contains($msg, 'db') || str_contains($msg, 'server') || str_contains($msg, 'connection')) {
            return 'SYSTEM';
        }
        return 'SYSTEM';
    }

    private function determineErrorCategory(Throwable $exception): string
    {
        $message = strtolower($exception->getMessage());

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
            if (!isset($payload[$field]) || $payload[$field] === '') {
                Log::warning("Missing required field: {$field}", ['payload' => $payload]);
                return false;
            }
        }

        return true;
    }

    /**
     * Example of a "send with retry" pattern if you prefer that approach.
     */
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
                $response = $this->httpClient->request('POST', self::API_URL . $endpoint, [
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