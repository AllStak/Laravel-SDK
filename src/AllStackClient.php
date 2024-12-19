<?php

namespace Techsea\AllStack;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;
use Illuminate\Cache\RateLimiter;
use Throwable;

class AllStackClient
{
    private const API_URL = 'http://localhost:8080/api/client';
    private const MAX_ATTEMPTS = 100; // per minute
    
    private string $apiKey;
    private string $environment;
    private Client $httpClient;
    private RateLimiter $rateLimiter;
    private array $tags = [];

    public function __construct(string $apiKey, string $environment = 'production')
    {
        $this->apiKey = $apiKey;
        $this->environment = $environment;
        $this->httpClient = new Client([
            'timeout' => 5,
            'connect_timeout' => 5,
            'http_errors' => true
        ]);
        $this->rateLimiter = app(RateLimiter::class);
    }

    public function setTag(string $key, string $value): self
    {
        $this->tags[$key] = $value;
        return $this;
    }

    public function captureException(Throwable $exception): bool
    {
        if ($this->shouldThrottle()) {
            Log::warning('AllStack rate limit exceeded');
            return false;
        }

        try {
            $payload = $this->buildExceptionPayload($exception);
            
            if (!$this->validatePayload($payload)) {
                return false;
            }

            return $this->sendWithRetry("/exception", $payload);
        } catch (\Exception $e) {
            Log::error('Failed to send error to AllStack: ' . $e->getMessage());
            return false;
        }
    }

    public function captureRequest(\Illuminate\Http\Request $request): bool
    {
        if ($this->shouldThrottle()) {
            Log::warning('AllStack rate limit exceeded');
            return false;
        }

        try {
            $payload = $this->buildHttpRequestPayload($request);
            
            if (!$this->validatePayload($payload)) {
                return false;
            }

            return $this->sendWithRetry("/http-request-transactions", $payload);
        } catch (\Exception $e) {
            Log::error('Failed to send request to AllStack: ' . $e->getMessage());
            return false;
        }
    }

    private function buildHttpRequestPayload(\Illuminate\Http\Request $request): array
    {
        // Build a payload that exactly matches the Java DTO structure
        return [
            'path' => $request->path(),
            'method' => $request->method(),
            'headers' => $this->transformHeaders($request->headers->all()),
            'queryParams' => $this->transformQueryParams($request->query()),
            'body' => $this->transformRequestBody($request->all()),
            'ip' => $request->ip(),
            'userAgent' => $request->userAgent() ?? '',
            'referer' => $request->header('referer') ?? '',
            'origin' => $request->header('origin') ?? '',
            'host' => $request->getHost(),
            'protocol' => $request->getScheme(),
            'hostname' => gethostname(),
            'port' => (string) $request->getPort()
        ];
    }

    private function buildExceptionPayload(Throwable $exception): array
    {
        return array_merge($this->buildBasePayload(), [
            'errorMessage' => $exception->getMessage(),
            'errorType' => get_class($exception),
            'stackTrace' => $this->formatStackTrace($exception),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
        ]);
    }

    private function buildBasePayload(): array
    {
        $timestamp = now()->format('Y-m-d\TH:i:s');

        $payload = [
            'timestamp' => $timestamp,
            'environment' => $this->environment,
            'tags' => $this->tags,
            'ip' => request()->ip(),
            'userAgent' => request()->userAgent() ?? '',
            'hostname' => gethostname(),
            'additionalData' => [
                'hostname' => gethostname(),
                'memoryUsage' => [
                    'rss' => memory_get_usage(true),
                    'heapTotal' => memory_get_peak_usage(true),
                    'heapUsed' => memory_get_usage(),
                ],
                'uptime' => time() - LARAVEL_START,
            ],
            'contexts' => [
                'runtime' => [
                    'name' => 'PHP',
                    'version' => PHP_VERSION,
                ],
                'system' => [
                    'platform' => PHP_OS,
                    'release' => php_uname('r'),
                    'cpu' => php_uname('m'),
                ],
                'process' => [
                    'pid' => getmypid(),
                    'argv' => $_SERVER['argv'] ?? [],
                    'execPath' => PHP_BINARY,
                    'cwd' => getcwd(),
                ],
            ],
        ];

        return $this->addUserContext($payload);
    }

    private function formatStackTrace(Throwable $exception): array
    {
        $stackTrace = [];
        $trace = $exception->getTrace();
        
        foreach ($trace as $index => $frame) {
            $frameKey = sprintf("frame_%d", $index);
            $stackTrace[$frameKey] = [
                'file' => $frame['file'] ?? '',
                'line' => $frame['line'] ?? '',
                'function' => $frame['function'] ?? '',
                'class' => $frame['class'] ?? '',
                'type' => $frame['type'] ?? '',
            ];
        }
        
        return $stackTrace;
    }

    private function transformHeaders(array $headers): array
    {
        // Headers come as arrays, we need to convert to strings for most cases
        $transformed = [];
        foreach ($headers as $key => $values) {
            // If it's a single value header, store as string
            // If multiple values, keep as array
            $transformed[$key] = count($values) === 1 ? $values[0] : $values;
        }
        return $transformed;
    }

    private function transformQueryParams(array $params): array
    {
        // Convert all query parameters to ensure proper typing
        return array_map(function ($value) {
            if (is_array($value)) {
                return $this->transformQueryParams($value);
            }
            // Convert boolean strings to actual booleans
            if ($value === 'true') return true;
            if ($value === 'false') return false;
            // Try to convert numeric strings to numbers
            if (is_numeric($value)) {
                return $value * 1;
            }
            return $value;
        }, $params);
    }

    private function transformRequestBody(array $data): array
    {
        $sensitiveFields = ['password', 'token', 'secret', 'credit_card'];
        
        return array_map(function ($value) use ($sensitiveFields) {
            if (is_array($value)) {
                return $this->transformRequestBody($value);
            }
            
            // Check for sensitive fields
            foreach ($sensitiveFields as $field) {
                if (is_string($value) && stripos($value, $field) !== false) {
                    return '[REDACTED]';
                }
            }
            
            // Convert types appropriately
            if ($value === 'true') return true;
            if ($value === 'false') return false;
            if (is_numeric($value)) {
                return $value * 1;
            }
            return $value;
        }, $data);
    }

    private function validatePayload(array $payload): bool
    {
        // Different required fields for different types of payloads
        $requiredFields = [];
        
        // If it's an exception payload
        if (isset($payload['errorMessage'])) {
            $requiredFields = ['errorMessage', 'errorType', 'stackTrace'];
        } 
        // If it's an HTTP request payload
        else if (isset($payload['path'])) {
            $requiredFields = ['path', 'method', 'ip', 'host'];
        }
        
        foreach ($requiredFields as $field) {
            if (empty($payload[$field])) {
                Log::warning("Missing required field: {$field}");
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
            function() { return true; }
        );
    }

    private function sendWithRetry(string $endpoint, array $payload, int $maxRetries = 3): bool
    {
        $attempt = 0;
        
        while ($attempt < $maxRetries) {
            try {
                $response = $this->httpClient->post(self::API_URL . $endpoint, [
                    'headers' => $this->getHeaders(),
                    'json' => $payload,
                ]);
                Log::info('Successfully sent to AllStack');
                return true;
            } catch (\Exception $e) {
                $attempt++;
                if ($attempt === $maxRetries) {
                    Log::error("Failed after {$maxRetries} attempts: " . $e->getMessage());
                    return false;
                }
                sleep(1); // Wait before retrying
            }
        }
        
        return false;
    }

    private function getHeaders(): array
    {
        return [
            'x-api-key' => "{$this->apiKey}",
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ];
    }

    private function addUserContext(array $payload): array
    {
        if (auth()->check()) {
            $payload['user'] = [
                'id' => auth()->id(),
                'email' => auth()->user()->email ?? null,
            ];
        }
        
        return $payload;
    }
}