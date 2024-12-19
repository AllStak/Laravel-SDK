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
            
            Log::debug('Request payload built', ['payload' => $payload]); // Debug log
            
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
        $headers = $this->transformHeaders($request->headers->all());
        $queryParams = $this->transformQueryParams($request->query());
        $body = $this->transformRequestBody($request->all());

        // Debug logs
        Log::debug('Building HTTP request payload', [
            'path' => $request->path(),
            'headers' => $headers,
            'queryParams' => $queryParams
        ]);

        return [
            'path' => $request->path(),
            'method' => $request->method(),
            'headers' => (object)$headers,
            'queryParams' => (object)$queryParams,
            'body' => (object)$body,
            'ip' => $request->ip(),
            'userAgent' => $request->userAgent() ?? '',
            'referer' => $request->header('referer') ?? '',
            'origin' => $request->header('origin') ?? '',
            'host' => $request->getHost(),
            'protocol' => $request->getScheme(),
            'hostname' => gethostname(),
            'port' => (string)$request->getPort()
        ];
    }

    private function buildExceptionPayload(Throwable $exception): array
    {
        return [
            'errorMessage' => $exception->getMessage(),
            'errorType' => get_class($exception),
            'stackTrace' => (object)$this->formatStackTrace($exception),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
        ];
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
        $transformed = [];
        
        foreach ($headers as $key => $values) {
            // Convert array of values to comma-separated string
            if (is_array($values)) {
                $transformed[strtolower($key)] = implode(', ', $values);
            } else {
                $transformed[strtolower($key)] = $values;
            }
        }
        
        Log::debug('Transformed headers', ['headers' => $transformed]); // Debug log
        return $transformed;
    }

    private function transformQueryParams(array $params): array
    {
        $transformed = [];
        
        foreach ($params as $key => $value) {
            if (is_array($value)) {
                // Convert array values to comma-separated strings
                $transformed[$key] = implode(',', $value);
            } else {
                // Convert primitive values appropriately
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
        
        Log::debug('Transformed query params', ['params' => $transformed]); // Debug log
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
                // Check for sensitive fields
                foreach ($sensitiveFields as $field) {
                    if (stripos($key, $field) !== false) {
                        $value = '[REDACTED]';
                        break;
                    }
                }
                
                // Convert types appropriately
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
        // Required fields for HTTP request
        if (isset($payload['path'])) {
            $requiredFields = ['path', 'method', 'ip', 'host'];
        }
        // Required fields for exception
        else if (isset($payload['errorMessage'])) {
            $requiredFields = ['errorMessage', 'errorType', 'stackTrace'];
        } else {
            Log::warning('Unknown payload type');
            return false;
        }
        
        foreach ($requiredFields as $field) {
            if (empty($payload[$field])) {
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
            function() { return true; }
        );
    }

    private function sendWithRetry(string $endpoint, array $payload, int $maxRetries = 3): bool
    {
        $attempt = 0;
        
        // Log the final payload for debugging
        Log::debug('Sending payload to AllStack', [
            'endpoint' => $endpoint,
            'payload' => $payload,
            'attempt' => $attempt + 1
        ]);
        
        while ($attempt < $maxRetries) {
            try {
                $response = $this->httpClient->post(self::API_URL . $endpoint, [
                    'headers' => $this->getHeaders(),
                    'json' => $payload,
                ]);
                
                Log::info('Successfully sent to AllStack', [
                    'endpoint' => $endpoint,
                    'status' => $response->getStatusCode()
                ]);
                return true;
            } catch (\Exception $e) {
                $attempt++;
                Log::error('Failed to send to AllStack', [
                    'endpoint' => $endpoint,
                    'attempt' => $attempt,
                    'error' => $e->getMessage()
                ]);
                
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
}