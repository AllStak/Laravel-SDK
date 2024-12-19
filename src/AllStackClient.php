<?php

namespace Techsea\AllStack;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;
use Throwable;

class AllStackClient
{
    private const API_URL = 'http://localhost:8080/api/client';
    private string $apiKey;
    private string $environment;
    private Client $httpClient;

    public function __construct(string $apiKey, string $environment = 'production')
    {
        $this->apiKey = $apiKey;
        $this->environment = $environment;
        $this->httpClient = new Client();
    }

    public function captureException(Throwable $exception): void
    {
        try {
            $payload = $this->buildExceptionPayload($exception);
            
            $this->httpClient->post(self::API_URL . "/exception", [
                'headers' => $this->getHeaders(),
                'json' => $payload,
            ]);

            Log::info('Error sent to AllStack');
        } catch (\Exception $e) {
            Log::error('Failed to send error to AllStack: ' . $e->getMessage());
        }
    }

    public function captureRequest(\Illuminate\Http\Request $request): void
    {
        try {
            $payload = $this->buildHttpRequestPayload($request);
            
            $this->httpClient->post(self::API_URL . "/http-request-transactions", [
                'headers' => $this->getHeaders(),
                'json' => $payload,
            ]);

            Log::info('HTTP request sent to AllStack');
        } catch (\Exception $e) {
            Log::error('Failed to send request to AllStack: ' . $e->getMessage());
        }
    }

    private function buildBasePayload(): array
    {
        return [
            'timestamp' => now()->toIso8601String(),
            'environment' => $this->environment,
            'tags' => [],
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
    }

    private function buildExceptionPayload(Throwable $exception): array
    {
        return array_merge($this->buildBasePayload(), [
            'errorMessage' => $exception->getMessage(),
            'errorType' => get_class($exception),
            'stackTrace' => $this->formatStackTrace($exception),
        ]);
    }

    private function buildHttpRequestPayload(\Illuminate\Http\Request $request): array
    {
        return array_merge($this->buildBasePayload(), [
            'path' => $request->path(),
            'method' => $request->method(),
            'headers' => $request->headers->all(),
            'queryParams' => $request->query(),
            'body' => $request->all(),
            'referer' => $request->header('referer'),
            'origin' => $request->header('origin'),
            'host' => $request->getHost(),
            'protocol' => $request->getScheme(),
            'port' => $request->getPort(),
        ]);
    }

    private function formatStackTrace(Throwable $exception): array
    {
        $stackTrace = [];
        $trace = $exception->getTrace();
        
        foreach ($trace as $frame) {
            $stackTrace[] = [
                'file' => $frame['file'] ?? '',
                'line' => $frame['line'] ?? '',
                'function' => $frame['function'] ?? '',
                'class' => $frame['class'] ?? '',
                'type' => $frame['type'] ?? '',
            ];
        }
        
        return $stackTrace;
    }

    private function getHeaders(): array
    {
        return [
            'Authorization' => "Bearer {$this->apiKey}",
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ];
    }
}