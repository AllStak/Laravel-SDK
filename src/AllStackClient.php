<?php

namespace Techsea\AllStack;

use Illuminate\Support\Facades\Log;
use Illuminate\Cache\RateLimiter;
use Techsea\AllStack\Helpers\ClientHelper;
use Techsea\AllStack\Helpers\SecurityHelper;
use Throwable;
use Illuminate\Http\Request;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class AllStackClient
{
    private const API_URL = 'https://api.allstak.io/api/client';
    private const MAX_ATTEMPTS = 100;

    private string $apiKey;
    private string $environment;
    private HttpClientInterface $httpClient;
    private RateLimiter $rateLimiter;
    private SecurityHelper $securityHelper;
    private ClientHelper $clientHelper;

    public function __construct(string $apiKey, string $environment = 'production')
    {
        $this->apiKey = $apiKey;
        $this->environment = $environment;
        $this->httpClient = HttpClient::create([
            'timeout' => 5,
            'headers' => [
                'x-api-key' => $this->apiKey,
                'Accept'    => 'application/json',
            ],
        ]);
        $this->rateLimiter = app(RateLimiter::class);
        $this->securityHelper = new SecurityHelper();
        $this->clientHelper = new ClientHelper($this->securityHelper);
    }

    public function captureException(Throwable $exception): bool
    {
        if ($this->shouldThrottle()) {
            Log::warning('AllStack rate limit exceeded');
            return false;
        }

        try {
            $errorSeverity = $this->clientHelper->determineErrorSeverity($exception);
            $errorLevel = $this->clientHelper->determineErrorLevel('error', $errorSeverity);

            $codeContextLines = $this->clientHelper->getCodeContextLines(
                $exception->getFile(),
                $exception->getLine(),
                5
            );
            $maskedCodeContext = $this->securityHelper->maskCodeLines($codeContextLines);

            // Get any breadcrumbs stored during the request lifecycle
            $breadcrumbs = app()->bound('allstack.breadcrumbs')
                ? app('allstack.breadcrumbs')->toArray()
                : [];

            $payload = [
                'errorMessage'   => $exception->getMessage() ?: 'Unknown Exception',
                'errorType'      => get_class($exception),
                'errorLevel'     => $errorLevel,
                'environment'    => $this->environment,
                'ip'             => $this->securityHelper->maskIp(request()->ip()),
                'userAgent'      => 'Laravel',
                'url'            => $this->securityHelper->sanitizeUrl(request()->fullUrl()),
                'timestamp'      => $this->clientHelper->formatTimestamp(now()),
                'additionalData' => [
                    'file'        => $exception->getFile(),
                    'line'        => $exception->getLine(),
                    'trace'       => $exception->getTraceAsString(),
                    'hostname'    => gethostname(),
                    'codeContext' => $maskedCodeContext,
                ],
                'stackTrace'     => (object) $this->clientHelper->formatStackTrace($exception),
                'contexts'       => $this->clientHelper->createContexts(),
                'errorCategory'  => $this->clientHelper->determineErrorCategory($exception),
                'errorCause'     => $this->clientHelper->determineErrorCause($exception),
                'release'        => env('RELEASE', '1.0.0'),
                'component'      => env('COMPONENT', 'my-component'),
                'memoryUsage'    => $this->clientHelper->getMemoryUsage(),
                'errorSeverity'  => $errorSeverity,
                'breadcrumbs'    => $breadcrumbs, // ✅ NEW
            ];

            Log::debug('AllStack Exception Payload', ['payload' => $payload]);

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

    public function captureRequest(Request $request, float $responseTime = 0): bool
    {
        if ($this->shouldThrottle()) {
            Log::warning('AllStack rate limit exceeded');
            return false;
        }

        try {
            // 👉 Add this line to track the request
            $this->addBreadcrumb('http-request', 'Incoming request', [
                'method' => $request->method(),
                'url' => $request->fullUrl(),
            ]);

            $payload = [
                'path'        => $request->path(),
                'method'      => $request->method(),
                'headers'     => (object) $this->clientHelper->transformHeaders($request->headers->all()),
                'queryParams' => (object) $this->clientHelper->transformQueryParams($request->query()),
                'body'        => (object) $this->clientHelper->transformRequestBody($request->all()),
                'ip'          => $this->securityHelper->maskIp($request->ip()),
                'userAgent'   => $request->userAgent() ?? 'unknown',
                'referer'     => $request->header('referer', 'unknown'),
                'origin'      => $request->header('origin', 'unknown'),
                'host'        => $request->getHost(),
                'protocol'    => $request->getScheme(),
                'hostname'    => gethostname() ?: 'unknown',
                'port'        => (string) $request->getPort(),
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
     * Validates the payload.
     *
     * If the payload contains a "path" key, we assume it’s from captureRequest;
     * otherwise, it’s an exception payload.
     */
    private function validatePayload(array $payload): bool
    {
        if (isset($payload['path'])) {
            // Request payload
            $requiredFields = [
                'path',
                'method',
                'headers',
                'queryParams',
                'body',
                'ip',
                'userAgent',
                'referer',
                'origin',
                'host',
                'protocol',
                'hostname',
                'port'
            ];
        } else {
            // Exception payload
            $requiredFields = ['errorMessage', 'errorType', 'errorLevel', 'environment', 'timestamp'];
        }

        foreach ($requiredFields as $field) {
            if (!isset($payload[$field]) || $payload[$field] === '') {
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
            fn() => true
        );
    }

    public function addBreadcrumb(string $eventType, string $message, array $metadata = []): void
    {
        if (!app()->bound('allstack.breadcrumbs')) {
            app()->singleton('allstack.breadcrumbs', function () {
                return collect();
            });
        }

        $breadcrumb = [
            'timestamp' => now()->toISOString(),
            'type' => $eventType,
            'message' => $message,
            'metadata' => $metadata,
        ];

        app('allstack.breadcrumbs')->push($breadcrumb);
    }


}
