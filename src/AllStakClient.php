<?php

namespace AllStak;

use AllStak\Tracing\SpanContext;
use Illuminate\Support\Facades\Log;
use Illuminate\Cache\RateLimiter;
use AllStak\Helpers\ClientHelper;
use AllStak\Helpers\SecurityHelper;
use Throwable;
use Illuminate\Http\Request;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class AllStakClient
{
//    const API_URL = 'https://api.allstak.io/api/client';
    const API_URL = 'http://localhost:8080/api/client';
    const MAX_ATTEMPTS = 100;

    private string $apiKey;
    private string $environment;
    private bool  $sendIpAddress = true;
    private HttpClientInterface $httpClient;
    private RateLimiter $rateLimiter;
    private SecurityHelper $securityHelper;
    private ClientHelper $clientHelper;
    protected $currentTransaction = null;
    protected $currentSpan = null;
    public function __construct(string $apiKey, string $environment = 'production', bool $sendIpAddress = true)
    {

        $this->apiKey = $apiKey;
        $this->environment = $environment;
        $this->sendIpAddress = $sendIpAddress;
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
            Log::warning('allstak rate limit exceeded');
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
            $payload = [
                'errorMessage'   => $exception->getMessage() ?: 'Unknown Exception',
                'errorType'      => get_class($exception),
                'errorLevel'     => $errorLevel,
                'environment'    => $this->environment,
                'ip'             =>  $this->sendIpAddress ? request()->ip() : $this->securityHelper->maskIp(request()->ip()),
                'userAgent'      =>  request()->userAgent() ?? 'unknown',
                'referer'        =>  request()->header('referer', 'unknown'),
                'origin'         =>  request()->header('origin', 'unknown'),
                'host'           =>  request()->getHost(),
                'protocol'       =>  request()->getScheme(),
                'port'           =>  (string) request()->getPort(),
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
            ];

            Log::debug('allstak Exception Payload', ['payload' => $payload]);

            if (!$this->validatePayload($payload)) {
                return false;
            }

            $this->httpClient->request('POST', self::API_URL . '/exception', [
                'json' => $payload,
            ]);
            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send error to allstak: ' . $e->getMessage());
            return false;
        }
    }

    public function captureRequest(Request $request, float $responseTime = 0): bool
    {
        if ($this->shouldThrottle()) {
            Log::warning('allstak rate limit exceeded');
            return false;
        }

        try {


            $payload = [
                'path'        => $request->path(),
                'method'      => $request->method(),
                'headers'     => (object) $this->clientHelper->transformHeaders($request->headers->all()),
                'queryParams' => (object) $this->clientHelper->transformQueryParams($request->query()),
                'body'        => (object) $this->clientHelper->transformRequestBody($request->all()),
                "ip"          =>  $this->sendIpAddress ? $request->ip() : $this->securityHelper->maskIp($request->ip()),
                'userAgent'   => $request->userAgent() ?? 'unknown',
                'referer'     => $request->header('referer', 'unknown'),
                'origin'      => $request->header('origin', 'unknown'),
                'host'        => $request->getHost(),
                'protocol'    => $request->getScheme(),
                'hostname'    => gethostname() ?: 'unknown',
                'port'        => (string) $request->getPort(),
            ];

            Log::debug('allstak Request Payload', ['payload' => $payload]);

            if (!$this->validatePayload($payload)) {
                return false;
            }

            $this->httpClient->request('POST', self::API_URL . '/http-request-transactions', [
                'json' => $payload,
            ]);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send request to allstak: ' . $e->getMessage());
            return false;
        }
    }
    public function sendDbSpan(array $span): bool
    {
        if ($this->shouldThrottle()) {
            \Log::warning('allstak rate limit exceeded');
            return false;
        }
        \Log::debug('sendDbSpan called', ['span' => $span]);

        try {
            $payload = [
                'spanId'      => $span['id'],
                'traceId'     => $span['trace_id'],
                'parentSpanId'=> $span['parent_span_id'] ?? null,
                'name'        => $span['name'],
                'startTime'   => $span['start_time'],
                'endTime'     => $span['end_time'],
                'attributes'  => $span['attributes'],
                'status'      => $span['status'] ?? 'ok',
                'error'       => $span['error'] ?? null,
                'environment' => $this->environment,
                'hostname'    => gethostname(),
                'component'   => env('COMPONENT', 'my-component'),
            ];
            \Log::debug('allstak DB Span Payload', ['payload' => $payload]);
            if (!$this->validatePayload($payload)) {
                return false;
            }
            $this->httpClient->request('POST', self::API_URL . '/db-span', [
                'json' => $payload,
            ]);
            return true;
        } catch (\Exception $e) {
            \Log::error('Failed to send DB span to allstak: ' . $e->getMessage());
            return false;
        }
    }




    /**
     * Start a new transaction (root span)
     */
    public function startTransaction(string $name, string $op = 'http.server'): array
    {
        $transaction = [
            'id' => bin2hex(random_bytes(8)),
            'trace_id' => bin2hex(random_bytes(16)),
            'parent_span_id' => null,
            'name' => $name,
            'op' => $op,
            'start_time' => microtime(true),
            'end_time' => null,
            'attributes' => [],
            'status' => 'ok',
            'children' => [],
        ];

        $this->currentTransaction = $transaction;
        $this->currentSpan = $transaction;

        // Store in SpanContext for global access
        SpanContext::setTraceId($transaction['trace_id']);
        SpanContext::setParentSpanId($transaction['id']);

        return $transaction;
    }

    /**
     * Start a child span
     */
    public function startSpan(string $name, string $op = 'custom', ?array $parentSpan = null): array
    {
        $parent = $parentSpan ?? $this->currentSpan;

        if (!$parent) {
            throw new \RuntimeException('No parent span or transaction found. Call startTransaction() first.');
        }

        $span = [
            'id' => bin2hex(random_bytes(8)),
            'trace_id' => $parent['trace_id'],
            'parent_span_id' => $parent['id'],
            'name' => $name,
            'op' => $op,
            'start_time' => microtime(true),
            'end_time' => null,
            'attributes' => [],
            'status' => 'ok',
        ];

        $this->currentSpan = $span;
        SpanContext::setParentSpanId($span['id']);

        return $span;
    }

    /**
     * Finish a span and send it
     */
    public function finishSpan(array &$span): void
    {
        $span['end_time'] = microtime(true);

        // Send the span
        $this->sendSpan($span);

        // Restore parent span as current
        if ($span['parent_span_id']) {
            SpanContext::setParentSpanId($span['parent_span_id']);
        }
    }

    /**
     * Finish the transaction
     */
    public function finishTransaction(array &$transaction): void
    {
        $transaction['end_time'] = microtime(true);
        $this->sendSpan($transaction);

        $this->currentTransaction = null;
        $this->currentSpan = null;
    }

    /**
     * Send a span to AllStak API
     */
    private function sendSpan(array $span): bool
    {
        if ($this->shouldThrottle()) {
            Log::warning('allstak rate limit exceeded');
            return false;
        }

        try {
            $payload = [
                'spanId'      => $span['id'],
                'traceId'     => $span['trace_id'],
                'parentSpanId'=> $span['parent_span_id'] ?? null,
                'name'        => $span['name'],
                'op'          => $span['op'] ?? 'custom',
                'startTime'   => $span['start_time'],
                'endTime'     => $span['end_time'],
                'attributes'  => $span['attributes'] ?? [],
                'status'      => $span['status'] ?? 'ok',
                'error'       => $span['error'] ?? null,
                'environment' => $this->environment,
                'hostname'    => gethostname(),
                'component'   => env('COMPONENT', 'my-component'),
            ];

            Log::debug('allstak Span Payload', ['payload' => $payload]);

            if (!$this->validateSpanPayload($payload)) {
                return false;
            }

            $this->httpClient->request('POST', self::API_URL . '/spans', [
                'json' => $payload,
            ]);

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to send span to allstak: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Validate span payload
     */
    private function validateSpanPayload(array $payload): bool
    {
        $requiredFields = ['spanId', 'traceId', 'name', 'startTime', 'endTime', 'environment'];

        foreach ($requiredFields as $field) {
            if (!isset($payload[$field]) || $payload[$field] === '') {
                Log::warning("Missing required span field: {$field}", ['payload' => $payload]);
                return false;
            }
        }

        return true;
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
        }
        else if (isset($payload['spanId'])) {
            // DB span payload
            $requiredFields = ['spanId', 'traceId', 'name', 'startTime', 'endTime', 'attributes', 'environment'];
        }
        else {
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
            'allstak-api',
            self::MAX_ATTEMPTS,
            fn() => true
        );
    }






}
