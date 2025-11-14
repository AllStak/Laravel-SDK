<?php

namespace AllStak;

use AllStak\DTO\ObservabilityHttpRequestDto;
use AllStak\DTO\ObservabilityErrorEventDto;
use AllStak\DTO\ObservabilityApplicationLogDto;
use AllStak\DTO\ObservabilityDatabaseQueryDto;
use AllStak\DTO\ObservabilitySpanDto;
use AllStak\DTO\TelemetryBatchDto;
use AllStak\Helpers\IdGenerator;
use AllStak\Transport\AsyncHttpTransport;
use AllStak\Tracing\SpanContext;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

class AllStakClient
{
    const SDK_VERSION = "2.0.0";
    const SDK_LANGUAGE = "php";
    const SDK_PLATFORM = "laravel";

    private string $apiKey;
    private string $projectId;
    private string $environment;
    private string $endpoint;
    private bool $enabled;

    // Feature flags
    private bool $captureHttp;
    private bool $captureErrors;
    private bool $captureLogs;
    private bool $captureDatabase;

    // Performance settings
    private float $sampleRate;
    private int $batchSize;
    private int $flushInterval;

    // Privacy settings
    private bool $sendClientIp;
    private bool $anonymizeIp;
    private array $scrubHeaders;

    // Context
    private array $tags;

    // Internal
    private ?HttpClientInterface $httpClient = null;
    private ?AsyncHttpTransport $transport = null;
    private TelemetryBatchDto $batch;
    private float $lastFlush;
    private array $activeSpans = [];

    /**
     * Safely get config value (works in both standalone and Laravel contexts)
     */
    private function getConfig(string $key, $default = null)
    {
        if (function_exists('config')) {
            try {
                return config($key, $default);
            } catch (\Exception $e) {
                return $default;
            }
        }
        return $default;
    }

    /**
     * Safely get Laravel version
     */
    private function getLaravelVersion(): string
    {
        if (function_exists('app')) {
            try {
                $app = app();
                if (method_exists($app, 'version')) {
                    return $app->version();
                }
                // Fallback: try to get from Illuminate\Foundation\Application constant
                if (defined('Illuminate\Foundation\Application::VERSION')) {
                    return constant('Illuminate\Foundation\Application::VERSION');
                }
                return 'unknown';
            } catch (\Exception $e) {
                return 'unknown';
            }
        }
        return 'standalone';
    }

    /**
     * Safely get current request
     */
    private function getRequest()
    {
        if (function_exists('request')) {
            try {
                return request();
            } catch (\Exception $e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Safely get session ID from request
     */
    private function getSessionId($request): ?string
    {
        if (!$request) {
            return null;
        }

        try {
            // Check if request has session method and session is started
            if (method_exists($request, 'hasSession') && method_exists($request, 'session')) {
                if ($request->hasSession()) {
                    $session = $request->session();
                    if ($session && method_exists($session, 'getId')) {
                        return $session->getId();
                    }
                }
            }
        } catch (\Exception $e) {
            // Session not available (e.g., during console commands, early boot)
            return null;
        }

        return null;
    }

    public function __construct(array $config = [])
    {
        $this->apiKey = $config['api_key'] ?? $this->getConfig('allstak.api_key', '');
        $this->projectId = $config['project_id'] ?? $this->getConfig('allstak.project_id', '');
        $this->environment = $config['environment'] ?? $this->getConfig('allstak.environment', 'production');
        $this->endpoint = $config['endpoint'] ?? $this->getConfig('allstak.endpoint', 'http://localhost:8080/api/v2/ingest');
        $this->enabled = $config['enabled'] ?? $this->getConfig('allstak.enabled', true);

        // Feature flags
        $this->captureHttp = $config['capture_http'] ?? $this->getConfig('allstak.capture_http', true);
        $this->captureErrors = $config['capture_errors'] ?? $this->getConfig('allstak.capture_errors', true);
        $this->captureLogs = $config['capture_logs'] ?? $this->getConfig('allstak.capture_logs', true);
        $this->captureDatabase = $config['capture_database'] ?? $this->getConfig('allstak.capture_database', true);

        // Performance
        $this->sampleRate = $config['sample_rate'] ?? $this->getConfig('allstak.sample_rate', 1.0);
        $this->batchSize = $config['batch_size'] ?? $this->getConfig('allstak.batch_size', 100);
        $this->flushInterval = ($config['flush_interval'] ?? $this->getConfig('allstak.flush_interval', 5000)) / 1000; // Convert to seconds

        // Privacy
        $this->sendClientIp = $config['send_client_ip'] ?? $this->getConfig('allstak.send_client_ip', true);
        $this->anonymizeIp = $config['anonymize_ip'] ?? $this->getConfig('allstak.anonymize_ip', false);
        $scrubHeadersString = $config['scrub_headers'] ?? $this->getConfig('allstak.scrub_headers', 'Authorization,Cookie');
        $this->scrubHeaders = array_map('trim', explode(',', $scrubHeadersString));

        // Context
        $this->tags = $config['tags'] ?? $this->getConfig('allstak.tags', []);

        // Validate configuration
        if (empty($this->apiKey) || strlen($this->apiKey) < 10) {
            $this->enabled = false;
            error_log('AllStak SDK disabled: Invalid or empty API key');
        }

        if (empty($this->projectId)) {
            $this->enabled = false;
            error_log('AllStak SDK disabled: Project ID is required');
        }

        // Initialize helpers and transport
        $this->batch = new TelemetryBatchDto();
        $this->lastFlush = microtime(true);

        if ($this->enabled) {
            $this->httpClient = HttpClient::create([
                'timeout' => $config['timeout'] ?? $this->getConfig('allstak.timeout', 5),
                'headers' => [
                    'x-api-key' => $this->apiKey,
                    'Content-Type' => 'application/json',
                    'X-Project-ID' => $this->projectId,
                ],
            ]);

            $this->transport = new AsyncHttpTransport(
                $this->httpClient,
                $this->apiKey
            );
        }
    }

    /**
     * Check if we should sample this event
     */
    private function shouldSample(): bool
    {
        return $this->enabled && (mt_rand() / mt_getrandmax()) <= $this->sampleRate;
    }

    /**
     * Generate trace ID
     */
    public function generateTraceId(): string
    {
        return IdGenerator::generateTraceId();
    }

    /**
     * Generate span ID
     */
    public function generateSpanId(): string
    {
        return IdGenerator::generateSpanId();
    }

    /**
     * Get client IP from request
     */
    private function getClientIp(?Request $request): ?string
    {
        if (!$request || !$this->sendClientIp) {
            return null;
        }

        $ip = $request->ip();

        if ($this->anonymizeIp && $ip) {
            // Mask last octet for IPv4
            $parts = explode('.', $ip);
            if (count($parts) === 4) {
                $parts[3] = '0';
                return implode('.', $parts);
            }
        }

        return $ip;
    }

    /**
     * Scrub sensitive headers
     */
    private function scrubSensitiveHeaders(array $headers): array
    {
        $scrubbed = [];
        foreach ($headers as $key => $value) {
            $shouldScrub = false;
            foreach ($this->scrubHeaders as $pattern) {
                if (stripos($key, $pattern) !== false) {
                    $shouldScrub = true;
                    break;
                }
            }
            $scrubbed[$key] = $shouldScrub ? '[REDACTED]' : $value;
        }
        return $scrubbed;
    }

    /**
     * Capture HTTP request (automatic via middleware)
     */
    public function captureRequest(Request $request, $response, float $duration, ?string $traceId = null, ?string $spanId = null): bool
    {
        if (!$this->captureHttp || !$this->shouldSample()) {
            return false;
        }

        try {
            $traceId = $traceId ?? SpanContext::getTraceId() ?? $this->generateTraceId();
            $spanId = $spanId ?? $this->generateSpanId();

            $headers = $request->headers->all();
            $scrubbedHeaders = $this->scrubSensitiveHeaders($headers);

            $dto = new ObservabilityHttpRequestDto([
                'httpMethod' => $request->method(),
                'httpUrl' => $request->fullUrl(),
                'httpStatusCode' => $response->getStatusCode(),
                'traceId' => $traceId,
                'spanId' => $spanId,
                'timestamp' => (new \DateTime())->format('c'),
                'httpPath' => $request->path(),
                'httpDuration' => (int)($duration * 1000), // Convert to ms
                'userAgent' => $request->userAgent(),
                'referer' => $request->header('referer'),
                'requestHeaders' => json_encode($scrubbedHeaders),
                'responseHeaders' => json_encode($response->headers->all()),
                'requestBody' => substr($request->getContent(), 0, 10000), // Truncate to 10k chars
                'responseBody' => substr($response->getContent(), 0, 10000), // Truncate to 10k chars
                'clientIp' => $this->getClientIp($request),
                'userId' => ($user = $request->user()) ? (string)$user->id : null,
                'sessionId' => $this->getSessionId($request),
                'attributes' => array_merge($this->tags, [
                    'service_name' => $this->tags['service_name'] ?? 'laravel-app',
                    'php_version' => PHP_VERSION,
                    'laravel_version' => $this->getLaravelVersion(),
                ]),
            ]);

            if (!$dto->validate()) {
                error_log('AllStak: Invalid HTTP request DTO');
                return false;
            }

            $this->batch->addRequest($dto);
            $this->flushIfNeeded();

            return true;
        } catch (\Exception $e) {
            error_log('AllStak: Failed to capture request: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Capture error/exception (automatic via error handler or manual)
     */
    public function captureError(Throwable $exception, ?Request $request = null, array $context = []): bool
    {
        if (!$this->captureErrors || !$this->shouldSample()) {
            return false;
        }

        try {
            $traceId = $context['traceId'] ?? SpanContext::getTraceId() ?? $this->generateTraceId();
            $spanId = $context['spanId'] ?? $this->generateSpanId();

            $dto = new ObservabilityErrorEventDto([
                'errorType' => get_class($exception),
                'errorMessage' => substr($exception->getMessage(), 0, 1000),
                'traceId' => $traceId,
                'spanId' => $spanId,
                'timestamp' => (new \DateTime())->format('c'),
                'errorClass' => get_class($exception),
                'severity' => $this->mapSeverity($exception),
                'status' => 'unresolved',
                'stackTrace' => $exception->getTraceAsString(),
                'sourceFile' => $exception->getFile(),
                'lineNumber' => $exception->getLine(),
                'handled' => $context['handled'] ?? true,
                'mechanism' => $context['mechanism'] ?? 'exception_handler',
                'osName' => PHP_OS,
                'osVersion' => php_uname('r'),
                'userId' => $request && ($user = $request->user()) ? (string)$user->id : null,
                'sessionId' => $this->getSessionId($request),
                'attributes' => array_merge($this->tags, $context['attributes'] ?? [], [
                    'php_version' => PHP_VERSION,
                    'laravel_version' => $this->getLaravelVersion(),
                ]),
            ]);

            // Add HTTP context if available
            if ($request) {
                $dto->httpMethod = $request->method();
                $dto->httpUrl = $request->fullUrl();
                if (method_exists($exception, 'getStatusCode')) {
                    $dto->httpStatusCode = $exception->getStatusCode();
                }
            }

            if (!$dto->validate()) {
                error_log('AllStak: Invalid error DTO');
                return false;
            }

            $this->batch->addError($dto);
            $this->flushIfNeeded();

            return true;
        } catch (\Exception $e) {
            error_log('AllStak: Failed to capture error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Manual logging (AllStak::log())
     */
    public function log(string $level, string $message, array $attributes = []): bool
    {
        if (!$this->captureLogs || !$this->shouldSample()) {
            return false;
        }

        try {
            $traceId = SpanContext::getTraceId() ?? $this->generateTraceId();
            $spanId = $this->generateSpanId();

            $dto = new ObservabilityApplicationLogDto([
                'level' => strtoupper($level),
                'logSource' => 'application',
                'message' => substr($message, 0, 5000),
                'traceId' => $traceId,
                'spanId' => $spanId,
                'timestamp' => (new \DateTime())->format('c'),
                'severityNumber' => $this->mapLogLevel($level),
                'severityText' => strtoupper($level),
                'processId' => getmypid(),
                'userId' => ($req = $this->getRequest()) && ($user = $req->user()) ? (string)$user->id : null,
                'sessionId' => $this->getSessionId($this->getRequest()),
                'attributes' => array_merge($this->tags, $attributes, [
                    'php_version' => PHP_VERSION,
                    'laravel_version' => $this->getLaravelVersion(),
                ]),
            ]);

            if (!$dto->validate()) {
                error_log('AllStak: Invalid log DTO');
                return false;
            }

            $this->batch->addLog($dto);
            $this->flushIfNeeded();

            return true;
        } catch (\Exception $e) {
            error_log('AllStak: Failed to capture log: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Capture database query (automatic via query listener)
     */
    public function captureQuery(string $sql, array $bindings, float $duration, string $connection, bool $success = true, ?string $errorMessage = null): bool
    {
        if (!$this->captureDatabase || !$this->shouldSample()) {
            return false;
        }

        try {
            $traceId = SpanContext::getTraceId() ?? $this->generateTraceId();
            $spanId = $this->generateSpanId();

            $dbConfig = $this->getConfig("database.connections.{$connection}", []);

            $dto = new ObservabilityDatabaseQueryDto([
                'dbSystem' => $dbConfig['driver'] ?? 'mysql',
                'dbOperation' => $this->extractOperation($sql),
                'traceId' => $traceId,
                'spanId' => $spanId,
                'timestamp' => (new \DateTime())->format('c'),
                'dbStatement' => substr($sql, 0, 10000),
                'dbTable' => $this->extractTable($sql),
                'dbName' => $dbConfig['database'] ?? null,
                'dbHost' => $dbConfig['host'] ?? null,
                'dbPort' => $dbConfig['port'] ?? null,
                'queryDuration' => (int)$duration,
                'querySuccess' => $success,
                'errorMessage' => $errorMessage,
                'userId' => ($req = $this->getRequest()) && ($user = $req->user()) ? (string)$user->id : null,
                'sessionId' => $this->getSessionId($this->getRequest()),
                'attributes' => array_merge($this->tags, [
                    'bindings' => json_encode($bindings),
                    'connection' => $connection,
                ]),
            ]);

            if (!$dto->validate()) {
                error_log('AllStak: Invalid query DTO');
                return false;
            }

            $this->batch->addQuery($dto);
            $this->flushIfNeeded();

            return true;
        } catch (\Exception $e) {
            error_log('AllStak: Failed to capture query: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Start a custom span (manual instrumentation)
     */
    public function startSpan(string $name, ?string $parentSpanId = null): array
    {
        $traceId = SpanContext::getTraceId() ?? $this->generateTraceId();
        $spanId = $this->generateSpanId();

        $span = [
            'spanName' => $name,
            'spanKind' => 'INTERNAL',
            'traceId' => $traceId,
            'spanId' => $spanId,
            'timestamp' => (new \DateTime())->format('c'),
            'parentSpanId' => $parentSpanId,
            'startTime' => microtime(true),
            'attributes' => [],
        ];

        $this->activeSpans[$spanId] = $span;
        SpanContext::setTraceId($traceId);

        return $span;
    }

    /**
     * End a custom span
     */
    public function endSpan(array $span, string $status = 'OK', ?string $statusMessage = null): bool
    {
        try {
            $endTime = microtime(true);
            $duration = (int)(($endTime - $span['startTime']) * 1000); // ms

            $dto = new ObservabilitySpanDto([
                'spanName' => $span['spanName'],
                'spanKind' => $span['spanKind'],
                'traceId' => $span['traceId'],
                'spanId' => $span['spanId'],
                'timestamp' => $span['timestamp'],
                'parentSpanId' => $span['parentSpanId'],
                'duration' => $duration,
                'statusCode' => $status,
                'statusMessage' => $statusMessage,
                'attributes' => array_merge($this->tags, $span['attributes']),
            ]);

            if (!$dto->validate()) {
                error_log('AllStak: Invalid span DTO');
                return false;
            }

            $this->batch->addSpan($dto);
            $this->flushIfNeeded();

            unset($this->activeSpans[$span['spanId']]);

            return true;
        } catch (\Exception $e) {
            error_log('AllStak: Failed to end span: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Flush batch if needed
     */
    private function flushIfNeeded(): void
    {
        $currentTime = microtime(true);
        $timeSinceLastFlush = $currentTime - $this->lastFlush;

        $totalEvents = count($this->batch->logs) + count($this->batch->errors) +
                       count($this->batch->requests) + count($this->batch->queries) +
                       count($this->batch->spans);

        if ($totalEvents >= $this->batchSize || $timeSinceLastFlush >= $this->flushInterval) {
            $this->flush();
        }
    }

    /**
     * Manually flush batch
     */
    public function flush(): bool
    {
        if ($this->batch->isEmpty() || !$this->transport) {
            return true;
        }

        try {
            $this->transport->send($this->endpoint . '/batch', $this->batch->toArray());
            $this->batch = new TelemetryBatchDto();
            $this->lastFlush = microtime(true);
            return true;
        } catch (\Exception $e) {
            error_log('AllStak: Failed to flush batch: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Map exception to severity
     */
    private function mapSeverity(Throwable $exception): string
    {
        if ($exception instanceof \Error) {
            return 'fatal';
        }

        if (method_exists($exception, 'getStatusCode')) {
            $code = $exception->getStatusCode();
            if ($code >= 500) return 'error';
            if ($code >= 400) return 'warning';
        }

        return 'error';
    }

    /**
     * Map log level to OpenTelemetry severity number
     */
    private function mapLogLevel(string $level): int
    {
        $map = [
            'trace' => 1,
            'debug' => 5,
            'info' => 9,
            'warn' => 13,
            'warning' => 13,
            'error' => 17,
            'fatal' => 21,
            'critical' => 21,
        ];

        return $map[strtolower($level)] ?? 9;
    }

    /**
     * Extract SQL operation type
     */
    private function extractOperation(string $sql): string
    {
        if (preg_match('/^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE)/i', $sql, $matches)) {
            return strtoupper($matches[1]);
        }
        return 'UNKNOWN';
    }

    /**
     * Extract table name from SQL
     */
    private function extractTable(string $sql): ?string
    {
        if (preg_match('/(?:FROM|INTO|UPDATE|TABLE)\s+`?(\w+)`?/i', $sql, $matches)) {
            return $matches[1];
        }
        return null;
    }

    /**
     * Destructor - flush remaining events
     */
    public function __destruct()
    {
        $this->flush();
    }
}

