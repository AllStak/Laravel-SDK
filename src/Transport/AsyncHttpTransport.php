<?php

namespace AllStak\Transport;

use Symfony\Contracts\HttpClient\HttpClientInterface;
use Illuminate\Support\Facades\Log;
use AllStak\Version;

class AsyncHttpTransport
{
    private HttpClientInterface $httpClient;
    private array $pendingRequests = [];
    private string $apiKey;
    private bool $useCompression;
    private bool $shutdownRegistered = false;

    public function __construct(
        HttpClientInterface $httpClient,
        string $apiKey,
        bool $useCompression = true
    ) {
        $this->httpClient = $httpClient;
        $this->apiKey = $apiKey;
        $this->useCompression = $useCompression;
    }

    /**
     * Queue event for async sending (non-blocking). ALWAYS sets Content-Type: application/json
     */
    public function send(string $endpoint, array $payload): void
    {
        if (!$this->shutdownRegistered) {
            register_shutdown_function([$this, 'flush']);
            $this->shutdownRegistered = true;
        }

        try {
            // CRITICAL: Base headers - ALWAYS include Content-Type for JSON body parsing
            $headers = [
                'x-api-key' => $this->apiKey,
                'Accept' => 'application/json',
                'Content-Type' => 'application/json', // Forces Tomcat/Spring to parse as JSON body, not form params
                'User-Agent' => Version::getUserAgent(),
                'X-AllStak-SDK-Version' => Version::get(),
            ];

            $options = [];

            if ($this->useCompression) {
                $jsonPayload = json_encode($payload);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    Log::error('AllStak: JSON encoding failed before compression', ['error' => json_last_error_msg()]);
                    return; // Skip invalid payload
                }

                $compressed = gzencode($jsonPayload, 6); // Level 6: balanced compression
                $headers['Content-Encoding'] = 'gzip'; // Tells server to decompress
                $options['body'] = $compressed; // Raw binary body (not 'json' option)

                Log::debug('AllStak: Queued compressed request', [
                    'endpoint' => $endpoint,
                    'original_size' => strlen($jsonPayload),
                    'compressed_size' => strlen($compressed),
                    'compression_ratio' => round((1 - strlen($compressed) / strlen($jsonPayload)) * 100, 2) . '%'
                ]);
            } else {
                $options['json'] = $payload; // Symfony auto-encodes to JSON with correct Content-Type
                Log::debug('AllStak: Queued uncompressed request', [
                    'endpoint' => $endpoint,
                    'payload_size' => strlen(json_encode($payload))
                ]);
            }

            $options['headers'] = $headers;

            // Register async request (starts send immediately but non-blocking)
            $this->pendingRequests[] = $this->httpClient->request('POST', $endpoint, $options);

        } catch (\Throwable $e) {
            Log::error('AllStak: Failed to queue event', [
                'endpoint' => $endpoint,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }
    }

    /**
     * Flush all pending requests (on shutdown or manual call)
     */
    public function flush(int $timeout = 2): void
    {
        if (empty($this->pendingRequests)) {
            return;
        }

        Log::info('AllStak: Flushing ' . count($this->pendingRequests) . ' pending requests');

        try {
            $successCount = 0;
            $errorCount = 0;

            foreach ($this->pendingRequests as $response) {
                try {
                    $statusCode = $response->getStatusCode(); // Waits briefly for response
                    if ($statusCode >= 200 && $statusCode < 300) {
                        $successCount++;
                    } else {
                        $errorCount++;
                        $content = $response->getContent(false); // Raw content, no decoding
                        Log::warning('AllStak: Flush failed', [
                            'status' => $statusCode,
                            'content' => substr($content, 0, 500) . '...', // Truncate for logs
                            'response_headers' => $response->getHeaders(false)
                        ]);
                    }
                } catch (\Throwable $e) {
                    $errorCount++;
                    Log::debug('AllStak: Individual request timed out during flush', [
                        'error' => $e->getMessage()
                    ]);
                }
            }

            Log::info('AllStak: Flush complete', [
                'success' => $successCount,
                'errors' => $errorCount,
                'total' => count($this->pendingRequests)
            ]);
        } catch (\Throwable $e) {
            Log::error('AllStak: Flush operation failed', ['error' => $e->getMessage()]);
        } finally {
            $this->pendingRequests = [];
        }
    }

    /**
     * Destructor flushes on object destruction
     */
    public function __destruct()
    {
        $this->flush();
    }
}
