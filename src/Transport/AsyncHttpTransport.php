<?php

namespace AllStak\Transport;

use AllStak\Version;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Illuminate\Support\Facades\Log;

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
     * Queue event for async sending (non-blocking)
     */
    public function send(string $endpoint, array $payload): void
    {
        if (!$this->shutdownRegistered) {
            register_shutdown_function([$this, 'flush']);
            $this->shutdownRegistered = true;
        }

        try {
            $headers = [
                'x-api-key' => $this->apiKey,
                'Accept' => 'application/json',
                'User-Agent' => Version::getUserAgent(),
                'X-AllStak-SDK-Version' => Version::get(),
            ];

            $options = [];

            if ($this->useCompression) {
                $jsonPayload = json_encode($payload);
                $compressed = gzencode($jsonPayload, 6);
                $headers['Content-Encoding'] = 'gzip';
                $options['body'] = $compressed;
            } else {
                $headers['Content-Type'] = 'application/json';
                $options['json'] = $payload;
            }

            $options['headers'] = $headers;

            // Register async request (non-blocking - doesn't wait for response)
            $this->pendingRequests[] = $this->httpClient->request('POST', $endpoint, $options);

        } catch (\Throwable $e) {
            Log::debug('AllStak: Failed to queue event', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Flush all pending requests (called on shutdown or manually)
     */
    public function flush(int $timeout = 2): void
    {
        if (empty($this->pendingRequests)) {
            return;
        }

        try {
            // Wait for all async requests to complete (with timeout)
            foreach ($this->pendingRequests as $response) {
                try {
                    // This will wait for the response but won't block individual requests
                    $response->getStatusCode();
                } catch (\Throwable $e) {
                    // Silent fail - already logged
                    Log::debug('AllStak: Request failed during flush', [
                        'error' => $e->getMessage()
                    ]);
                }
            }
        } catch (\Throwable $e) {
            Log::debug('AllStak: Flush failed', ['error' => $e->getMessage()]);
        } finally {
            $this->pendingRequests = [];
        }
    }

    /**
     * Destructor ensures requests are sent
     */
    public function __destruct()
    {
        $this->flush();
    }
}
