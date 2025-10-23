<?php

namespace AllStak\Helpers\Http;

use GuzzleHttp\Client;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\ResponseInterface;

class HttpHelper
{
    private Client $httpClient;
    
    public function __construct(?Client $httpClient = null)
    {
        $this->httpClient = $httpClient ?? new Client([
            'timeout' => 5,
            'connect_timeout' => 10,
        ]);
    }
    
    /**
     * Send an asynchronous POST request
     *
     * @param string $url
     * @param array $data
     * @param array $headers
     * @return PromiseInterface
     */
    public function postAsync(string $url, array $data, array $headers = []): PromiseInterface
    {
        return $this->httpClient->requestAsync('POST', $url, [
            'headers' => $headers,
            'json' => $data,
        ]);
    }
    
    /**
     * Send a synchronous POST request
     *
     * @param string $url
     * @param array $data
     * @param array $headers
     * @return array
     */
    public function post(string $url, array $data, array $headers = []): array
    {
        $response = $this->httpClient->request('POST', $url, [
            'headers' => $headers,
            'json' => $data,
        ]);
        
        return [
            'status_code' => $response->getStatusCode(),
            'content' => $response->getBody()->getContents(),
            'headers' => $response->getHeaders(),
        ];
    }
}