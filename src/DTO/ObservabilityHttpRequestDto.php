<?php

namespace AllStak\DTO;

/**
 * ObservabilityHttpRequestDto
 *
 * Purpose: Capture HTTP requests and responses
 * Used For: Automatic HTTP monitoring, performance tracking
 * Trigger: Automatic (middleware) or Manual (API call)
 */
class ObservabilityHttpRequestDto
{
    // REQUIRED fields
    public string $httpMethod;
    public string $httpUrl;
    public int $httpStatusCode;
    public string $traceId;
    public string $spanId;
    public string $timestamp;

    // Optional fields
    public ?string $httpPath = null;
    public ?int $httpDuration = null;
    public ?string $userAgent = null;
    public ?string $referer = null;
    public ?string $requestHeaders = null;
    public ?string $responseHeaders = null;
    public ?string $requestBody = null;
    public ?string $responseBody = null;
    public ?string $errorMessage = null;
    public ?string $clientIp = null;
    public ?string $parentSpanId = null;
    public ?string $traceState = null;
    public ?int $traceFlags = null;
    public ?string $userId = null;
    public ?string $sessionId = null;
    public ?array $attributes = null;

    public function __construct(array $data)
    {
        // Required fields
        $this->httpMethod = $data['httpMethod'];
        $this->httpUrl = $data['httpUrl'];
        $this->httpStatusCode = $data['httpStatusCode'];
        $this->traceId = $data['traceId'];
        $this->spanId = $data['spanId'];
        $this->timestamp = $data['timestamp'];

        // Optional fields
        $this->httpPath = $data['httpPath'] ?? null;
        $this->httpDuration = $data['httpDuration'] ?? null;
        $this->userAgent = $data['userAgent'] ?? null;
        $this->referer = $data['referer'] ?? null;
        $this->requestHeaders = $data['requestHeaders'] ?? null;
        $this->responseHeaders = $data['responseHeaders'] ?? null;
        $this->requestBody = $data['requestBody'] ?? null;
        $this->responseBody = $data['responseBody'] ?? null;
        $this->errorMessage = $data['errorMessage'] ?? null;
        $this->clientIp = $data['clientIp'] ?? null;
        $this->parentSpanId = $data['parentSpanId'] ?? null;
        $this->traceState = $data['traceState'] ?? null;
        $this->traceFlags = $data['traceFlags'] ?? null;
        $this->userId = $data['userId'] ?? null;
        $this->sessionId = $data['sessionId'] ?? null;
        $this->attributes = $data['attributes'] ?? null;
    }

    public function validate(): bool
    {
        // httpMethod validation
        if (!preg_match('/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)$/', $this->httpMethod)) {
            return false;
        }

        // httpUrl max length
        if (strlen($this->httpUrl) > 2000) {
            return false;
        }

        // httpStatusCode range
        if ($this->httpStatusCode < 100 || $this->httpStatusCode > 599) {
            return false;
        }

        // traceId format
        if (!preg_match('/^[a-f0-9]{32}$/', $this->traceId)) {
            return false;
        }

        // spanId format
        if (!preg_match('/^[a-f0-9]{16}$/', $this->spanId)) {
            return false;
        }

        // httpDuration validation
        if ($this->httpDuration !== null && $this->httpDuration < 0) {
            return false;
        }

        // requestBody and responseBody max length (backend validation)
        if ($this->requestBody !== null && strlen($this->requestBody) > 10000) {
            return false;
        }
        if ($this->responseBody !== null && strlen($this->responseBody) > 10000) {
            return false;
        }

        return true;
    }

    public function toArray(): array
    {
        $data = [
            'httpMethod' => $this->httpMethod,
            'httpUrl' => $this->httpUrl,
            'httpStatusCode' => $this->httpStatusCode,
            'traceId' => $this->traceId,
            'spanId' => $this->spanId,
            'timestamp' => $this->timestamp,
        ];

        // Add optional fields if set
        if ($this->httpPath !== null) $data['httpPath'] = $this->httpPath;
        if ($this->httpDuration !== null) $data['httpDuration'] = $this->httpDuration;
        if ($this->userAgent !== null) $data['userAgent'] = $this->userAgent;
        if ($this->referer !== null) $data['referer'] = $this->referer;
        if ($this->requestHeaders !== null) $data['requestHeaders'] = $this->requestHeaders;
        if ($this->responseHeaders !== null) $data['responseHeaders'] = $this->responseHeaders;
        if ($this->requestBody !== null) $data['requestBody'] = $this->requestBody;
        if ($this->responseBody !== null) $data['responseBody'] = $this->responseBody;
        if ($this->errorMessage !== null) $data['errorMessage'] = $this->errorMessage;
        if ($this->clientIp !== null) $data['clientIp'] = $this->clientIp;
        if ($this->parentSpanId !== null) $data['parentSpanId'] = $this->parentSpanId;
        if ($this->traceState !== null) $data['traceState'] = $this->traceState;
        if ($this->traceFlags !== null) $data['traceFlags'] = $this->traceFlags;
        if ($this->userId !== null) $data['userId'] = $this->userId;
        if ($this->sessionId !== null) $data['sessionId'] = $this->sessionId;
        if ($this->attributes !== null) $data['attributes'] = $this->attributes;

        return $data;
    }
}

