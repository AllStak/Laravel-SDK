<?php

namespace AllStak\DTO;

/**
 * ObservabilityErrorEventDto
 *
 * Purpose: Capture errors, exceptions, and crashes
 * Used For: Automatic error tracking, manual error reporting
 * Trigger: Automatic (error handlers) or Manual (captureError)
 */
class ObservabilityErrorEventDto
{
    // REQUIRED fields
    public string $errorType;
    public string $errorMessage;
    public string $traceId;
    public string $spanId;
    public string $timestamp;

    // Optional fields
    public ?string $errorCode = null;
    public ?string $errorClass = null;
    public ?string $errorFingerprint = null;
    public ?string $severity = null;
    public ?string $status = null;
    public ?string $stackTrace = null;
    public ?string $stackFrames = null;
    public ?string $sourceFile = null;
    public ?int $lineNumber = null;
    public ?int $columnNumber = null;
    public ?string $functionName = null;
    public ?string $httpMethod = null;
    public ?string $httpUrl = null;
    public ?int $httpStatusCode = null;
    public ?bool $handled = null;
    public ?string $mechanism = null;
    public ?string $browserName = null;
    public ?string $browserVersion = null;
    public ?string $osName = null;
    public ?string $osVersion = null;
    public ?string $deviceType = null;
    public ?string $userId = null;
    public ?string $sessionId = null;
    public ?string $breadcrumbs = null;
    public ?array $attributes = null;
    public ?string $parentSpanId = null;
    public ?string $traceState = null;
    public ?int $traceFlags = null;

    public function __construct(array $data)
    {
        // Required fields
        $this->errorType = $data['errorType'];
        $this->errorMessage = $data['errorMessage'];
        $this->traceId = $data['traceId'];
        $this->spanId = $data['spanId'];
        $this->timestamp = $data['timestamp'];

        // Optional fields
        $this->errorCode = $data['errorCode'] ?? null;
        $this->errorClass = $data['errorClass'] ?? null;
        $this->errorFingerprint = $data['errorFingerprint'] ?? null;
        $this->severity = $data['severity'] ?? null;
        $this->status = $data['status'] ?? null;
        $this->stackTrace = $data['stackTrace'] ?? null;
        $this->stackFrames = $data['stackFrames'] ?? null;
        $this->sourceFile = $data['sourceFile'] ?? null;
        $this->lineNumber = $data['lineNumber'] ?? null;
        $this->columnNumber = $data['columnNumber'] ?? null;
        $this->functionName = $data['functionName'] ?? null;
        $this->httpMethod = $data['httpMethod'] ?? null;
        $this->httpUrl = $data['httpUrl'] ?? null;
        $this->httpStatusCode = $data['httpStatusCode'] ?? null;
        $this->handled = $data['handled'] ?? null;
        $this->mechanism = $data['mechanism'] ?? null;
        $this->browserName = $data['browserName'] ?? null;
        $this->browserVersion = $data['browserVersion'] ?? null;
        $this->osName = $data['osName'] ?? null;
        $this->osVersion = $data['osVersion'] ?? null;
        $this->deviceType = $data['deviceType'] ?? null;
        $this->userId = $data['userId'] ?? null;
        $this->sessionId = $data['sessionId'] ?? null;
        $this->breadcrumbs = $data['breadcrumbs'] ?? null;
        $this->attributes = $data['attributes'] ?? null;
        $this->parentSpanId = $data['parentSpanId'] ?? null;
        $this->traceState = $data['traceState'] ?? null;
        $this->traceFlags = $data['traceFlags'] ?? null;
    }

    public function validate(): bool
    {
        // errorType max length
        if (strlen($this->errorType) > 255) {
            return false;
        }

        // errorMessage max length
        if (strlen($this->errorMessage) > 1000) {
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

        // severity validation
        if ($this->severity !== null && !in_array($this->severity, ['fatal', 'error', 'warning', 'info', 'debug'])) {
            return false;
        }

        // lineNumber and columnNumber validation
        if ($this->lineNumber !== null && $this->lineNumber < 0) {
            return false;
        }
        if ($this->columnNumber !== null && $this->columnNumber < 0) {
            return false;
        }

        return true;
    }

    public function toArray(): array
    {
        $data = [
            'errorType' => $this->errorType,
            'errorMessage' => $this->errorMessage,
            'traceId' => $this->traceId,
            'spanId' => $this->spanId,
            'timestamp' => $this->timestamp,
        ];

        // Add optional fields if set
        if ($this->errorCode !== null) $data['errorCode'] = $this->errorCode;
        if ($this->errorClass !== null) $data['errorClass'] = $this->errorClass;
        if ($this->errorFingerprint !== null) $data['errorFingerprint'] = $this->errorFingerprint;
        if ($this->severity !== null) $data['severity'] = $this->severity;
        if ($this->status !== null) $data['status'] = $this->status;
        if ($this->stackTrace !== null) $data['stackTrace'] = $this->stackTrace;
        if ($this->stackFrames !== null) $data['stackFrames'] = $this->stackFrames;
        if ($this->sourceFile !== null) $data['sourceFile'] = $this->sourceFile;
        if ($this->lineNumber !== null) $data['lineNumber'] = $this->lineNumber;
        if ($this->columnNumber !== null) $data['columnNumber'] = $this->columnNumber;
        if ($this->functionName !== null) $data['functionName'] = $this->functionName;
        if ($this->httpMethod !== null) $data['httpMethod'] = $this->httpMethod;
        if ($this->httpUrl !== null) $data['httpUrl'] = $this->httpUrl;
        if ($this->httpStatusCode !== null) $data['httpStatusCode'] = $this->httpStatusCode;
        if ($this->handled !== null) $data['handled'] = $this->handled;
        if ($this->mechanism !== null) $data['mechanism'] = $this->mechanism;
        if ($this->browserName !== null) $data['browserName'] = $this->browserName;
        if ($this->browserVersion !== null) $data['browserVersion'] = $this->browserVersion;
        if ($this->osName !== null) $data['osName'] = $this->osName;
        if ($this->osVersion !== null) $data['osVersion'] = $this->osVersion;
        if ($this->deviceType !== null) $data['deviceType'] = $this->deviceType;
        if ($this->userId !== null) $data['userId'] = $this->userId;
        if ($this->sessionId !== null) $data['sessionId'] = $this->sessionId;
        if ($this->breadcrumbs !== null) $data['breadcrumbs'] = $this->breadcrumbs;
        if ($this->attributes !== null) $data['attributes'] = $this->attributes;
        if ($this->parentSpanId !== null) $data['parentSpanId'] = $this->parentSpanId;
        if ($this->traceState !== null) $data['traceState'] = $this->traceState;
        if ($this->traceFlags !== null) $data['traceFlags'] = $this->traceFlags;

        return $data;
    }
}

