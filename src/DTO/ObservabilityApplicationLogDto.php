<?php

namespace AllStak\DTO;

/**
 * ObservabilityApplicationLogDto
 *
 * Purpose: Capture application logs (structured logging)
 * Used For: Automatic framework logs, manual logging
 * Trigger: Automatic (logger hooks) or Manual (AllStak::log())
 */
class ObservabilityApplicationLogDto
{
    // REQUIRED fields
    public string $level;
    public string $logSource;
    public string $message;
    public string $traceId;
    public string $spanId;
    public string $timestamp;

    // Optional fields
    public ?int $severityNumber = null;
    public ?string $severityText = null;
    public ?int $logFlags = null;
    public ?string $loggerName = null;
    public ?string $threadName = null;
    public ?int $processId = null;
    public ?string $fileName = null;
    public ?int $lineNumber = null;
    public ?string $functionName = null;
    public ?string $exception = null;
    public ?string $stackTrace = null;
    public ?string $userId = null;
    public ?string $sessionId = null;
    public ?array $attributes = null;
    public ?string $parentSpanId = null;
    public ?string $traceState = null;
    public ?int $traceFlags = null;

    public function __construct(array $data)
    {
        // Required fields
        $this->level = $data['level'];
        $this->logSource = $data['logSource'];
        $this->message = $data['message'];
        $this->traceId = $data['traceId'];
        $this->spanId = $data['spanId'];
        $this->timestamp = $data['timestamp'];

        // Optional fields
        $this->severityNumber = $data['severityNumber'] ?? null;
        $this->severityText = $data['severityText'] ?? null;
        $this->logFlags = $data['logFlags'] ?? null;
        $this->loggerName = $data['loggerName'] ?? null;
        $this->threadName = $data['threadName'] ?? null;
        $this->processId = $data['processId'] ?? null;
        $this->fileName = $data['fileName'] ?? null;
        $this->lineNumber = $data['lineNumber'] ?? null;
        $this->functionName = $data['functionName'] ?? null;
        $this->exception = $data['exception'] ?? null;
        $this->stackTrace = $data['stackTrace'] ?? null;
        $this->userId = $data['userId'] ?? null;
        $this->sessionId = $data['sessionId'] ?? null;
        $this->attributes = $data['attributes'] ?? null;
        $this->parentSpanId = $data['parentSpanId'] ?? null;
        $this->traceState = $data['traceState'] ?? null;
        $this->traceFlags = $data['traceFlags'] ?? null;
    }

    public function validate(): bool
    {
        // level validation
        if (!preg_match('/^(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)$/', $this->level)) {
            return false;
        }

        // logSource max length
        if (strlen($this->logSource) > 50) {
            return false;
        }

        // message max length
        if (strlen($this->message) > 5000) {
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

        // severityNumber validation
        if ($this->severityNumber !== null && ($this->severityNumber < 1 || $this->severityNumber > 24)) {
            return false;
        }

        return true;
    }

    public function toArray(): array
    {
        $data = [
            'level' => $this->level,
            'logSource' => $this->logSource,
            'message' => $this->message,
            'traceId' => $this->traceId,
            'spanId' => $this->spanId,
            'timestamp' => $this->timestamp,
        ];

        // Add optional fields if set
        if ($this->severityNumber !== null) $data['severityNumber'] = $this->severityNumber;
        if ($this->severityText !== null) $data['severityText'] = $this->severityText;
        if ($this->logFlags !== null) $data['logFlags'] = $this->logFlags;
        if ($this->loggerName !== null) $data['loggerName'] = $this->loggerName;
        if ($this->threadName !== null) $data['threadName'] = $this->threadName;
        if ($this->processId !== null) $data['processId'] = $this->processId;
        if ($this->fileName !== null) $data['fileName'] = $this->fileName;
        if ($this->lineNumber !== null) $data['lineNumber'] = $this->lineNumber;
        if ($this->functionName !== null) $data['functionName'] = $this->functionName;
        if ($this->exception !== null) $data['exception'] = $this->exception;
        if ($this->stackTrace !== null) $data['stackTrace'] = $this->stackTrace;
        if ($this->userId !== null) $data['userId'] = $this->userId;
        if ($this->sessionId !== null) $data['sessionId'] = $this->sessionId;
        if ($this->attributes !== null) $data['attributes'] = $this->attributes;
        if ($this->parentSpanId !== null) $data['parentSpanId'] = $this->parentSpanId;
        if ($this->traceState !== null) $data['traceState'] = $this->traceState;
        if ($this->traceFlags !== null) $data['traceFlags'] = $this->traceFlags;

        return $data;
    }
}

