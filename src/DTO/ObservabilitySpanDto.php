<?php

namespace AllStak\DTO;

/**
 * ObservabilitySpanDto
 *
 * Purpose: Custom span for distributed tracing
 * Used For: Manual instrumentation of code blocks
 * Trigger: Manual (AllStak::startSpan())
 */
class ObservabilitySpanDto
{
    // REQUIRED fields
    public string $spanName;
    public string $spanKind;
    public string $traceId;
    public string $spanId;
    public string $timestamp;

    // Optional fields
    public ?string $parentSpanId = null;
    public ?int $duration = null;
    public ?string $statusCode = null;
    public ?string $statusMessage = null;
    public ?array $attributes = null;
    public ?string $events = null;
    public ?string $links = null;
    public ?string $traceState = null;
    public ?int $traceFlags = null;

    public function __construct(array $data)
    {
        // Required fields
        $this->spanName = $data['spanName'];
        $this->spanKind = $data['spanKind'];
        $this->traceId = $data['traceId'];
        $this->spanId = $data['spanId'];
        $this->timestamp = $data['timestamp'];

        // Optional fields
        $this->parentSpanId = $data['parentSpanId'] ?? null;
        $this->duration = $data['duration'] ?? null;
        $this->statusCode = $data['statusCode'] ?? null;
        $this->statusMessage = $data['statusMessage'] ?? null;
        $this->attributes = $data['attributes'] ?? null;
        $this->events = $data['events'] ?? null;
        $this->links = $data['links'] ?? null;
        $this->traceState = $data['traceState'] ?? null;
        $this->traceFlags = $data['traceFlags'] ?? null;
    }

    public function validate(): bool
    {
        // spanKind validation
        if (!in_array($this->spanKind, ['INTERNAL', 'SERVER', 'CLIENT', 'PRODUCER', 'CONSUMER'])) {
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

        // statusCode validation
        if ($this->statusCode !== null && !in_array($this->statusCode, ['OK', 'ERROR', 'UNSET'])) {
            return false;
        }

        return true;
    }

    public function toArray(): array
    {
        $data = [
            'spanName' => $this->spanName,
            'spanKind' => $this->spanKind,
            'traceId' => $this->traceId,
            'spanId' => $this->spanId,
            'timestamp' => $this->timestamp,
        ];

        // Add optional fields if set
        if ($this->parentSpanId !== null) $data['parentSpanId'] = $this->parentSpanId;
        if ($this->duration !== null) $data['duration'] = $this->duration;
        if ($this->statusCode !== null) $data['statusCode'] = $this->statusCode;
        if ($this->statusMessage !== null) $data['statusMessage'] = $this->statusMessage;
        if ($this->attributes !== null) $data['attributes'] = $this->attributes;
        if ($this->events !== null) $data['events'] = $this->events;
        if ($this->links !== null) $data['links'] = $this->links;
        if ($this->traceState !== null) $data['traceState'] = $this->traceState;
        if ($this->traceFlags !== null) $data['traceFlags'] = $this->traceFlags;

        return $data;
    }
}

