<?php

namespace AllStak\Tracing;

class Span
{
    public string $id;
    public string $traceId;
    public ?string $parentSpanId;
    public string $name;
    public float $startTime;
    public ?float $endTime = null;
    public array $attributes = [];
    public ?string $status = null;
    public ?array $error = null;

    public function __construct(
        string $name,
        ?string $traceId = null,
        ?string $parentSpanId = null
    ) {
        $this->id = bin2hex(random_bytes(8));
        $this->traceId = $traceId ?? bin2hex(random_bytes(16));
        $this->parentSpanId = $parentSpanId;
        $this->name = $name;
        $this->startTime = microtime(true);
    }

    public function setAttribute(string $key, $value): self
    {
        $this->attributes[$key] = $value;
        return $this;
    }

    public function setStatus(string $status): self
    {
        $this->status = $status;
        return $this;
    }

    public function recordException(\Throwable $exception): self
    {
        $this->status = 'error';
        $this->error = [
            'type' => get_class($exception),
            'message' => $exception->getMessage(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'stacktrace' => $exception->getTraceAsString(),
        ];
        return $this;
    }

    public function end(): self
    {
        $this->endTime = microtime(true);
        return $this;
    }
}
