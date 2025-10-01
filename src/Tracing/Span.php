<?php


namespace App\Tracing;

class Span
{
    public $id;
    public $traceId;
    public $parentSpanId;
    public $name;
    public $startTime;
    public $endTime;
    public $attributes = [];
    public $status = 'ok';
    public $error = null;

    public function __construct($name, $traceId = null, $parentSpanId = null)
    {
        $this->id = bin2hex(random_bytes(8));
        $this->traceId = $traceId ?? bin2hex(random_bytes(16));
        $this->parentSpanId = $parentSpanId;
        $this->name = $name;
        $this->startTime = microtime(true);
    }

    public function setAttribute($key, $value)
    {
        $this->attributes[$key] = $value;
    }

    public function setStatus($status)
    {
        $this->status = $status;
    }

    public function recordException($exception)
    {
        $this->status = 'error';
        $this->error = [
            'type' => get_class($exception),
            'message' => $exception->getMessage(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'stacktrace' => $exception->getTraceAsString(),
        ];
    }

    public function end()
    {
        $this->endTime = microtime(true);
    }
}
