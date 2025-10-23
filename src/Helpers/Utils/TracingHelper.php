<?php

namespace AllStak\Helpers\Utils;

use AllStak\Tracing\Span;
use AllStak\Tracing\SpanContext;
use Exception;

/**
 * Helper class for handling tracing functionality
 */
class TracingHelper
{
    private array $activeSpans = [];
    
    /**
     * Generate a unique trace ID for the current request
     */
    public function generateTraceId(): string
    {
        return bin2hex(random_bytes(16));
    }
    
    /**
     * Start a new span with the given name and context
     */
    public function startSpan(string $name, ?SpanContext $parentContext = null): Span
    {
        $span = new Span($name, $parentContext);
        $this->activeSpans[$span->id] = $span;
        return $span;
    }
    
    /**
     * End the span with the given ID
     */
    public function endSpan(string $spanId): void
    {
        if (isset($this->activeSpans[$spanId])) {
            $this->activeSpans[$spanId]->end();
            unset($this->activeSpans[$spanId]);
        }
    }
    
    /**
     * Get all active spans
     */
    public function getActiveSpans(): array
    {
        return $this->activeSpans;
    }
    
    /**
     * Get a specific active span by ID
     */
    public function getSpan(string $spanId): ?Span
    {
        return $this->activeSpans[$spanId] ?? null;
    }
}