<?php

namespace AllStak\Tracing;

class SpanContext
{
    protected static ?string $currentTraceId = null;
    protected static ?string $currentParentSpanId = null;

    public static function setTraceId(string $traceId): void
    {
        self::$currentTraceId = $traceId;
    }

    public static function getTraceId(): ?string
    {
        return self::$currentTraceId;
    }

    public static function setParentSpanId(?string $spanId): void
    {
        self::$currentParentSpanId = $spanId;
    }

    public static function getParentSpanId(): ?string
    {
        return self::$currentParentSpanId;
    }

    public static function clear(): void
    {
        self::$currentTraceId = null;
        self::$currentParentSpanId = null;
    }
}
