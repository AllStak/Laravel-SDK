<?php

namespace AllStak;

class SpanContext
{
    private static ?string $traceId = null;
    private static ?string $parentSpanId = null;

    public static function setTraceId(string $traceId): void
    {
        self::$traceId = $traceId;
    }

    public static function getTraceId(): ?string
    {
        return self::$traceId;
    }

    public static function setParentSpanId(string $parentSpanId): void
    {
        self::$parentSpanId = $parentSpanId;
    }

    public static function getParentSpanId(): ?string
    {
        return self::$parentSpanId;
    }

    public static function clear(): void
    {
        self::$traceId = null;
        self::$parentSpanId = null;
    }
}
