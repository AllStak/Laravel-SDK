<?php

namespace AllStak\Helpers;

/**
 * IdGenerator - Generates OpenTelemetry compliant trace and span IDs
 */
class IdGenerator
{
    /**
     * Generate a 32-character hex trace ID
     * @return string
     */
    public static function generateTraceId(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Generate a 16-character hex span ID
     * @return string
     */
    public static function generateSpanId(): string
    {
        return bin2hex(random_bytes(8));
    }

    /**
     * Validate trace ID format
     * @param string $traceId
     * @return bool
     */
    public static function isValidTraceId(string $traceId): bool
    {
        return preg_match('/^[a-f0-9]{32}$/', $traceId) === 1;
    }

    /**
     * Validate span ID format
     * @param string $spanId
     * @return bool
     */
    public static function isValidSpanId(string $spanId): bool
    {
        return preg_match('/^[a-f0-9]{16}$/', $spanId) === 1;
    }
}

