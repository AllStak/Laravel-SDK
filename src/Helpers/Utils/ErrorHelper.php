<?php

namespace AllStak\Helpers\Utils;

use Throwable;

/**
 * Helper class for error handling and classification
 */
class ErrorHelper
{
    /**
     * Map error category to error type
     */
    public function mapErrorType(string $category): string
    {
        return match ($category) {
            'DATABASE_ERROR' => 'DatabaseError',
            'NETWORK_ERROR' => 'HttpError',
            'SECURITY_ERROR' => 'ApplicationError',
            'PERFORMANCE_ERROR' => 'ApplicationError',
            default => 'ApplicationError',
        };
    }

    /**
     * Generate a unique error code from exception
     */
    public function generateErrorCode(Throwable $exception): string
    {
        return 'E' . substr(md5(get_class($exception)), 0, 6);
    }

    /**
     * Extract tags from exception message
     */
    public function extractTags(Throwable $exception): array
    {
        $tags = [];
        $message = strtolower($exception->getMessage());

        if (str_contains($message, 'payment')) $tags[] = 'payment';
        if (str_contains($message, 'auth')) $tags[] = 'authentication';
        if (str_contains($message, 'database')) $tags[] = 'database';
        if (str_contains($message, 'validation')) $tags[] = 'validation';

        return $tags;
    }

    /**
     * Check if exception is HTTP-related
     */
    public function isHttpException(Throwable $exception): bool
    {
        return method_exists($exception, 'getStatusCode');
    }

    /**
     * Get HTTP status code from exception
     */
    public function getHttpStatusCode(Throwable $exception): int
    {
        if (method_exists($exception, 'getStatusCode')) {
            return call_user_func([$exception, 'getStatusCode']);
        }
        return 500;
    }

    /**
     * Check if exception is a client error (4xx)
     */
    public function isClientError(Throwable $exception): bool
    {
        $code = $this->getHttpStatusCode($exception);
        return $code >= 400 && $code < 500;
    }

    /**
     * Check if exception is a server error (5xx)
     */
    public function isServerError(Throwable $exception): bool
    {
        $code = $this->getHttpStatusCode($exception);
        return $code >= 500;
    }

    /**
     * Check if exception is database-related
     */
    public function isDatabaseException(Throwable $exception): bool
    {
        $className = get_class($exception);
        return str_contains($className, 'PDOException') ||
            str_contains($className, 'QueryException') ||
            str_contains($className, 'DatabaseException');
    }

    /**
     * Extract SQL query from database exception
     */
    public function extractQueryFromException(Throwable $exception): ?string
    {
        if (method_exists($exception, 'getSql')) {
            return call_user_func([$exception, 'getSql']);
        }
        return null;
    }

    /**
     * Extract constraint violation from exception message
     */
    public function extractConstraintViolation(Throwable $exception): ?string
    {
        $message = $exception->getMessage();
        if (preg_match('/Integrity constraint violation: (.+?)\\n/', $message, $matches)) {
            return $matches[1];
        }
        return null;
    }

    /**
     * Extract function name from exception trace
     */
    public function extractFunctionName(Throwable $exception): ?string
    {
        $trace = $exception->getTrace();
        return $trace[0]['function'] ?? null;
    }

    /**
     * Extract class name from exception trace
     */
    public function extractClassName(Throwable $exception): ?string
    {
        $trace = $exception->getTrace();
        return $trace[0]['class'] ?? null;
    }
}