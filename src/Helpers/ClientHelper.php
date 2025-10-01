<?php

namespace Techsea\AllStak\Helpers;

use DateTimeInterface;
use Throwable;

class ClientHelper
{
    private SecurityHelper $securityHelper;

    public function __construct(SecurityHelper $securityHelper)
    {
        $this->securityHelper = $securityHelper;
    }

    public function getCodeContextLines(string $file, int $line, int $context): array
    {
        if (!is_readable($file)) {
            return [];
        }

        $lines = @file($file, FILE_IGNORE_NEW_LINES);
        if (!$lines) {
            return [];
        }

        $start = max($line - $context - 1, 0);
        $end = min($line + $context - 1, count($lines) - 1);

        $snippet = [];
        for ($i = $start; $i <= $end; $i++) {
            $snippet[$i + 1] = $lines[$i];
        }
        return $snippet;
    }

    public function formatStackTrace(Throwable $exception): array
    {
        $stackTrace = [];
        foreach ($exception->getTrace() as $index => $frame) {
            $stackTrace["frame_$index"] = [
                'file'     => $frame['file'] ?? '',
                'line'     => $frame['line'] ?? '',
                'function' => $frame['function'] ?? '',
                'class'    => $frame['class'] ?? '',
                'type'     => $frame['type'] ?? '',
            ];
        }
        return $stackTrace;
    }

    public function createContexts(): array
    {
        return [
            'runtime' => [
                'name'    => 'PHP',
                'version' => PHP_VERSION,
            ],
            'system'  => [
                'os'    => PHP_OS,
                'uname' => php_uname(),
            ],
            'process' => [
                'pid' => getmypid(),
            ],
        ];
    }

    public function getMemoryUsage(): int
    {
        return memory_get_usage(true);
    }

    public function formatTimestamp(DateTimeInterface $dt): string
    {
        return $dt->format('Y-m-d\TH:i:s');
    }

    public function transformRequestBody(array $data): array
    {
        $transformed = [];
        foreach ($data as $key => $value) {
            // Redact if sensitive key or value
            if ($this->securityHelper->isSensitiveKey($key) 
                || (is_string($value) && $this->securityHelper->isSensitiveValue($value))) 
            {
                $transformed[$key] = '******';
            } 
            else if (is_array($value)) {
                $transformed[$key] = $this->transformRequestBody($value);
            } 
            else {
                $transformed[$key] = $this->convertValueType($value);
            }
        }

        return $transformed;
    }


    public function determineErrorCause(Throwable $exception): string
    {
        $msg = strtolower($exception->getMessage());
        if (str_contains($msg, 'validation') || str_contains($msg, 'input')) {
            return 'USER';
        }
        if (str_contains($msg, 'db') || str_contains($msg, 'server') || str_contains($msg, 'connection')) {
            return 'SYSTEM';
        }
        return 'SYSTEM';
    }

    public function determineErrorCategory(Throwable $exception): string
    {
        $message = strtolower($exception->getMessage());
        if (str_contains($message, 'sql') || str_contains($message, 'db')) {
            return 'DATABASE_ERROR';
        }
        if (str_contains($message, 'network') || str_contains($message, 'timeout')) {
            return 'NETWORK_ERROR';
        }
        if (str_contains($message, 'security') || str_contains($message, 'unauthorized')) {
            return 'SECURITY_ERROR';
        }
        if (str_contains($message, 'performance') || str_contains($message, 'slow')) {
            return 'PERFORMANCE_ERROR';
        }
        if (str_contains($message, 'app') || str_contains($message, 'logic')) {
            return 'APPLICATION_ERROR';
        }
        return 'UNKNOWN_ERROR';
    }

    public function determineErrorSeverity(Throwable $exception): string
    {
        if ($exception instanceof \TypeError || $exception instanceof \ErrorException) {
            return 'high';
        }
        if (stripos($exception->getMessage(), 'syntax') !== false) {
            return 'critical';
        }
        if (stripos($exception->getMessage(), 'timeout') !== false || stripos($exception->getMessage(), 'network') !== false) {
            return 'medium';
        }
        return 'low';
    }

    public function determineErrorLevel(string $type, string $severity): string
    {
        if ($type === 'error') {
            return $severity === 'critical' ? 'CRITICAL' : 'ERROR';
        }
        return $severity === 'critical' ? 'CRITICAL' : 'WARNING';
    }

    /**
     * Recursively converts any array (associative or sequential) to a stdClass.
     *
     * Even if the array is empty or numerically indexed, this method forces an object.
     * (Used below, but NOT for headers anymore.)
     */
    private function recursiveCast($data)
    {
        if (is_array($data)) {
            $object = new \stdClass();
            foreach ($data as $key => $value) {
                $object->{$key} = $this->recursiveCast($value);
            }
            return $object;
        }
        return $data;
    }

    /**
     * Transforms header arrays to a plain array (no stdClass).
     */
    public function transformHeaders(array $headers): array
    {
        $transformed = [];
        foreach ($headers as $key => $values) {
            // $values is typically an array of header strings, so join them with commas.
            $value = is_array($values) ? implode(', ', $values) : $values;

            $lowerKey = strtolower($key);
            if ($this->securityHelper->isSensitiveKey($lowerKey) || $this->securityHelper->isSensitiveValue($value)) {
                $transformed[$lowerKey] = '********';
            } else {
                $transformed[$lowerKey] = $value;
            }
        }

        return $transformed;
    }

    /**
     * Transforms query parameters to a stdClass.
     * If you also want to remove stdClass here, you could return an array similarly.
     */
    public function transformQueryParams(array $query): array
    {
        $transformed = [];
        foreach ($query as $key => $value) {
            if ($this->securityHelper->isSensitiveKey($key) 
                || (is_string($value) && $this->securityHelper->isSensitiveValue($value))) 
            {
                $transformed[$key] = '*******';
            } 
            else if (is_array($value)) {
                // Recursively transform if needed:
                $transformed[$key] = $this->transformQueryParams($value);
            } 
            else {
                $transformed[$key] = $value;
            }
        }

        return $transformed;
    }


    /**
     * (Optional) Convert data to an API-friendly structure.
     */
    public function transformToApiStructure($data)
    {
        if (is_array($data)) {
            if (!$this->isAssociativeArray($data)) {
                return [
                    '_type' => 'array', 
                    '_items' => array_map([$this, 'transformToApiStructure'], $data)
                ];
            }
            return array_map([$this, 'transformToApiStructure'], $data);
        }
        return $data;
    }

    private function isAssociativeArray(array $arr): bool
    {
        return array_keys($arr) !== range(0, count($arr) - 1);
    }




    private function convertValueType($value)
    {
        if ($value === 'true') {
            return true;
        } elseif ($value === 'false') {
            return false;
        } elseif (is_numeric($value)) {
            // Convert to int or float
            return $value * 1;
        }
        return $value;
    }






}
