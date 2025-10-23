<?php

namespace AllStak\Helpers\Security;

use Illuminate\Support\Facades\Log;
use Throwable;

class SecurityHelper
{
    private const SENSITIVE_KEY_PATTERNS = [
        '/\b(password|token|api_key|access_token|secret_key|iban|username|email|session_id|auth_token|jwt|credit_card|ssn|private_key|key|oauth_token|csrf_token|refresh_token|pin)\b/i',
    ];

    private const SENSITIVE_VALUE_PATTERNS = [
        '/[a-zA-Z0-9]{32,45}/',
        '/AKIA[0-9A-Z]{16}/',
        '/[A-Za-z0-9\/+=]{40}/',
        '/xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/',
        '/[a-f0-9]{40}/',
        '/AIza[0-9A-Za-z-_]{35}/',
        '/sk_live_[0-9a-zA-Z]{24}/',
        '/SK[0-9a-fA-F]{32}/',
        '/key-[0-9a-zA-Z]{32}/',
        '/access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/',
        '/sq0atp-[0-9A-Za-z-_]{22}/',
        '/[1-9][0-9]+-[0-9a-zA-Z]{40}/',
        '/\b\d{13,19}\b/',
        '/\b\d{3}-\d{2}-\d{4}\b/',
        '/\b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}\b/',
        '/^[a-zA-Z0-9]{6,16}$/',
        '/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,32}$/',
    ];

    public function maskIp(string $ip): string
    {
        return hash('sha256', $ip);
    }

    public function sanitizeUrl(string $url): string
    {
        $parsedUrl = parse_url($url);
        if (!isset($parsedUrl['query'])) {
            return $url;
        }

        parse_str($parsedUrl['query'], $queryParams);
        foreach ($queryParams as $key => $value) {
            if ($this->isSensitiveKey($key) || $this->isSensitiveValue($value)) {
                $queryParams[$key] = '*****';
            }
        }

        $parsedUrl['query'] = http_build_query($queryParams);
        return $this->buildUrl($parsedUrl);
    }

    public function isSensitiveKey(string $key): bool
    {
        foreach (self::SENSITIVE_KEY_PATTERNS as $pattern) {
            if (preg_match($pattern, $key)) {
                return true;
            }
        }
        return false;
    }

    public function isSensitiveValue(string $value): bool
    {
        foreach (self::SENSITIVE_VALUE_PATTERNS as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        return false;
    }

    public function maskExceptionMessage(string $message, Throwable $exception): string
    {
        // Mask any sensitive data in exception message
        foreach (self::SENSITIVE_KEY_PATTERNS as $pattern) {
            $message = preg_replace($pattern, '******', $message);
        }
        
        return $message;
    }

    public function maskCodeLines(array $codeLines): array
    {
        $maskedLines = [];
        foreach ($codeLines as $lineNumber => $line) {
            // Mask sensitive data in code lines
            $maskedLine = $line;
            foreach (self::SENSITIVE_KEY_PATTERNS as $pattern) {
                // Extract the pattern without delimiters and modifiers
                $cleanPattern = trim($pattern, '/i');
                $maskedLine = preg_replace('/' . $cleanPattern . '(\s*=\s*[\'"])[^\'"]+([\'"])/i', '$1******$2', $maskedLine);
            }
            $maskedLines[$lineNumber] = $maskedLine;
        }
        return $maskedLines;
    }

    private function buildUrl(array $parts): string
    {
        $scheme   = isset($parts['scheme']) ? $parts['scheme'] . '://' : '';
        $host     = $parts['host'] ?? '';
        $port     = isset($parts['port']) ? ':' . $parts['port'] : '';
        $user     = $parts['user'] ?? '';
        $pass     = isset($parts['pass']) ? ':' . $parts['pass']  : '';
        $pass     = ($user || $pass) ? "$pass@" : '';
        $path     = $parts['path'] ?? '';
        $query    = isset($parts['query']) ? '?' . $parts['query'] : '';
        $fragment = isset($parts['fragment']) ? '#' . $parts['fragment'] : '';
        
        return "$scheme$user$pass$host$port$path$query$fragment";
    }

    /**
     * Mask sensitive data in SQL query text
     */
    public function maskQueryText(string $query): string
    {
        // Mask potential sensitive values in SQL queries
        foreach (self::SENSITIVE_VALUE_PATTERNS as $pattern) {
            $query = preg_replace($pattern, '******', $query);
        }
        
        // Mask common SQL injection patterns
        $query = preg_replace('/(\bWHERE\s+\w+\s*=\s*[\'"])[^\'"]+([\'"])/i', '$1******$2', $query);
        
        return $query;
    }

    /**
     * Mask sensitive database parameters/bindings
     */
    public function maskDbParameters(array $parameters): array
    {
        $masked = [];
        foreach ($parameters as $key => $value) {
            if (is_string($value) && ($this->isSensitiveKey((string)$key) || $this->isSensitiveValue($value))) {
                $masked[$key] = '******';
            } else {
                $masked[$key] = $value;
            }
        }
        return $masked;
    }
}