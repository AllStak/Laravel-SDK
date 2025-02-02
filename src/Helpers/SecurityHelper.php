<?php

namespace Techsea\AllStack\Helpers;

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

        $sanitizedQuery = http_build_query($queryParams);
        return $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . ($parsedUrl['path'] ?? '') . '?' . $sanitizedQuery;
    }

    public function maskCodeLines(array $lines): array
    {
        $maskedLines = [];
        foreach ($lines as $lineNumber => $lineContent) {
            $maskedLine = $lineContent;
            foreach (self::SENSITIVE_VALUE_PATTERNS as $pattern) {
                $maskedLine = preg_replace($pattern, 'xxxxxx', $maskedLine);
            }
            $maskedLines[$lineNumber] = $maskedLine;
        }
        return $maskedLines;
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


    public function sanitizeSql(string $sql): string
    {
        // Match and redact sensitive values in SQL
        $patterns = [
            // Redact string literals containing sensitive patterns
            '/(["\'])(?:[^"\']*?(?:@|%40|%20(?:card|cc|ssn|pass)).*?)(["\'])/i' => '$1[REDACTED]$2',
            // Redact numeric literals matching credit card/ssn patterns
            '/(=\s*)(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})(\b)/i' => '$1[REDACTED]$3',
            '/(=\s*)(\d{3}-\d{2}-\d{4})(\b)/i' => '$1[REDACTED]$3',
        ];

        foreach ($patterns as $pattern => $replacement) {
            $sql = preg_replace($pattern, $replacement, $sql);
        }

        return $sql;
    }

    public function sanitize($data)
    {
        if (is_array($data)) {
            return $this->sanitizeArray($data);
        }
        if (is_string($data)) {
            return $this->sanitizeString($data);
        }
        return $data;
    }


    private function sanitizeArray(array $array): array
    {
        $sanitized = [];
        foreach ($array as $key => $value) {
            $cleanKey = $this->sanitizeKey((string)$key);
            $cleanValue = $this->sanitize($value);
            $sanitized[$cleanKey] = $cleanValue;
        }
        return $sanitized;
    }

    private function sanitizeKey(string $key): string
    {
        foreach (self::SENSITIVE_KEY_PATTERNS as $pattern) {
            if (preg_match($pattern, $key)) {
                return '*****';
            }
        }
        return $key;
    }



    private function sanitizeString(string $value): string
    {
        foreach (self::SENSITIVE_VALUE_PATTERNS as $pattern) {
            $value = preg_replace($pattern, '******', $value);
        }
        return $value;
    }


}
