<?php

namespace AllStak\Helpers;

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

    /**
     * Mask PII in exception messages, especially SQL queries with bindings.
     * Handles Laravel's interpolated SQL in QueryException messages.
     */
    public function maskExceptionMessage(string $message, Throwable $exception): string
    {
        $message = $this->sanitizeString($message);  // Base sanitize

        // If DB exception (Illuminate\Database\QueryException), mask SQL and bindings
        if ($exception instanceof \Illuminate\Database\QueryException) {
            // Extract SQL from message (Laravel format: "SQL: select ... where email = [value]")
            if (preg_match('/SQL:\s*(.+?)(?:\s*\(SQL:|\s*\(Query:|$)/s', $message, $matches)) {
                $sqlPart = $matches[1];
                $maskedSql = $this->maskQueryText($sqlPart);  // From previous: masks literals/bindings
                $message = preg_replace('/SQL:\s*.+?(\s*\(SQL:|\s*\(Query:|$)/s', "SQL: $maskedSql\$1", $message);
            }

            // Mask bindings if mentioned (e.g., "bindings: ['sensitive@example.com']")
            if (preg_match('/bindings:\s*\[([^\]]+)\]/', $message, $matches)) {
                $bindingsStr = $matches[1];
                $bindings = explode(',', $bindingsStr);
                $maskedBindings = array_map(function ($binding) {
                    return $this->maskDbParameter($binding);  // Single param mask (trimmed)
                }, array_map('trim', $bindings));
                $maskedBindingsStr = implode(', ', $maskedBindings);
                $message = preg_replace('/bindings:\s*\[([^\]]+)\]/', "bindings: [$maskedBindingsStr]", $message);
            }
        }

        // General PII scan (emails, IPs, keys) on entire message
        $message = $this->maskDbParameters([$message])[0];  // Reuse array masker (treat as single param)

        return $message;
    }

    /**
     * Mask single DB parameter (helper for maskDbParameters)
     */
    private function maskDbParameter(string $param): string
    {
        $param = trim($param, "'\"[]");  // Clean wrappers

        // Reuse rules from maskDbParameters (emails, IPs, keys, etc.)
        if (filter_var($param, FILTER_VALIDATE_EMAIL)) {
            return preg_replace('/^([^@*]+)@/', '***@', $param);
        }
        if (preg_match('/^(sk|pk|ak)-[a-zA-Z0-9]{4,}/', $param)) {
            return preg_replace('/^(sk|pk|ak)-[a-zA-Z0-9]{4}/', '$1-****', $param);
        }
        if (filter_var($param, FILTER_VALIDATE_IP)) {
            return preg_replace('/\.\d{1,3}\.\d{1,3}$/', '.***.***', $param);
        }
        // Add more (phones, SSNs); default to full mask if suspicious
        if (preg_match('/password|secret|key|ssn|credit/i', strtolower($param)) || strlen($param) > 50) {
            return str_repeat('*', min(strlen($param), 10)) . (strlen($param) > 10 ? '...' : '');
        }

        return $param;  // Unchanged if safe
    }

    public function maskDbParameters(array $parameters): array
    {
        $masked = [];
        $maskedCount = 0;  // For logging

        foreach ($parameters as $param) {
            if (is_string($param) && strlen($param) > 0) {
                $original = $param;
                $maskedParam = $param;

                // Mask emails: user@domain.com → ***@domain.com (keep domain for debugging)
                if (filter_var($maskedParam, FILTER_VALIDATE_EMAIL)) {
                    $maskedParam = preg_replace('/^(.{0,3})?([^@]*)@(.+)$/', '***@$3', $maskedParam);
                    $maskedCount++;
                }

                // Mask API keys (e.g., sk-, pk-, ak- patterns from Stripe/OpenAI/etc.)
                if (preg_match('/^(sk|pk|ak|Bearer )-[a-zA-Z0-9]{8,}/i', $maskedParam)) {
                    $maskedParam = preg_replace('/^(sk|pk|ak|Bearer )-[a-zA-Z0-9]{4}/i', '$1-****', $maskedParam);
                    $maskedCount++;
                }

                // Mask IP addresses: 192.168.1.1 → 192.***.*** or 2001:db8::1 → 2001:db8::***
                if (filter_var($maskedParam, FILTER_VALIDATE_IP)) {
                    if (strpos($maskedParam, ':') !== false) {  // IPv6: Mask last groups
                        $maskedParam = preg_replace('/:([0-9a-f]{1,4}:){2,}$/i', ':***', $maskedParam);
                    } else {  // IPv4: Mask last two octets
                        $maskedParam = preg_replace('/\.\d{1,3}\.\d{1,3}$/', '.***.***', $maskedParam);
                    }
                    $maskedCount++;
                }

                // Mask phone numbers: +1-123-456-7890 → ***-***-**** or 1234567890 → ***4567890
                if (preg_match('/^(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$/', $maskedParam) ||
                    preg_match('/^\+?[1-9]\d{1,14}$/', $maskedParam)) {
                    $maskedParam = preg_replace('/^\+?1[-.\s]?(\(?[0-9]{3}\)?)?[-.\s]?([0-9]{3})/', '***-***', $maskedParam);
                    $maskedCount++;
                }

                // Mask potential passwords/secrets/SSNs/credit cards (keywords or long strings)
                if (preg_match('/(password|secret|token|key|ssn|credit|card|passport)/i', strtolower($maskedParam)) ||
                    (strlen($maskedParam) > 20 && ctype_alnum($maskedParam))) {  // Alphanumeric >20 chars (e.g., hashes/keys)
                    $maskedParam = str_repeat('*', min(8, strlen($maskedParam))) . (strlen($maskedParam) > 8 ? '...' : '');
                    $maskedCount++;
                }

                // General PII: Names/IDs (basic; enhance with NLP libs if needed)
                if (preg_match('/^[A-Z][a-z]+ [A-Z][a-z]+$/i', $maskedParam) ||  // Full names
                    preg_match('/^\d{3}-\d{2}-\d{4}$/', $maskedParam)) {  // SSN pattern
                    $maskedParam = '***';
                    $maskedCount++;
                }

                // Final sanitize (from earlier: remove control chars, UTF-8)
                $maskedParam = $this->sanitizeString($maskedParam);  // Assume sanitizeString exists

                $masked[] = $maskedParam;

                // Optional: Log masking for dev (disable in prod)
                if ($maskedParam !== $original && config('app.debug')) {
                    Log::debug('DB Parameter Masked', [
                        'original_preview' => substr($original, 0, 10) . '...',  // No full log
                        'masked' => $maskedParam,
                        'type' => gettype($original)
                    ]);
                }
            } else {
                // Non-strings (ints, bools, null) unchanged
                $masked[] = $param;
            }
        }

        if ($maskedCount > 0) {
            Log::info("Masked {$maskedCount} sensitive DB parameters in query");  // Audit log
        }

        return $masked;
    }

    /**
     * Mask sensitive data in SQL query text by targeting inline string literals.
     * Preserves SQL structure; masks PII in quoted values (e.g., 'user@example.com' → '***@example.com').
     * Bindings placeholders (? or $1) are untouched – mask those separately with maskDbParameters.
     *
     * @param string $query Raw SQL (e.g., "SELECT * FROM users WHERE email = 'sensitive.user@example.com'")
     * @return string Masked SQL (e.g., "SELECT * FROM users WHERE email = '***@example.com'")
     */
    public function maskQueryText(string $query): string
    {
        $query = $this->sanitizeString($query);  // Base sanitize first (UTF-8, trim, limit length)

        // Regex to find all quoted string literals: Handles single/double quotes, escapes
        // Pattern: Optional leading spaces + quote + content + quote + optional trailing
        // Captures content inside quotes for masking
        if (preg_match_all('/(?:\'([^\']*(?:\'\'[^\']*)*)\')|(?:"([^"]*(?:""[^"]*)*)"]/u', $query, $matches, PREG_SET_ORDER)) {
            $maskedLiterals = 0;
            foreach ($matches as $match) {
                $literal = trim($match[1] ?? $match[2] ?? '', '\'');  // Extract content (unescape if needed)
                $quoteType = $match[1] ? "'" : '"';  // Preserve quote type
                $originalFull = $match[0];  // Full quoted string

                if (empty($literal)) {
                    continue;  // Empty literal, skip
                }

                // Mask the literal using same logic as maskDbParameters (treat as single param)
                $maskedLiteral = $this->maskDbParameter($literal);  // Reuse from previous: emails, IPs, etc.

                if ($maskedLiteral !== $literal) {
                    $maskedFull = $quoteType . $maskedLiteral . $quoteType;
                    $query = str_replace($originalFull, $maskedFull, $query);
                    $maskedLiterals++;
                }
            }

            if ($maskedLiterals > 0) {
                Log::info("Masked {$maskedLiterals} inline literals in SQL query");  // Audit log
            }
        }

        // Additional: Mask any unquoted potential PII (rare, but e.g., numbers in WHERE without quotes)
        // E.g., WHERE id = 123 (int OK), but if email without quotes (bad SQL), still mask if email-like
        $query = preg_replace_callback('/\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/', function ($matches) {
            return $this->maskDbParameter($matches[0]);  // Mask emails/IPs unquoted
        }, $query);

        // Log preview for debug (no full query)
        if (config('app.debug')) {
            Log::debug('SQL Query Masked', ['preview' => substr($query, 0, 100) . '...']);
        }

        return $query;
    }



}
