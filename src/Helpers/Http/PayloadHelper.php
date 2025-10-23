<?php

namespace AllStak\Helpers\Http;

use AllStak\Helpers\Security\SecurityHelper;

/**
 * Helper class for payload sanitization and processing
 */
class PayloadHelper
{
    private SecurityHelper $securityHelper;

    public function __construct(SecurityHelper $securityHelper)
    {
        $this->securityHelper = $securityHelper;
    }

    /**
     * Sanitize payload: Encode arrays/objects to JSON strings for String DTO fields;
     * Apply string sanitization; Limit sizes
     */
    public function sanitizePayload(array $payload): array
    {
        // Fields that should STAY as arrays (not be JSON-encoded)
        $keepAsArray = ['tags', 'breadcrumbs', 'contexts'];

        // Fields that are nested objects to recurse into
        $nestedObjects = ['database_error', 'additional_data', 'http_error', 'application_error'];

        foreach ($payload as $key => $value) {
            if (is_array($value)) {
                // Check if this should stay as an array
                if (in_array($key, $keepAsArray)) {
                    // Keep as array, just sanitize string values inside
                    $payload[$key] = array_map(function ($item) {
                        return is_string($item) ? $this->sanitizeString($item) : $item;
                    }, $value);
                }
                // Recurse into nested objects
                elseif (in_array($key, $nestedObjects)) {
                    $payload[$key] = $this->sanitizePayload($value);
                }
                // Otherwise, encode to JSON string (for fields already intended as JSON)
                else {
                    $payload[$key] = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
                }
            } elseif (is_object($value)) {
                $payload[$key] = $this->sanitizePayload((array) $value);
            } elseif (is_string($value)) {
                // For DB fields, extra mask if SQL-like
                if (strpos($value, 'SELECT') !== false || strpos($value, 'INSERT') !== false) {
                    $payload[$key] = $this->securityHelper->maskQueryText($value);
                } else {
                    $payload[$key] = $this->sanitizeString($value);
                }
                // Truncate long strings (e.g., stack_trace)
                $payload[$key] = substr($payload[$key], 0, 10000);
            } elseif (is_numeric($value) && $key === 'memory_usage') {
                $payload[$key] = min($value, 1073741824);  // Cap 1GB
            }
        }

        return $payload;
    }

    /**
     * Sanitize string for JSON: Remove/escape control chars, ensure UTF-8, trim and limit length.
     * Prevents JSON parse errors (e.g., illegal CTRL-CHAR) and payload bloat.
     */
    private function sanitizeString(?string $input): string
    {
        if ($input === null) {
            return '';
        }

        // Remove control chars (0-31, 127) except allowed whitespace (\t=9, \n=10, \r=13)
        $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $input);

        // Ensure UTF-8 encoding (fix any encoding issues from sources like DB/files)
        $input = mb_convert_encoding($input, 'UTF-8', 'UTF-8');

        // Trim whitespace and limit length to prevent huge payloads (e.g., long stack traces)
        $input = trim(substr($input, 0, 10000)); // Max 10KB per field; adjust if needed

        return $input;
    }
}