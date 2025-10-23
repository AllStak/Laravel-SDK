<?php

namespace AllStak\Helpers\Utils;

/**
 * Helper class for data transformation and query parsing
 */
class DataTransformHelper
{
    /**
     * Extract query type from SQL query
     */
    public function extractQueryType(string $query): string
    {
        $query = trim(strtoupper($query));
        if (str_starts_with($query, 'SELECT')) return 'SELECT';
        if (str_starts_with($query, 'INSERT')) return 'INSERT';
        if (str_starts_with($query, 'UPDATE')) return 'UPDATE';
        if (str_starts_with($query, 'DELETE')) return 'DELETE';
        return 'OTHER';
    }

    /**
     * Extract all table names from query (useful for JOIN queries)
     * Returns array of table names
     */
    public function extractAllTableNames(string $query): array
    {
        $query = preg_replace('/\s+/', ' ', trim($query));
        $tables = [];

        // Universal pattern for all DB engines
        // Matches: `table`, "table", [table], table with optional schema
        $pattern = '/(?:FROM|JOIN)\s+(?:[`"\[]?(?:\w+)[`"\]]?\.)?[`"\[]?(\w+)[`"\]]?/i';

        if (preg_match_all($pattern, $query, $matches)) {
            $tables = array_unique($matches[1]);
        }

        // Fallback for INSERT/UPDATE/DELETE
        if (empty($tables)) {
            $singlePattern = '/(?:INTO|UPDATE)\s+(?:[`"\[]?(?:\w+)[`"\]]?\.)?[`"\[]?(\w+)[`"\]]?/i';
            if (preg_match($singlePattern, $query, $matches)) {
                $tables[] = $matches[1];
            }
        }

        return array_values($tables);
    }

    /**
     * Get primary table (first table in query)
     */
    public function extractTableName(string $query): ?string
    {
        $tables = $this->extractAllTableNames($query);
        return !empty($tables) ? $tables[0] : 'unknown';
    }

    /**
     * Get response body with size limit
     */
    public function getResponseBody($response): ?string
    {
        if (method_exists($response, 'getContent')) {
            $content = $response->getContent();
            return strlen($content) > 10000 ? substr($content, 0, 10000) . '...' : $content;
        }
        return null;
    }

    /**
     * Get response size
     */
    public function getResponseSize($response): ?int
    {
        if (method_exists($response, 'getContent')) {
            return strlen($response->getContent());
        }
        return null;
    }

    /**
     * Sanitize string for JSON: Remove/escape control chars, ensure UTF-8, trim and limit length.
     * Prevents JSON parse errors (e.g., illegal CTRL-CHAR) and payload bloat.
     */
    public function sanitizeString(?string $input): string
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