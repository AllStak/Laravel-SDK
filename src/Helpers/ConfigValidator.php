<?php

namespace AllStak\Helpers;

/**
 * Validates AllStak configuration array and returns normalized values + warnings.
 */
class ConfigValidator
{
    /**
     * Validate and normalize configuration.
     *
     * @param array $config Raw config (from merged Laravel config)
     * @return array{config: array, warnings: string[], errors: string[]}
     */
    public static function validate(array $config): array
    {
        $warnings = [];
        $errors = [];

        $normalized = $config;

        // Required fields
        if (empty($normalized['api_key'])) {
            $errors[] = 'api_key is missing or empty';
        } elseif (!is_string($normalized['api_key']) || strlen($normalized['api_key']) < 10) {
            $errors[] = 'api_key appears invalid (length < 10)';
        }

        if (empty($normalized['project_id'])) {
            $errors[] = 'project_id is missing or empty';
        }

        // Types & ranges
        $normalized['sample_rate'] = isset($normalized['sample_rate']) ? (float)$normalized['sample_rate'] : 1.0;
        if ($normalized['sample_rate'] < 0.0 || $normalized['sample_rate'] > 1.0) {
            $warnings[] = 'sample_rate out of range (0.0-1.0); clamping';
            $normalized['sample_rate'] = max(0.0, min(1.0, $normalized['sample_rate']));
        }

        $normalized['batch_size'] = isset($normalized['batch_size']) ? (int)$normalized['batch_size'] : 100;
        if ($normalized['batch_size'] <= 0) {
            $warnings[] = 'batch_size must be > 0; resetting to 10';
            $normalized['batch_size'] = 10;
        } elseif ($normalized['batch_size'] > 5000) {
            $warnings[] = 'batch_size very large; may cause memory pressure';
        }

        $normalized['flush_interval'] = isset($normalized['flush_interval']) ? (int)$normalized['flush_interval'] : 5000;
        if ($normalized['flush_interval'] < 100) {
            $warnings[] = 'flush_interval too low (<100ms); may increase overhead';
        }

        // Privacy lists
        if (!isset($normalized['scrub_headers'])) {
            $normalized['scrub_headers'] = 'Authorization,Cookie';
        }
        if (is_string($normalized['scrub_headers'])) {
            $normalized['scrub_headers'] = implode(',', array_filter(array_map('trim', explode(',', $normalized['scrub_headers']))));
        }

        // Tags
        if (!isset($normalized['tags']) || !is_array($normalized['tags'])) {
            $warnings[] = 'tags missing or not array; initializing empty tags';
            $normalized['tags'] = [];
        }

        // Enabled flag logic: disable if errors
        if (!empty($errors)) {
            $normalized['enabled'] = false;
        }

        return [
            'config' => $normalized,
            'warnings' => $warnings,
            'errors' => $errors,
        ];
    }
}

