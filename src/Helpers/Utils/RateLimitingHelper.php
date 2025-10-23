<?php

namespace AllStak\Helpers\Utils;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Exception;

/**
 * Helper class for handling rate limiting functionality
 */
class RateLimitingHelper
{
    private const MAX_ATTEMPTS = 100;
    private const DECAY_SECONDS = 60; // 1 minute window
    
    private string $rateLimitKey;
    
    public function __construct(string $apiKey)
    {
        $this->rateLimitKey = 'allstak:' . md5($apiKey); // Unique per API key
    }
    
    /**
     * Check if the current request should be throttled
     *
     * @return bool
     */
    public function shouldThrottle(): bool
    {
        try {
            // Check if Laravel facades are available
            if (!class_exists('\Illuminate\Support\Facades\Cache')) {
                return false; // Skip rate limiting if Cache facade not available
            }

            $attempts = Cache::get($this->rateLimitKey, 0);

            if ($attempts >= self::MAX_ATTEMPTS) {
                if (class_exists('\Illuminate\Support\Facades\Log')) {
                    Log::debug('AllStak rate limit exceeded', ['attempts' => $attempts]);
                }
                return true;
            }

            // Increment attempts
            Cache::put($this->rateLimitKey, $attempts + 1, self::DECAY_SECONDS);

            if (class_exists('\Illuminate\Support\Facades\Log')) {
                Log::debug('AllStak rate limit check', ['attempts' => $attempts + 1]);
            }
            return false;
        } catch (\Exception $e) {
            if (class_exists('\Illuminate\Support\Facades\Log')) {
                Log::warning('AllStak rate limiting failed, proceeding without limit', [
                    'error' => $e->getMessage()
                ]);
            }
            return false; // Fail open to avoid blocking
        }
    }
    
    /**
     * Reset the rate limit counter
     *
     * @return void
     */
    public function resetRateLimit(): void
    {
        if (class_exists('\Illuminate\Support\Facades\Cache')) {
            Cache::forget($this->rateLimitKey);
        }
    }
    
    /**
     * Get current attempt count
     *
     * @return int
     */
    public function getCurrentAttempts(): int
    {
        if (class_exists('\Illuminate\Support\Facades\Cache')) {
            return Cache::get($this->rateLimitKey, 0);
        }
        return 0;
    }
}