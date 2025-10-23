<?php

namespace AllStak;

class Version
{
    public const MAJOR = 1;
    public const MINOR = 0;
    public const PATCH = 0;

    public static function get(): string
    {
        return sprintf('%d.%d.%d', self::MAJOR, self::MINOR, self::PATCH);
    }

    public static function getUserAgent(): string
    {
        $laravelVersion = 'unknown';
        if (function_exists('app') && function_exists('version')) {
            try {
                $laravelVersion = \app()->version();
            } catch (\Exception $e) {
                $laravelVersion = 'not-available';
            }
        }
        
        return sprintf(
            'allstak-php/%s (PHP %s; Laravel %s)',
            self::get(),
            PHP_VERSION,
            $laravelVersion
        );
    }
}
