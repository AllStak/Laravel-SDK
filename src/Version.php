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
        return sprintf(
            'allstak-php/%s (PHP %s; Laravel %s)',
            self::get(),
            PHP_VERSION,
            app()->version()
        );
    }
}
