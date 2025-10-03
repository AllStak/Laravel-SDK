<?php

namespace AllStak;

use Throwable;
use AllStak\AllStakClient;

if (!function_exists('AllStak\captureException')) {
    /**
     * Capture exception helper function mirroring Sentry style.
     *
     * @param Throwable $exception
     */
    function captureException(Throwable $exception)
    {
        app(AllStakClient::class)->captureException($exception);
    }
}
