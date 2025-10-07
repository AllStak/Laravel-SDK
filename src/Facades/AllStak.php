<?php

namespace AllStak\Tracing\Facades;

use Illuminate\Support\Facades\Facade;

class AllStak extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'allstak';
    }
}
