<?php

namespace AllStak\Facades;

use Illuminate\Support\Facades\Facade;

class AllStak extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'allstak';
    }
}
