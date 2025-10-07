<?php

namespace AllStak;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\ServiceProvider;
use AllStak\Tracing\DBSpanRecorder;

class AllStakServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Register the config file
        $this->mergeConfigFrom(
            __DIR__ . '/../config/AllStakConfig.php', 'allstak'
        );
        $this->app->alias(AllStakClient::class, 'allstak');
        $this->app->singleton(AllStakClient::class, function ($app) {
            $config = $app['config']['allstak'];

            return new AllStakClient(
                $config['api_key'] ?? env('ALLSTAK_API_KEY', ''),
                $config['environment'] ?? env('ALLSTAK_ENV', app()->environment()),
                $config['SEND_IP_ADDRESS'] ?? env('ALLSTAK_SEND_IP_ADDRESS', false)
            );
        });

        $this->app->alias(AllStakClient::class, 'allstak');
    }

    public function boot()
    {
        // Publish the config file
        $this->publishes([
            __DIR__ . '/../config/AllStakConfig.php' => config_path('allstak.php')
        ], 'allstak-config');

        // 1. HTTP request span (global middleware)
        $this->app['router']->pushMiddlewareToGroup('web', \AllStak\Tracing\Middleware\AllStakTracingMiddleware::class);
        $this->app['router']->pushMiddlewareToGroup('api', \AllStak\Tracing\Middleware\AllStakTracingMiddleware::class);

        // 2. DB query tracing
        $recorder = new DBSpanRecorder(app(AllStakClient::class));
        DB::listen(function ($query) use ($recorder) {
            $recorder->record($query);
        });
    }
}
