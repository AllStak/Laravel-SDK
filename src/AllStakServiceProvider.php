<?php

namespace AllStak;

use AllStak\Console\Commands\InstallAllStakCommand;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
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
        $this->app['router']->pushMiddlewareToGroup('web', \AllStak\Middleware\AllStakTracingMiddleware::class);
        $this->app['router']->pushMiddlewareToGroup('api', \AllStak\Middleware\AllStakTracingMiddleware::class);

        // 2. DB query tracing
        $recorder = new DBSpanRecorder(app(AllStakClient::class));
        DB::listen(function ($query) use ($recorder) {
            $recorder->record($query);
        });

        // Add to service provider
        Event::listen('cache.hit', function ($key, $value) {
            app(AllStakClient::class)->addBreadcrumb('cache', "Cache hit: {$key}");
        });

        Event::listen('cache.missed', function ($key) {
            app(AllStakClient::class)->addBreadcrumb('cache', "Cache miss: {$key}");
        });


        // 3. Register console commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                InstallAllStakCommand::class,
            ]);
        }
    }
}
