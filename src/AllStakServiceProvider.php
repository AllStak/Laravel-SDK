<?php

namespace AllStak;

use AllStak\AllStakClient;
use AllStak\Helpers\SecurityHelper;  // Confirmed import for binding
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use AllStak\Middleware\AllStakTracingMiddleware;
use AllStak\Tracing\DBSpanRecorder;

class AllStakServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Register the config file (merge as 'allstak')
        $this->mergeConfigFrom(
            __DIR__ . '/../config/AllStakConfig.php', 'allstak'
        );

        // Bind AllStakClient (as before; alias optional but harmless)
        $this->app->singleton(AllStakClient::class, function ($app) {
            $config = $app['config']['allstak'];

            return new AllStakClient(
                $config['api_key'] ?? env('ALLSTAK_API_KEY', ''),
                $config['environment'] ?? env('ALLSTAK_ENV', app()->environment()),
                $config['SEND_IP_ADDRESS'] ?? env('ALLSTAK_SEND_IP_ADDRESS', true)
            );
        });

        $this->app->alias(AllStakClient::class, 'allstak');

        // FIXED: Bind SecurityHelper to container (singleton; assumes no deps)
        // If SecurityHelper constructor needs args (e.g., config), pass them: new SecurityHelper($config)
        $this->app->singleton(SecurityHelper::class, function ($app) {
            return new SecurityHelper();  // Direct instantiation; adjust if needed
        });

        // Optional: If ClientHelper or other helpers used elsewhere, bind similarly
        // $this->app->singleton(ClientHelper::class, fn($app) => new ClientHelper());

        Log::debug('AllStak dependencies registered (Client + SecurityHelper)');
    }

    public function boot()
    {
        // Publish config
        $this->publishes([
            __DIR__ . '/../config/AllStakConfig.php' => config_path('allstak.php')
        ], 'allstak-config');

        try {
            // 1. HTTP request span (global middleware) – unchanged
            $this->app['router']->pushMiddlewareToGroup('web', AllStakTracingMiddleware::class);
            $this->app['router']->pushMiddlewareToGroup('api', AllStakTracingMiddleware::class);

            // 2. DB query tracing – FIXED: Enhanced check + binding confirmation
            if ($this->app->bound(AllStakClient::class)) {
                if ($this->app->bound(SecurityHelper::class)) {
                    // Both bound: Instantiate and register listener
                    $recorder = new DBSpanRecorder(
                        app(AllStakClient::class),
                        app(SecurityHelper::class)
                    );

                    DB::listen(function ($query) use ($recorder) {
                        $recorder->record($query);
                    });

                    Log::info('AllStak DB tracing enabled (with SecurityHelper masking)');
                } else {
                    Log::warning('AllStak DB tracing skipped: SecurityHelper not bound. Check register() binding.');
                }
            } else {
                Log::warning('AllStak DB tracing skipped: AllStakClient not bound. Check config/env.');
            }

        } catch (\Exception $e) {
            Log::error('AllStak boot failed: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString(),
                'file' => $e->getFile() . ':' . $e->getLine()
            ]);
        }

        Log::info('AllStak SDK booted successfully');
    }
}
