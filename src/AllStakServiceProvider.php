<?php

namespace AllStak;

use Illuminate\Support\ServiceProvider;
use AllStak\AllStakClient;
use AllStak\Helpers\SecurityHelper;  // Adjust namespace if different (e.g., from SecurityHelper.php)
use AllStak\Helpers\ClientHelper;   // If used elsewhere; optional
use AllStak\Middleware\AllStakMiddleware;
use AllStak\Middleware\AllStakTracingMiddleware;
use AllStak\Tracing\DBSpanRecorder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class AllStakServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Bind core classes to container (auto-wires if no deps; manual if needed)
        $this->app->singleton(AllStakClient::class, function ($app) {
            return new AllStakClient(
                $app->make(SecurityHelper::class),  // Inject SecurityHelper into Client if needed
                $app->make(ClientHelper::class),    // If ClientHelper is used
                config('allstak')                   // Config array
            );
        });

        $this->app->singleton(SecurityHelper::class, function ($app) {
            return new SecurityHelper();  // No deps; instantiate directly
            // If SecurityHelper has deps (e.g., config), pass them: new SecurityHelper(config('allstak'))
        });

        // Optional: Bind other helpers (e.g., ClientHelper)
        $this->app->singleton(ClientHelper::class, function ($app) {
            return new ClientHelper();
        });

        // Merge config (if config/allstak.php published)
        $this->mergeConfigFrom(__DIR__ . '/../config/allstak.php', 'allstak');
    }

    public function boot()
    {
        // Publish config file
        $this->publishes([
            __DIR__ . '/../config/allstak.php' => config_path('allstak.php')
        ], 'allstak-config');

        try {
            // 1. HTTP request span (global middleware)
            $this->app['router']->pushMiddlewareToGroup('web', AllStakTracingMiddleware::class);
            $this->app['router']->pushMiddlewareToGroup('api', AllStakTracingMiddleware::class);

            // 2. DB query tracing (successes via DB::listen)
            if ($this->app->bound(AllStakClient::class) && $this->app->bound(SecurityHelper::class)) {
                // FIXED: Pass both dependencies to DBSpanRecorder
                $recorder = new DBSpanRecorder(
                    app(AllStakClient::class),
                    app(SecurityHelper::class)
                );

                DB::listen(function ($query) use ($recorder) {
                    $recorder->record($query);
                });
            } else {
                Log::warning('AllStak DB tracing skipped: Missing dependencies (AllStakClient or SecurityHelper)');
            }

            // 3. Optional: HTTP logging middleware (if using AllStakMiddleware for non-tracing HTTP logs)
            // $this->app['router']->pushMiddlewareToGroup('web', AllStakMiddleware::class);
            // $this->app['router']->pushMiddlewareToGroup('api', AllStakMiddleware::class);

            Log::info('AllStak SDK booted successfully');

        } catch (\Exception $e) {
            Log::error('AllStak initialization failed: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString(),
                'file' => $e->getFile(),
                'line' => $e->getLine()
            ]);
        }
    }
}
