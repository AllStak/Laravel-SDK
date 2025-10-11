<?php

namespace AllStak;

use AllStak\AllStakClient;
use AllStak\Helpers\SecurityHelper;  // Confirmed import for binding
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use AllStak\Middleware\AllStakTracingMiddleware;
use AllStak\Tracing\DBSpanRecorder;

class AllStakServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register()
    {
        // Register the config file (merge as 'allstak')
        $this->mergeConfigFrom(
            __DIR__ . '/../config/AllStakConfig.php', 'allstak'
        );

        // Bind AllStakClient as singleton
        $this->app->singleton(AllStakClient::class, function ($app) {
            $config = $app['config']['allstak'];

            return new AllStakClient(
                $config['api_key'] ?? env('ALLSTAK_API_KEY', ''),
                $config['environment'] ?? env('ALLSTAK_ENV', app()->environment()),
                $config['SEND_IP_ADDRESS'] ?? env('ALLSTAK_SEND_IP_ADDRESS', true),
                $config['service_name'] ?? env('ALLSTAK_SERVICE_NAME', config('app.name'))
            );
        });

        $this->app->alias(AllStakClient::class, 'allstak');

        // Bind SecurityHelper to container
        $this->app->singleton(SecurityHelper::class, function ($app) {
            return new SecurityHelper();
        });

        // ✅ Bind DBSpanRecorder as singleton
        $this->app->singleton(DBSpanRecorder::class, function ($app) {
            return new DBSpanRecorder(
                $app->make(AllStakClient::class),
                $app->make(SecurityHelper::class)
            );
        });

        Log::debug('AllStak dependencies registered (Client + SecurityHelper + DBSpanRecorder)');
    }

    /**
     * Bootstrap any application services.
     */
    public function boot()
    {
        // Publish config
        $this->publishes([
            __DIR__ . '/../config/AllStakConfig.php' => config_path('allstak.php')
        ], 'allstak-config');

        // Check if SDK is enabled
        if (!config('allstak.enabled', true)) {
            Log::info('AllStak SDK is disabled in config');
            return;
        }

        try {
            // 1. HTTP request span (global middleware)
            $this->app['router']->pushMiddlewareToGroup('web', AllStakTracingMiddleware::class);
            $this->app['router']->pushMiddlewareToGroup('api', AllStakTracingMiddleware::class);

            // 2. ✅ DB query tracing - Listen for SUCCESSFUL queries
            if ($this->app->bound(AllStakClient::class) && $this->app->bound(SecurityHelper::class)) {

                DB::listen(function (QueryExecuted $query) {
                    try {
                        $recorder = $this->app->make(DBSpanRecorder::class);
                        $recorder->record($query);
                    } catch (\Exception $e) {
                        Log::error('AllStak: Failed to record successful query', [
                            'error' => $e->getMessage()
                        ]);
                    }
                });

                Log::info('AllStak DB tracing enabled (with SecurityHelper masking)');
            } else {
                Log::warning('AllStak DB tracing skipped: Required dependencies not bound');
            }

            // 3. ✅ AUTOMATIC: Register failed query handler (no user action required)
            $this->registerFailedQueryHandler();

        } catch (\Exception $e) {
            Log::error('AllStak boot failed: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString(),
                'file' => $e->getFile() . ':' . $e->getLine()
            ]);
        }

        Log::info('AllStak SDK booted successfully');
    }

    /**
     * ✅ Automatically hook into Laravel's exception handler to capture failed queries
     * This works automatically without requiring users to modify Handler.php
     */
    protected function registerFailedQueryHandler()
    {
        try {
            $handler = $this->app->make(ExceptionHandler::class);

            // Use reportable() method to register QueryException handler
            // This is available in Laravel 8+ and works automatically
            if (method_exists($handler, 'reportable')) {
                $handler->reportable(function (QueryException $exception) {
                    try {
                        $recorder = $this->app->make(DBSpanRecorder::class);
                        $recorder->recordFailedQuery($exception);

                        Log::debug('AllStak: Failed query recorded', [
                            'error_code' => $exception->getCode(),
                            'trace_id' => class_exists('\AllStak\LaravelSDK\Context\SpanContext')
                                ? \AllStak\LaravelSDK\Context\SpanContext::getTraceId()
                                : null
                        ]);
                    } catch (\Exception $e) {
                        Log::error('AllStak: Failed to record database error', [
                            'error' => $e->getMessage(),
                            'query_exception' => $exception->getMessage()
                        ]);
                    }

                    // Don't return false - let Laravel handle the exception normally
                    // This ensures error still gets logged and displayed to user
                });

                Log::info('AllStak: Failed query handler registered successfully');
            } else {
                Log::warning('AllStak: reportable() method not available on ExceptionHandler (Laravel < 8)');
            }
        } catch (\Exception $e) {
            Log::error('AllStak: Failed to register query exception handler', [
                'error' => $e->getMessage()
            ]);
        }
    }
}