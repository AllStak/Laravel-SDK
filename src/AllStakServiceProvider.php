<?php

namespace AllStak;

use AllStak\AllStakClient;
use AllStak\Logging\AllStakLogHandler;
use AllStak\Middleware\AllStakMiddleware;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use Monolog\Logger;

class AllStakServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Register the config file
        $this->mergeConfigFrom(
            __DIR__ . '/../config/AllStakConfig.php', 'allstak'
        );

        // Bind AllStakClient as singleton
        $this->app->singleton(AllStakClient::class, function ($app) {
            return new AllStakClient($app['config']['allstak']);
        });

        $this->app->alias(AllStakClient::class, 'allstak');
    }

    public function boot()
    {
        // Publish config
        $this->publishes([
            __DIR__ . '/../config/AllStakConfig.php' => config_path('allstak.php')
        ], 'allstak-config');

        // Check if SDK is enabled
        if (!config('allstak.enabled', true)) {
            return;
        }

        $client = $this->app->make(AllStakClient::class);

        try {
            // 1. Register HTTP middleware for automatic request tracking
            if (config('allstak.capture_http', true)) {
                $this->app['router']->pushMiddlewareToGroup('web', AllStakMiddleware::class);
                $this->app['router']->pushMiddlewareToGroup('api', AllStakMiddleware::class);
            }

            // 2. Register database query listener for automatic query tracking
            if (config('allstak.capture_database', true)) {
                DB::listen(function (QueryExecuted $query) use ($client) {
                    try {
                        $client->captureQuery(
                            $query->sql,
                            $query->bindings,
                            $query->time,
                            $query->connectionName
                        );
                    } catch (\Exception $e) {
                        error_log('AllStak: Failed to capture query: ' . $e->getMessage());
                    }
                });
            }

            // 3. Register custom log handler for automatic log capture
            if (config('allstak.capture_logs', true)) {
                $this->app['log']->extend('allstak', function ($app, $config) use ($client) {
                    $handler = new AllStakLogHandler($client, Logger::DEBUG);
                    return new Logger('allstak', [$handler]);
                });
            }

            // 4. Register global exception handler for automatic error tracking
            if (config('allstak.capture_errors', true)) {
                $this->registerExceptionHandler($client);
            }

        } catch (\Exception $e) {
            error_log('AllStak boot failed: ' . $e->getMessage());
        }
    }

    /**
     * Register exception handler for automatic error tracking
     */
    protected function registerExceptionHandler(AllStakClient $client)
    {
        try {
            $handler = $this->app->make(ExceptionHandler::class);

            if (method_exists($handler, 'reportable')) {
                $handler->reportable(function (\Throwable $exception) use ($client) {
                    try {
                        $request = null;
                        if (function_exists('request') && request() !== null) {
                            $request = request();
                        }
                        $client->captureError($exception, $request);
                    } catch (\Exception $e) {
                        error_log('AllStak: Failed to capture error: ' . $e->getMessage());
                    }
                });
            }
        } catch (\Exception $e) {
            error_log('AllStak: Failed to register exception handler: ' . $e->getMessage());
        }
    }
}

