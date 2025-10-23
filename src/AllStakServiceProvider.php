<?php

namespace AllStak;

use AllStak\AllStakClient;
use AllStak\Helpers\SecurityHelper;  // Confirmed import for binding
use AllStak\Logging\AllStakLogChannel;
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
    public function register()
    {
        // Register the config file
        $this->mergeConfigFrom(
            __DIR__ . '/../config/AllStakConfig.php', 'allstak'
        );

        // Bind AllStakClient as singleton
        $this->app->singleton(AllStakClient::class, function ($app) {
            $config = $app['config']['allstak'];
            return new AllStakClient(
                $config['api_key'] ?? env('ALLSTAK_API_KEY', ''),
                $config['environment'] ?? env('ALLSTAK_ENV', \app()->environment()),
                $config['SEND_IP_ADDRESS'] ?? env('ALLSTAK_SEND_IP_ADDRESS', true),
                $config['service_name'] ?? env('ALLSTAK_SERVICE_NAME', config('app.name'))
            );
        });

        $this->app->alias(AllStakClient::class, 'allstak');

        // Bind SecurityHelper
        $this->app->singleton(SecurityHelper::class, function ($app) {
            return new SecurityHelper();
        });

        // Bind DBSpanRecorder as singleton
        $this->app->singleton(DBSpanRecorder::class, function ($app) {
            return new DBSpanRecorder(
                $app->make(AllStakClient::class),
                $app->make(SecurityHelper::class)
            );
        });

    }

    public function boot()
    {
        // Publish config
        $this->publishes([
            __DIR__ . '/../config/AllStakConfig.php' => config_path('allstak.php')
        ], 'allstak-config');

        // Register custom log channel in boot method
        $this->app['log']->extend('allstak', function ($app, $config) {
            return (new AllStakLogChannel())($config);
        });

        // Check if SDK is enabled
        if (!config('allstak.enabled', true)) {
            Log::info('AllStak SDK is disabled in config');
            return;
        }

        try {
            // 1. HTTP request span (global middleware)
            $this->app['router']->pushMiddlewareToGroup('web', AllStakTracingMiddleware::class);
            $this->app['router']->pushMiddlewareToGroup('api', AllStakTracingMiddleware::class);

            // 2. Listen for SUCCESSFUL queries
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

                Log::info('AllStak DB tracing enabled');
            }

            // 3. ✅ FIXED: Register failed query handler using reportable
            $this->registerFailedQueryHandler();

        } catch (\Exception $e) {
            Log::error('AllStak boot failed: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString()
            ]);
        }

        Log::info('AllStak SDK booted successfully');
    }

    /**
     * ✅ Register handler for failed database queries
     */
    protected function registerFailedQueryHandler()
    {
        try {
            // Get the exception handler instance
            $handler = $this->app->make(ExceptionHandler::class);

            // Check if reportable method exists (Laravel 8+)
            if (method_exists($handler, 'reportable')) {
                $handler->reportable(function (QueryException $exception) {
                    try {
                        Log::info('AllStak: QueryException caught', [
                            'code' => $exception->getCode(),
                            'message' => substr($exception->getMessage(), 0, 100)
                        ]);

                        $recorder = $this->app->make(DBSpanRecorder::class);
                        $recorder->recordFailedQuery($exception);

                        Log::info('AllStak: Failed query recorded successfully');
                    } catch (\Exception $e) {
                        Log::error('AllStak: Failed to record database error', [
                            'error' => $e->getMessage(),
                            'trace' => $e->getTraceAsString()
                        ]);
                    }

                    // IMPORTANT: Don't return false, let Laravel handle exception normally
                });

                Log::info('AllStak: QueryException handler registered via reportable()');
            } else {
                Log::warning('AllStak: reportable() not available, using alternative method');

                // ✅ ALTERNATIVE: Use extending the handler (works in older Laravel versions)
                $this->app->extend(ExceptionHandler::class, function ($handler, $app) {
                    return new class($handler, $app) extends \Illuminate\Foundation\Exceptions\Handler {
                        private $original;
                        private $app;

                        public function __construct($original, $app) {
                            $this->original = $original;
                            $this->app = $app;
                            parent::__construct($app);
                        }

                        public function report(\Throwable $exception)
                        {
                            if ($exception instanceof QueryException) {
                                try {
                                    $recorder = $this->app->make(DBSpanRecorder::class);
                                    $recorder->recordFailedQuery($exception);
                                    Log::info('AllStak: Failed query recorded via extended handler');
                                } catch (\Exception $e) {
                                    Log::error('AllStak: Failed in extended handler', [
                                        'error' => $e->getMessage()
                                    ]);
                                }
                            }

                            return $this->original->report($exception);
                        }

                        public function render($request, \Throwable $exception)
                        {
                            return $this->original->render($request, $exception);
                        }
                    };
                });
            }
        } catch (\Exception $e) {
            Log::error('AllStak: Failed to register query exception handler', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }
    }
}