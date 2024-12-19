<?php

namespace Techsea\AllStack;

use Illuminate\Support\ServiceProvider;

class AllStackServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Register the config file
        $this->mergeConfigFrom(
            __DIR__.'/../config/allstack.php', 'allstack'
        );

        $this->app->singleton(AllStackClient::class, function ($app) {
            $config = $app['config']['allstack'];
            
            return new AllStackClient(
                $config['api_key'] ?? env('ALLSTACK_API_KEY', ''),
                $config['environment'] ?? env('ALLSTACK_ENVIRONMENT', app()->environment())
            );
        });

        $this->app->alias(AllStackClient::class, 'allstack');
    }

    public function boot()
    {
        // Publish the config file
        $this->publishes([
            __DIR__.'/../config/allstack.php' => config_path('allstack.php')
        ], 'allstack-config');
    }
}