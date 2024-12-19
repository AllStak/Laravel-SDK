<?php

namespace Techsea\AllStack;

use Illuminate\Support\ServiceProvider;

class AllStackServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton(AllStackClient::class, function ($app) {
            $config = $app['config']['services.allstack'];
            
            return new AllStackClient(
                $config['api_key'],
                $config['environment'] ?? app()->environment()
            );
        });

        $this->app->alias(AllStackClient::class, 'allstack');
    }

    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/allstack.php' => config_path('services.php'),
        ]);
    }
}