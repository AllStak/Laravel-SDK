<?php

namespace AllStak\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class InstallAllStakCommand extends Command
{
    protected $signature = 'allstak:install {--key=} {--environment=production}';
    protected $description = 'Wizard to install and configure AllStak SDK in your Laravel app';

    public function handle()
    {
        $this->info('⚡ Installing AllStak...');

        // 1. Add API key + environment to .env
        $apiKey = $this->option('key') ?: $this->ask('Enter your AllStak API Key');
        $environment = $this->option('environment') ?: 'production';
        $this->updateEnv('ALLSTAK_API_KEY', $apiKey);
        $this->updateEnv('ALLSTAK_ENV', $environment);
        $this->info('✅ .env updated with AllStak config');

        // 2. Create config/allstak.php
        $configPath = config_path('allstak.php');
        if (!File::exists($configPath)) {
            File::put($configPath, $this->getConfigStub());
            $this->info('✅ Config file created: config/allstak.php');
        } else {
            $this->warn('⚠️ Config file already exists, skipped.');
        }

        // 3. Patch Kernel.php (middleware)
        $this->patchKernel();

        // 4. Patch Exception Handler
        $this->patchHandler();

        // 5. Check for Sentry
        $this->checkSentry();

        $this->info('🎉 AllStak installation completed successfully!');
    }

    private function updateEnv($key, $value)
    {
        $envPath = base_path('.env');
        if (!File::exists($envPath)) return;

        $content = File::get($envPath);

        if (strpos($content, $key . '=') === false) {
            File::append($envPath, "\n{$key}={$value}\n");
        } else {
            $content = preg_replace("/^{$key}=.*/m", "{$key}={$value}", $content);
            File::put($envPath, $content);
        }
    }

    private function getConfigStub()
    {
        return <<<PHP
<?php

return [

    /*
    |--------------------------------------------------------------------------
    | AllStak API Key
    |--------------------------------------------------------------------------
    */
    'api_key' => env('ALLSTAK_API_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Environment
    |--------------------------------------------------------------------------
    */
    'environment' => env('ALLSTAK_ENVIRONMENT', 'production'),

    'enabled' => true,
];
PHP;
    }

    private function patchKernel()
    {
        $kernelPath = app_path('Http/Kernel.php');
        if (!File::exists($kernelPath)) return;

        $content = File::get($kernelPath);
        if (strpos($content, 'AllStak\Middleware\AllStakMiddleware::class') === false) {
            $content = str_replace(
                "protected \$middleware = [",
                "protected \$middleware = [\n        \AllStak\Middleware\AllStakMiddleware::class,",
                $content
            );
            File::put($kernelPath, $content);
            $this->info('✅ AllStakMiddleware added to Kernel.php');
        } else {
            $this->warn('⚠️ Middleware already exists in Kernel.php, skipped.');
        }
    }

    private function patchHandler()
    {
        $handlerPath = app_path('Exceptions/Handler.php');
        if (!File::exists($handlerPath)) return;

        $content = File::get($handlerPath);

        if (strpos($content, 'AllStakClient') === false) {
            // Add use statement
            $content = preg_replace(
                '/namespace App\\\\Exceptions;(\s+)/',
                "namespace App\\Exceptions;\n\nuse AllStak\\AllStakClient;$1",
                $content
            );

            // Add reportable() block if not exists
            if (strpos($content, '$this->reportable') === false) {
                $content = preg_replace(
                    '/public function register\(\)\s*\{/',
                    "public function register()\n    {\n        \$this->reportable(function (Throwable \$e) {\n            app(AllStakClient::class)->captureException(\$e);\n        });\n",
                    $content
                );
            } else {
                $content = preg_replace(
                    '/\$this->reportable\(function\s*\(Throwable \$e\)\s*\{[^}]*\}\);/m',
                    "\$this->reportable(function (Throwable \$e) {\n            app(AllStakClient::class)->captureException(\$e);\n        });",
                    $content
                );
            }

            File::put($handlerPath, $content);
            $this->info('✅ Exception Handler patched for AllStak');
        } else {
            $this->warn('⚠️ Handler already patched, skipped.');
        }
    }

    private function checkSentry()
    {
        $composerJsonPath = base_path('composer.json');
        if (!File::exists($composerJsonPath)) return;

        $composerJson = json_decode(File::get($composerJsonPath), true);

        if (isset($composerJson['require']['sentry/sentry-laravel'])) {
            if ($this->confirm('⚠️ Sentry detected. Do you want to remove it?')) {
                exec('composer remove sentry/sentry-laravel');
                $this->info('✅ Sentry removed from project.');
            }
        }
    }
}
