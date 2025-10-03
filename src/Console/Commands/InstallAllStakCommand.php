<?php

namespace AllStak\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class InstallAllStakCommand extends Command
{
    protected $signature = 'allstak:install {--key=} {--environment=production}';
    protected $description = 'Wizard to install and configure AllStak SDK in your Laravel app';

    private $knownPackages = [
        'Sentry' => 'sentry/sentry-laravel',
        'Bugsnag' => 'bugsnag/bugsnag-laravel',
        'Rollbar' => 'rollbar/rollbar-laravel',
        'NewRelic' => 'newrelic/newrelic-php-agent',
    ];

    public function handle()
    {
        $this->info('⚡ Installing AllStak...');

        $apiKey = $this->option('key') ?: $this->ask('Enter your AllStak API Key');
        $environment = $this->option('environment') ?: 'production';

        $this->updateEnv('ALLSTAK_API_KEY', $apiKey);
        $this->updateEnv('ALLSTAK_ENV', $environment);
        $this->info('✅ Updated .env');

        $this->createConfigFile();
        $this->createCaptureExceptionHelper();
        $this->checkAndRemoveCompetitors();
        $this->patchKernel();
        $this->patchHandler();

        $this->info("🎉 AllStak installation completed!");
        $this->newLine();
        $this->info("✨ You can now use: captureException(\$exception) in your code.");
        $this->newLine();

        return 0;
    }

    private function updateEnv($key, $value)
    {
        $envPath = base_path('.env');
        if (!File::exists($envPath)) return;

        $content = File::get($envPath);

        if (strpos($content, "{$key}=") === false) {
            File::append($envPath, "\n{$key}={$value}\n");
        } else {
            $content = preg_replace("/^{$key}=.*/m", "{$key}={$value}", $content);
            File::put($envPath, $content);
        }
    }

    private function createConfigFile()
    {
        $configPath = config_path('allstak.php');
        if (!File::exists($configPath)) {
            File::put($configPath, $this->getConfigStub());
            $this->info('✅ Config file created: config/allstak.php');
        }
    }

    private function getConfigStub()
    {
        return <<<'PHP'
<?php

return [
    'api_key' => env('ALLSTAK_API_KEY'),
    'environment' => env('ALLSTAK_ENV', 'production'),
    'enabled' => true,
];
PHP;
    }

    private function createCaptureExceptionHelper()
    {
        $helperDir = base_path('app/Helpers');
        if (!File::exists($helperDir)) {
            mkdir($helperDir, 0755, true);
        }

        $helperFile = $helperDir . '/CaptureException.php';
        if (!File::exists($helperFile)) {
            File::put($helperFile, $this->getHelperStub());
            $this->info("✅ Helper file created: app/Helpers/CaptureException.php");
        }
    }

    private function getHelperStub()
    {
        return <<<'PHP'
<?php

namespace AllStak;

use Throwable;
use AllStak\AllStakClient;

if (!function_exists('AllStak\captureException')) {
    function captureException(Throwable $exception)
    {
        app(AllStakClient::class)->captureException($exception);
    }
}
PHP;
    }

    private function patchKernel()
    {
        $kernelPath = app_path('Http/Kernel.php');
        if (!File::exists($kernelPath)) {
            return;
        }

        $content = File::get($kernelPath);
        $middlewareClass = '\AllStak\Middleware\AllStakMiddleware::class';

        if (strpos($content, $middlewareClass) === false) {
            $backup = $kernelPath . '.bak_' . time();
            File::copy($kernelPath, $backup);

            $content = preg_replace(
                '/protected \$middleware = \[.*?\];/s',
                "protected \$middleware = [\n        {$middlewareClass},\n    ];",
                $content,
                1
            );

            File::put($kernelPath, $content);
            $this->info('✅ AllStakMiddleware added to Kernel.php');
        }
    }

    private function deleteHandlerCompletely()
    {
        $handlerPath = app_path('Exceptions/Handler.php');

        if (File::exists($handlerPath)) {
            // Create backup
            $backup = $handlerPath . '.bak_delete_' . time();
            File::copy($handlerPath, $backup);
            $this->info("📦 Backup: {$backup}");

            // DELETE the file completely
            unlink($handlerPath);
            clearstatcache(true, $handlerPath);

            $this->info('🗑️  Deleted Handler.php temporarily');
        }
    }

    private function recreateCleanHandler()
    {
        $handlerPath = app_path('Exceptions/Handler.php');

        // Fresh minimal handler
        $cleanHandler = <<<'HANDLER'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;

class Handler extends ExceptionHandler
{
    protected $dontFlash = ['current_password', 'password', 'password_confirmation'];
    
    public function register() {}
}
HANDLER;

        file_put_contents($handlerPath, $cleanHandler);
        chmod($handlerPath, 0644);

        if (function_exists('opcache_invalidate')) {
            opcache_invalidate($handlerPath, true);
        }

        clearstatcache(true, $handlerPath);
        $this->info('✅ Clean Handler.php recreated');
    }

    private function patchHandler()
    {
        $handlerPath = app_path('Exceptions/Handler.php');

        $handlerWithAllStak = <<<'HANDLER'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;
use AllStak\AllStakClient;

class Handler extends ExceptionHandler
{
    protected $dontFlash = ['current_password', 'password', 'password_confirmation'];
    
    public function register()
    {
        $this->reportable(function (Throwable $e) {
            app(AllStakClient::class)->captureException($e);
        });
    }
}
HANDLER;

        file_put_contents($handlerPath, $handlerWithAllStak);
        chmod($handlerPath, 0644);

        if (function_exists('opcache_invalidate')) {
            opcache_invalidate($handlerPath, true);
        }

        clearstatcache(true, $handlerPath);
        $this->info('✅ Exception Handler patched for AllStak');
    }

    private function checkAndRemoveCompetitors()
    {
        $composerJsonPath = base_path('composer.json');
        if (!File::exists($composerJsonPath)) {
            return;
        }

        $composer = json_decode(File::get($composerJsonPath), true);
        if (!isset($composer['require'])) {
            return;
        }

        foreach ($this->knownPackages as $name => $package) {
            if (isset($composer['require'][$package])) {
                if ($this->confirm(" ⚠️ Sentry detected. Do you want to remove it?", true)) {

                    $this->newLine();
                    $this->info("🔄 Removing {$name}...");

                    if ($name === 'Sentry') {
                        // STEP 1: Completely DELETE Handler.php
                        $this->deleteHandlerCompletely();

                        // STEP 2: Clear opcache
                        if (function_exists('opcache_reset')) {
                            opcache_reset();
                        }

                        // STEP 3: Remove Sentry package
                        $output = shell_exec("cd " . base_path() . " && composer remove {$package} 2>&1");

                        // STEP 4: Recreate clean Handler
                        $this->recreateCleanHandler();

                        // STEP 5: Clear everything
                        shell_exec('composer dump-autoload 2>&1');

                        $this->info("✅ Sentry removed from project.");
                        $this->newLine();
                    }
                }
            }
        }
    }
}
