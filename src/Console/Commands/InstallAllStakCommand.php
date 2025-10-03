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

        $this->patchKernel();

        $this->patchHandler();

        $this->checkAndRemoveCompetitors();

        $this->info("🎉 AllStak installation completed!");
        $this->info("Please use: 'use function AllStak\\captureException;' for error capturing in your project.");
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
            $this->info('✅ Created config/allstak.php');
        } else {
            $this->warn('⚠️ Config file exists, skipping.');
        }
    }

    private function getConfigStub()
    {
        return <<<PHP
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
            $this->info("✅ Created helper file at app/Helpers/CaptureException.php");
        } else {
            $this->warn('⚠️ Helper file already exists, skipping.');
        }
    }

    private function getHelperStub()
    {
        return <<<PHP
<?php

namespace AllStak;

use Throwable;
use AllStak\AllStakClient;

if (!function_exists('AllStak\\captureException')) {
    function captureException(Throwable \$exception)
    {
        app(AllStakClient::class)->captureException(\$exception);
    }
}
PHP;
    }

    private function patchKernel()
    {
        $kernelPath = app_path('Http/Kernel.php');
        if (!File::exists($kernelPath)) {
            $this->warn("Kernel file not found.");
            return;
        }

        $content = File::get($kernelPath);
        $middlewareClass = '\AllStak\Middleware\AllStakMiddleware::class';

        if (strpos($content, $middlewareClass) === false) {
            $backup = $kernelPath . '.bak_' . time();
            File::copy($kernelPath, $backup);
            $this->info("Backup created: {$backup}");

            $content = preg_replace(
                '/protected \$middleware = \[.*?\];/s',
                "protected \$middleware = [\n        {$middlewareClass},\n    ];",
                $content,
                1
            );

            File::put($kernelPath, $content);
            $this->info('✅ Patched Kernel.php with AllStak middleware');
        } else {
            $this->warn('⚠️ Middleware already patched.');
        }
    }

    private function patchHandler()
    {
        $handlerPath = app_path('Exceptions/Handler.php');
        if (!File::exists($handlerPath)) {
            $this->warn("Exception Handler not found.");
            return;
        }

        $content = File::get($handlerPath);

        if (strpos($content, 'AllStak\\AllStakClient') === false) {
            $backup = $handlerPath . '.bak_' . time();
            File::copy($handlerPath, $backup);
            $this->info("Backup created: {$backup}");

            $content = preg_replace(
                '/namespace App\\\\Exceptions;(\s+)/',
                "namespace App\\Exceptions;\n\nuse AllStak\\AllStakClient;$1",
                $content,
                1
            );

            if (strpos($content, '$this->reportable') === false) {
                $content = preg_replace(
                    '/public function register\(\)\s*\{/',
                    "public function register()\n    {\n        \$this->reportable(function (\\\Throwable \$e) {\n            app(AllStakClient::class)->captureException(\$e);\n        });\n",
                    $content,
                    1
                );
            } else {
                $content = preg_replace(
                    '/\$this->reportable\(function\s*\(\\\Throwable \$e\)\s*\{[^}]*\}\);/m',
                    "\$this->reportable(function (\\\Throwable \$e) {\n            app(AllStakClient::class)->captureException(\$e);\n        });",
                    $content,
                    1
                );
            }

            File::put($handlerPath, $content);
            $this->info('✅ Patched Exception Handler for AllStak');
        } else {
            $this->warn('⚠️ Exception Handler already patched.');
        }
    }

    private function revertHandlerPatch()
    {
        $handlerPath = app_path('Exceptions/Handler.php');
        if (!File::exists($handlerPath)) {
            return;
        }

        $content = File::get($handlerPath);

        // Remove AllStak use statement
        $content = preg_replace('/use AllStak\\\\AllStakClient;/', '', $content);

        // Remove the closure inside the register method that references AllStakClient
        $content = preg_replace(
            '/\$this->reportable\(function\s*\(\\\Throwable \$e\)\s*\{[^}]*app\(AllStakClient::class\)->captureException\(\$e\);[^}]*\}\);/m',
            '',
            $content
        );

        File::put($handlerPath, $content);
        $this->info('✅ Reverted Exception Handler patch related to AllStak');
    }
    private function restoreHandlerBackup()
    {
        $handlerPath = app_path('Exceptions/Handler.php');
        $backupPathPattern = $handlerPath . '.bak_*';

        $backups = glob($backupPathPattern);
        if (count($backups) > 0) {
            // Sort backups by modification time descending
            usort($backups, function ($a, $b) {
                return filemtime($b) - filemtime($a);
            });
            $latestBackup = $backups[0];
            File::copy($latestBackup, $handlerPath);
            $this->info("✅ Restored Handler.php from backup: {$latestBackup}");
        }
    }

    private function revertSentryPatch()
    {
        $handlerPath = app_path('Exceptions/Handler.php');
        if (!File::exists($handlerPath)) {
            return;
        }

        // Restore backup of Handler.php automatically before cleaning
        $this->restoreHandlerBackup();

        $content = File::get($handlerPath);

        // Remove all use statements referencing Sentry
        $content = preg_replace('/use\s+Sentry\\\\Laravel\\\\Integration\s*;/', '', $content);

        // Remove all static method calls on Sentry Integration (any method)
        $content = preg_replace('/Sentry\\\\Laravel\\\\Integration::[a-zA-Z0-9_]+\([^)]*\);/', '', $content);

        File::put($handlerPath, $content);

        $this->info('✅ Fully reverted Exception Handler patches related to Sentry');
    }
    private function clearCachesAndAutoload()
    {
        $this->info('🔄 Clearing caches and regenerating optimized autoload...');
        exec('composer dump-autoload -o');
        exec('php artisan config:clear');
        exec('php artisan cache:clear');
        exec('php artisan route:clear');
        exec('php artisan view:clear');
        $this->info('✅ All caches cleared and optimized autoload regenerated.');
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
                if ($this->confirm("Detected {$name} package. Remove it?")) {
                    exec("composer remove {$package}");
                    $this->info("✅ Removed {$name} package.");

                    if ($name === 'Sentry') {
                        // Fully revert any Sentry patches automatically
                        $this->revertHandlerPatch();
                        $this->revertSentryPatch();
                        $this->clearCachesAndAutoload();
                    }
                } else {
                    $this->warn("⚠️ Please remove {$name} manually to avoid conflicts.");
                }
            }
        }
    }
}
