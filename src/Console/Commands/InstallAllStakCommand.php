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

    private function createFreshHandler()
    {
        $handlerPath = app_path('Exceptions/Handler.php');

        // Backup existing handler
        if (File::exists($handlerPath)) {
            $backup = $handlerPath . '.bak_' . time();
            File::copy($handlerPath, $backup);
            $this->info("Backup created: {$backup}");
        }

        // Create fresh Laravel Handler
        $freshHandler = <<<'PHP'
<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    /**
     * A list of exception types with their corresponding custom log levels.
     *
     * @var array<class-string<\Throwable>, \Psr\Log\LogLevel::*>
     */
    protected $levels = [
        //
    ];

    /**
     * A list of the exception types that are not reported.
     *
     * @var array<int, class-string<\Throwable>>
     */
    protected $dontReport = [
        //
    ];

    /**
     * A list of the inputs that are never flashed to the session on validation exceptions.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    /**
     * Register the exception handling callbacks for the application.
     *
     * @return void
     */
    public function register()
    {
        //
    }
}
PHP;

        File::put($handlerPath, $freshHandler);
        $this->info('✅ Created fresh Exception Handler');
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
            $content = preg_replace(
                '/namespace App\\\\Exceptions;(\s+)/',
                "namespace App\\Exceptions;\n\nuse AllStak\\AllStakClient;$1",
                $content,
                1
            );

            $content = preg_replace(
                '/public function register\(\)\s*\{/',
                "public function register()\n    {\n        \$this->reportable(function (\\\Throwable \$e) {\n            app(AllStakClient::class)->captureException(\$e);\n        });\n",
                $content,
                1
            );

            File::put($handlerPath, $content);
            $this->info('✅ Patched Exception Handler for AllStak');
        } else {
            $this->warn('⚠️ Exception Handler already patched.');
        }
    }

    private function clearCachesAndAutoload()
    {
        $this->info('🔄 Clearing caches and regenerating optimized autoload...');

        shell_exec('composer dump-autoload -o 2>&1');
        shell_exec('php artisan config:clear 2>&1');
        shell_exec('php artisan cache:clear 2>&1');
        shell_exec('php artisan route:clear 2>&1');
        shell_exec('php artisan view:clear 2>&1');

        // Clear opcache if available
        if (function_exists('opcache_reset')) {
            opcache_reset();
        }

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
                if ($this->confirm("⚠️  Detected {$name}. Do you want to remove it?", true)) {

                    $this->info("🔄 Preparing to remove {$name}...");

                    // For Sentry, create fresh handler first
                    if ($name === 'Sentry') {
                        $this->createFreshHandler();
                        $this->clearCachesAndAutoload();
                    }

                    // Remove the package
                    $this->info("Removing {$package}...");
                    shell_exec("composer remove {$package} 2>&1");
                    $this->info("✅ Removed {$name} package.");

                    // Clear everything again after removal
                    if ($name === 'Sentry') {
                        $this->clearCachesAndAutoload();
                    }
                } else {
                    $this->warn("⚠️  Skipped {$name} removal. Please remove manually to avoid conflicts.");
                }
            }
        }
    }
}
