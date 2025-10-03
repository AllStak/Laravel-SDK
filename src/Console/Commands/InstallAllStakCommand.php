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

        // Force exit to prevent any cached code from running
        exit(0);
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

    private function removeSentryFromHandler()
    {
        $handlerPath = app_path('Exceptions/Handler.php');

        if (!File::exists($handlerPath)) {
            return;
        }

        // Backup
        $backup = $handlerPath . '.bak_sentry_removal_' . time();
        File::copy($handlerPath, $backup);
        $this->info("🔒 Backup created: {$backup}");

        // Read file line by line
        $lines = file($handlerPath);
        $cleanedLines = [];
        $skipNextBrace = false;

        foreach ($lines as $line) {
            $trimmedLine = trim($line);

            // Skip any line containing "Sentry"
            if (stripos($line, 'Sentry') !== false) {
                continue;
            }

            // Skip any line containing "Integration"
            if (stripos($line, 'Integration') !== false) {
                continue;
            }

            $cleanedLines[] = $line;
        }

        // Write cleaned content
        file_put_contents($handlerPath, implode('', $cleanedLines));

        // Force file system sync
        if (function_exists('fsync')) {
            $fp = fopen($handlerPath, 'r');
            fsync($fp);
            fclose($fp);
        }

        $this->info('✅ Removed all Sentry references from Handler.php');
    }

    private function createCleanHandler()
    {
        $handlerPath = app_path('Exceptions/Handler.php');

        // Backup existing
        if (File::exists($handlerPath)) {
            $backup = $handlerPath . '.bak_clean_' . time();
            File::copy($handlerPath, $backup);
            $this->info("🔒 Backup created: {$backup}");
        }

        // Create completely clean handler
        $cleanHandler = '<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    protected $levels = [];
    
    protected $dontReport = [];
    
    protected $dontFlash = [
        \'current_password\',
        \'password\',
        \'password_confirmation\',
    ];

    public function register()
    {
        // Clean handler - no integrations
    }
}
';

        // Write with file_put_contents for direct disk write
        file_put_contents($handlerPath, $cleanHandler);
        chmod($handlerPath, 0644);

        // Force sync
        clearstatcache(true, $handlerPath);

        $this->info('✅ Created clean Exception Handler');
    }

    private function patchHandler()
    {
        $handlerPath = app_path('Exceptions/Handler.php');
        if (!File::exists($handlerPath)) {
            $this->warn("Exception Handler not found.");
            return;
        }

        // Create fresh handler with AllStak
        $handlerWithAllStak = '<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;
use AllStak\AllStakClient;

class Handler extends ExceptionHandler
{
    protected $levels = [];
    
    protected $dontReport = [];
    
    protected $dontFlash = [
        \'current_password\',
        \'password\',
        \'password_confirmation\',
    ];

    public function register()
    {
        $this->reportable(function (Throwable $e) {
            app(AllStakClient::class)->captureException($e);
        });
    }
}
';

        file_put_contents($handlerPath, $handlerWithAllStak);
        chmod($handlerPath, 0644);
        clearstatcache(true, $handlerPath);

        $this->info('✅ Patched Exception Handler for AllStak');
    }

    private function aggressiveCacheClear()
    {
        $this->info('🔄 Clearing all caches...');

        // Clear opcache FIRST
        if (function_exists('opcache_reset')) {
            opcache_reset();
        }

        // Clear Laravel caches
        @shell_exec('php artisan config:clear 2>&1');
        @shell_exec('php artisan cache:clear 2>&1');
        @shell_exec('php artisan route:clear 2>&1');
        @shell_exec('php artisan view:clear 2>&1');
        @shell_exec('php artisan clear-compiled 2>&1');

        // Clear bootstrap cache
        $bootstrapCache = base_path('bootstrap/cache');
        if (File::exists($bootstrapCache)) {
            $files = File::files($bootstrapCache);
            foreach ($files as $file) {
                if ($file->getFilename() !== '.gitignore') {
                    @unlink($file->getPathname());
                }
            }
        }

        // Clear stat cache
        clearstatcache(true);

        $this->info('✅ All caches cleared');
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

                    $this->info("🔄 Preparing to remove {$name} safely...");

                    if ($name === 'Sentry') {
                        // Step 1: Create completely clean handler
                        $this->createCleanHandler();

                        // Step 2: Clear all caches
                        $this->aggressiveCacheClear();

                        // Step 3: Remove using line-by-line approach
                        $this->removeSentryFromHandler();

                        // Step 4: Clear caches again
                        $this->aggressiveCacheClear();

                        // Step 5: Remove package
                        $this->info("Removing {$package}...");
                        shell_exec("composer remove {$package} --no-scripts --no-plugins 2>&1");

                        // Step 6: Dump autoload separately
                        shell_exec("composer dump-autoload --no-scripts 2>&1");

                        // Step 7: Final cache clear
                        $this->aggressiveCacheClear();

                        $this->info("✅ Removed {$name} package safely.");
                    } else {
                        shell_exec("composer remove {$package} 2>&1");
                        $this->info("✅ Removed {$name} package.");
                    }
                } else {
                    $this->warn("⚠️  Skipped {$name} removal.");
                }
            }
        }
    }
}
