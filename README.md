# AllStak Laravel SDK

Official Laravel SDK for AllStak error tracking and monitoring by Techsea. This package provides seamless integration for error tracking and monitoring in your Laravel applications.

## Installation

You can install the package via composer:

```bash
composer require AllStak/Laravel-SDK
```

## Configuration

1. Add the following variables to your `.env` file:

```env
AllStak_API_KEY=your-api-key
AllStak_ENVIRONMENT=production
```

2. The service provider will be automatically registered thanks to Laravel's package discovery.

## Usage

### Capturing Exceptions

```php
try {
    // Your code here
} catch (\Throwable $e) {
    app(Techsea\AllStak\AllStakClient::class)->captureException($e);
}
```

### Tracking HTTP Requests

Add the middleware to your `app/Http/Kernel.php`:

```php
protected $middleware = [
    // ...
    \Techsea\AllStak\Middleware\AllStakMiddleware::class,
];
```

Or use it in specific routes:

```php
Route::middleware([\Techsea\AllStak\Middleware\AllStakMiddleware::class])->group(function () {
    // Your routes here
});
```

### Features

- Exception tracking with stack traces
- HTTP request monitoring
- System information collection
- Environment-specific configuration
- Automatic context gathering
- Error handling and logging

## Testing

```bash
composer test
```

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email support@techsea.com instead of using the issue tracker.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.