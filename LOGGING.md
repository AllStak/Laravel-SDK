# AllStak Laravel Logging Integration

The AllStak SDK provides seamless integration with Laravel's logging system, allowing you to send application logs directly to the AllStak backend for centralized monitoring and analysis.

## Configuration

### 1. Add AllStak Log Channel to `config/logging.php`

Add the AllStak channel to your Laravel logging configuration:

```php
'channels' => [
    // ... existing channels

    'allstak' => [
        'driver' => 'allstak',
        'level' => env('LOG_LEVEL', 'debug'),
        'api_key' => env('ALLSTAK_API_KEY'),
        'environment' => env('ALLSTAK_ENV', 'production'),
        'service_name' => env('ALLSTAK_SERVICE_NAME', 'laravel-app'),
    ],
],
```

### 2. Environment Variables

Add these variables to your `.env` file:

```env
ALLSTAK_API_KEY=your_api_key_here
ALLSTAK_ENV=production
ALLSTAK_SERVICE_NAME=my-laravel-app
```

### 3. Using AllStak as Default Log Channel

To use AllStak as your default logging channel, update your `.env`:

```env
LOG_CHANNEL=allstak
```

Or use it alongside other channels in a stack:

```php
'channels' => [
    'stack' => [
        'driver' => 'stack',
        'channels' => ['single', 'allstak'],
        'ignore_exceptions' => false,
    ],
],
```

## Usage

### Basic Logging

Once configured, use Laravel's standard logging methods:

```php
use Illuminate\Support\Facades\Log;

// Different log levels
Log::debug('Debug message', ['user_id' => 123]);
Log::info('User logged in', ['user_id' => 123, 'ip' => '192.168.1.1']);
Log::warning('High memory usage detected', ['memory' => '85%']);
Log::error('Database connection failed', ['error' => $exception->getMessage()]);
```

### Contextual Logging

Add context data that will be sent to AllStak:

```php
Log::info('Order processed', [
    'order_id' => 12345,
    'user_id' => 67890,
    'amount' => 99.99,
    'payment_method' => 'credit_card'
]);
```

### Trace Correlation

To correlate logs with traces, include a `trace_id` in the context:

```php
Log::info('Processing payment', [
    'trace_id' => $traceId,
    'order_id' => 12345
]);
```

### Channel-Specific Logging

Log directly to the AllStak channel:

```php
Log::channel('allstak')->info('This goes only to AllStak', [
    'custom_data' => 'value'
]);
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `driver` | Must be set to `'allstak'` | Required |
| `level` | Minimum log level to send | `'debug'` |
| `api_key` | Your AllStak API key | From config/env |
| `environment` | Environment name | `'production'` |
| `service_name` | Service identifier | `'laravel-app'` |

## Log Data Structure

Each log entry sent to AllStak includes:

- **trace_id**: Correlation ID for tracing
- **level**: Log level (debug, info, warning, error)
- **message**: The log message
- **context**: Additional context data
- **timestamp**: ISO 8601 timestamp
- **service_name**: Your service identifier
- **environment**: Environment name
- **user_id**: Current authenticated user ID (if available)
- **session_id**: Laravel session ID
- **request_id**: X-Request-ID header value
- **process_id**: PHP process ID
- **hostname**: Server hostname
- **sdk_version**: AllStak SDK version
- **sdk_language**: 'php'
- **sdk_platform**: 'laravel'
- **php_version**: PHP version
- **laravel_version**: Laravel version

## Best Practices

### 1. Use Appropriate Log Levels

```php
// Use debug for development information
Log::debug('Cache miss for key: ' . $key);

// Use info for general application flow
Log::info('User registration completed', ['user_id' => $user->id]);

// Use warning for concerning but non-critical issues
Log::warning('API rate limit approaching', ['remaining' => 10]);

// Use error for actual errors
Log::error('Payment processing failed', ['error' => $e->getMessage()]);
```

### 2. Include Relevant Context

```php
// Good: Includes relevant context
Log::info('Order created', [
    'order_id' => $order->id,
    'user_id' => $order->user_id,
    'total' => $order->total,
    'items_count' => $order->items->count()
]);

// Avoid: Too much unnecessary data
Log::info('Order created', $order->toArray()); // May include sensitive data
```

### 3. Avoid Logging Sensitive Information

The AllStak SDK automatically sanitizes common sensitive patterns, but be mindful:

```php
// Good: Log relevant non-sensitive data
Log::info('Payment processed', [
    'order_id' => $order->id,
    'amount' => $order->total,
    'payment_method' => 'credit_card'
]);

// Avoid: Logging sensitive data
Log::info('Payment processed', [
    'credit_card_number' => $card->number, // Will be sanitized
    'cvv' => $card->cvv // Will be sanitized
]);
```

## Troubleshooting

### Logs Not Appearing in AllStak

1. Check your API key is correct
2. Verify the AllStak service is enabled in config
3. Check Laravel logs for AllStak-related errors
4. Ensure your log level allows the messages you're sending

### Performance Considerations

- AllStak logging uses asynchronous transport by default
- Logs are sent in the background and won't block your application
- Failed log transmissions are logged to Laravel's default log channel

### Testing

To test your AllStak logging configuration:

```php
// In a controller or artisan command
Log::channel('allstak')->info('Test log from AllStak integration', [
    'test' => true,
    'timestamp' => now()
]);
```

Check your AllStak dashboard to verify the log appears.