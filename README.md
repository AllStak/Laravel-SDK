# AllStak Laravel SDK v2.0
Official Laravel SDK for AllStak Observability Platform - Complete error tracking, performance monitoring, and distributed tracing for Laravel applications.
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](CHANGELOG.md)
[![PHP](https://img.shields.io/badge/PHP-%3E%3D7.4-purple.svg)](composer.json)
[![Laravel](https://img.shields.io/badge/Laravel-5.0--12.0-red.svg)](composer.json)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)
## ✨ Features
### Automatic Monitoring (Zero Code Required!)
- ✅ **HTTP Request Tracking** - All requests/responses with full context
- ✅ **Error & Exception Capture** - Stack traces, context, user info
- ✅ **Database Query Monitoring** - SQL queries with execution time
- ✅ **Application Logging** - All Laravel logs automatically captured
- ✅ **Distributed Tracing** - OpenTelemetry-compliant trace propagation
### Manual Instrumentation
- 📊 **Custom Spans** - Monitor performance of any operation
- 🔍 **Custom Logging** - Log with rich context and attributes
- ⚡ **Error Reporting** - Report handled errors with context
- 🎯 **Query Tracking** - Track custom database operations
### Performance & Privacy
- 🚀 **Event Batching** - Efficient batching with compression (70-80% reduction)
- 🔐 **Privacy Controls** - IP anonymization, header scrubbing
- ⚙️ **Sampling** - Control data volume and costs
- 🎛️ **Path Exclusion** - Exclude health checks and metrics
## 📦 Quick Start
### 1. Install
```bash
composer require allstak/laravel-sdk
```
### 2. Publish Configuration
```bash
php artisan vendor:publish --tag=allstak-config
```
### 3. Configure Environment
Add to your `.env`:
```env
ALLSTAK_API_KEY=your-api-key-here
ALLSTAK_PROJECT_ID=your-project-uuid
ALLSTAK_ENV=production
```
### 4. Start Monitoring! 🎉
**That's it!** AllStak now automatically monitors:
- All HTTP requests and responses
- All exceptions and errors
- All database queries
- All application logs
## 🚀 Usage
### Automatic Monitoring
No code needed! Once configured, AllStak automatically captures everything.
### Manual Instrumentation
```php
use AllStak\Facades\AllStak;
// Log anything
AllStak::log('info', 'User logged in', [
    'user_id' => auth()->id(),
    'timestamp' => now()->toDateTimeString(),
]);
// Track errors
try {
    $this->riskyOperation();
} catch (\Exception $e) {
    AllStak::captureError($e, request(), [
        'handled' => true,
        'operation' => 'riskyOperation',
    ]);
}
// Monitor performance
$span = AllStak::startSpan('payment_processing');
$result = $this->processPayment($order);
$span['attributes']['order_id'] = $order->id;
AllStak::endSpan($span, 'OK');
// Force immediate send
AllStak::flush();
```
### Quick Test
```php
Route::get('/test-allstak', function() {
    AllStak::log('info', 'AllStak is working!', ['test' => true]);
    AllStak::flush();
    return 'Check your AllStak dashboard!';
});
```
## 📚 Documentation
### Core Documentation
- **[Complete Usage Guide](USAGE_GUIDE.md)** - Comprehensive documentation (start here!)
- **[How to Use](HOW_TO_USE.md)** - Quick reference and summary
- **[API Documentation](README-API.md)** - API endpoint reference
- **[Code Examples](examples.php)** - Practical code examples
### Additional Resources
- **[Testing Guide](TESTING.md)** - Test the SDK in a Laravel app
- **[Changelog](CHANGELOG.md)** - Version history
- **[Migration Guide](MIGRATION.md)** - Upgrading from v1.x
- **[Logging Guide](LOGGING.md)** - Laravel logging integration
## ⚙️ Configuration
### Essential Settings
```env
# Authentication
ALLSTAK_API_KEY=your-api-key
ALLSTAK_PROJECT_ID=your-project-id
# Features (all default to true)
ALLSTAK_CAPTURE_HTTP=true
ALLSTAK_CAPTURE_ERRORS=true
ALLSTAK_CAPTURE_LOGS=true
ALLSTAK_CAPTURE_DATABASE=true
# Performance
ALLSTAK_SAMPLE_RATE=1.0         # 0.0 to 1.0 (1.0 = 100%)
ALLSTAK_BATCH_SIZE=100
ALLSTAK_FLUSH_INTERVAL=5000     # milliseconds
# Privacy
ALLSTAK_ANONYMIZE_IP=false
ALLSTAK_SCRUB_HEADERS="Authorization,Cookie"
ALLSTAK_EXCLUDED_PATHS="/health,/metrics"
```
See **[config/AllStakConfig.php](config/AllStakConfig.php)** for all options.
## 🔍 What Gets Captured?
### HTTP Requests
- Method, URL, headers, body
- Response status, headers, body
- Duration, client IP, user agent
- Session and user information
### Errors & Exceptions
- Exception type and message
- Stack trace with file/line numbers
- Request context
- User and session data
### Database Queries
- SQL statements (parameterized)
- Query bindings (separately)
- Execution time
- Success/failure status
### Application Logs
- Log level (debug, info, warn, error)
- Message and context
- Timestamp and trace ID
- File and line number
### Custom Spans
- Operation name and duration
- Parent-child relationships
- Custom attributes
- Success/error status
## 🛠️ Requirements
- **PHP:** >= 7.4
- **Laravel:** 5.0 - 12.0
- **Symfony HTTP Client:** >= 4.4
- **Monolog:** >= 1.25
## 🧪 Testing
Run the standalone test suite:
```bash
php test_suite.php
```
Or see **[TESTING.md](TESTING.md)** for testing in a Laravel app.
## 🔐 Privacy & Security
### IP Address Control
```env
ALLSTAK_ANONYMIZE_IP=true  # Mask last octet
ALLSTAK_SEND_CLIENT_IP=false  # Don't send at all
```
### Header Scrubbing
Sensitive headers are automatically redacted:
```env
ALLSTAK_SCRUB_HEADERS="Authorization,Cookie,X-API-Key"
```
### SQL Safety
Query bindings are sent separately, never interpolated into SQL strings.
## 📊 API Reference
### Main Methods
```php
// Error tracking
AllStak::captureError(Throwable $e, ?Request $request, array $context): bool
// Logging
AllStak::log(string $level, string $message, array $attributes): bool
// Performance monitoring
AllStak::startSpan(string $name, ?string $parentSpanId): array
AllStak::endSpan(array $span, string $status, ?string $message): bool
// Database tracking
AllStak::captureQuery(string $sql, array $bindings, float $duration, 
                     string $connection, bool $success, ?string $error): bool
// Batch management
AllStak::flush(): bool
// ID generation
AllStak::generateTraceId(): string  // 32-char hex (OpenTelemetry)
AllStak::generateSpanId(): string   // 16-char hex (OpenTelemetry)
```
## 🐛 Troubleshooting
### No Events Appearing?
1. **Check configuration:**
```bash
php artisan tinker
>>> config('allstak.api_key')
>>> config('allstak.enabled')
```
2. **Test connectivity:**
```bash
curl -X POST http://localhost:8080/api/v2/ingest/batch \
  -H "x-api-key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"logs":[],"errors":[],"requests":[],"queries":[],"spans":[]}'
```
3. **Force flush:**
```php
AllStak::log('test', 'Test message');
AllStak::flush();
```
See **[USAGE_GUIDE.md](USAGE_GUIDE.md#troubleshooting)** for more help.
## 📝 Version Information
**Current Version:** 2.0.0  
**Release Date:** November 14, 2025  
**API Version:** v2  
**Authentication:** x-api-key header  
**Endpoint:** /api/v2/ingest/batch
## 🤝 Support
- **Documentation:** [USAGE_GUIDE.md](USAGE_GUIDE.md)
- **Examples:** [examples.php](examples.php)
- **Issues:** Report bugs and request features
- **Email:** support@allstak.io
## 📄 License
MIT License - See [LICENSE.md](LICENSE.md) for details
---
**Made with ❤️ by the AllStak Team**
