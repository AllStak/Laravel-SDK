<?php

namespace AllStak\DTO;

/**
 * ObservabilityDatabaseQueryDto
 *
 * Purpose: Capture database queries and performance
 * Used For: Automatic DB query monitoring
 * Trigger: Automatic (ORM/query interceptors)
 */
class ObservabilityDatabaseQueryDto
{
    // ============= REQUIRED FIELDS =============

    /** Query Text - The actual SQL/NoSQL query executed (max 10000 chars) */
    public string $queryText;

    /** Query Hash - Hash of normalized query for grouping (max 64 chars) */
    public string $queryHash;

    /** Query Type - SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER (max 20 chars) */
    public string $queryType;

    /** Database Name - Name of the database/schema (max 255 chars) */
    public string $databaseName;

    /** OpenTelemetry Trace ID (32 hex characters) */
    public string $traceId;

    /** OpenTelemetry Span ID (16 hex characters) */
    public string $spanId;

    /** Event timestamp - When the query was executed (ISO-8601) */
    public string $timestamp;

    // ============= QUERY DETAILS =============

    /** Table Name - Primary table accessed in query (max 255 chars) */
    public ?string $tableName = null;

    /** Execution Time (milliseconds) - Time taken to execute query */
    public ?int $executionTime = null;

    /** Rows Affected - Number of rows inserted/updated/deleted */
    public ?int $rowsAffected = null;

    /** Rows Examined - Number of rows scanned by database */
    public ?int $rowsExamined = null;

    /** Query Plan - EXPLAIN output or query execution plan (max 5000 chars) */
    public ?string $queryPlan = null;

    /** Query Parameters - Bound parameters, sanitized (max 2000 chars) */
    public ?string $parameters = null;

    // ============= CONNECTION DETAILS =============

    /** Connection ID - Database connection identifier (max 100 chars) */
    public ?string $connectionId = null;

    /** Transaction ID - Transaction identifier if query is in transaction (max 100 chars) */
    public ?string $transactionId = null;

    /** Database System - postgresql, mysql, mongodb, redis, elasticsearch (max 50 chars) */
    public ?string $dbSystem = null;

    /** Database Connection String - Credentials MUST be scrubbed (max 500 chars) */
    public ?string $dbConnectionString = null;

    // ============= SERVICE CONTEXT =============

    /** Service Name - Name of the service executing query (max 255 chars) */
    public ?string $serviceName = null;

    /** Environment - production, staging, development (max 50 chars) */
    public ?string $environment = null;

    /** User ID - Application user who triggered query (max 255 chars) */
    public ?string $userId = null;

    // ============= PERFORMANCE FLAGS =============

    /** Is Slow Query (0 or 1) - Whether query exceeded slow query threshold */
    public ?int $isSlowQuery = null;

    /** Is Cached (0 or 1) - Whether query was served from cache */
    public ?int $isCached = null;

    /** Cache Hit (0 or 1) - Alias for isCached for compatibility */
    public ?int $cacheHit = null;

    // ============= ERROR TRACKING =============

    /** Is Error (0 or 1) - Whether query execution failed */
    public ?int $isError = null;

    /** Error Code - Database-specific error code (max 50 chars) */
    public ?string $errorCode = null;

    /** Error Message - Human-readable error message from database (max 1000 chars) */
    public ?string $errorMessage = null;

    /** Error Type - Category of error (max 100 chars) */
    public ?string $errorType = null;

    /** Is Connection Error (0 or 1) - Whether error was connection-related */
    public ?int $isConnectionError = null;

    /** Is Timeout (0 or 1) - Whether query timed out */
    public ?int $isTimeout = null;

    // ============= CONNECTION POOL METRICS =============

    /** Connection Pool Size - Current size of connection pool */
    public ?int $connectionPoolSize = null;

    /** Connection Wait Time (milliseconds) - Time spent waiting for connection */
    public ?int $connectionWaitTimeMs = null;

    // ============= NETWORK/IP =============

    /** Client IP Address - IP of client that triggered query (max 45 chars for IPv6) */
    public ?string $clientIp = null;

    // ============= OPENTELEMETRY TRACING =============

    /** Parent Span ID - Parent span for hierarchy (16 hex chars) */
    public ?string $parentSpanId = null;

    /** Trace State - W3C trace state for vendor-specific data (max 512 chars) */
    public ?string $traceState = null;

    /** Trace Flags - W3C trace flags (sampled bit = 1) */
    public ?int $traceFlags = null;

    // ============= OPENTELEMETRY DATABASE SEMANTICS =============

    /** Database Operation - OpenTelemetry db.operation (max 50 chars) */
    public ?string $dbOperation = null;

    /** Database Table - OpenTelemetry db.sql.table (max 255 chars) */
    public ?string $dbTable = null;

    /** Is N+1 Query (0 or 1) - Whether this query is part of N+1 problem */
    public ?int $isN1Query = null;

    /** Query Pool Wait Time (milliseconds) - Alias for connectionWaitTimeMs */
    public ?int $queryPoolWaitMs = null;

    // ============= LEGACY/COMPATIBILITY FIELDS =============

    /** @deprecated Use queryText instead */
    public ?string $dbStatement = null;

    /** @deprecated Use databaseName instead */
    public ?string $dbName = null;

    /** Database Host */
    public ?string $dbHost = null;

    /** Database Port */
    public ?int $dbPort = null;

    /** @deprecated Use executionTime instead */
    public ?int $queryDuration = null;

    /** @deprecated Use rowsAffected instead */
    public ?int $rowsReturned = null;

    /** @deprecated Use isError instead */
    public ?bool $querySuccess = null;

    /** Session ID */
    public ?string $sessionId = null;

    /** Additional attributes */
    public ?array $attributes = null;

    public function __construct(array $data)
    {
        // ============= REQUIRED FIELDS =============
        $this->traceId = $data['traceId'];
        $this->spanId = $data['spanId'];
        $this->timestamp = $data['timestamp'];

        // Query text is required
        $this->queryText = $data['queryText'] ?? $data['dbStatement'] ?? '';

        // Query type is required
        $this->queryType = $data['queryType'] ?? $data['dbOperation'] ?? '';

        // Generate query hash if not provided (MD5 of the normalized query text)
        $this->queryHash = $data['queryHash'] ?? md5($this->queryText);

        // Database name is required
        $this->databaseName = $data['databaseName'] ?? $data['dbName'] ?? 'unknown';

        // ============= QUERY DETAILS =============
        $this->tableName = $data['tableName'] ?? null;
        $this->executionTime = $data['executionTime'] ?? $data['queryDuration'] ?? null;
        $this->rowsAffected = $data['rowsAffected'] ?? null;
        $this->rowsExamined = $data['rowsExamined'] ?? null;
        $this->queryPlan = $data['queryPlan'] ?? null;
        $this->parameters = $data['parameters'] ?? null;

        // ============= CONNECTION DETAILS =============
        $this->connectionId = $data['connectionId'] ?? null;
        $this->transactionId = $data['transactionId'] ?? null;
        $this->dbSystem = $data['dbSystem'] ?? null;
        $this->dbConnectionString = $data['dbConnectionString'] ?? null;

        // ============= SERVICE CONTEXT =============
        $this->serviceName = $data['serviceName'] ?? null;
        $this->environment = $data['environment'] ?? null;
        $this->userId = $data['userId'] ?? null;

        // ============= PERFORMANCE FLAGS =============
        $this->isSlowQuery = $data['isSlowQuery'] ?? null;
        $this->isCached = $data['isCached'] ?? null;
        $this->cacheHit = $data['cacheHit'] ?? $data['isCached'] ?? null;

        // ============= ERROR TRACKING =============
        $this->isError = $data['isError'] ?? null;
        $this->errorCode = $data['errorCode'] ?? null;
        $this->errorMessage = $data['errorMessage'] ?? null;
        $this->errorType = $data['errorType'] ?? null;
        $this->isConnectionError = $data['isConnectionError'] ?? null;
        $this->isTimeout = $data['isTimeout'] ?? null;

        // ============= CONNECTION POOL METRICS =============
        $this->connectionPoolSize = $data['connectionPoolSize'] ?? null;
        $this->connectionWaitTimeMs = $data['connectionWaitTimeMs'] ?? null;

        // ============= NETWORK/IP =============
        $this->clientIp = $data['clientIp'] ?? null;

        // ============= OPENTELEMETRY TRACING =============
        $this->parentSpanId = $data['parentSpanId'] ?? null;
        $this->traceState = $data['traceState'] ?? null;
        $this->traceFlags = $data['traceFlags'] ?? null;

        // ============= OPENTELEMETRY DATABASE SEMANTICS =============
        $this->dbOperation = $data['dbOperation'] ?? $this->queryType;
        $this->dbTable = $data['dbTable'] ?? $data['tableName'] ?? null;
        $this->isN1Query = $data['isN1Query'] ?? null;
        $this->queryPoolWaitMs = $data['queryPoolWaitMs'] ?? $data['connectionWaitTimeMs'] ?? null;

        // ============= LEGACY/COMPATIBILITY FIELDS =============
        $this->dbStatement = $data['dbStatement'] ?? $this->queryText;
        $this->dbName = $data['dbName'] ?? $this->databaseName;
        $this->dbHost = $data['dbHost'] ?? null;
        $this->dbPort = $data['dbPort'] ?? null;
        $this->queryDuration = $data['queryDuration'] ?? $this->executionTime;
        $this->rowsReturned = $data['rowsReturned'] ?? null;
        $this->querySuccess = $data['querySuccess'] ?? null;
        $this->sessionId = $data['sessionId'] ?? null;
        $this->attributes = $data['attributes'] ?? null;
    }

    public function validate(): bool
    {
        // ============= REQUIRED FIELDS VALIDATION =============

        // Query text is required and max 10000 chars
        if (empty($this->queryText)) {
            return false;
        }
        if (strlen($this->queryText) > 10000) {
            return false;
        }

        // Query hash is required and max 64 chars
        if (empty($this->queryHash)) {
            return false;
        }
        if (strlen($this->queryHash) > 64) {
            return false;
        }

        // Query type is required and max 20 chars
        if (empty($this->queryType)) {
            return false;
        }
        if (strlen($this->queryType) > 20) {
            return false;
        }

        // Database name is required and max 255 chars
        if (empty($this->databaseName)) {
            return false;
        }
        if (strlen($this->databaseName) > 255) {
            return false;
        }

        // Trace ID format (32 hex characters)
        if (!preg_match('/^[a-f0-9]{32}$/', $this->traceId)) {
            return false;
        }

        // Span ID format (16 hex characters)
        if (!preg_match('/^[a-f0-9]{16}$/', $this->spanId)) {
            return false;
        }

        // ============= OPTIONAL FIELDS VALIDATION =============

        // Table name max 255 chars
        if ($this->tableName !== null && strlen($this->tableName) > 255) {
            return false;
        }

        // Execution time cannot be negative
        if ($this->executionTime !== null && $this->executionTime < 0) {
            return false;
        }

        // Rows affected cannot be negative
        if ($this->rowsAffected !== null && $this->rowsAffected < 0) {
            return false;
        }

        // Rows examined cannot be negative
        if ($this->rowsExamined !== null && $this->rowsExamined < 0) {
            return false;
        }

        // Query plan max 5000 chars
        if ($this->queryPlan !== null && strlen($this->queryPlan) > 5000) {
            return false;
        }

        // Parameters max 2000 chars
        if ($this->parameters !== null && strlen($this->parameters) > 2000) {
            return false;
        }

        // Connection ID max 100 chars
        if ($this->connectionId !== null && strlen($this->connectionId) > 100) {
            return false;
        }

        // Transaction ID max 100 chars
        if ($this->transactionId !== null && strlen($this->transactionId) > 100) {
            return false;
        }

        // Database system max 50 chars
        if ($this->dbSystem !== null && strlen($this->dbSystem) > 50) {
            return false;
        }

        // Database connection string max 500 chars
        if ($this->dbConnectionString !== null && strlen($this->dbConnectionString) > 500) {
            return false;
        }

        // Service name max 255 chars
        if ($this->serviceName !== null && strlen($this->serviceName) > 255) {
            return false;
        }

        // Environment max 50 chars
        if ($this->environment !== null && strlen($this->environment) > 50) {
            return false;
        }

        // User ID max 255 chars
        if ($this->userId !== null && strlen($this->userId) > 255) {
            return false;
        }

        // Performance flags (0 or 1)
        if ($this->isSlowQuery !== null && ($this->isSlowQuery < 0 || $this->isSlowQuery > 1)) {
            return false;
        }
        if ($this->isCached !== null && ($this->isCached < 0 || $this->isCached > 1)) {
            return false;
        }
        if ($this->cacheHit !== null && ($this->cacheHit < 0 || $this->cacheHit > 1)) {
            return false;
        }

        // Error flags (0 or 1)
        if ($this->isError !== null && ($this->isError < 0 || $this->isError > 1)) {
            return false;
        }
        if ($this->isConnectionError !== null && ($this->isConnectionError < 0 || $this->isConnectionError > 1)) {
            return false;
        }
        if ($this->isTimeout !== null && ($this->isTimeout < 0 || $this->isTimeout > 1)) {
            return false;
        }

        // Error code max 50 chars
        if ($this->errorCode !== null && strlen($this->errorCode) > 50) {
            return false;
        }

        // Error message max 1000 chars
        if ($this->errorMessage !== null && strlen($this->errorMessage) > 1000) {
            return false;
        }

        // Error type max 100 chars
        if ($this->errorType !== null && strlen($this->errorType) > 100) {
            return false;
        }

        // Connection pool size cannot be negative
        if ($this->connectionPoolSize !== null && $this->connectionPoolSize < 0) {
            return false;
        }

        // Connection wait time cannot be negative
        if ($this->connectionWaitTimeMs !== null && $this->connectionWaitTimeMs < 0) {
            return false;
        }

        // Client IP max 45 chars (IPv6)
        if ($this->clientIp !== null && strlen($this->clientIp) > 45) {
            return false;
        }

        // Parent span ID format (16 hex chars)
        if ($this->parentSpanId !== null && !preg_match('/^[a-f0-9]{16}$/', $this->parentSpanId)) {
            return false;
        }

        // Trace state max 512 chars
        if ($this->traceState !== null && strlen($this->traceState) > 512) {
            return false;
        }

        // Trace flags (0-255)
        if ($this->traceFlags !== null && ($this->traceFlags < 0 || $this->traceFlags > 255)) {
            return false;
        }

        // DB operation max 50 chars
        if ($this->dbOperation !== null && strlen($this->dbOperation) > 50) {
            return false;
        }

        // DB table max 255 chars
        if ($this->dbTable !== null && strlen($this->dbTable) > 255) {
            return false;
        }

        // Is N+1 query (0 or 1)
        if ($this->isN1Query !== null && ($this->isN1Query < 0 || $this->isN1Query > 1)) {
            return false;
        }

        // Query pool wait time cannot be negative
        if ($this->queryPoolWaitMs !== null && $this->queryPoolWaitMs < 0) {
            return false;
        }

        // Legacy fields validation
        if ($this->dbStatement !== null && strlen($this->dbStatement) > 10000) {
            return false;
        }
        if ($this->queryDuration !== null && $this->queryDuration < 0) {
            return false;
        }
        if ($this->rowsReturned !== null && $this->rowsReturned < 0) {
            return false;
        }

        return true;
    }

    public function toArray(): array
    {
        $data = [
            // Required fields
            'queryText' => $this->queryText,
            'queryHash' => $this->queryHash,
            'queryType' => $this->queryType,
            'databaseName' => $this->databaseName,
            'traceId' => $this->traceId,
            'spanId' => $this->spanId,
            'timestamp' => $this->timestamp,
        ];

        // Query details
        if ($this->tableName !== null) $data['tableName'] = $this->tableName;
        if ($this->executionTime !== null) $data['executionTime'] = $this->executionTime;
        if ($this->rowsAffected !== null) $data['rowsAffected'] = $this->rowsAffected;
        if ($this->rowsExamined !== null) $data['rowsExamined'] = $this->rowsExamined;
        if ($this->queryPlan !== null) $data['queryPlan'] = $this->queryPlan;
        if ($this->parameters !== null) $data['parameters'] = $this->parameters;

        // Connection details
        if ($this->connectionId !== null) $data['connectionId'] = $this->connectionId;
        if ($this->transactionId !== null) $data['transactionId'] = $this->transactionId;
        if ($this->dbSystem !== null) $data['dbSystem'] = $this->dbSystem;
        if ($this->dbConnectionString !== null) $data['dbConnectionString'] = $this->dbConnectionString;

        // Service context
        if ($this->serviceName !== null) $data['serviceName'] = $this->serviceName;
        if ($this->environment !== null) $data['environment'] = $this->environment;
        if ($this->userId !== null) $data['userId'] = $this->userId;

        // Performance flags
        if ($this->isSlowQuery !== null) $data['isSlowQuery'] = $this->isSlowQuery;
        if ($this->isCached !== null) $data['isCached'] = $this->isCached;
        if ($this->cacheHit !== null) $data['cacheHit'] = $this->cacheHit;

        // Error tracking
        if ($this->isError !== null) $data['isError'] = $this->isError;
        if ($this->errorCode !== null) $data['errorCode'] = $this->errorCode;
        if ($this->errorMessage !== null) $data['errorMessage'] = $this->errorMessage;
        if ($this->errorType !== null) $data['errorType'] = $this->errorType;
        if ($this->isConnectionError !== null) $data['isConnectionError'] = $this->isConnectionError;
        if ($this->isTimeout !== null) $data['isTimeout'] = $this->isTimeout;

        // Connection pool metrics
        if ($this->connectionPoolSize !== null) $data['connectionPoolSize'] = $this->connectionPoolSize;
        if ($this->connectionWaitTimeMs !== null) $data['connectionWaitTimeMs'] = $this->connectionWaitTimeMs;

        // Network/IP
        if ($this->clientIp !== null) $data['clientIp'] = $this->clientIp;

        // OpenTelemetry tracing
        if ($this->parentSpanId !== null) $data['parentSpanId'] = $this->parentSpanId;
        if ($this->traceState !== null) $data['traceState'] = $this->traceState;
        if ($this->traceFlags !== null) $data['traceFlags'] = $this->traceFlags;

        // OpenTelemetry database semantics
        if ($this->dbOperation !== null) $data['dbOperation'] = $this->dbOperation;
        if ($this->dbTable !== null) $data['dbTable'] = $this->dbTable;
        if ($this->isN1Query !== null) $data['isN1Query'] = $this->isN1Query;
        if ($this->queryPoolWaitMs !== null) $data['queryPoolWaitMs'] = $this->queryPoolWaitMs;

        // Legacy/compatibility fields
        if ($this->dbStatement !== null) $data['dbStatement'] = $this->dbStatement;
        if ($this->dbName !== null) $data['dbName'] = $this->dbName;
        if ($this->dbHost !== null) $data['dbHost'] = $this->dbHost;
        if ($this->dbPort !== null) $data['dbPort'] = $this->dbPort;
        if ($this->queryDuration !== null) $data['queryDuration'] = $this->queryDuration;
        if ($this->rowsReturned !== null) $data['rowsReturned'] = $this->rowsReturned;
        if ($this->querySuccess !== null) $data['querySuccess'] = $this->querySuccess;
        if ($this->sessionId !== null) $data['sessionId'] = $this->sessionId;
        if ($this->attributes !== null) $data['attributes'] = $this->attributes;

        return $data;
    }
}

