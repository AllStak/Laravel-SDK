<?php

namespace AllStak\DTO;

/**
 * TelemetryBatchDto
 *
 * Purpose: Batch multiple events in a single request
 * Used For: Efficient bulk ingestion
 * Trigger: Automatic (batch flushing)
 */
class TelemetryBatchDto
{
    public array $logs = [];
    public array $errors = [];
    public array $requests = [];
    public array $queries = [];
    public array $spans = [];

    public function addLog(ObservabilityApplicationLogDto $log): void
    {
        $this->logs[] = $log->toArray();
    }

    public function addError(ObservabilityErrorEventDto $error): void
    {
        $this->errors[] = $error->toArray();
    }

    public function addRequest(ObservabilityHttpRequestDto $request): void
    {
        $this->requests[] = $request->toArray();
    }

    public function addQuery(ObservabilityDatabaseQueryDto $query): void
    {
        $this->queries[] = $query->toArray();
    }

    public function addSpan(ObservabilitySpanDto $span): void
    {
        $this->spans[] = $span->toArray();
    }

    public function isEmpty(): bool
    {
        return empty($this->logs) &&
               empty($this->errors) &&
               empty($this->requests) &&
               empty($this->queries) &&
               empty($this->spans);
    }

    public function toArray(): array
    {
        return [
            'logs' => $this->logs,
            'errors' => $this->errors,
            'requests' => $this->requests,
            'queries' => $this->queries,
            'spans' => $this->spans,
        ];
    }
}

