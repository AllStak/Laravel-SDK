<?php

namespace AllStak\Tracing;
use AllStak\AllStakClient;

class JobSpanRecorder
{
    protected AllStakClient $client;
    public function recordJobStart(string $jobName): array
    {
        return $this->client->startSpan('job.process', $jobName, [
            'job.name' => $jobName,
            'queue.name' => Queue::getConnectionName(),
        ]);
    }
}
