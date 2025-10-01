<?php
namespace AllStak\Listeners;

use Illuminate\Database\Events\QueryExecuted;
use AllStak\AllStakClient;

class QuerySpanLogger
{
    public function handle(QueryExecuted $event): void
    {
        if (!app()->bound(AllStakClient::class)) return;

        $client = app(AllStakClient::class);

        $sql = str_replace(["\n", "\r", "\t"], ' ', $event->sql);

        $client->addSpan('DB Query', LARAVEL_START + ($event->time / 1000), LARAVEL_START + ($event->time / 1000), [
            'sql' => $sql,
            'time_ms' => $event->time,
            'bindings' => $event->bindings,
            'connection' => $event->connectionName,
        ]);
    }
}
