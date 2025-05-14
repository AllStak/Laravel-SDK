<?php
namespace Techsea\AllStack\Listeners;

use Illuminate\Database\Events\QueryExecuted;
use Techsea\AllStack\AllStackClient;

class QuerySpanLogger
{
    public function handle(QueryExecuted $event): void
    {
        if (!app()->bound(AllStackClient::class)) return;

        $client = app(AllStackClient::class);

        $sql = str_replace(["\n", "\r", "\t"], ' ', $event->sql);

        $client->addSpan('DB Query', LARAVEL_START + ($event->time / 1000), LARAVEL_START + ($event->time / 1000), [
            'sql' => $sql,
            'time_ms' => $event->time,
            'bindings' => $event->bindings,
            'connection' => $event->connectionName,
        ]);
    }
}
