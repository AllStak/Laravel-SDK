<?php

namespace AllStak\Logging;

use AllStak\AllStakClient;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Logger;
use Monolog\LogRecord;

class AllStakLogHandler extends AbstractProcessingHandler
{
    private AllStakClient $client;

    public function __construct(AllStakClient $client, $level = Logger::DEBUG, bool $bubble = true)
    {
        parent::__construct($level, $bubble);
        $this->client = $client;
    }

    /**
     * Write log record to AllStak
     *
     * @param array|LogRecord $record
     * @return void
     */
    protected function write($record): void
    {
        // Handle both old array format and new LogRecord format
        if ($record instanceof LogRecord) {
            $level = $record->level->getName();
            $message = $record->message;
            $context = $record->context;
        } else {
            $level = $record['level_name'] ?? 'INFO';
            $message = $record['message'] ?? '';
            $context = $record['context'] ?? [];
        }

        // Map Monolog level to our level format
        $levelMap = [
            'DEBUG' => 'debug',
            'INFO' => 'info',
            'NOTICE' => 'info',
            'WARNING' => 'warn',
            'ERROR' => 'error',
            'CRITICAL' => 'fatal',
            'ALERT' => 'fatal',
            'EMERGENCY' => 'fatal',
        ];

        $mappedLevel = $levelMap[$level] ?? 'info';

        try {
            $this->client->log($mappedLevel, $message, $context);
        } catch (\Exception $e) {
            error_log('AllStak: Failed to send log: ' . $e->getMessage());
        }
    }
}

