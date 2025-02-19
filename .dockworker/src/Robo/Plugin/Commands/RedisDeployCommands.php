<?php

namespace Dockworker\Robo\Plugin\Commands;

use Dockworker\DockworkerDaemonCommands;

/**
 * Provides commands for building and deploying the Redis application.
 */
class RedisDeployCommands extends DockworkerDaemonCommands
{
    /**
     * Provides error log trigers and exceptions for the redis application.
     *
     * @hook on-event dockworker-logs-errors-exceptions
     *
     * @return mixed[]
     *   The error log exceptions.
     */
    public function provideErrorLogConfiguration(): array
    {
        return [
            [],
            array_values(
                [
                    'Module, not an error.' => 'WARNING Memory overcommit must be enabled',
                ]
            ),
        ];
    }
}