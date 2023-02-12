<?php declare(strict_types=1);
/**
 * This file is part of Swoft.
 *
 * @link     https://swoft.org
 * @document https://swoft.org/docs
 * @contact  group@swoft.org
 * @license  https://github.com/swoft-cloud/swoft/blob/master/LICENSE
 */

namespace App\Listener;

use Swoft\Bean\Annotation\Mapping\Inject;
use Swoft\Consul\Agent;
use Swoft\Event\Annotation\Mapping\Listener;
use Swoft\Event\EventHandlerInterface;
use Swoft\Event\EventInterface;
use Swoft\Http\Server\HttpServer;
use Swoft\Log\Helper\CLog;
use Swoft\Server\SwooleEvent;

/**
 * Class RegisterServiceListener
 *
 * @since 2.0
 *
 * @Listener(event=SwooleEvent::START)
 */
class RegisterServiceListener implements EventHandlerInterface
{
    /**
     * @Inject()
     *
     * @var Agent
     */
    private $agent;

    /**
     * @param EventInterface $event
     */
    public function handle(EventInterface $event): void
    {
        /** @var HttpServer $httpServer */
        $httpServer = $event->getTarget();
        $consul = config('app.consul');
        $service = [
            'ID'                => $consul['id'],
            'Name'              => $consul['name'],
            'Tags'              => [
                'http'
            ],
            'Address'           => $consul['address'],
            'Port'              => $consul['port'],
            'Meta'              => [
                'version' => '1.0'
            ],
            'EnableTagOverride' => false,
            'Weights'           => [
                'Passing' => 10,
                'Warning' => 1,
                //'WeightsValue' => 1,
            ],
            'Checks' => [
                [
                    'http' => 'http://'.$consul['address'].':'.$consul['port'].'/v1/ping/index',
                    'tls_skip_verify' => false,
                    'method' => 'GET',
                    'interval' => '10s',
                    'timeout' => '2s'
                ]
            ]
        ];

        // Register
        $this->agent->registerService($service);
        CLog::info('Swoft http register service success by consul!');
    }
}
