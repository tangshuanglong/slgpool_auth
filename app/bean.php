<?php
/**
 * This file is part of Swoft.
 *
 * @link     https://swoft.org
 * @document https://swoft.org/docs
 * @contact  group@swoft.org
 * @license  https://github.com/swoft-cloud/swoft/blob/master/LICENSE
 */
use App\Common\DbSelector;
use App\Process\MonitorProcess;
use Swoft\Crontab\Process\CrontabProcess;
use Swoft\Db\Pool;
use Swoft\Http\Server\HttpServer;
use Swoft\Task\Swoole\SyncTaskListener;
use Swoft\Task\Swoole\TaskListener;
use Swoft\Task\Swoole\FinishListener;
use Swoft\Rpc\Client\Client as ServiceClient;
use Swoft\Rpc\Client\Pool as ServicePool;
use Swoft\Rpc\Server\ServiceServer;
use Swoft\Http\Server\Swoole\RequestListener;
use Swoft\WebSocket\Server\WebSocketServer;
use Swoft\Server\SwooleEvent;
use Swoft\Db\Database;
use Swoft\Redis\RedisDb;

return [
    'noticeHandler'      => [
        'logFile' => '@runtime/logs/notice-%d{Y-m-d-H}.log',
    ],
    'applicationHandler' => [
        'logFile' => '@runtime/logs/error-%d{Y-m-d}.log',
    ],
    'logger'            => [
        'flushRequest' => false,
        'enable'       => true,
        'json'         => true,
    ],
    'httpServer'        => [
        'class'    => HttpServer::class,
        'port'     => 18306,
        'pidName'  => 'auth-http',
        //同时启动的服务
        'listener' => [
            'rpc' => bean('rpcServer')
        ],
        //同时启动的进程
        'process'  => [
            'code' => bean(\App\Process\CodeProcess::class),
            'config' => bean(\App\Process\ConfigProcess::class)
        ],
        //绑定事件
        'on'       => [
//            SwooleEvent::TASK   => bean(SyncTaskListener::class),  // Enable sync task
//            SwooleEvent::TASK   => bean(TaskListener::class),  // Enable task must task and finish event
//            SwooleEvent::FINISH => bean(FinishListener::class)
        ],
        //设置进程数和task进程数
        /* @see HttpServer::$setting */
        'setting' => [
//            'task_worker_num'       => 12,
//            'task_enable_coroutine' => true,
            'worker_num'            => 8,
            'open_cpu_affinity'     => 1,
            'log_file' => '/logs/web_server/auth.log'
        ],

    ],
    'httpRoute'  => [
        'class'    => HttpServer::class,
        //是否忽略url path最后的/, 默认值为true
        'ignoreLastSlash' => false,
        //是否处理 MethodNotAllowed,为了加快匹配速度，默认method不匹配也是直接抛出 Route not found 错误。如有特殊需要可以开启此选项，开启后将会抛出 Method Not Allowed 错误
        'handleMethodNotAllowed' => true,
        //动态参数路由匹配后会缓存下来，下次相同的路由将会更快的匹配命中。
        'tmpCacheNumber' => 500,
    ],
    'httpDispatcher'    => [
        // Add global http middleware
        'middlewares'      => [
            \App\Http\Middleware\BaseMiddleware::class,
            \App\Http\Middleware\FavIconMiddleware::class,
            // \Swoft\Whoops\WhoopsMiddleware::class,
            // Allow use @View tag
            //\Swoft\View\Middleware\ViewMiddleware::class,
        ],
        'afterMiddlewares' => [
            //\Swoft\Http\Server\Middleware\ValidatorMiddleware::class
        ]
    ],
    'db'                => [
        'class'    => Database::class,
        'dsn'      => config('mysql_config.db1.dsn'),
        'username' => config('mysql_config.db1.username'),
        'password' => config('mysql_config.db1.password'),
        'charset'  => 'utf8mb4',
        'prefix'   => 'bt_',
    ],
//    'db'  => [
//        'class'    => Database::class,
//        'charset'  => 'utf8mb4',
//        'prefix'   => 'bt_',
//        //'dbSelector' => bean(DbSelector::class),
//        'writes' => [
//            [
//                'dsn'      => 'mysql:dbname=cn_db;host=192.168.0.115',
//                'username' => 'root',
//                'password' => '123456',
//            ],
//        ],
//        'reads'  => [
//            [
//                'dsn'      => 'mysql:dbname=cn_db;host=192.168.0.115',
//                'username' => 'root',
//                'password' => '123456',
//            ],
//        ],
//    ],
    'db.pool' => [
        'class'    => Pool::class,
        'database' => bean('db'),
        'minActive'   => 10,
        'maxActive'   => 100,
        'maxWait'     => 0,
        'maxWaitTime' => 0,
        'maxIdleTime' => 60,
    ],
    'migrationManager'  => [
        'migrationPath' => '@database/Migration',
    ],
    'redis'             => [
        'class'    => RedisDb::class,
        'host'     => config('redis.host'),
        'port'     => config('redis.port'),
        'password'     => config('redis.password'),
        'database' => 0,
        'option'   => [
            'prefix' => '',
            'serializer' => 0
        ]
    ],
    'redis.pool'        => [
        'class' => \Swoft\Redis\Pool::class,
        'redisDb' => bean('redis'),
        'minActive' => 10,
        'MaxActive' => 50,
        'maxWait' => 0,
        'maxWaitTime' => 0,
        'maxIdleTime' => 60,
    ],
    'system'              => [
        'class'   => ServiceClient::class,
        'host'    => config('system_rpc.host'),
        'port'    => config('system_rpc.port'),
        'setting' => [
            'timeout'         =>10,
            'connect_timeout' =>2,
            'write_timeout'   => 10.0,
            'read_timeout'    => 10,
        ],
        'packet'  => bean('rpcClientPacket')
    ],
    'system.pool'         => [
        'class'  => ServicePool::class,
        'client' => bean('system'),
    ],
    'user'              => [
        'class'   => ServiceClient::class,
        'host'    => config('user_rpc.host'),
        'port'    => config('user_rpc.port'),
        'setting' => [
            'timeout'         =>10,
            'connect_timeout' =>2,
            'write_timeout'   => 10.0,
            'read_timeout'    => 10,
        ],
        'packet'  => bean('rpcClientPacket'),
        'isReconnect' => true,
    ],
    'user.pool'         => [
        'class'  => ServicePool::class,
        'client' => bean('user'),
    ],
    'rpcServer'         => [
        'class' => ServiceServer::class,
        'port'  => 18307,
    ],
    'cliRouter'         => [
        // 'disabledGroups' => ['demo', 'test'],
    ],
    'apollo' => [
        'host'    => config('app.apollo.host'),
        'port'    => config('app.apollo.port'),
        'appId'   => config('app.apollo.appId'),
        'timeout' => 6
    ]
];
