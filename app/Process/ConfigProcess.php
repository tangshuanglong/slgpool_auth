<?php

namespace App\Process;

use App\Lib\MyCommon;
use Swoft\Apollo\Config;
use Swoft\Bean\Annotation\Mapping\Bean;
use Swoft\Co;
use Swoft\Exception\SwoftException;
use Swoft\Http\Server\HttpServer;
use Swoft\Log\Helper\CLog;
use Swoft\Process\Process;
use Swoft\Process\UserProcess;
use Swoft\Rpc\Server\ServiceServer;
use Swoft\WebSocket\Server\WebSocketServer;
use Swoft\Bean\Annotation\Mapping\Inject;

/**
 * Class ConfigProcess
 * @package App\Process
 * @Bean()
 */
class ConfigProcess extends UserProcess{

    /**
     * @Inject()
     *
     * @var Config
     */
    private $config;

    /**
     * @Inject()
     *
     * @var MyCommon
     */
    private $myCommon;

    /**
     * Run
     *
     * @param Process $process
     */
    public function run(Process $process): void
    {
        $namespaces = [
            'base',
            'mysql_config'
        ];

        while (true) {
            try {
                $this->config->listen($namespaces, [$this, 'updateFile']);
            } catch (Throwable $e) {
                CLog::error('Config agent fail(%s %s %d)!', $e->getMessage(), $e->getFile(), $e->getLine());
                sleep(10);
            }
        }
    }

    /**
     * @param array $data
     *
     * @throws SwoftException
     */
    public function updateFile(array $data): void
    {
        foreach ($data as $namespace => $namespaceData) {
            $configFile = sprintf('@config/%s.php', $namespace);

            $configKVs = $namespaceData['configurations'] ?? '';
            ksort($configKVs);
            foreach ($configKVs as $key => $val) {
                $data = json_decode($val, true);
                if (JSON_ERROR_NONE === json_last_error()) {
                    $configKVs[$key] = $data;
                }
                unset($val, $data, $key);
            }
            $content   = '<?php return ' . var_export($configKVs, true) . ';';
            Co::writeFile(alias($configFile), $content, FILE_NO_DEFAULT_CONTEXT);

            CLog::info($namespace.' update success！');

//            /** @var HttpServer $server */
//            $server = bean('httpServer');
//            $server->restart();
//
//            /** @var ServiceServer $server */
//            $server = bean('rpcServer');
//            $server->restart();

            /** @var WebSocketServer $server */
//            $server = bean('wsServer');
//            $server->restart();
        }
    }


}
