<?php

namespace App\Process;

use App\Lib\MyCommon;
use Swoft\Apollo\Config;
use Swoft\Bean\Annotation\Mapping\Bean;
use Swoft\Co;
use Swoft\Http\Server\HttpServer;
use Swoft\Log\Helper\CLog;
use Swoft\Process\Process;
use Swoft\Process\UserProcess;
use Swoft\Rpc\Server\ServiceServer;
use Swoft\WebSocket\Server\WebSocketServer;
use Swoft\Bean\Annotation\Mapping\Inject;

/**
 * Class CodeProcess
 * @package App\Process
 * @Bean()
 */
class CodeProcess extends UserProcess {

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
            'MyCode'
        ];

        while (true) {
            try {
                $this->config->listen($namespaces, [$this, 'updateFile']);
            } catch (Throwable $e) {
                CLog::error('Config code fail(%s %s %d)!', $e->getMessage(), $e->getFile(), $e->getLine());
                sleep(10);
            }
        }
    }

    /**
     * @param array $data
     */
    public function updateFile(array $data)
    {
        foreach ($data as $namespace => $namespaceData) {
            $configFile = sprintf('@app/Lib/%s.php', $namespace);

            $configKVs = $namespaceData['configurations'] ?? '';
            asort($configKVs);
            $content   = "<?php \n\n namespace App\Lib; \n\n/**
    *   功能模块状态码
    *   基础类别状态码为0000-1000，统一4位，不足4位前面补零
    *   法币交易功能状态码为2000-2999
    *   币币交易功能状态码为3000-3999
    *   用户信息功能状态码为4000-4999
    *   登录，注册，修改密码，google验证码，二步登录，交易密码等安全类别统一用5000-5999
    *   其他功能类别统一用7000-7999
    *   8000以后的留着备用，以后有后续功能可以往后添加
    **/ \n class MyCode{ \n\n";
            foreach ($configKVs as $key => $val) {
                $content .= "    CONST ".$key." = '".$val."';\n\n";
            }
            $content   .= "\n}";
            Co::writeFile(alias($configFile), $content, FILE_NO_DEFAULT_CONTEXT);

            CLog::info('MyCode update success！');

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
