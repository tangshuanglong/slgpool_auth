<?php

namespace App\Http\Middleware;

use App\Lib\MyCode;
use App\Lib\MyCommon;
use App\Lib\MyQuit;
use App\Lib\MyRedisHelper;
use App\Rpc\Lib\VerifyInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SebastianBergmann\CodeCoverage\Report\PHP;
use Swoft\Http\Server\Contract\MiddlewareInterface;
use Swoft\Bean\Annotation\Mapping\Bean;
use Swoft\Bean\Annotation\Mapping\Inject;
use Swoft\Context\Context;
use Swoft\Rpc\Client\Annotation\Mapping\Reference;

/**
 * Class BaseMiddleware
 * 基础验证
 * @package App\Http\Middleware
 * @Bean()
 */
class BaseMiddleware implements MiddlewareInterface{

    /**
     * @Inject("MySign")
     *
     */
    private $myAuth;

    /**
     * @Inject("MyCommon")
     * @var
     */
    private $myCommon;

    /**
     * @Reference(pool="system.pool")
     * @var VerifyInterface
     */
    private $verifyService;


    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $serer_info = $request->getServerParams();
        $request_uri = $serer_info['request_uri'];
        $ip = MyCommon::get_ip($request);
        //ping接口放行
        if ($request->getMethod() == 'GET' && $request_uri == '/v1/ping/index'){
            return $handler->handle($request);
        }
        MyCommon::write_log('请求url: '.$request_uri.' 请求数据: ' . $request->getRawBody(), config('log_path'));
        $response = context()->getResponse();
        $client_type = $request->getHeaderLine('client-type');
        if (empty($client_type)){
            return $response->withStatus(400);
        }
        $device_id = '';
        if ($client_type !== 'web') {
            $device_id = $request->getHeaderLine('device-id');
            if (empty($device_id)){
                return $response->withStatus(400);
            }
        }
        $request_data = $request->input();
        $request->client_type = $client_type;
        $request->device_id = $device_id;
        $request->ip = $ip;
        //get请求不处理数据，放行
        if ($request->getMethod() == 'GET'){
            $request->params = $request_data;
            return $handler->handle($request);
        }
        //防止重复点击，引起并发
        $key = $request_uri.'/'.$ip;
        $lock_res = MyRedisHelper::lock($key, 5);
        if ($lock_res === false) {
            $json = MyQuit::returnMessage(MyCode::FREPUENT_REQUEST, '您的请求太频繁了！');
            $response = Context::mustGet()->getResponse();
            return $response->withData($json);
        }
        if (empty($request_data)){
            return $response->withStatus(400);
        }
        if ($client_type !== 'web') {
            if (!isset($request_data['timestamp']) || !isset($request_data['sign'])) {
                return $response->withStatus(400);
            }
            if (config('debug') != 1) {
                $res = $this->verifyService->verify_sign($request_data);
                if ($res === false) {
                    return $response->withStatus(403);
                }
            }
            unset($request_data['timestamp'], $request_data['sign']);
        }
        $request->params = $request_data;
        //请求时候的操作，handle后就是响应时候的操作
        $response = $handler->handle($request);
        //响应时候的操作
        //请求完成，解锁
        MyRedisHelper::unLock($key, $lock_res);
        return $response;
    }
}
