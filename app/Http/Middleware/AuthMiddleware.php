<?php
namespace App\Http\Middleware;

use App\Lib\MyCode;
use App\Lib\MyCommon;
use App\Lib\MyQuit;
use App\Model\Data\UserData;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Swoft\Bean\Annotation\Mapping\Bean;
use Swoft\Context\Context;

/**
 * Class AuthMiddleware
 * 验证登录
 * @package App\Http\Middleware
 * @Bean()
 */
class AuthMiddleware implements MiddlewareInterface{


    /**
     * Process an incoming server request.
     *
     * Processes an incoming server request in order to produce a response.
     * If unable to produce the response itself, it may delegate to the provided
     * request handler to do so.
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws \Swoft\Db\Exception\DbException
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $request->getHeaderLine('token');
        if (empty($token)){
            $json_data = MyQuit::returnMessage(MyCode::USER_NOT_LOGIN, '未登录');
            $response = Context::mustGet()->getResponse();
            return $response->withData($json_data);
        }
        //验证登录
        $res_data = UserData::verify_login($token, $request->client_type, $request->device_id);
        if ($res_data == false) {
            $json_data = MyQuit::returnMessage(MyCode::LOGIN_EXPIRE, '登录已过期');
            $response = Context::mustGet()->getResponse();
            return $response->withData($json_data);
        }
        //保存登录信息
        $request->user_info = $res_data;
        $request->uid = $res_data['id'];
        $request->account = $res_data['account'];
        return $handler->handle($request);
    }

}
