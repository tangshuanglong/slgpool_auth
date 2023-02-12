<?php

namespace App\Lib;

use App\Lib\MyCommon;
use Swoft\Bean\Annotation\Mapping\Inject;
use Swoft\Http\Message\Request;
use Swoft\Log\Helper\CLog;

/**
 * 接口返回数据类
 */
class MyQuit {

    //状态码
    private static $statusCode = [
    //常用状态码
    '200' => 'OK',
    '201' => 'Create OK',
    '204' => 'Not Content',
    '304' => 'Not Modify',
    '400' => 'Bad Request',
    '401' => 'Unauthorized',
    '403' => 'Forbidden',
    '404' => 'Not Found',
    '405' => 'Request Not Allowed',
    '415' => 'Unsupported Media Type',
    '422' => 'Validate Failed',
    '500' => 'Server Internal Error',
    ];

    /**
     * 日志路径
     * @var string
     */
    private static $log_path = '/logs/web_log';

    /**
     * 统一返回结果
     * @param string $body 需要返回的数据
     * @param array $header 状态码和消息
     * @param int $statusCode
     * @return array
     */
    public static function returnRst($body = '', array $header = array(), int $statusCode = 200): array
    {
        $data = '';
        $code = isset($header['code']) ? $header['code'] : '0000';
        $message = isset($header['message']) ? $header['message'] : '';
        if(empty($body)){
            $data = (object)array();
        }elseif(is_array($body)){
            $data = $body;
        }
        $params = [
            'code' => $code,
            'msg' => $message,
            'body' => $data,
        ];
        //不打印日志
        $debugLogArr = array();
        $request = \context()->getRequest();
        $uri = $request->getUriPath();
        if(!in_array($uri, $debugLogArr))
        {
            MyCommon::write_log('请求url:' . $uri .' 接口返回数据: ' .  print_r($params, true), config('log_path'));
        }
        //self::setCommonHeader($request, $statusCode);

        return $params;
    }


    /**
     * 返回错误消息
     * @param type $code 自定义状态码
     * @param type $message 返回的消息
     * @param type $statusCode http状态码
     * @return type
     */
    public static function returnError(string $code, string $message, int $statusCode = 200): array
    {
        if($code === '0000'){
            throw new \Exception('返回错误信息code码不能为0000');
        }
        return self::returnRst([], ['code' => $code,'message' => $message], $statusCode);
    }

    /**
     * 返回成功消息
     * @param array $data 返回的数据
     * @param string $code
     * @param string $message 返回的消息
     * @return array
     */
    public static function returnSuccess($data, string $code, string $message): array
    {
        return self::returnRst($data, ['message' => $message, 'code' => $code], $statusCode = 200);
    }

    /**
     * 返回提示消息
     * @param type $code 状态码
     * @param type $message 消息
     * @return array
     */
    public static function returnMessage(string $code, string $message): array
    {
        return self::returnRst('', ['code' => $code,'message' => $message], $statusCode = 200);
    }


    /**
     * 设置响应头信息
     * @param \swoole_http_request $request
     * @param int $statusCode
     */
    public static function setCommonHeader(Request $request, int $statusCode): void
    {
        $trust_origin = array(
            'http://localhost:3000',
        );
        $origin = $request->getHeaderLine('origin');
        $response = \context()->getResponse();
        $response->withStatus($statusCode);
        $response->withHeaders([
            'Access-Control-Allow-Credentials' => true,
            'Access-Control-Allow-Origin' => in_array($origin, $trust_origin) ? $origin : $trust_origin[0],
            'Access-Control-Allow-Method' => 'POST,OPTIONS,GET',
            'Access-Control-Allow-Headers' => 'dw_token,Content-Type,Version',
        ]);
    }

    /**
     * 设置响应数据内容类型
     */
    public static function setContentType()
    {
        header("Content-Type:application/json;charset=utf-8");
    }

}
