<?php

namespace App\Lib;

use Swoft\Bean\Annotation\Mapping\Bean;
use App\Lib\MyCommon;
use Swoft\Db\DB;
use Swoft\Redis\Redis;
use Swoft\Bean\Annotation\Mapping\Inject;
use function config;

/**
 * 验签类
 * Class MySign
 * @package App\Lib
 * @Bean("MySign")
 */
class MySign
{

    private $hash_key;
    private $redis_key = 'redis_rsa_pub_key';
    private $redis_sign_token_key = 'redis_sign_token';

    /**
     * @var mixed
     */
    private $app_sign_timeout;

    /**
     * @var mixed
     */
    private $app_sign_cache_timeout;

    /**
     * @Inject("MyRsa")
     * @var
     */
    private $myrsa;

    /**
     * @Inject("MyAes")
     * @var
     */
    private $myaes;

    public function __construct()
    {
        $this->encryption_key = 'encryption_key';
        $this->app_sign_timeout = config('app_sign_timeout', 3600);
        $this->app_sign_cache_timeout = config('app_sign_cache_timeout', 3600);
    }

    /**
     * sha256接口验签
     * @param type $data 数组 请求数据
     * @return boolean
     */
    public function checkSign(array $data): bool
    {
        $verifyedSign = $data['sign'];
        if(env('SWOFT_DEBUG') != 1){
            //请求超时
            if(time() > (round($data['timestamp'] / 1000) + $this->app_sign_timeout)){
                return false;
            }
            //每个签名只可以使用一次
//            if(Redis::exists($verifyedSign)){
//                return false;
//            }
        }
        //将sign置为空，在生成签名字符串时会自动去掉
        $data['sign'] = '';
        $signContent = $this->getSignContent($data);
        //生成签名
        $sign = $this->sign($signContent);
        //验签
        if(strcasecmp($verifyedSign, $sign) != 0){
            return false;
        }
        //将签名为唯一key存入缓存
        //Redis::set($verifyedSign, true, $this->app_sign_cache_timeout);
        return true;
    }

    /**
     * rsa验签
     * @param type $data 数组 请求数据
     * @return boolean
     */
    public function rsaCheckSign(array $data): bool
    {
        $verifyedSign = $data['Sign'];
        if(env('SWOFT_DEBUG') != 1){
            //请求超时
            if(time() > (round($data['Timestamp'] / 1000) + $this->app_sign_timeout)){
                return false;
            }
            //每个签名只可以使用一次
            if(Redis::exists($verifyedSign)){
                return false;
            }
        }
        //将sign置为空，在生成签名字符串时会自动去掉
        $data['Sign'] = '';
        //获取缓存的公钥，如果不存在，从数据库获取
        $pub_key = Redis::get($this->redis_key.'_'.$data['device_id']);
        if(!$pub_key){
            $rsa_key = DB::table('rsa')->select('pub_key')->where(['imei' => $data['Did']])->first();
            if(!isset($rsa_key['pub_key']) ){
                return false;
            }
            $pub_key = $rsa_key['pub_key'];
            //缓存一个小时
            Redis::set($this->redis_key.'_'.$data['device_id'], $pub_key, ["EX" => 3600]);
        }

        //生成签名
        $signContent = $this->getSignContent($data, $type = 2);
        $res = $this->myrsa->verify($signContent, $verifyedSign, $pub_key);
        //验签
        if(!$res){
            return false;
        }
        //将签名为唯一key存入缓存
        Redis::set($verifyedSign, true, ["EX" => $this->app_sign_cache_timeout]);
        return true;
    }


    /**
     * PC端和手机端需要登录的接口及app创建签名
     * @param type $params
     * @return type
     */
    public function appGenerateSign($params, $key = '')
    {
        //获取待生成验签字符串
        $signContent = $this->getSignContent($params, $type = 2);
        //生成签名字符串
        return $this->myrsa->sign($signContent, $key);
    }

    /**
     * PC端和手机端无需登录的接口创建签名
     * @param type $params
     * @return type
     */
    public function generateSign($params, $isAes = false)
    {
        //获取待生成验签字符串
        $signContent = $this->getSignContent($params, $type = 1);
        //生成签名字符串
        $signString = $this->sign($signContent);
        if($isAes){
            //aes加密返回
            return $this->myaes()->encrypt($signString, $this->encryption_key);
        }else{
            return $signString;
        }
    }

    /**
     * PC端和手机端无需登录的接口生成签名字符串
     * @param type $data
     * @param type $secretKey
     * @return type
     */
    public function sign($data)
    {
        $chiphertext = hash('sha256', $data, true);
        return base64_encode($chiphertext);
    }

    /**
     * 获取签名字符串
     * @param type $params
     * @param type $type 1-PC端和手机端无需登录的接口签名字符串，2-app和PC端和手机端需要登录的接口
     * @return string
     */
    public function getSignContent($params, $type = 1)
    {
        //按关联数组的键名做升序排序
        ksort($params);
        reset($params);
        $stringToBeSigned = '';
        $i = 0;
        //拼接成key=value&key=value字符串形式
        foreach($params as $key => $val){
            if(MyCommon::checkEmpty($val) === false && substr($val, 0, 1) != '@'){
                if($i == 0){
                    if($type === 1){
                        $stringToBeSigned .= $key . "=" . $val;
                    }else{
                        $stringToBeSigned .= $key . "-" . $val;
                    }
                }else{
                    if($type === 1){
                        $stringToBeSigned .= "&" . $key . "=" . $val;
                    }else{
                        $stringToBeSigned .= "&" . $key . "-" . $val;
                    }

                }
                $i++;
            }
            unset($key, $val);
        }

        return $stringToBeSigned;
    }
}
