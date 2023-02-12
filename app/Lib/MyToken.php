<?php

namespace App\Lib;

use Swoft\Log\Helper\Log;
use Swoft\Redis\Redis;
use Swoft\Bean\Annotation\Mapping\Bean;
use Swoft\Bean\Annotation\Mapping\Inject;
use App\Lib\MyAes;
use Swoft\Stdlib\Helper\JsonHelper;

/**
 * Class MyToken
 * @package App\Lib
 * 生成登录token
 * @Bean("MyToken")
 */
class MyToken
{
    /**
     * @var string
     */
    private $redis_token_key = 'redis_token';

    /**
     * @var string
     */
    private $redis_sign_token_key = 'redis_sign_token';

    /**
     * @var
     */
    private $hmac_key;

    /**
     * @Inject("MyAes")
     * @var MyAes
     */
    private $myAes;


    public function __construct()
    {
        $this->hmac_key = config('hmac_key');
    }

    /**
     * 生成token
     * @param int $invite_id
     * @param string $account
     * @param string $client_type
     * @param string $device_id
     * @return string
     */
    public function generateToken(int $invite_id, string $account, string $client_type, string $device_id = '')
    {
        $time = time();
        $prefix = 'app_';
        if($client_type === 'web'){
            $exp = $time + 28800;
            $prefix = 'compute_';
        }else{
            $exp = $time + (86400*15);
        }
        $payload = [
            'user_id' => $invite_id,
            'account' => $account,
            'exp' => $exp,
        ];
        $header = [
            'alg' => 'SHA256',
            'typ' => 'JWT',
            'did' => $device_id,
        ];
        //对头信息进行aes加密
        $aes_header = $this->myAes->encrypt(JsonHelper::encode($header));
        //对载荷信息进行base64编码
        $base64_payload = base64_encode(JsonHelper::encode($payload));
        //生成签名
        $sign = base64_encode(hash_hmac('sha256', $aes_header.'.'.$base64_payload, $this->hmac_key, true));
        //拼接token
        $token = $aes_header.'.'.$base64_payload.'.'.$sign;
        $key = $prefix.$invite_id;

        Redis::hset($this->redis_token_key, $key, $token);
        return $token;
    }


    /**
     * 验证token
     * @param string $userToken
     * @param string $client_type
     * @param string $device_id
     * @return array|bool
     */
    public function checkToken(string $userToken, string $client_type, string $device_id)
    {
        if($userToken === '0' || $userToken === ''){
            return false;
        }
        $prefix = 'app_';
        if($client_type === 'web'){
            $prefix = 'compute_';
        }
        $explode_token = explode('.', $userToken);
        if (count($explode_token) !== 3){
            return false;
        }
        list($aes_header, $base64_payload, $verify_sign) = $explode_token;
        //生成签名
        $sign = base64_encode(hash_hmac('sha256', $aes_header.'.'.$base64_payload, $this->hmac_key, true));
        //签名不一致返回登录过期
        if(strcasecmp($verify_sign, $sign) != 0){
            return false;
        }
        $header = JsonHelper::decode($this->myAes->decrypt($aes_header), true);
        $payload = JsonHelper::decode(base64_decode($base64_payload), true);
        if(!$payload || !$header){
            MyCommon::write_log('解析不到数据', config('log_path'));
            return false;
        }
        //缓存的token和上传的token不一致
        $key = $prefix.$payload['user_id'];
        $redis_token = Redis::hget($this->redis_token_key, $key);
        if(strcasecmp($redis_token, $userToken) != 0){
            MyCommon::write_log('缓存的token和上传的token不一致', config('log_path'));
            return false;
        }
        //如果缓存不存在或did不一致，或过期返回登录过期
        if($device_id !== $header['did'] || $payload['exp'] < time()){
            MyCommon::write_log('如果缓存不存在或did不一致，或过期返回登录过期', __DIR__.'/../../token');
            Redis::hdel($this->redis_token_key, $key);
            return false;
        }
        $uid = $payload['user_id'] - config('invite_prefix');//推荐码减推荐码前缀得到uid
        $rst_data = [
            'uid' => $uid,
            'account' => $payload['account'],
        ];
        return $rst_data;
    }

    /**
     * @param $invite_id
     * @param string $client_type
     * @return string
     */
    public function deleteToken($invite_id, string $client_type)
    {
        $prefix = 'app_';
        if($client_type === 'web'){
            $prefix = 'compute_';
        }
        $key = $prefix.$invite_id;
        return Redis::hDel($this->redis_token_key, $key);
    }


}
