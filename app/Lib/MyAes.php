<?php

namespace App\Lib;

use Swoft\Bean\Annotation\Mapping\Bean;

/**
 * AES加解密类
 * Class MyAes
 * @package App\Lib
 * @Bean("MyAes")
 */
class MyAes
{

    public function __construct()
    {
        $this->handle = 'AES-128-CBC';
        $this->key = hex2bin(config('aes_encryption_key'));
    }

    /**
    *加密
    */
    public function encrypt($input, $key = '')
    {
        if($key == ''){
            $key = $this->key;
        }
        //获取iv长度
        $iv_size = openssl_cipher_iv_length($this->handle);
        if(!$iv_size){
            return false;
        }
        //生成iv
        $iv = substr(md5(time().mt_rand(0,1000000), true), 0, $iv_size);
        //加密数据
        $crypted = openssl_encrypt($input,$this->handle, $key,OPENSSL_RAW_DATA , $iv);
        //iv拼在加密数据签名base64返回
        return base64_encode($iv.$crypted);
    }

    /**
    *解密
    */
    public function decrypt($input, $key = '')
    {
        if($key == ''){
            $key = $this->key;
        }
        $data = base64_decode($input);
        if(empty($data)){
            return false;
        }
        $iv_size = openssl_cipher_iv_length($this->handle);
        if(!$iv_size){
            return false;
        }
        //得到iv和加密数据
        $iv = substr($data, 0, $iv_size);
        $crypted = substr($data, $iv_size);
        if(empty($crypted)){
            return false;
        }
        return openssl_decrypt($crypted, $this->handle, $key, OPENSSL_RAW_DATA, $iv);
    }

}
