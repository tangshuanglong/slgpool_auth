<?php

namespace App\Lib;

use Swoft\Bean\Annotation\Mapping\Bean;

/**
 * RSA加解密类
 * Class MyRsa
 * @package App\Lib
 * @Bean("MyRsa")
 */
class MyRsa
{
    public $public_key;
    public $private_key;
    public function __construct()
    {
        $this->public_key = 'public_key';
        $this->private_key = 'private_key';
    }

    //rsa生成签名
    public function sign($input, $key = '')
    {
        if($key !== ''){
            $this->private_key = $key;
        }
        $res = $this->priKey($this->private_key);
        if(!$res){
            return false;
        }
        openssl_private_encrypt(md5($input), $sign, $res);
        return base64_encode($sign);
    }

    //rsa验证签名
    public function verify($input, $sign, $key = '')
    {
        if($key !== ''){
            $this->public_key = $key;
        }
        $res = $this->pubKey($this->public_key);
        if(!$res){
            return false;
        }
        $algo = md5($input);
        openssl_public_decrypt(base64_decode($sign), $decrypted, $res);
        if(strcasecmp($algo, $decrypted) != 0){
            return false;
        }
        return true;
    }


    /**
    *加密
    */
    public function encrypt($input, $key = '')
    {
        if($key !== ''){
            $this->public_key = $key;
        }
        $res = $this->pubKey($this->public_key);
        if(!$res){
            return false;
        }
        openssl_public_encrypt($input, $crypted, $res);
        return base64_encode($crypted);
    }

    /**
    *解密
    */
    public function decrypt($crypted, $key = '')
    {
        if($key !== ''){
            $this->private_key = $key;
        }
        $res = $this->priKey($this->private_key);
        if(!$res){
            return false;
        }
        openssl_private_decrypt(base64_decode($crypted), $decrypted, $res);
        return $decrypted;
    }

    //公钥
    public function pubKey($key)
    {
        return "-----BEGIN PUBLIC KEY-----\n" .
                wordwrap($key, 64, "\n", true) .
                "\n-----END PUBLIC KEY-----";
    }

    //私钥
    public function priKey($key)
    {
        return "-----BEGIN RSA PRIVATE KEY-----\n" .
                wordwrap($key, 64, "\n", true) .
                "\n-----END RSA PRIVATE KEY-----";
    }

}
