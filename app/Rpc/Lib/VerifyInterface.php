<?php

namespace App\Rpc\Lib;

/**
 * Interface VerifyInterface
 * @package App\Rpc\Lib
 */
interface VerifyInterface
{

    /**
     * 验证签名
     * @param $sign 签名
     * @param $data 签名的数据
     * @return mixed
     */
    public function verify_sign(array $data): bool;

    /**
     * 验证验证码
     * @param string $account
     * @param string $code
     * @param string $action
     * @return bool
     */
    public function verify_code(string $account, string $code, string $action): bool;

    /**
     * 谷歌验证
     * @param string $code
     * @param $uid
     * @return mixed
     */
    public function google_verify(string $code, $uid): bool;

    /**
     * 验证所有验证码
     * @param array $data
     * @return bool|mixed|string
     */
    public function verify_all(array $data);

    /**
     * 验证所有验证码
     * @param $uid
     * @param array $params
     * @param string $action
     * @return mixed
     */
    public function auth_all_verify_code($uid, array $params, string $action);

}
