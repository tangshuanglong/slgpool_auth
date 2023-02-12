<?php

namespace App\Rpc\Lib;

/**
 * Interface VerifyCodeInterface
 */
interface VerifyCodeInterface{

    /**
     * 发送验证码
     * @param string $account
     * @param string $area_code
     * @param string $action
     * @return mixed
     */
    public function send_verify_code(string $account, string $area_code, string $action);

}
