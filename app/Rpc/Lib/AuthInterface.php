<?php

namespace App\Rpc\Lib;
/**
 * Interface AuthInterface
 */
interface AuthInterface
{

    /**
     * 验证登录
     * @param string $token 登录token jwt
     * @param string $client_type
     * @param string $device_id
     * @return
     */
    public function verify_login(string $token, string $client_type, string $device_id);

    /**
     * 刷新用户信息缓存
     * @param int $uid
     * @return bool|int|string
     * @throws \Swoft\Db\Exception\DbException
     */
    public function reset_user_all_info(int $uid);

}
