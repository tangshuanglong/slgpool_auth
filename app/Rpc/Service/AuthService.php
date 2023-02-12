<?php

namespace App\Rpc\Service;

use App\Lib\MyToken;
use App\Model\Data\UserData;
use App\Rpc\Lib\AuthInterface;
use Swoft\Bean\Annotation\Mapping\Bean;
use Swoft\Bean\Annotation\Mapping\Inject;
use Swoft\Redis\Redis;
use Swoft\Rpc\Server\Annotation\Mapping\Service;
use Swoft\Stdlib\Helper\JsonHelper;

/**
 * Class AuthService
 * @package App\Rpc\Service
 * @Service()
 */
class AuthService implements AuthInterface
{

    /**
     * @Inject()
     * @var MyToken
     */
    private $myToken;

    /**
     * 验证登录
     * @param string $token
     * @param string $client_type
     * @param string $device_id
     * @return array|bool|mixed
     * @throws \Swoft\Db\Exception\DbException
     */
    public function verify_login(string $token, string $client_type, string $device_id)
    {
        return UserData::verify_login($token, $client_type, $device_id);
    }

    /**
     * 验证登录token
     * @param string $token
     * @param string $client_type
     * @param string $device_id
     * @return array|bool
     */
    public function checkToken(string $token, string $client_type, string $device_id)
    {
        return $this->myToken->checkToken($token, $client_type, $device_id);
    }

    /**
     * 刷新用户信息缓存
     * @param int $uid
     * @return bool|int|string
     * @throws \Swoft\Db\Exception\DbException
     */
    public function reset_user_all_info(int $uid)
    {
        return UserData::reset_user_all_info($uid);
    }

}
