<?php declare(strict_types=1);
/**
 * This file is part of Swoft.
 *
 * @link     https://swoft.org
 * @document https://swoft.org/docs
 * @contact  group@swoft.org
 * @license  https://github.com/swoft-cloud/swoft/blob/master/LICENSE
 */

namespace App\Rpc\Service;

use App\Model\Data\UserData;
use App\Model\Entity\UserBasicalInfo;
use App\Rpc\Lib\UserInterface;
use Exception;
use Swoft\Bean\BeanFactory;
use Swoft\Co;
use Swoft\Db\DB;
use Swoft\Rpc\Server\Annotation\Mapping\Service;

/**
 * Class UserService
 *
 * @since 2.0
 *
 * @Service()
 */
class UserService implements UserInterface
{

    /**
     * 获取用户的所有信息
     * @param $uid
     * @return mixed
     * @throws \Swoft\Db\Exception\DbException
     */
    public function get_user_all_info($uid)
    {
        return UserData::get_user_all_info($uid);
    }

    /**
     * 判断数据是否存在
     * @param array $where
     * @return mixed
     */
    public function is_exists(array $where)
    {
        return UserBasicalInfo::where($where)->exists();
    }

    /**
     * 获取绑定验证信息
     * @param $uid
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     */
    public function get_bind_info($uid)
    {
        return UserData::get_bind_info($uid);
    }

    /**
     * 是否设置交易密码
     * @param int $uid
     * @return bool
     * @throws \ReflectionException
     * @throws \Swoft\Bean\Exception\ContainerException
     * @throws \Swoft\Db\Exception\DbException
     */
    public function is_set_trade_pwd(int $uid)
    {
        $data = UserData::get_user_all_info($uid);
        return !empty($data['trade_pwd']);
    }

    /**
     * 验证交易密码
     * @param int $uid
     * @param string $trade_pwd
     * @return bool
     * @throws \Swoft\Db\Exception\DbException
     */
    public function verify_trade_pwd(int $uid, string $trade_pwd)
    {
        $data = UserData::get_user_all_info($uid);
        /**@var MyAuth $myAuth */
        $myAuth = BeanFactory::getBean('MyAuth');
        return $myAuth->password_auth($trade_pwd, $data['salt'], $data['trade_pwd']);
    }

    /**
     * 注册总数
     * @return int
     */
    public function get_total_register()
    {
        return UserBasicalInfo::count();
    }
}
