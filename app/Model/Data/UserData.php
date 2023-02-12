<?php declare(strict_types=1);
/**
 * This file is part of Swoft.
 *
 * @link     https://swoft.org
 * @document https://swoft.org/docs
 * @contact  group@swoft.org
 * @license  https://github.com/swoft-cloud/swoft/blob/master/LICENSE
 */

namespace App\Model\Data;

use App\Lib\MyCommon;
use App\Lib\MyToken;
use App\Model\Entity\UserBasicalInfo;
use Swoft\Bean\Annotation\Mapping\Inject;
use Swoft\Bean\BeanFactory;
use Swoft\Db\DB;
use Swoft\Redis\Redis;
use Swoft\Stdlib\Helper\JsonHelper;

/**
 * Class UserData
 * @package App\Model\Data
 */
class UserData
{

    /**
     * 获取用户所有信息
     * @param $uid
     * @return array|bool|mixed
     * @throws \Swoft\Db\Exception\DbException
     */
    public static function get_user_all_info($uid)
    {
        $key = config('login_user_info_key');
        $field = config('field_prefix').$uid;
        $data = Redis::hGet($key, $field);
        //如果缓存获取不到
        if (!$data) {
            $data = DB::table('user_basical_info')->where(['id' => $uid])->first();
            if (!$data) {
                return false;
            }
            //设置缓存
            Redis::hSet($key, $field, json_encode($data));
        }else{
            $data = json_decode($data, true);
        }
        return $data;
    }

    /**
     * 重置用户所有信息的缓存
     * @param $uid
     * @return bool|int|string
     * @throws \Swoft\Db\Exception\DbException
     */
    public static function reset_user_all_info($uid)
    {
        $key = config('login_user_info_key');
        $field = config('field_prefix').$uid;
        $res = Redis::hDel($key, $field);
        if ($res) {
            $data = DB::table('user_basical_info')->where(['id' => $uid])->first();
            if (!$data) {
                return false;
            }
            //设置缓存
            return Redis::hSet($key, $field, json_encode($data));
        }
        return $res;
    }

    /**
     * 获取用户信息
     * @param $uid
     * @return array|bool
     * @throws \Swoft\Db\Exception\DbException
     */
    public static function get_user_info($uid)
    {
        $user_info = self::get_user_all_info($uid);
        if (!$user_info) {
            return false;
        }
        /**@var MyCommon $myCommon */
        $myCommon = BeanFactory::getBean('MyCommon');
        $mobile = $user_info['mobile'];
        $email = $user_info['email'];
        if ($user_info['mobile'] != '') {
            $mobile = $myCommon->phoneCipher($user_info['mobile'], 3, 5);
        }
        if ($user_info['email'] != '') {
            $email = $myCommon->phoneCipher($user_info['email'], 3, 5);
        }
        $data = [
            'user_id' => $user_info['invite_id'],
            'nickname' => $user_info['nickname'],
            'user_pic'  => MyCommon::get_filepath($user_info['user_pic']),
            'mobile' => $mobile,
            'email' => $email,
            'mobile_verify' => $user_info['mobile_verify'],
            'email_verify' => $user_info['email_verify'],
            'google_auth' => $user_info['google_auth'],
            'google_validator' => $user_info['google_validator'],
            'security_level' => $user_info['security_level'],
            'trade_pwd_status' => empty($user_info['trade_pwd']) ? 0 : 1,
            'login_time' => date("Y-m-d H:i:s", $user_info['login_time']),
            'login_ip' => $user_info['login_ip']
        ];
        return $data;
    }

    /**
     * 获取用户绑定的信息
     * @param $uid
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     */
    public static function get_bind_info($uid): array
    {
        $user_info = self::get_user_all_info($uid);
        $data = [
            'mobile_verify' => $user_info['mobile_verify'],
            'mobile' => $user_info['mobile'],
            'email_verify' => $user_info['email_verify'],
            'email' => $user_info['email'],
            'google_validator' => $user_info['google_validator'],
        ];
        return $data;
    }

    /**
     * 验证登录
     * @param string $token
     * @param string $client_type
     * @param string $device_id
     * @return array|bool|mixed
     * @throws \Swoft\Db\Exception\DbException
     */
    public static function verify_login(string $token, string $client_type, string $device_id)
    {
        /**@var MyToken $myToken */
        $myToken = BeanFactory::getBean('MyToken');
        $res_data = $myToken->checkToken($token, $client_type, $device_id);
        if ($res_data === false) {
            return false;
        }
        $user_info = UserData::get_user_all_info($res_data['uid']);
        if (!$user_info) {
            return false;
        }
        $user_info['account'] = $res_data['account'];
        $key = config('login_user_info_key');
        $field = config('field_prefix').$res_data['uid'];
        Redis::hSet($key, $field, JsonHelper::encode($user_info));
        return $user_info;
    }
}
