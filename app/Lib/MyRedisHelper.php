<?php

namespace App\Lib;

use Swoft\Redis\Redis;
use Swoft\Stdlib\Helper\JsonHelper;

/**
 * Class MyRedisHelper
 * @package App\Lib
 */
class MyRedisHelper{

    /**
     * 设置hash缓存，
     * @param string $key
     * @param string $field
     * @param array $value
     * @return bool
     */
    public static function hSet(string $key, string $field, array $value): bool
    {
        $scrpty = '
            if(redis.call("hExists", KEYS[1], KEYS[2]) == 1) then
                if(redis.call("hDel", KEYS[1], KEYS[2]) == 0) then
                    return 0
                end
            end
            return redis.call("hSet", KEYS[1], KEYS[2], ARGV[1])
        ';
        return Redis::eval($scrpty, [$key, $field, JsonHelper::encode($value)], 2);
    }

    /**
     * @param string $key
     * @param string $field
     * @return mixed
     */
    public static function hGet(string $key, string $field)
    {
        $res = Redis::hGet($key, $field);
        if (!empty($res)){
            return JsonHelper::decode($res, true);
        }
        return $res;
    }


    /**
     * 分布式锁,单机适用
     * @param string $key
     * @param int $timeout 超时时间
     * @param int $retry 如果获取锁失败重复获取的次数
     * @return bool|string
     */
    public static function lock(string $key, int $timeout = 2)
    {
        //保证轮训的次数达到超时时间
        $retry = intval($timeout / ($timeout / 2 * 0.1));
        do{
            $token = uniqid().mt_rand(100, 999);
            $res = Redis::set($key, $token, ["NX", "EX" => $timeout]);
            if ($res) {
                return $token;
            }
            //随机睡眠时间
            $retry_delay = $timeout * 100;
            $delay = mt_rand(floor($retry_delay / 2), $retry_delay);
            usleep($delay * 1000);
            $retry --;
        }while($retry > 0);

        return false;
    }

    /**
     * 分布式锁， 解锁
     * @param string $key
     * @param $token
     * @return mixed
     */
    public static function unLock(string $key, $token)
    {
        $script = '
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            else
                return 0
            end
        ';
        return Redis::eval($script, [$key, $token], 1);
    }

}
