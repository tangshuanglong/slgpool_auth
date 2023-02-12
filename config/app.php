<?php

return [
    //consul注册配置
    'consul'                   => [
        'address' => '127.0.0.1',
        'port'    => 18306,
        'name'    => 'at',
        'id'      => 'at',
    ],

    //登录错误次数
    'login_error_limit'        => 5,
    'login_error_key'          => 'login:error:number:account', //缓存错误次数的key

    //二步登录过期时间
    'second_login_expire_time' => 3600,

    'apollo' => require_once __DIR__ . "/../../../apollo.php",

];
