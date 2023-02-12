<?php

namespace App\Lib;

use App\Lib\MyRabbitMq;
use Swoft\Bean\Annotation\Mapping\Bean;
use Swoft\Bean\Annotation\Mapping\Inject;
use Swoft\Bean\BeanFactory;
use Swoft\Http\Message\Request;
use App\Lib\MyCommon;

/**
 * Class MyPushQueue
 * @package App\Lib
 * @Bean("MyPushQueue")
 */
class MyPushQueue{


    /**
     * @Inject()
     * @var MyRabbitMq
     */
    private $myRabbitMq;

    /**
     * @Inject()
     * @var MyCommon
     */
    private $myCommon;

    /**
     * push安全日志到队列
     * @param array $data
     * @param string $type
     * @param int $status
     * @param int $fail_type
     * @return bool
     */
    public function push_security_log(array $data, string $type, int $status = 1, int $fail_type = 0): bool
    {
        $key = 'security_log_key';
        $data['type_name'] = $type;
        $data['status'] = $status;
        $data['fail_type'] = $fail_type;
        return $this->myRabbitMq->push($key, $data);
    }

    /**
     * 登录后插入安全记录到队列
     * @param Request $request
     * @param string $type
     * @return bool
     */
    public function push_security_log_login(Request $request, string $type): bool
    {
        $ip_area = $this->myCommon->get_ip_area($request->ip);
        $security_log = [
            'uid' => $request->uid,
            'ip' => $request->ip,
            'address' => $ip_area,
            'device_type' => $request->client_type,
            'device_id' => $request->device_id,
        ];
        unset($request);
        return $this->push_security_log($security_log, $type);
    }



}
