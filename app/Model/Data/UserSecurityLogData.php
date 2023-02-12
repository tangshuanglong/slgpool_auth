<?php

namespace App\Model\Data;

use App\Lib\MyCommon;
use App\Model\Entity\UserSecurityLog;
use App\Model\Entity\UserSecurityType;
use Swoft\Bean\Annotation\Mapping\Bean;
use Swoft\Bean\Annotation\Mapping\Inject;
use Swoft\Http\Message\Request;

/**
 * Class UserSecurityLogData
 * @package App\Model\Data
 * @Bean("UserSecurityLogData")
 */
class UserSecurityLogData{

    /**
     * @Inject()
     * @var MyCommon
     */
    private $myCommon;

    public function insert_security_log(array $data, string $type, int $status = 1, int $fail_type = 0): bool
    {
        $data['type_name'] = $type;
        $data['status'] = $status;
        $data['fail_type'] = $fail_type;
        $type_info = UserSecurityType::select('id')->where(['type_name_en' => $data['type_name']])->first();
        if (empty($type_info)) {
            return false;
        }
        $data['type_id'] = $type_info['id'];
        $data['create_time'] = time();
        return UserSecurityLog::insert($data);
    }

    /**
     * 登录后插入安全记录到队列
     * @param Request $request
     * @param string $type
     * @return bool
     */
    public function insert_security_log_login(Request $request, string $type): bool
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
        return $this->insert_security_log($security_log, $type);
    }
}
