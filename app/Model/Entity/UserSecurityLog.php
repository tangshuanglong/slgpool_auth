<?php declare(strict_types=1);


namespace App\Model\Entity;

use Swoft\Db\Annotation\Mapping\Column;
use Swoft\Db\Annotation\Mapping\Entity;
use Swoft\Db\Annotation\Mapping\Id;
use Swoft\Db\Eloquent\Model;


/**
 *
 * Class UserSecurityLog
 *
 * @since 2.0
 *
 * @Entity(table="user_security_log")
 */
class UserSecurityLog extends Model
{
    /**
     * 用户安全类信息日志表
     * @Id()
     * @Column()
     *
     * @var int
     */
    private $id;

    /**
     * 用户ID
     *
     * @Column()
     *
     * @var int
     */
    private $uid;

    /**
     * 安全记录类型，如登出、登入、修改密码等的id，可暂时不用，留空
     *
     * @Column(name="type_id", prop="typeId")
     *
     * @var int|null
     */
    private $typeId;

    /**
     * 安全记录类型，如登出、登入、修改密码等
     *
     * @Column(name="type_name", prop="typeName")
     *
     * @var string
     */
    private $typeName;

    /**
     * 客户端IP
     *
     * @Column()
     *
     * @var string
     */
    private $ip;

    /**
     * IP对应的地区
     *
     * @Column()
     *
     * @var string
     */
    private $address;

    /**
     * 设备类型
     *
     * @Column(name="device_type", prop="deviceType")
     *
     * @var string
     */
    private $deviceType;

    /**
     * 设备id， 如果是app,就是手机的imei
     *
     * @Column(name="device_id", prop="deviceId")
     *
     * @var string
     */
    private $deviceId;

    /**
     * 状态，1-成功， 0-失败
     *
     * @Column()
     *
     * @var int
     */
    private $status;

    /**
     * 错误类型，1-登录密码错误, 2-服务器异常
     *
     * @Column(name="fail_type", prop="failType")
     *
     * @var int
     */
    private $failType;

    /**
     * 创建时间
     *
     * @Column(name="create_time", prop="createTime")
     *
     * @var int
     */
    private $createTime;


    /**
     * @param int $id
     *
     * @return void
     */
    public function setId(int $id): void
    {
        $this->id = $id;
    }

    /**
     * @param int $uid
     *
     * @return void
     */
    public function setUid(int $uid): void
    {
        $this->uid = $uid;
    }

    /**
     * @param int|null $typeId
     *
     * @return void
     */
    public function setTypeId(?int $typeId): void
    {
        $this->typeId = $typeId;
    }

    /**
     * @param string $typeName
     *
     * @return void
     */
    public function setTypeName(string $typeName): void
    {
        $this->typeName = $typeName;
    }

    /**
     * @param string $ip
     *
     * @return void
     */
    public function setIp(string $ip): void
    {
        $this->ip = $ip;
    }

    /**
     * @param string $address
     *
     * @return void
     */
    public function setAddress(string $address): void
    {
        $this->address = $address;
    }

    /**
     * @param string $deviceType
     *
     * @return void
     */
    public function setDeviceType(string $deviceType): void
    {
        $this->deviceType = $deviceType;
    }

    /**
     * @param string $deviceId
     *
     * @return void
     */
    public function setDeviceId(string $deviceId): void
    {
        $this->deviceId = $deviceId;
    }

    /**
     * @param int $status
     *
     * @return void
     */
    public function setStatus(int $status): void
    {
        $this->status = $status;
    }

    /**
     * @param int $failType
     *
     * @return void
     */
    public function setFailType(int $failType): void
    {
        $this->failType = $failType;
    }

    /**
     * @param int $createTime
     *
     * @return void
     */
    public function setCreateTime(int $createTime): void
    {
        $this->createTime = $createTime;
    }

    /**
     * @return int
     */
    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * @return int
     */
    public function getUid(): ?int
    {
        return $this->uid;
    }

    /**
     * @return int|null
     */
    public function getTypeId(): ?int
    {
        return $this->typeId;
    }

    /**
     * @return string
     */
    public function getTypeName(): ?string
    {
        return $this->typeName;
    }

    /**
     * @return string
     */
    public function getIp(): ?string
    {
        return $this->ip;
    }

    /**
     * @return string
     */
    public function getAddress(): ?string
    {
        return $this->address;
    }

    /**
     * @return string
     */
    public function getDeviceType(): ?string
    {
        return $this->deviceType;
    }

    /**
     * @return string
     */
    public function getDeviceId(): ?string
    {
        return $this->deviceId;
    }

    /**
     * @return int
     */
    public function getStatus(): ?int
    {
        return $this->status;
    }

    /**
     * @return int
     */
    public function getFailType(): ?int
    {
        return $this->failType;
    }

    /**
     * @return int
     */
    public function getCreateTime(): ?int
    {
        return $this->createTime;
    }

    /**
     * @param array $data 插入的数据
     * @param string $type 安全记录类型
     * @param int $status 状态，1-成功， 0-失败
     * @param int $fail_type 错误类型，1-登录密码错误, 2-服务器异常
     * @return bool
     */
    public static function insert_log(array $data, string $type, int $status = 1, int $fail_type = 0): bool
    {
        $type_info = UserSecurityType::select('id')->where(['type_name_en' => $type])->first();
        if (empty($type_info)) {
            throw new \Exception('security type error!');
        }
        $data['type_id'] = $type_info['id'];
        $data['type_name'] = $type;
        $data['status'] = $status;
        $data['fail_type'] = $fail_type;
        $data['create_time'] = time();
        return UserSecurityLog::insert($data);
    }

}
