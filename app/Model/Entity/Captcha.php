<?php declare(strict_types=1);


namespace App\Model\Entity;

use Swoft\Db\Annotation\Mapping\Column;
use Swoft\Db\Annotation\Mapping\Entity;
use Swoft\Db\Annotation\Mapping\Id;
use Swoft\Db\Eloquent\Model;


/**
 *
 * Class Captcha
 *
 * @since 2.0
 *
 * @Entity(table="captcha")
 */
class Captcha extends Model
{
    /**
     * 发送验证码记录
     * @Id()
     * @Column()
     *
     * @var int
     */
    private $id;

    /**
     * 账号
     *
     * @Column()
     *
     * @var string
     */
    private $account;

    /**
     * 类型
     *
     * @Column()
     *
     * @var string
     */
    private $type;

    /**
     * 客户端IP
     *
     * @Column()
     *
     * @var string
     */
    private $ip;

    /**
     * 发送时间
     *
     * @Column(name="create_time", prop="createTime")
     *
     * @var int
     */
    private $createTime;

    /**
     * 验证码
     *
     * @Column()
     *
     * @var string
     */
    private $code;

    /**
     * 行为
     *
     * @Column()
     *
     * @var string
     */
    private $action;

    /**
     *
     *
     * @Column(name="user_agent", prop="userAgent")
     *
     * @var string
     */
    private $userAgent;


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
     * @param string $account
     *
     * @return void
     */
    public function setAccount(string $account): void
    {
        $this->account = $account;
    }

    /**
     * @param string $type
     *
     * @return void
     */
    public function setType(string $type): void
    {
        $this->type = $type;
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
     * @param int $createTime
     *
     * @return void
     */
    public function setCreateTime(int $createTime): void
    {
        $this->createTime = $createTime;
    }

    /**
     * @param string $code
     *
     * @return void
     */
    public function setCode(string $code): void
    {
        $this->code = $code;
    }

    /**
     * @param string $action
     *
     * @return void
     */
    public function setAction(string $action): void
    {
        $this->action = $action;
    }

    /**
     * @param string $userAgent
     *
     * @return void
     */
    public function setUserAgent(string $userAgent): void
    {
        $this->userAgent = $userAgent;
    }

    /**
     * @return int
     */
    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getAccount(): ?string
    {
        return $this->account;
    }

    /**
     * @return string
     */
    public function getType(): ?string
    {
        return $this->type;
    }

    /**
     * @return string
     */
    public function getIp(): ?string
    {
        return $this->ip;
    }

    /**
     * @return int
     */
    public function getCreateTime(): ?int
    {
        return $this->createTime;
    }

    /**
     * @return string
     */
    public function getCode(): ?string
    {
        return $this->code;
    }

    /**
     * @return string
     */
    public function getAction(): ?string
    {
        return $this->action;
    }

    /**
     * @return string
     */
    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }


}
