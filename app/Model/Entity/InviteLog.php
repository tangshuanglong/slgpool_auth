<?php declare(strict_types=1);


namespace App\Model\Entity;

use Swoft\Db\Annotation\Mapping\Column;
use Swoft\Db\Annotation\Mapping\Entity;
use Swoft\Db\Annotation\Mapping\Id;
use Swoft\Db\Eloquent\Model;


/**
 * 邀请记录表
 * Class InviteLog
 *
 * @since 2.0
 *
 * @Entity(table="invite_log")
 */
class InviteLog extends Model
{
    /**
     * 
     * @Id()
     * @Column()
     *
     * @var int
     */
    private $id;

    /**
     * 邀请用户id
     *
     * @Column()
     *
     * @var int
     */
    private $uid;

    /**
     * 被邀请的用户id
     *
     * @Column(name="invited_uid", prop="invitedUid")
     *
     * @var string
     */
    private $invitedUid;

    /**
     * 被邀请注册时的账号
     *
     * @Column(name="invited_account", prop="invitedAccount")
     *
     * @var string
     */
    private $invitedAccount;

    /**
     * 状态，0-已失效，1-生效中
     *
     * @Column()
     *
     * @var int
     */
    private $status;

    /**
     * 邀请时间
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
     * @param string $invitedUid
     *
     * @return void
     */
    public function setInvitedUid(string $invitedUid): void
    {
        $this->invitedUid = $invitedUid;
    }

    /**
     * @param string $invitedAccount
     *
     * @return void
     */
    public function setInvitedAccount(string $invitedAccount): void
    {
        $this->invitedAccount = $invitedAccount;
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
     * @return string
     */
    public function getInvitedUid(): ?string
    {
        return $this->invitedUid;
    }

    /**
     * @return string
     */
    public function getInvitedAccount(): ?string
    {
        return $this->invitedAccount;
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
    public function getCreateTime(): ?int
    {
        return $this->createTime;
    }

}
