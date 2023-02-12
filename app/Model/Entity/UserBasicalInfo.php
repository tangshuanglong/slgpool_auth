<?php declare(strict_types=1);


namespace App\Model\Entity;

use Swoft\Db\Annotation\Mapping\Column;
use Swoft\Db\Annotation\Mapping\Entity;
use Swoft\Db\Annotation\Mapping\Id;
use Swoft\Db\Eloquent\Model;


/**
 * 用户基本信息
 * Class UserBasicalInfo
 *
 * @since 2.0
 *
 * @Entity(table="user_basical_info")
 */
class UserBasicalInfo extends Model
{
    /**
     * 国家手机号前缀码
     *
     * @Column(name="area_code", prop="areaCode")
     *
     * @var string
     */
    private $areaCode;

    /**
     * 
     *
     * @Column()
     *
     * @var string
     */
    private $email;

    /**
     * 邮箱验证， 0-关闭， 1-开启
     *
     * @Column(name="email_verify", prop="emailVerify")
     *
     * @var int
     */
    private $emailVerify;

    /**
     * 限制登录，0为正常，1为限制登录，用户无法登录
     *
     * @Column(name="forbidden_login", prop="forbiddenLogin")
     *
     * @var int
     */
    private $forbiddenLogin;

    /**
     * google认证开启（0：关闭，1:开启）
     *
     * @Column(name="google_auth", prop="googleAuth")
     *
     * @var int
     */
    private $googleAuth;

    /**
     * 谷歌验证器，1-已绑定，0-未绑定
     *
     * @Column(name="google_validator", prop="googleValidator")
     *
     * @var int
     */
    private $googleValidator;

    /**
     * 用户基本资料表
     * @Id()
     * @Column()
     *
     * @var int
     */
    private $id;

    /**
     * 推荐ID，常数1598450+用户ID
     *
     * @Column(name="invite_id", prop="inviteId")
     *
     * @var int
     */
    private $inviteId;

    /**
     * 邀请总数
     *
     * @Column(name="invite_total_times", prop="inviteTotalTimes")
     *
     * @var int
     */
    private $inviteTotalTimes;

    /**
     * 推荐人的推荐ID
     *
     * @Column(name="invitor_uid", prop="invitorUid")
     *
     * @var int
     */
    private $invitorUid;

    /**
     * 登录ip
     *
     * @Column(name="login_ip", prop="loginIp")
     *
     * @var string
     */
    private $loginIp;

    /**
     * 登录密码
     *
     * @Column(name="login_pwd", prop="loginPwd")
     *
     * @var string
     */
    private $loginPwd;

    /**
     * 最后登录时间
     *
     * @Column(name="login_time", prop="loginTime")
     *
     * @var int|null
     */
    private $loginTime;

    /**
     * 
     *
     * @Column()
     *
     * @var string
     */
    private $mobile;

    /**
     * 手机验证，0-关闭，1-开启
     *
     * @Column(name="mobile_verify", prop="mobileVerify")
     *
     * @var int
     */
    private $mobileVerify;

    /**
     * 用户昵称
     *
     * @Column()
     *
     * @var string
     */
    private $nickname;

    /**
     * 注册ip
     *
     * @Column(name="register_ip", prop="registerIp")
     *
     * @var string
     */
    private $registerIp;

    /**
     * 注册时间
     *
     * @Column(name="register_time", prop="registerTime")
     *
     * @var int
     */
    private $registerTime;

    /**
     * 密码加密的盐值
     *
     * @Column()
     *
     * @var string
     */
    private $salt;

    /**
     * 是否开启第二步登录验证。1为开启，0为关闭。
     *
     * @Column(name="second_check", prop="secondCheck")
     *
     * @var int
     */
    private $secondCheck;

    /**
     * 安全等级， 1,2,3级
     *
     * @Column(name="security_level", prop="securityLevel")
     *
     * @var int
     */
    private $securityLevel;

    /**
     * 交易密码
     *
     * @Column(name="trade_pwd", prop="tradePwd")
     *
     * @var string
     */
    private $tradePwd;

    /**
     * 用户所属组。10为普通用户，20为商家用户, 30为测试用户组
     *
     * @Column(name="user_group", prop="userGroup")
     *
     * @var int
     */
    private $userGroup;

    /**
     * 用户头像
     *
     * @Column(name="user_pic", prop="userPic")
     *
     * @var string
     */
    private $userPic;

    /**
     * 有效推荐总数
     *
     * @Column(name="valid_invite_total_times", prop="validInviteTotalTimes")
     *
     * @var int|null
     */
    private $validInviteTotalTimes;


    /**
     * @param string $areaCode
     *
     * @return self
     */
    public function setAreaCode(string $areaCode): self
    {
        $this->areaCode = $areaCode;

        return $this;
    }

    /**
     * @param string $email
     *
     * @return self
     */
    public function setEmail(string $email): self
    {
        $this->email = $email;

        return $this;
    }

    /**
     * @param int $emailVerify
     *
     * @return self
     */
    public function setEmailVerify(int $emailVerify): self
    {
        $this->emailVerify = $emailVerify;

        return $this;
    }

    /**
     * @param int $forbiddenLogin
     *
     * @return self
     */
    public function setForbiddenLogin(int $forbiddenLogin): self
    {
        $this->forbiddenLogin = $forbiddenLogin;

        return $this;
    }

    /**
     * @param int $googleAuth
     *
     * @return self
     */
    public function setGoogleAuth(int $googleAuth): self
    {
        $this->googleAuth = $googleAuth;

        return $this;
    }

    /**
     * @param int $googleValidator
     *
     * @return self
     */
    public function setGoogleValidator(int $googleValidator): self
    {
        $this->googleValidator = $googleValidator;

        return $this;
    }

    /**
     * @param int $id
     *
     * @return self
     */
    public function setId(int $id): self
    {
        $this->id = $id;

        return $this;
    }

    /**
     * @param int $inviteId
     *
     * @return self
     */
    public function setInviteId(int $inviteId): self
    {
        $this->inviteId = $inviteId;

        return $this;
    }

    /**
     * @param int $inviteTotalTimes
     *
     * @return self
     */
    public function setInviteTotalTimes(int $inviteTotalTimes): self
    {
        $this->inviteTotalTimes = $inviteTotalTimes;

        return $this;
    }

    /**
     * @param int $invitorUid
     *
     * @return self
     */
    public function setInvitorUid(int $invitorUid): self
    {
        $this->invitorUid = $invitorUid;

        return $this;
    }

    /**
     * @param string $loginIp
     *
     * @return self
     */
    public function setLoginIp(string $loginIp): self
    {
        $this->loginIp = $loginIp;

        return $this;
    }

    /**
     * @param string $loginPwd
     *
     * @return self
     */
    public function setLoginPwd(string $loginPwd): self
    {
        $this->loginPwd = $loginPwd;

        return $this;
    }

    /**
     * @param int|null $loginTime
     *
     * @return self
     */
    public function setLoginTime(?int $loginTime): self
    {
        $this->loginTime = $loginTime;

        return $this;
    }

    /**
     * @param string $mobile
     *
     * @return self
     */
    public function setMobile(string $mobile): self
    {
        $this->mobile = $mobile;

        return $this;
    }

    /**
     * @param int $mobileVerify
     *
     * @return self
     */
    public function setMobileVerify(int $mobileVerify): self
    {
        $this->mobileVerify = $mobileVerify;

        return $this;
    }

    /**
     * @param string $nickname
     *
     * @return self
     */
    public function setNickname(string $nickname): self
    {
        $this->nickname = $nickname;

        return $this;
    }

    /**
     * @param string $registerIp
     *
     * @return self
     */
    public function setRegisterIp(string $registerIp): self
    {
        $this->registerIp = $registerIp;

        return $this;
    }

    /**
     * @param int $registerTime
     *
     * @return self
     */
    public function setRegisterTime(int $registerTime): self
    {
        $this->registerTime = $registerTime;

        return $this;
    }

    /**
     * @param string $salt
     *
     * @return self
     */
    public function setSalt(string $salt): self
    {
        $this->salt = $salt;

        return $this;
    }

    /**
     * @param int $secondCheck
     *
     * @return self
     */
    public function setSecondCheck(int $secondCheck): self
    {
        $this->secondCheck = $secondCheck;

        return $this;
    }

    /**
     * @param int $securityLevel
     *
     * @return self
     */
    public function setSecurityLevel(int $securityLevel): self
    {
        $this->securityLevel = $securityLevel;

        return $this;
    }

    /**
     * @param string $tradePwd
     *
     * @return self
     */
    public function setTradePwd(string $tradePwd): self
    {
        $this->tradePwd = $tradePwd;

        return $this;
    }

    /**
     * @param int $userGroup
     *
     * @return self
     */
    public function setUserGroup(int $userGroup): self
    {
        $this->userGroup = $userGroup;

        return $this;
    }

    /**
     * @param string $userPic
     *
     * @return self
     */
    public function setUserPic(string $userPic): self
    {
        $this->userPic = $userPic;

        return $this;
    }

    /**
     * @param int|null $validInviteTotalTimes
     *
     * @return self
     */
    public function setValidInviteTotalTimes(?int $validInviteTotalTimes): self
    {
        $this->validInviteTotalTimes = $validInviteTotalTimes;

        return $this;
    }

    /**
     * @return string
     */
    public function getAreaCode(): ?string
    {
        return $this->areaCode;
    }

    /**
     * @return string
     */
    public function getEmail(): ?string
    {
        return $this->email;
    }

    /**
     * @return int
     */
    public function getEmailVerify(): ?int
    {
        return $this->emailVerify;
    }

    /**
     * @return int
     */
    public function getForbiddenLogin(): ?int
    {
        return $this->forbiddenLogin;
    }

    /**
     * @return int
     */
    public function getGoogleAuth(): ?int
    {
        return $this->googleAuth;
    }

    /**
     * @return int
     */
    public function getGoogleValidator(): ?int
    {
        return $this->googleValidator;
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
    public function getInviteId(): ?int
    {
        return $this->inviteId;
    }

    /**
     * @return int
     */
    public function getInviteTotalTimes(): ?int
    {
        return $this->inviteTotalTimes;
    }

    /**
     * @return int
     */
    public function getInvitorUid(): ?int
    {
        return $this->invitorUid;
    }

    /**
     * @return string
     */
    public function getLoginIp(): ?string
    {
        return $this->loginIp;
    }

    /**
     * @return string
     */
    public function getLoginPwd(): ?string
    {
        return $this->loginPwd;
    }

    /**
     * @return int|null
     */
    public function getLoginTime(): ?int
    {
        return $this->loginTime;
    }

    /**
     * @return string
     */
    public function getMobile(): ?string
    {
        return $this->mobile;
    }

    /**
     * @return int
     */
    public function getMobileVerify(): ?int
    {
        return $this->mobileVerify;
    }

    /**
     * @return string
     */
    public function getNickname(): ?string
    {
        return $this->nickname;
    }

    /**
     * @return string
     */
    public function getRegisterIp(): ?string
    {
        return $this->registerIp;
    }

    /**
     * @return int
     */
    public function getRegisterTime(): ?int
    {
        return $this->registerTime;
    }

    /**
     * @return string
     */
    public function getSalt(): ?string
    {
        return $this->salt;
    }

    /**
     * @return int
     */
    public function getSecondCheck(): ?int
    {
        return $this->secondCheck;
    }

    /**
     * @return int
     */
    public function getSecurityLevel(): ?int
    {
        return $this->securityLevel;
    }

    /**
     * @return string
     */
    public function getTradePwd(): ?string
    {
        return $this->tradePwd;
    }

    /**
     * @return int
     */
    public function getUserGroup(): ?int
    {
        return $this->userGroup;
    }

    /**
     * @return string
     */
    public function getUserPic(): ?string
    {
        return $this->userPic;
    }

    /**
     * @return int|null
     */
    public function getValidInviteTotalTimes(): ?int
    {
        return $this->validInviteTotalTimes;
    }

}
