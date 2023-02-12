<?php

namespace App\Validator;

use Swoft\Validator\Annotation\Mapping\ChsAlphaDash;
use Swoft\Validator\Annotation\Mapping\Enum;
use Swoft\Validator\Annotation\Mapping\Email;
use Swoft\Validator\Annotation\Mapping\IsInt;
use Swoft\Validator\Annotation\Mapping\IsString;
use Swoft\Validator\Annotation\Mapping\Length;
use Swoft\Validator\Annotation\Mapping\NotEmpty;
use Swoft\Validator\Annotation\Mapping\NotInEnum;
use Swoft\Validator\Annotation\Mapping\Validator;


/**
 * Class AuthValidator
 * @package App\Validator
 *
 * @Validator(name="SecurityValidator")
 */
class SecurityValidator{

    /**
     * 原密码
     * @IsString()
     * @NotEmpty()
     * @Length(min=32, max=32, message="old_pwd length error")
     * @var string
     */
    protected $old_pwd;

    /**
     * 登录密码
     * @IsString()
     * @NotEmpty()
     * @Length(min=32, max=32, message="登录密码长度错误")
     * @var string
     */
    protected $login_pwd;

    /**
     * 新密码
     * @IsString()
     * @NotEmpty()
     * @Length(min=32, max=32, message="new_pwd length error")
     * @var string
     */
    protected $new_pwd;

    /**
     * 交易密码
     * @IsString()
     * @NotEmpty()
     * @Length(min=32, max=32, message="trade_pwd length error")
     * @var string
     */
    protected $trade_pwd;

    /**
     * 手机验证码
     * @IsString()
     * @var
     */
    protected $mv_code;

    /**
     * 邮箱验证码
     * @IsString()
     * @var
     */
    protected $ev_code;

    /**
     * 谷歌验证码
     * @IsString()
     * @var
     */
    protected $gv_code;

    /**
     * @IsString()
     * @Email()
     * @NotEmpty()
     * @var
     */
    protected $email;

    /**
     * @IsString()
     * @NotEmpty()
     * @var
     */
    protected $mobile;

    /**
     * 手机区码
     * @IsString()
     * @NotEmpty()
     * @var
     */
    protected $area_code;

    /**
     * @IsString()
     * @NotEmpty()
     * @Enum(values={"email_verify", "mobile_verify", "google_validator"})
     * @var
     */
    protected $type;

    /**
     * 谷歌验证操作类型
     * @IsString()
     * @NotEmpty()
     * @Enum(values={"bind", "modify"})
     * @var
     */
    protected $operate_type;

    /**
     * 头像
     * @IsString()
     * @NotEmpty()
     * @var
     */
    protected $pic;

    /**
     * 头像
     * @IsString()
     * @NotEmpty()
     * @ChsAlphaDash()
     * @var
     */
    protected $nickname;



}
