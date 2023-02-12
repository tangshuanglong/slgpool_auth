<?php

namespace App\Validator;

use Swoft\Validator\Annotation\Mapping\Email;
use Swoft\Validator\Annotation\Mapping\IsInt;
use Swoft\Validator\Annotation\Mapping\IsString;
use Swoft\Validator\Annotation\Mapping\Length;
use Swoft\Validator\Annotation\Mapping\NotEmpty;
use Swoft\Validator\Annotation\Mapping\NotInEnum;
use Swoft\Validator\Annotation\Mapping\Validator;
use Swoft\Validator\Annotation\Mapping\Enum;

/**
 * Class AuthValidator
 * @package App\Validator
 *
 * @Validator(name="AuthValidator")
 */
class AuthValidator{

    /**
     * 账号
     * @IsString()
     * @NotEmpty()
     * @var string
     */
    protected $account;

    /**
     * 密码
     * @IsString()
     * @NotEmpty()
     * @Length(min=32, max=32, message="登录密码长度错误")
     * @var string
     */
    protected $login_pwd;


    /**
     * 验证码
     * @IsString()
     * @NotEmpty()
     * @Length(min=6, max=6, message="验证码长度错误")
     * @var string
     */
    protected $verify_code;

    /**
     * 国家id
     * @IsInt()
     * @NotEmpty()
     * @var int
     */
    protected $country_id;

    /**
     * 邀请码
     * @IsString()
     * @var int
     */
    protected $invitor_code;

    /**
     * 注册类型
     * @IsString()
     */
    protected $register_type;

    /**
     * 发送短信类型
     * @IsString()
     * @var
     */
    protected $action;

    /**
     * 手机域码
     * @IsString()
     * @var
     */
    protected $area_code;

    /**
     * 登录类型
     * @IsString()
     * @NotEmpty()
     * @Enum(values={"mobile", "email"})
     * @var
     */
    protected $login_type;

    /**
     *
     * @IsString()
     * @Length(min=32, max=32, message="登录密码长度错误")
     * @var string
     */
    protected $token;

}
