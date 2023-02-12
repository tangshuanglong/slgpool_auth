<?php

namespace App\Http\Controller\Api;

use App\Lib\MyAuth;
use App\Lib\MyCode;
use App\Lib\MyCommon;
use App\Lib\MyGA;
use App\Lib\MyPushQueue;
use App\Lib\MyQuit;
use App\Lib\MyRedisHelper;
use App\Lib\MyToken;
use App\Lib\MyTrie;
use App\Lib\MyValidator;
use App\Model\Data\PaginationData;
use App\Model\Data\UserData;
use App\Model\Data\UserSecurityLogData;
use App\Model\Entity\GoogleSecret;
use App\Model\Entity\UserBasicalInfo;
use App\Rpc\Lib\VerifyInterface;
use Swoft\Bean\Annotation\Mapping\Inject;
use Swoft\Bean\BeanFactory;
use Swoft\Db\DB;
use Swoft\Http\Message\Request;
use Swoft\Http\Server\Annotation\Mapping\Controller;
use Swoft\Http\Server\Annotation\Mapping\Middleware;
use Swoft\Http\Server\Annotation\Mapping\Middlewares;
use App\Http\Middleware\AuthMiddleware;
use Swoft\Http\Server\Annotation\Mapping\RequestMapping;
use Swoft\Http\Server\Annotation\Mapping\RequestMethod;
use Swoft\Log\Helper\CLog;
use Swoft\Log\Helper\Log;
use Swoft\Redis\Redis;
use Swoft\Rpc\Client\Annotation\Mapping\Reference;

/**
 * Class SecurityController
 * @package App\Http\Controller\Api
 * @Controller(prefix="/v1/security")
 * @Middlewares({
 *     @Middleware(AuthMiddleware::class)
 * })
 */
class SecurityController
{

    /**
     * @Inject()
     * @var MyToken
     */
    private $myToken;

    /**
     * @Inject()
     * @var MyAuth
     */
    private $myAuth;

    /**
     * @Inject()
     * @var UserSecurityLogData
     */
    private $userSecurityLogData;

    /**
     * @Inject()
     * @var MyValidator
     */
    private $myValidator;

    /**
     * @Inject()
     * @var MyCommon
     */
    private $myCommon;

    /**
     * @Inject()
     * @var MyGA
     */
    private $myGA;

    /**
     * @Reference(pool="system.pool")
     * @var VerifyInterface
     */
    private $verifyService;

    /**
     * @Inject()
     * @var MyTrie
     */
    private $myTrie;

    /**
     * 用户登出
     * @param Request $request
     * @return mixed
     * @RequestMapping(method={RequestMethod::GET})
     */
    public function logout(Request $request)
    {
        Redis::hDel(config('login_user_info_key'), config('field_prefix') . $request->uid);
        $this->myToken->deleteToken($request->user_info['invite_id'], $request->client_type);
        return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
    }

    /**
     * 用户基本信息
     * @param Request $request
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     * @RequestMapping(method={RequestMethod::GET})
     */
    public function user_auth(Request $request)
    {
        $user_info = UserData::get_user_info($request->uid);
        if (!$user_info) {
            return MyQuit::returnMessage(MyCode::PARAM_ERROR, '请求错误');
        }
        //$user_info['account'] = $this->myCommon->phoneCipher($request->account, 3, 5);
        $user_info['account'] = $this->myCommon->phoneCipher($user_info['mobile'], 3, 5);
        return MyQuit::returnSuccess($user_info, MyCode::SUCCESS, 'success');
    }

    /**
     * 绑定邮箱
     * @param Request $request
     * @return array
     * @throws \ReflectionException
     * @throws \Swoft\Bean\Exception\ContainerException
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function bind_email(Request $request)
    {
        $params = $request->params;
        //验证参数
        //validate($params, 'SecurityValidator', ['email']);
        validate($params, 'AuthValidator', ['login_pwd', 'verify_code']);
        if (!$this->myCommon->is_email($params['email'])) {
            return MyQuit::returnMessage(MyCode::EMAIL_BING, '邮箱格式错误');
        }
        $email_exists = $this->myValidator->account_exists($params['email'], 'email');
        if ($email_exists) {
            return MyQuit::returnMessage(MyCode::EMAIL_BING, '邮箱已存在');
        }
        $verify_res = $this->myValidator->password_verify($request->uid, $params['login_pwd']);
        if (!$verify_res) {
            return MyQuit::returnMessage(MyCode::LOGIN_PASSWORD_ERROR, '密码错误');
        }
        //验证 验证码
        $res = $this->verifyService->verify_code($params['email'], $params['verify_code'], 'bind_email');
        if (!$res) {
            return MyQuit::returnMessage(MyCode::CAPTCHA, '验证码错误');
        }
        $up_res = UserBasicalInfo::where(['id' => $request->uid])->update(['email' => $params['email'], 'email_verify' => 1]);
        if ($up_res) {
            //添加安全记录
            $this->userSecurityLogData->insert_security_log_login($request, 'bind_email');
            //重置缓存信息
            UserData::reset_user_all_info($request->uid);
            return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnMessage(MyCode::SERVER_ERROR, '系统繁忙');
    }

    /**
     * 绑定手机
     * @param Request $request
     * @return array
     * @throws \ReflectionException
     * @throws \Swoft\Bean\Exception\ContainerException
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function bind_mobile(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'SecurityValidator', ['mobile', 'area_code']);
        validate($params, 'AuthValidator', ['login_pwd', 'verify_code']);
        //验证手机号码格式
        $res = $this->myCommon->is_mobile($params['mobile'], $params['area_code']);
        if (!$res) {
            return MyQuit::returnMessage(MyCode::PHONE_FORMAT_ERROR, '手机号格式错误');
        }
        $mobile_exists = $this->myValidator->account_exists($params['mobile'], 'mobile');
        if ($mobile_exists) {
            return MyQuit::returnMessage(MyCode::PHONE_BING, '手机号已被绑定');
        }
        $verify_res = $this->myValidator->password_verify($request->uid, $params['login_pwd']);
        if (!$verify_res) {
            return MyQuit::returnMessage(MyCode::LOGIN_PASSWORD_ERROR, '密码错误');
        }
        //验证 验证码
        $res = $this->verifyService->verify_code($params['mobile'], $params['verify_code'], 'bind_mobile');
        if (!$res) {
            return MyQuit::returnMessage(MyCode::CAPTCHA, '验证码错误');
        }

        $up_res = UserBasicalInfo::where(['id' => $request->uid])->update(['mobile' => $params['mobile'], 'mobile_verify' => 1]);
        if ($up_res) {
            //添加安全记录
            $this->userSecurityLogData->insert_security_log_login($request, 'bind_mobile');
            //重置缓存信息
            UserData::reset_user_all_info($request->uid);
            return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnMessage(MyCode::SERVER_ERROR, '服务器错误');
    }

    /**
     * 修改手机时第一步，先验证新的手机的正确性
     * @param Request $request
     * @return array
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function verify_mobile(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'SecurityValidator', ['mobile', 'area_code']);
        validate($params, 'AuthValidator', ['verify_code']);
        //验证手机号码格式
        $res = $this->myCommon->is_mobile($params['mobile'], $params['area_code']);
        if (!$res) {
            return MyQuit::returnMessage(MyCode::PHONE_FORMAT_ERROR, '手机号格式错误');
        }
        $mobile_exists = $this->myValidator->account_exists($params['mobile'], 'mobile');
        if ($mobile_exists) {
            return MyQuit::returnMessage(MyCode::PHONE_BING, '手机号已被绑定');
        }
        //验证 验证码
        $res = $this->verifyService->verify_code($params['mobile'], $params['verify_code'], 'modify_mobile');
        if (!$res) {
            return MyQuit::returnMessage(MyCode::CAPTCHA, '验证码错误');
        }
        $data = [
            'mobile'    => $params['mobile'],
            'area_code' => $params['area_code'],
        ];
        $res = Redis::set(config('modify_mobile_key') . $request->uid, json_encode($data), ['EX' => 86400]);
        if ($res) {
            return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnMessage(MyCode::SERVER_ERROR, '服务器错误');
    }

    /**
     * 修改手机
     * @param Request $request
     * @return array|bool|int|string
     * @throws \ReflectionException
     * @throws \Swoft\Bean\Exception\ContainerException
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function modify_mobile(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'SecurityValidator', ['gv_code', 'mv_code', 'ev_code']);
        //验证
        $data = Redis::get(config("modify_mobile_key") . $request->uid);
        if (empty($data)) {
            return MyQuit::returnMessage(MyCode::OPERATE_EXPIRE, '操作到期');
        }
        $data = json_decode($data, true);
        //验证所有开启验证的验证码
        $action = 'modify_mobile';
        $res = $this->verifyService->auth_all_verify_code($request->uid, $params, $action);
        if ($res !== true) {
            return MyQuit::returnMessage($res['code'], $res['msg']);
        }
        $res = UserBasicalInfo::where(['id' => $request->uid])->update(['mobile' => $data['mobile'], 'area_code' => $data['area_code']]);
        if ($res) {
            //设置24小时内不能提现
            Redis::set(config('not_withdraw_key') . '_' . $request->uid, 1, ["EX" => config('not_withdraw_time')]);
            //重置缓存信息
            UserData::reset_user_all_info($request->uid);
            //添加安全记录
            $this->userSecurityLogData->insert_security_log_login($request, $action);
            //删除缓存
            Redis::del(config("modify_mobile_key") . $request->uid);
            return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnMessage(MyCode::SERVER_ERROR, '服务器错误');
    }

    /**
     * 谷歌验证秘钥
     * @param Request $request
     * @return array
     * @RequestMapping(method={RequestMethod::GET})
     */
    public function google_secret(Request $request)
    {
        $secret = $this->myGA->createSecret();
        $qrCodeUrl = $this->myGA->getQRCodeGoogleUrl($request->account, $secret, config('google_secret_title'));
        $data = [
            'secret' => $secret,
            'url'    => $qrCodeUrl,
        ];

        $res = MyRedisHelper::hSet(config("google_secret_key"), (string)$request->uid, $data);
        if ($res) {
            return MyQuit::returnSuccess($data, MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnMessage(MyCode::SERVER_ERROR, '服务器错误');
    }

    /**
     * 绑定/修改谷歌验证
     * @param Request $request
     * @return array|bool|string
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function set_google_auth(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'SecurityValidator', ['gv_code', 'operate_type']);
        validate($params, 'AuthValidator', ['login_pwd', 'verify_code']);
        //验证
        $secret_data = Redis::hGet(config("google_secret_key"), (string)$request->uid);
        if (empty($secret_data)) {
            return MyQuit::returnMessage(MyCode::OPERATE_EXPIRE, '操作到期');
        }
        $secret_data = json_decode($secret_data, true);
        // 验证谷歌验证码
        $res = $this->myGA->verifyCode($secret_data['secret'], $params['verify_code'], 2);
        if (!$res) {
            return MyQuit::returnMessage(MyCode::NEW_CAPTCHA_GOOGLE_ERROR, '谷歌验证码错误');
        }
        //验证手机和邮箱验证码
        $is_exists = GoogleSecret::where(['uid' => $request->uid])->exists();
        if ($params['operate_type'] === 'bind') {
            $action = 'bind_google_auth';
            if ($is_exists) {
                return MyQuit::returnMessage(MyCode::OPERATE_ERROR, '操作错误');
            }
        } else {
            $action = 'modify_google_auth';
            if (!$is_exists) {
                return MyQuit::returnMessage(MyCode::OPERATE_ERROR, '操作错误');
            }
            //验证谷歌验证码
            $res = $this->verifyService->google_verify($params['gv_code'], $request->uid);
            if (!$res) {
                return MyQuit::returnMessage(MyCode::OLD_CAPTCHA_GOOGLE_ERROR, '谷歌验证码错误');
            }
        }
        $verify_res = $this->myValidator->password_verify($request->uid, $params['login_pwd']);
        if (!$verify_res) {
            return MyQuit::returnMessage(MyCode::LOGIN_PASSWORD_ERROR, '密码错误');
        }
        DB::beginTransaction();
        try {
            if ($params['operate_type'] === 'bind') {
                $up_res = UserBasicalInfo::where(['id' => $request->uid])->update(['google_auth' => 1, 'google_validator' => 1]);
                if (!$up_res) {
                    throw new \Exception('update UserBasicalInfo info error');
                }
            }
            $secret_data['uid'] = $request->uid;
            $secret_data['create_time'] = time();
            if ($params['operate_type'] === 'bind') {
                $insert_res = GoogleSecret::insert($secret_data);
                if (!$insert_res) {
                    throw new \Exception('insert GoogleSecret info error');
                }
            } else {
                $update_res = GoogleSecret::where(['uid' => $request->uid])->update($secret_data);
                if (!$update_res) {
                    throw new \Exception('update GoogleSecret info error');
                }
            }
            //删除缓存
            $del_res = Redis::hDel(config("google_secret_key"), (string)$request->uid);
            if (!$del_res) {
                throw new \Exception('del google_secret_key error');
            }
            DB::commit();
            UserData::reset_user_all_info($request->uid);
            //如果为修改，禁止24内提现
            if ($params['operate_type'] === 'modify') {
                Redis::set(config('not_withdraw_key') . '_' . $request->uid, 1, ["EX" => config('not_withdraw_time')]);
            }
            //添加安全记录
            $this->userSecurityLogData->insert_security_log_login($request, $action);
            return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
        } catch (\Exception $e) {
            DB::rollBack();
            // Log
            Log::error($e->getMessage());
            CLog::error($e->getMessage());
            return MyQuit::returnMessage(MyCode::SERVER_ERROR, '系统繁忙');
        }
    }

    /**
     * 关闭验证
     * @param Request $request
     * @return array
     * @throws \ReflectionException
     * @throws \Swoft\Bean\Exception\ContainerException
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function off_verify(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'SecurityValidator', ['type', 'mv_code', 'ev_code', 'gv_code']);
        $action = '';
        if ($params['type'] === 'email_verify') {
            if ($request->user_info['email'] == '') {
                return MyQuit::returnMessage(MyCode::PARAM_ERROR, '参数错误');
            }
            $action = 'off_email_verify';
        }
        if ($params['type'] === 'mobile_verify') {
            if ($request->user_info['mobile'] == '') {
                return MyQuit::returnMessage(MyCode::PARAM_ERROR, '参数错误');
            }
            $action = 'off_mobile_verify';
        }
        if ($params['type'] === 'google_validator') {
            $action = 'off_ga_verify';
        }
        //验证 验证码
        $res = $this->verifyService->auth_all_verify_code($request->uid, $params, $action);
        if ($res !== true) {
            return MyQuit::returnMessage($res['code'], $res['msg']);
        }
        $verify_times = 0;
        if ($request->user_info['email_verify'] == 1) {
            $verify_times++;
        }
        if ($request->user_info['mobile_verify'] == 1) {
            $verify_times++;
        }
        if ($request->user_info['google_validator'] == 1) {
            $verify_times++;
        }
        if ($verify_times <= 1) {
            return MyQuit::returnMessage(MyCode::VERIFY_ITEM, '验证项至少有一个');
        }
        //置为0
        $res = UserBasicalInfo::where(['id' => $request->uid])->update([$params['type'] => 0]);
        if ($res) {
            //设置24小时内不能提现
            Redis::set(config('not_withdraw_key') . '_' . $request->uid, 1, ["EX" => config('not_withdraw_time')]);
            //重置缓存信息
            UserData::reset_user_all_info($request->uid);
            //添加安全记录
            $this->userSecurityLogData->insert_security_log_login($request, $action);
            return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnMessage(MyCode::SERVER_ERROR, '系统繁忙');
    }

    /**
     * 开启验证
     * @param Request $request
     * @return array
     * @throws \ReflectionException
     * @throws \Swoft\Bean\Exception\ContainerException
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function on_verify(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'SecurityValidator', ['type']);
        validate($params, 'AuthValidator', ['verify_code']);
        $res = false;
        $action = '';
        //TODO 如果是否验证的表字段进行修改，前端type传参和这里判断都需要进行修改
        if ($params['type'] === 'email_verify') {
            $action = 'on_email_verify';
            $res = $this->verifyService->verify_code($request->user_info['email'], $params['verify_code'], 'on_email_verify');
        }
        if ($params['type'] === 'mobile_verify') {
            $action = 'on_mobile_verify';
            $res = $this->verifyService->verify_code($request->user_info['mobile'], $params['verify_code'], 'on_mobile_verify');
        }
        if ($params['type'] === 'google_validator') {
            $action = 'on_ga_verify';
            $res = $this->verifyService->google_verify($params['verify_code'], $request->uid);
        }
        if (!$res) {
            return MyQuit::returnMessage(MyCode::CAPTCHA, '验证码错误');
        }

        //置为1
        $userInfo = DB::table('user_basical_info')->where(['id' => $request->uid])->firstArray();
        if ($userInfo[$params['type']] === 1) {
            return MyQuit::returnMessage(MyCode::SERVER_ERROR, '该验证已是开启状态');
        }

        $res = UserBasicalInfo::where(['id' => $request->uid])->update([$params['type'] => 1]);
        if ($res) {
            //重置缓存信息
            UserData::reset_user_all_info($request->uid);
            //添加安全记录
            $this->userSecurityLogData->insert_security_log_login($request, $action);
            return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnMessage(MyCode::SERVER_ERROR, '系统繁忙');
    }

    /**
     * 修改密码， 修改后24小时内不能提现
     * @param Request $request
     * @return array
     * @throws \ReflectionException
     * @throws \Swoft\Bean\Exception\ContainerException
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function modify_pwd(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'SecurityValidator', ['old_pwd', 'new_pwd', 'gv_code']);
        if ($params['old_pwd'] === $params['new_pwd']) {
            return MyQuit::returnMessage(MyCode::PWD_SIMILARITY, '新的密码不能与旧的密码相同');
        }
        $res = $this->myValidator->password_verify($request->uid, $params['old_pwd']);
        if (!$res) {
            return MyQuit::returnMessage(MyCode::LOGIN_PASSWORD_ERROR, '旧密码错误');
        }
        $user_bind_info = UserData::get_bind_info($request->uid);
        //如果开启谷歌验证
        if ($user_bind_info['google_validator'] == 1) {
            //验证谷歌验证码
            if ($params['gv_code'] === '') {
                return MyQuit::returnMessage(MyCode::PARAM_ERROR, '参数错误');
            }
            $res = $this->verifyService->google_verify($params['gv_code'], $request->uid);
            if (!$res) {
                return MyQuit::returnMessage(MyCode::CAPTCHA_GOOGLE_ERROR, '谷歌验证码错误');
            }
        }
        $pwd = $this->myAuth->generate_password($params['new_pwd'], $request->user_info['salt']);
        $res = UserBasicalInfo::where(['id' => $request->uid])->update(['login_pwd' => $pwd['password_hash']]);
        if ($res) {
            //设置24小时内不能提现
            Redis::set(config('not_withdraw_key') . '_' . $request->uid, 1, ["EX" => config('not_withdraw_time')]);
            //添加安全记录
            $this->userSecurityLogData->insert_security_log_login($request, 'modify_pwd');
            //删除登录状态
            Redis::hDel(config('login_user_info_key'), config('field_prefix') . $request->uid);
            $this->myToken->deleteToken($request->user_info['invite_id'], $request->client_type);
            return MyQuit::returnMessage(MyCode::SUCCESS, '');
        }
        return MyQuit::returnMessage(MyCode::SERVER_ERROR, '系统繁忙');
    }

    /**
     * 设置和重置交易密码
     * @param Request $request
     * @return array
     * @throws \ReflectionException
     * @throws \Swoft\Bean\Exception\ContainerException
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function set_trade_pwd(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'SecurityValidator', ['trade_pwd', 'mv_code', 'ev_code', 'gv_code']);

        //验证 验证码
        $action = 'set_trade_pwd';
        if ($request->user_info['trade_pwd']) {
            $action = 'reset_trade_pwd';
        }
        $res = $this->verifyService->auth_all_verify_code($request->uid, $params, $action);
        if ($res !== true) {
            return MyQuit::returnMessage($res['code'], $res['msg']);
        }
        $trade_pwd = $this->myAuth->generate_trade_password($params['trade_pwd'], $request->user_info['salt']);
        if ($trade_pwd === $request->user_info['login_pwd']) {
            return MyQuit::returnMessage(MyCode::PWD_DIFF, '交易密码不能和登录密码一致');
        }
        if ($trade_pwd === $request->user_info['trade_pwd']) {
            return MyQuit::returnMessage(MyCode::TRADE_PWD_SAME, '交易密码一致');
        }
        $res = UserBasicalInfo::where(['id' => $request->uid])->update(['trade_pwd' => $trade_pwd]);
        if ($res) {
            //重置缓存信息
            UserData::reset_user_all_info($request->uid);
            //添加安全记录
            $this->userSecurityLogData->insert_security_log_login($request, $action);
            return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnMessage(MyCode::SERVER_ERROR, '系统繁忙');
    }

    /**
     * 设置用户昵称
     * @param Request $request
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function set_nickname(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'SecurityValidator', ['nickname']);
        //验证是否存在敏感词汇
        if ($this->myTrie->exists($params['nickname'])) {
            return MyQuit::returnMessage(MyCode::NICKNAME_INVALID, '昵称存在敏感词汇');
        }
        UserBasicalInfo::where(['id' => $request->uid])->update(['nickname' => $params['nickname']]);
        //重置缓存信息
        UserData::reset_user_all_info($request->uid);
        return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
    }

    /**
     * 设置用户头像
     * @param Request $request
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function set_user_pic(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'SecurityValidator', ['pic']);
        $user_pic = MyCommon::get_filename($params['pic']);
        if (!$user_pic) {
            return MyQuit::returnMessage(MyCode::PARAM_ERROR, '头像路径错误');
        }
        UserBasicalInfo::where(['id' => $request->uid])->update(['user_pic' => $user_pic]);
        //重置缓存信息
        UserData::reset_user_all_info($request->uid);
        return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
    }

    /**
     * 安全日志类型列表【暂时没用】
     * @param Request $request
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     * @RequestMapping(method={RequestMethod::GET})
     */
    public function security_type_list(Request $request)
    {
        $data = DB::table('user_security_type')->get()->toArray();
        return MyQuit::returnSuccess($data, MyCode::SUCCESS, 'success');
    }

    /**
     * 登录记录【暂时没用】
     * @param Request $request
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     * @RequestMapping(method={RequestMethod::GET})
     */
    public function login_record(Request $request)
    {
        $params = $request->params;
        $page = $params['page'] ?? 1;
        $size = $params['size'] ?? config('page_num');
        //登录记录的类型id为1
        $where = [];
        $data = PaginationData::table('user_security_log')->select('id', 'ip', 'address', 'device_type', 'status', 'fail_type', 'create_time')
            ->where(['uid' => $request->uid, 'type_id' => 1])->forPage($page, $size)->orderBy('id', 'desc')->get();
        foreach ($data['data'] as $key => $val) {
            $data['data'][$key]['create_time'] = date("Y-m-d H:i:s", $val['create_time']);
        }
        return MyQuit::returnSuccess($data, MyCode::SUCCESS, 'success');
    }

    /**
     * 安全记录【暂时没用】
     * @param Request $request
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     * @RequestMapping(method={RequestMethod::GET})
     */
    public function security_record(Request $request)
    {
        $params = $request->params;
        $page = $params['page'] ?? 1;
        $size = $params['size'] ?? config('page_num');
        //除了登录类型
        $data = PaginationData::table('user_security_log')->select('id', 'type_id', 'type_name', 'ip', 'address', 'device_type', 'create_time')
            ->where(['uid' => $request->uid, ['type_id', '!=', 1]])->forPage($page, $size)->orderBy('id', 'desc')->get();
        foreach ($data['data'] as $key => $val) {
            $data['data'][$key]['create_time'] = date("Y-m-d H:i:s", $val['create_time']);
        }
        return MyQuit::returnSuccess($data, MyCode::SUCCESS, 'success');
    }

}
