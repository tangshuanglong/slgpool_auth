<?php declare(strict_types=1);

namespace App\Http\Controller\Api;

use App\Lib\MyPushQueue;
use App\Lib\MyRedisHelper;
use App\Lib\MyToken;
use App\Migration\User;
use App\Model\Data\UserData;
use App\Model\Data\UserSecurityLogData;
use App\Model\Entity\CountryCode;
use App\Model\Entity\InviteLog;
use App\Model\Entity\UserBasicalInfo;
use App\Model\Entity\UserSecurityLog;
use App\Rpc\Lib\AuthInterface;
use App\Rpc\Lib\CountryCodeInterface;
use App\Rpc\Lib\InviteLogInterface;
use App\Rpc\Lib\VerifyCodeInterface;
use Swoft\Bean\BeanFactory;
use Swoft\Db\DB;
use Swoft\Http\Server\Annotation\Mapping\RequestMapping;
use Swoft\Http\Server\Annotation\Mapping\Controller;
use Swoft\Http\Server\Annotation\Mapping\RequestMethod;
use Swoft\Http\Message\Request;
use App\Http\Middleware\BaseMiddleware;
use Swoft\Http\Server\Annotation\Mapping\Middleware;
use Swoft\Http\Server\Annotation\Mapping\Middlewares;
use Swoft\Log\Helper\CLog;
use Swoft\Log\Helper\Log;
use Swoft\Redis\Redis;
use Swoft\Bean\Annotation\Mapping\Inject;
use App\Lib\MyQuit;
use App\Lib\MyCode;
use App\Lib\MyAuth;
use App\Lib\MyCommon;
use App\Lib\MyValidator;
use Swoft\Rpc\Client\Annotation\Mapping\Reference;
use Swoft\Stdlib\Helper\JsonHelper;
use App\Rpc\Lib\VerifyInterface;


/**
 * 登录，注册验证类
 * Class AuthController
 * @package App\Http\Controller\Api
 *
 * Author j
 * Date 2019/11/28
 *
 * @Controller(prefix="/v1/auth")
 */
class AuthController
{

    /**
     * @Inject()
     * @var MyCommon
     */
    private $myCommon;

    /**
     * @Inject()
     * @var MyAuth
     */
    private $myAuth;

    /**
     * @Inject()
     * @var MyValidator
     */
    private $myValidator;

    /**
     * @Inject()
     * @var MyToken
     */
    private $myToken;

    /**
     * @Inject()
     * @var UserSecurityLogData
     */
    private $userSecurityLogData;

    /**
     * @Reference(pool="system.pool")
     * @var CountryCodeInterface
     */
    private $countryCode;

    /**
     * @Reference(pool="system.pool")
     * @var VerifyInterface
     */
    private $verifyService;

    /**
     * @Reference(pool="system.pool")
     * @var VerifyCodeInterface
     */
    private $verifyCodeService;

    private $login_key = 'login_second_verify_key';

    private $forbidden_key = 'login_forbidden_key';

    /**
     * @Reference(pool="user.pool")
     * @var InviteLogInterface
     */
    private $InviteLogServer;

    /**
     * 注册接口
     * @param Request $request
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function register(Request $request): array
    {
        $params = $request->params;
        //验证参数
        validate($params, 'AuthValidator', ['account', 'login_pwd', 'verify_code', 'invitor_code', 'area_code']);
        //验证account类型
        $account_type = $this->myValidator->account_check($params['account'], $params['area_code']);
        if ($account_type === false) {
            return MyQuit::returnMessage(MyCode::ACCOUNT_ERROR, '账号必须为邮箱/手机号码！');
        }
        //判断area_code是否存在， 和国家信息不对应，存在国籍和使用的手机号不同
        if (!$this->myCommon->is_email($params['account'])) {
            $area_code_exists = $this->countryCode->is_exists(['area_code' => $params['area_code']]);
            if ($area_code_exists == false) {
                return MyQuit::returnMessage(MyCode::PARAM_ERROR, '参数错误！');
            }
        }
        //验证验证码
        $code_verify = $this->verifyService->verify_code($params['account'], $params['verify_code'], 'register');
        if ($code_verify === false) {
            return MyQuit::returnMessage(MyCode::CAPTCHA, '验证码错误或超时！');
        }
        //验证账号是否已经注册
        $account_exists = $this->myValidator->account_exists($params['account'], $account_type);
        if ($account_exists) {
            return MyQuit::returnMessage(MyCode::REGISTER_ALREADY, '注册用户已经存在！');
        }
        //如果存在推荐码，查看推荐码是否存在
        $invitor_id = [];
        if (!empty($params['invitor_code'])) {
            $invitor_id = UserBasicalInfo::select('id')->where(['invite_id' => $params['invitor_code']])->first();
            if (!$invitor_id) {
                return MyQuit::returnMessage(MyCode::INVITE_CODE_NOT_EXISTS, '推荐码不存在！');
            }
            $params['invitor_uid'] = $invitor_id['id'];
        }
        $login_pwd = $this->myAuth->generate_password($params['login_pwd']);
        $current_time = time();
        $params[$account_type] = $params['account'];
        $params['login_pwd'] = $login_pwd['password_hash'];
        $params['salt'] = $login_pwd['salt'];
        $params['register_time'] = $current_time;
        $params['user_agent'] = $request->client_type;
        $params[$account_type . '_verify'] = 1;
        //获取ip和ip的地域
        $params['register_ip'] = $request->ip;
        $ip_area = $this->myCommon->get_ip_area($request->ip);
        DB::beginTransaction();
        try {
            $uid = UserBasicalInfo::insertGetId($params);
            if (!$uid) {
                throw new \Exception('user info insert error!');
            }
            $invite_id = (int)($uid + config('invite_prefix'));
            $up_res = UserBasicalInfo::where(['id' => $uid])->update(['invite_id' => $invite_id, 'nickname' => $invite_id]);
            if (!$up_res) {
                throw new \Exception('up user info error!');
            }
            //如果有推荐人
            if (isset($params['invitor_uid'])) {
                //邀请总数加1
                $invitor_update_res = UserBasicalInfo::where(['id' => $invitor_id['id']])->increment('invite_total_times', 1);
                if (!$invitor_update_res) {
                    throw new \Exception('up invitor user info error!');
                }
                //增加邀请记录表
                $invite_data = [
                    'uid'             => $invitor_id['id'],
                    'invited_uid'     => $uid,
                    'invited_account' => $params['account'],
                    'create_time'     => $current_time
                ];
                $invite_log = $this->InviteLogServer->insert_invite_log($invite_data);
                if (!$invite_log) {
                    throw new \Exception('invited log insert error!');
                }
            }

            //增加用户安全信息表
            $security_log = [
                'uid'         => $uid,
                'ip'          => $request->ip,
                'address'     => $ip_area,
                'device_type' => $request->client_type,
                'device_id'   => $request->device_id,
            ];
            $security_log_res = $this->userSecurityLogData->insert_security_log($security_log, 'register');
            if (!$security_log_res) {
                throw new \Exception('security log info insert error!');
            }
            DB::commit();
            //发送短信通知
            $this->myCommon->push_notice_queue($params['account'], $params['area_code'], 'register_success_id');
            $response = MyQuit::returnSuccess([], MyCode::SUCCESS, '注册成功');
        } catch (\Exception $e) {
            DB::rollBack();
            // Log
            Log::error($e->getMessage());
            CLog::error($e->getMessage());
            $response = MyQuit::returnMessage(MyCode::SERVER_ERROR, '服务器繁忙');
        }
        return $response;
    }

    /**
     * 登录接口
     * @param Request $request
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function login(Request $request): array
    {
        $params = $request->post();
        //验证参数
        validate($params, 'AuthValidator', ['account', 'login_type', 'login_pwd']);
        $login_error_key = config('app.login_error_key') . ':' . $params['account'];
        if (Redis::get($login_error_key) >= config('app.login_error_limit')) {
            return MyQuit::returnMessage(MyCode::LOGIN_ERROR_LIMIT, '登录错误次数太多，请5分钟后重试！');
        }

        //判断账号是否存在和密码是否正确，正确返回用户信息array，密码错误返回用户id
        $user_info = $this->myValidator->account_verify($params['account'], $params['login_type'], $params['login_pwd']);
        if ($user_info === false || is_numeric($user_info)) {
            $ip_area = $this->myCommon->get_ip_area($request->ip);
            $security_log = [
                'uid'         => $user_info,
                'ip'          => $request->ip,
                'address'     => $ip_area,
                'device_type' => $request->client_type,
                'device_id'   => $request->device_id,
            ];
            $this->userSecurityLogData->insert_security_log($security_log, 'login', 0, 1);
            //记录密码错误次数
            Redis::incr($login_error_key);
            Redis::expire($login_error_key, 300);
            return MyQuit::returnMessage(MyCode::PASSWORD_ERROR, '用户名不存在或密码错误');
        }
        //返回数据给前端，二步验证用
        $data = [
            'account'          => $params['account'],
            'uid'              => $user_info['id'],
            'user_id'          => $user_info['invite_id'],
            'google_validator' => (int)$user_info['google_validator'],
            'mobile_verify'    => (int)$user_info['mobile_verify'],
            'email_verify'     => (int)$user_info['email_verify'],
        ];
        //删除错误次数记录
        Redis::del($login_error_key);
        //二步登录使用的缓存数据
        // $redis_data = $data;
        // $redis_data['uid'] = $user_info['id'];
        // $redis_data['create_time'] = time();
        // $res = MyRedisHelper::hSet($this->login_key, $params['account'], $redis_data);
        // if ($res) {
        //     //谷歌验证>手机验证>邮箱验证
        //     if ($data['google_validator'] === 0) {
        //         $action = 'login';
        //         if ($data['mobile_verify'] === 1) {
        //             $this->verifyCodeService->send_verify_code($user_info['mobile'], $user_info['area_code'], $action);
        //         } else {
        //             $this->verifyCodeService->send_verify_code($user_info['email'], $user_info['area_code'], $action);
        //         }
        //     }
        //     return MyQuit::returnSuccess($data, MyCode::SUCCESS, 'success');
        // }
        // return MyQuit::returnMessage(MyCode::SERVER_ERROR, '服务繁忙');

        DB::beginTransaction();
        try {
        $ip_area = $this->myCommon->get_ip_area($request->ip);
        $security_log = [
            'uid'         => $data['uid'],
            'ip'          => $request->ip,
            'address'     => $ip_area,
            'device_type' => $request->client_type,
            'device_id'   => $request->device_id,
        ];
        $res = $this->userSecurityLogData->insert_security_log($security_log, 'login');
        if (!$res) {
            throw new \Exception('insert secure log error');
        }
        $login_data = [
            'login_ip'   => $request->ip,
            'login_time' => time(),
        ];
        $res = UserBasicalInfo::where(['id' => $data['uid']])->update($login_data);
        if (!$res) {
            throw new \Exception('update login log error');
        }
        $token = $this->myToken->generateToken($data['user_id'], $data['account'], $request->client_type, $request->device_id);
        //记录用户活跃时间，用于判断用户是否已经下线
        array_push($user_info, time());
        Redis::hSet(config('login_user_info_key'), config('field_prefix') . $user_info['id'],
            JsonHelper::encode($user_info));
        $send_data = [
            $params['account'],
            $date = date("Y/m/d H:i:s") . '(UTC/GMT+08:00)',
        ];
        $this->myCommon->push_notice_queue($data['account'], $user_info['area_code'], 'login_temp_id', '', $send_data);
        // Redis::hDel($this->login_key, $params['account']);
        DB::commit();
        $data['token'] = $token;
        return MyQuit::returnSuccess($data, MyCode::SUCCESS, '登录成功');
        } catch (\Exception $e) {
            print_r($e->getMessage());
            DB::rollBack();
            return MyQuit::returnMessage(MyCode::SERVER_ERROR, '服务繁忙');
        }
    }

    /**
     * 用户二步登录【暂时不用】
     * @param Request $request
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @throws \Swoft\Db\Exception\DbException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function second_verify(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'AuthValidator', ['account', 'verify_code']);

        $data = Redis::hGet($this->login_key, $params['account']);
        if (!$data) {
            return MyQuit::returnMessage(MyCode::PARAM_ERROR, '参数错误');
        }
        $data = JsonHelper::decode($data, true);
        if (time() > $data['create_time'] + config('app.second_login_expire_time', 3600)) {
            return MyQuit::returnMessage(MyCode::SECOND_CHECK_EXPIRE, '二步验证过期');
        }

        $user_info = DB::table('user_basical_info')->where(['id' => $data['uid']])->first();
        if (!$user_info) {
            return MyQuit::returnMessage(MyCode::PARAM_ERROR, '参数错误');
        }

        $action = 'login';
        if ($data['google_validator'] == 0) {
            //验证短信验证码
            if ($data['mobile_verify']) {
                $verify_res = $this->verifyService->verify_code($user_info['mobile'], $params['verify_code'], $action);
            } else {//验证邮箱
                $verify_res = $this->verifyService->verify_code($user_info['email'], $params['verify_code'], $action);
            }
        } else {//验证谷歌验证码
            $verify_res = $this->verifyService->google_verify($params['verify_code'], $data['uid']);
        }
        if (!$verify_res) {
            return MyQuit::returnMessage(MyCode::CAPTCHA, '验证码错误或超时！');
        }

        DB::beginTransaction();
        try {
            $ip_area = $this->myCommon->get_ip_area($request->ip);
            $security_log = [
                'uid'         => $data['uid'],
                'ip'          => $request->ip,
                'address'     => $ip_area,
                'device_type' => $request->client_type,
                'device_id'   => $request->device_id,
            ];
            $res = $this->userSecurityLogData->insert_security_log($security_log, 'login');
            if (!$res) {
                throw new \Exception('insert secure log error');
            }
            $login_data = [
                'login_ip'   => $request->ip,
                'login_time' => time(),
            ];
            $res = UserBasicalInfo::where(['id' => $data['uid']])->update($login_data);
            if (!$res) {
                throw new \Exception('update login log error');
            }
            $token = $this->myToken->generateToken($data['user_id'], $data['account'], $request->client_type, $request->device_id);
            //记录用户活跃时间，用于判断用户是否已经下线
            $user_info['action_time'] = time();
            Redis::hSet(config('login_user_info_key'), config('field_prefix') . $user_info['id'],
                JsonHelper::encode($user_info));
            $send_data = [
                $params['account'],
                $date = date("Y/m/d H:i:s") . '(UTC/GMT+08:00)',
            ];
            $this->myCommon->push_notice_queue($data['account'], $user_info['area_code'], 'login_temp_id', '', $send_data);
            Redis::hDel($this->login_key, $params['account']);
            DB::commit();
            return MyQuit::returnSuccess(['token' => $token], MyCode::SUCCESS, '登录成功');
        } catch (\Exception $e) {
            print_r($e->getMessage());
            DB::rollBack();
            return MyQuit::returnMessage(MyCode::SERVER_ERROR, '服务繁忙');
        }
    }

    /**
     * 验证账号
     * @param Request $request
     * @return array
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function verify_account(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'AuthValidator', ['account']);
        $account_type = 'mobile';
        if ($this->myCommon->is_email($params['account'])) {
            $account_type = 'email';
        }
        //验证账号是否已经注册
        $user_info = DB::table('user_basical_info')->where([$account_type => $params['account']])->first();
        if (empty($user_info)) {
            return MyQuit::returnMessage(MyCode::UNREGISTERED, '账号未注册');
        }
        $mobile = $user_info['mobile'];
        $email = $user_info['email'];
        if ($user_info['mobile'] != '') {
            $mobile = $this->myCommon->phoneCipher($user_info['mobile'], 3, 5);
        }
        if ($user_info['email'] != '') {
            $email = $this->myCommon->phoneCipher($user_info['email'], 3, 5);
        }
        $token = $this->myCommon->get_token($params['account']);
        $data = [
            'user_id'          => $user_info['invite_id'],
            'mobile'           => $mobile,
            'email'            => $email,
            'mobile_verify'    => $user_info['mobile_verify'],
            'email_verify'     => $user_info['email_verify'],
            'google_auth'      => $user_info['google_auth'],
            'google_validator' => $user_info['google_validator'],
            'account'          => $params['account'],
            'token'            => $token,
        ];
        $redis_data = [
            'id'        => $user_info['id'],
            'mobile'    => $user_info['mobile'],
            'email'     => $user_info['email'],
            'area_code' => $user_info['area_code'],
            'login_pwd' => $user_info['login_pwd'],
            'salt'      => $user_info['salt'],
        ];
        $res = Redis::set($params['account'] . '_' . $token, json_encode($redis_data),
            ["EX" => config('app.second_login_expire_time')]);
        if ($res) {
            return MyQuit::returnSuccess($data, MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnSuccess($data, MyCode::SERVER_ERROR, 'server error');
    }

    /**
     * 验证码安全验证
     * @param Request $request
     * @return array|bool|string
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function security_verify(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'AuthValidator', ['token', 'account']);
        validate($params, 'SecurityValidator', ['mv_code', 'ev_code', 'gv_code']);
        //验证token
        $user_info = Redis::get($params['account'] . '_' . $params['token']);
        if (empty($user_info)) {
            return MyQuit::returnMessage(MyCode::OPERATE_EXPIRE, '操作到期');
        }
        $user_info = json_decode($user_info, true);
        //验证验证码
        $res = $this->verifyService->auth_all_verify_code($user_info['id'], $params, 'reset_pwd');
        if ($res !== true) {
            return MyQuit::returnMessage($res['code'], $res['msg']);
        }
        $data['reset_token'] = $this->myCommon->get_token($params['token']);
        $data['account'] = $params['account'];
        $res = Redis::set($params['account'] . '_' . $data['reset_token'], json_encode($user_info), ["EX" => config('app.second_login_expire_time')]);
        if ($res) {
            Redis::del($params['account'] . '_' . $params['token']);
            return MyQuit::returnSuccess($data, MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnSuccess($data, MyCode::SERVER_ERROR, 'server error');
    }

    /**
     * 重置密码
     * @param Request $request
     * @return array
     * @throws \ReflectionException
     * @throws \Swoft\Bean\Exception\ContainerException
     * @throws \Swoft\Db\Exception\DbException
     * @throws \Swoft\Validator\Exception\ValidatorException
     * @RequestMapping(method={RequestMethod::POST})
     */
    public function reset_pwd(Request $request)
    {
        $params = $request->params;
        //验证参数
        validate($params, 'AuthValidator', ['account', 'token', 'login_pwd']);
        //验证token
        $user_info = Redis::get($params['account'] . '_' . $params['token']);
        if (empty($user_info)) {
            return MyQuit::returnMessage(MyCode::OPERATE_EXPIRE, '操作到期');
        }
        $user_info = json_decode($user_info, true);
        $login_pwd = $this->myAuth->generate_password($params['login_pwd'], $user_info['salt']);
        if ($login_pwd['password_hash'] === $user_info['login_pwd']) {
            return MyQuit::returnMessage(MyCode::PWD_SIMILARITY, '新的密码不能与旧的密码相同');
        }
        $res = UserBasicalInfo::where(['id' => $user_info['id']])->update(['login_pwd' => $login_pwd['password_hash']]);
        if ($res) {
            $request->uid = $user_info['id'];
            //设置24小时内不能提现
            Redis::set(config('not_withdraw_key') . '_' . $request->uid, 1, ["EX" => config('not_withdraw_time')]);
            //添加安全记录
            $this->userSecurityLogData->insert_security_log_login($request, 'reset_pwd');
            //删除缓存
            Redis::del($params['account'] . '_' . $params['token']);
            return MyQuit::returnMessage(MyCode::SUCCESS, 'success');
        }
        return MyQuit::returnMessage(MyCode::SERVER_ERROR, 'server error');
    }

}
