<?php
namespace App\Console\Command;

use App\Lib\MyCommon;
use App\Lib\MyRedisHelper;
use Swoft\Console\Annotation\Mapping\Command;
use Swoft\Console\Annotation\Mapping\CommandMapping;
use Swoft\Consul\Agent;
use Swoft\Bean\Annotation\Mapping\Inject;
use Swoft\Consul\Health;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use Swoft\Redis\Redis;

/**
*@Command()
*/
class ServerCommand{

    /**
     * @Inject()
     *
     * @var Agent
     */
    private $agent;

    /**
     * @Inject()
     *
     * @var Health
     */
    private $health;

	/**
	*@CommandMapping()
	*/
	public function run()
	{
	}

    /**
     * @CommandMapping()
     */
	public function redis_lock()
    {
        $start_time = MyCommon::getMillisecond();
        $token = MyRedisHelper::lock('test_redis_key', 20);
        echo $token.PHP_EOL;
        sleep(25);
        MyRedisHelper::unLock('test_redis_key', $token);
        $end_time = MyCommon::getMillisecond();
        echo $end_time - $start_time;
    }

    /**
     * @CommandMapping()
     */
    public function consul_list()
    {
        $result = $this->agent->services(['dc' => 'dc1']);
        print_r(json_decode($result->getBody(), true));
        print_r($this->agent->members());
    }

    /**
     * @CommandMapping()
     */
    public function consul_note()
    {
        $result = $this->health->service('swoft');
        print_r(json_decode($result->getBody(),true));
    }

    /**
     * @CommandMapping()
     */
//    public function send_email()
//    {
//        $mailto='942509984@qq.com';
//        $mailsubject="登录验证码";
//        $mailbody='您的登录验证码：123456, 请在15分钟内填写！';
//        $smtpserver     = "smtpdm.aliyun.com";
//        $smtpserverport = 465;
//        $smtpusermail   = "lyj@mail.lyjtech.cn";
//        // 发件人的账号，填写控制台配置的发信地址,比如xxx@xxx.com
//        $smtpuser       = "lyj@mail.lyjtech.cn";
//        // 访问SMTP服务时需要提供的密码(在控制台选择发信地址进行设置)
//        $smtppass       = "LYJlyj874250789";
//        //$mailsubject    = "=?UTF-8?B?" . base64_encode($mailsubject) . "?=";
//        $mailtype       = "HTML";
//        //可选，设置回信地址
//        $smtpreplyto    = "";
//        $smtp           = new smtp($smtpserver, $smtpserverport, true, $smtpuser, $smtppass);
//        $smtp->debug    = true;
//        $cc   ="";
//        $bcc  = "";
//        $additional_headers = "";
//        //设置发件人名称，名称用户可以自定义填写。
//        $sender  = "量化平台";
//        $smtp->sendmail($mailto,$smtpusermail, $mailsubject, $mailbody, $mailtype, $cc, $bcc, $additional_headers, $sender, $smtpreplyto);
//    }

    /**
     * @CommandMapping()
     */
    public function send_email()
    {
        $mail = new PHPMailer(true);

        try {
            //Server settings
            $mail->SMTPDebug = SMTP::DEBUG_SERVER;                      // Enable verbose debug output
            $mail->Timeout   = 3;
            $mail->CharSet = "utf-8";
            $mail->isSMTP();                                            // Send using SMTP
            $mail->Host       = 'smtpdm.aliyun.com';                    // Set the SMTP server to send through
            $mail->SMTPAuth   = true;                                   // Enable SMTP authentication
            $mail->Username   = 'lyj@mail.lyjtech.cn';                     // SMTP username
            $mail->Password   = 'LYJlyj874250789';                               // SMTP password
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;         // Enable TLS encryption; `PHPMailer::ENCRYPTION_SMTPS` also accepted
            $mail->Port       = 465;                                    // TCP port to connect to
            $mail->SMTPOptions = array(
                'ssl' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true,
                )
            );
            //Recipients
            $mail->setFrom($mail->Username, '量化平台');
            $mail->addAddress('942509984@qq.com');     // Add a recipient
            $mail->addReplyTo($mail->Username, '回信');
//            $mail->addCC('cc@example.com');
//            $mail->addBCC('bcc@example.com');

            // Attachments
//            $mail->addAttachment('/var/tmp/file.tar.gz');         // Add attachments
//            $mail->addAttachment('/tmp/image.jpg', 'new.jpg');    // Optional name

            // Content
            $mail->isHTML(true);                                  // Set email format to HTML
            $mail->Subject = 'Here is the subject';
            $mail->Body    = 'This is the HTML message body <b>in bold!</b>';
            $mail->AltBody = 'This is the body in plain text for non-HTML mail clients';

            $mail->send();
            echo 'Message has been sent';
        } catch (Exception $e) {
            echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
        }
    }
}
