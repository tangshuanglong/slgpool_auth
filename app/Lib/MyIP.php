<?php

namespace App\Lib;

/*
    全球 IPv4 地址归属地数据库(IPIP.NET 版)
    高春辉(pAUL gAO) <gaochunhui@gmail.com>
    Build 20170905 版权所有 IPIP.NET
    (C) 2006 - 2017 保留所有权利，北京天特信科技有限公司
    本代码仅用于 DAT 格式，请注意及时更新 IP 数据库版本
    数据问题请加 QQ 交流群: 346280296
    Code for PHP 5.3+ only!
*/

use Swoft\Co;
use Symfony\Component\Yaml\Tests\B;

class MyIP
{
    private $ip     = NULL;

    private $fp     = NULL;
    private $offset = NULL;
    private $index  = NULL;

    public function find($ip)
    {
        if (empty($ip) === TRUE)
        {
            return 'N/A';
        }

        $nip   = gethostbyname($ip);
        $ipdot = explode('.', $nip);

        if ($ipdot[0] < 0 || $ipdot[0] > 255 || count($ipdot) !== 4)
        {
            return 'N/A';
        }

        if ($this->fp === NULL)
        {
            self::init();
        }

        $nip2 = pack('N', ip2long($nip));

        $tmp_offset = (int)$ipdot[0] * 4;
        $start      = unpack('Vlen', $this->index[$tmp_offset] . $this->index[$tmp_offset + 1] . $this->index[$tmp_offset + 2] . $this->index[$tmp_offset + 3]);

        $index_offset = $index_length = NULL;
        $max_comp_len = $this->offset['len'] - 1024 - 4;
        for ($start = $start['len'] * 8 + 1024; $start < $max_comp_len; $start += 8)
        {
            if ($this->index{$start} . $this->index{$start + 1} . $this->index{$start + 2} . $this->index{$start + 3} >= $nip2)
            {
                $index_offset = unpack('Vlen', $this->index{$start + 4} . $this->index{$start + 5} . $this->index{$start + 6} . "\x0");
                $index_length = unpack('Clen', $this->index{$start + 7});

                break;
            }
        }

        if ($index_offset === NULL)
        {
            return 'N/A';
        }

        fseek($this->fp, $this->offset['len'] + $index_offset['len'] - 1024);

        return explode("\t", fread($this->fp, $index_length['len']));
    }

    private function init()
    {
        if ($this->fp === NULL)
        {
            $this->ip = new self();
            $this->fp = fopen(dirname(dirname(__DIR__)) . '/public/17monipdb.dat', 'rb');
            if ($this->fp === FALSE)
            {
                throw new Exception('Invalid 17monipdb.dat file!');
            }

            $this->offset = unpack('Nlen', fread($this->fp, 4));
            if ($this->offset['len'] < 4)
            {
                throw new Exception('Invalid 17monipdb.dat file!');
            }

            $this->index = fread($this->fp, $this->offset['len'] - 4);
        }
    }

    public function __destruct()
    {
        if ($this->fp !== NULL)
        {
            fclose($this->fp);

            $this->fp = NULL;
        }
    }
}

?>
