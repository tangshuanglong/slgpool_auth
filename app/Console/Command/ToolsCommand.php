<?php

namespace App\Console\Command;

use App\Model\Entity\CountryCode;
use GuzzleHttp\Client;
use Swlib\Saber;
use Swlib\SaberGM;
use Swoft\Console\Annotation\Mapping\Command;
use Swoft\Console\Annotation\Mapping\CommandMapping;
use Swoft\Db\DB;
use Swoft\Stdlib\Helper\JsonHelper;

/**
 * Class ToolsCommand
 * @package App\Console\Command
 * @Command()
 */
class ToolsCommand{

    /**
     * @CommandMapping()
     */
    public function get_huobi_country_code()
    {
        $url = 'https://api-www.huobiasia.vip/-/x/uc/uc/open/country_code/list?r=x8x1o';
        $client = new Client();
        $response = $client->request('get', $url);
        if ($response->getStatusCode() == 200){
            $data = JsonHelper::decode($response->getBody(), true);
            if ($data['code'] != 200){
                print_r('请求失败');
            }
            CountryCode::insert($data['data']);
        }
    }
}
