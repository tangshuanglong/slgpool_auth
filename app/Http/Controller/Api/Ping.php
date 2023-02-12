<?php

namespace App\Http\Controller\Api;

use Swoft\Http\Server\Annotation\Mapping\Controller;
use Swoft\Http\Server\Annotation\Mapping\RequestMapping;

/**
 * Class Ping
 *@Controller(prefix="/v1/ping")
 */
class Ping{

    /**
     * @RequestMapping()
     */
    public function index()
    {
        return time();
    }


}
