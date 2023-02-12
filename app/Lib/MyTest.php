<?php

namespace App\Lib;

use Swoft\Bean\Annotation\Mapping\Bean;

/**
 * @Bean("MyTest")
 * Class MyTest
 * @package App\Lib
 */
class MyTest{

    public $discount = 0.8;

    public function calc_discount(array $data)
    {
        if(!$data){
            return false;
        }
        $data['admin_type'] = $data['admin_type']*$this->discount;
        return $data;
    }
}
