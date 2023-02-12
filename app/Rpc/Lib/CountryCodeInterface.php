<?php

namespace App\Rpc\Lib;

/**
 * Interface CountryCodeInterface
 * @package App\Rpc\Lib
 * 国家信息接口类
 */
interface CountryCodeInterface{

    /**
     * 根据$where条件获取对应的国家信息
     * @param array $where
     * @return mixed
     */
    public function get_country_code(array $where): array;

    /**
     * 根据where条件判断国家信息是否存在
     * @param array $where
     * @return bool
     */
    public function is_exists(array $where): bool ;

}
