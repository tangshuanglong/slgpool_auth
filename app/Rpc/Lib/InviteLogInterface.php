<?php

namespace App\Rpc\Lib;

interface InviteLogInterface{

    /**
     * @param int $uid
     * @param $status
     * @param $page
     * @param $size
     * @return mixed
     */
    public function get_invite_info(int $uid, $status, $page, $size);


    /**
     * 插入推荐记录
     * @param array $data
     * @return bool
     */
    public function insert_invite_log(array $data);

}
