<?php

namespace sudoim\jwt\algorithm\HMAC;

final class HS512 extends HMAC
{
    /**
     * 返回算法名称
     *
     * @return string
     */
    public function name()
    {
        return 'HS512';
    }

    /**
     * 获取算法标识
     *
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha512';
    }
}