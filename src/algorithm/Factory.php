<?php

namespace sudoim\jwt\algorithm;

use sudoim\jwt\algorithm\HMAC\HS256;
use sudoim\jwt\algorithm\HMAC\HS384;
use sudoim\jwt\algorithm\HMAC\HS512;

class Factory
{
    /**
     * 创建算法实例对象
     *
     * @param string $name 算法名称
     * @return mixed
     * @throws
     */
    public static function create($name)
    {
        switch ($name) {
            case 'HS256':
                return new HS256();
            case 'HS384':
                return new HS384();
            case 'HS512':
                return new HS512();
            default:
                throw new \Exception('Algorithm is invalid');
        }
    }
}