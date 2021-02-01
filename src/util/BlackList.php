<?php

namespace sudoim\jwt\util;

use sudoim\jwt\util\Cache;

class BlackList
{
    const PREFIX = 'jwt:blacklist:jti:';

    /**
     * 加入黑名单
     *
     * @param string  $jti 唯一标识
     * @param integer $ttl 黑名单维护时间
     * @throws
     */
    public static function add($jti, $ttl)
    {
        (new Cache())->set(self::PREFIX . $jti, time(), $ttl);
    }

    /**
     * 是否在黑名单中
     *
     * @param string $jti 唯一标识
     * @return bool
     */
    public static function has($jti)
    {
        return (new Cache())->has(self::PREFIX . $jti);
    }
}