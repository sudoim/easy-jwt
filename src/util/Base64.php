<?php

namespace sudoim\jwt\util;

class Base64
{
    public static function encode($data)
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    public static function decode($data)
    {
        if ($remainder = strlen($data) % 4) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }
}
