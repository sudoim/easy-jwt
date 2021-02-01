<?php

namespace sudoim\jwt\algorithm\HMAC;

abstract class HMAC
{
    /**
     * 签名
     *
     * @param string $data 源数据
     * @param string $key  密钥
     * @return string
     */
    public function sign($data, $key)
    {
        return hash_hmac($this->getHashAlgorithm(), $data, $key);
    }

    /**
     * 验证签名
     *
     * @param string $sign 签名字符串
     * @param string $data 源数据
     * @param string $key  密钥
     * @return boolean
     */
    public function verify($sign, $data, $key)
    {
        return hash_equals($sign, $this->sign($data, $key));
    }

    abstract protected function getHashAlgorithm();
}