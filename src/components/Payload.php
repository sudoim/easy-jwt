<?php

namespace sudoim\jwt\components;

use sudoim\jwt\util\Base64;

class Payload
{
    /**
     * @var array 载荷数据
     */
    protected $claims;

    /**
     * 构造函数
     *
     * @param array 载荷组成数组
     */
    public function __construct($claims = [])
    {
        // 去重
        $this->claims = array_unique($claims);
    }

    /**
     * 设置Claim
     *
     * @param string $name
     * @param string $value
     */
    public function setClaim($name, $value)
    {
        $this->claims[$name] = $value;
    }

    /**
     * 获取Claim
     *
     * @param string $name
     * @param string $default
     * @return string
     */
    public function getClaim($name, $default = '')
    {
        return array_key_exists($name, $this->claims) ? $this->claims[$name] : $default;
    }

    /**
     * 获取所有Claim
     *
     * @return array
     */
    public function claims()
    {
        return $this->claims;
    }

    /**
     * 解析Base64字符串
     *
     * @param string $base64 Base64字符串
     * @return Payload
     */
    public static function parse($base64)
    {
        $payload = json_decode(Base64::decode($base64), true);

        return new self($payload);
    }

    /**
     * 获取Base64字符串
     *
     * @return string
     */
    public function toBase64String()
    {
        return Base64::encode($this->toJsonString());
    }

    /**
     * 获取Json字符串
     *
     * @return string
     */
    public function toJsonString()
    {
        return json_encode($this->claims);
    }

    /**
     * 返回字符串
     */
    public function __toString()
    {
        return $this->toBase64String();
    }
}