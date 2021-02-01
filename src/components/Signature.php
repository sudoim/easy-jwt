<?php

namespace sudoim\jwt\components;

use sudoim\jwt\algorithm\Factory;
use sudoim\jwt\util\Base64;

class Signature
{
    /**
     * @var Header 头部
     */
    protected $header;

    /**
     * @var Payload 载荷
     */
    protected $payload;

    /**
     * @var string 密钥
     */
    protected $key;

    /**
     * 构造函数
     *
     * @param Header  $header
     * @param Payload $payload
     * @param string  $key
     */
    public function __construct($header, $payload, $key = 'Thanks for your use!')
    {
        $this->header  = $header;
        $this->payload = $payload;
        $this->key     = $key;
    }

    /**
     * 解析Base64字符串
     *
     * @param Header  $header
     * @param Payload $payload
     * @param string  $base64
     * @param string  $key
     * @return Signature|boolean
     */
    public static function parse($header, $payload, $base64, $key = 'Thanks for your use!')
    {
        $signature = new self($header, $payload, $key);

        if ($signature->verify(Base64::decode($base64))) {
            return $signature;
        } else {
            return false;
        }
    }

    /**
     * 签名
     *
     * @return string
     */
    public function sign()
    {
        $signer = Factory::create($this->header->getAlg());

        return $signer->sign($this->header . '.' . $this->payload, $this->key);
    }

    /**
     * 验证签名
     *
     * @param String $signature 加密后的签名
     * @return Boolean
     */
    public function verify($signature)
    {
        return $this->sign() === $signature;
    }

    /**
     * 返回字符串
     */
    public function __toString()
    {
        return Base64::encode($this->sign());
    }
}