<?php

namespace sudoim\jwt\components;

use sudoim\jwt\util\Base64;

class Header
{
    /**
     * @var string 加密算法
     */
    private $alg;

    /**
     * @var string 令牌类型
     */
    private $typ;

    /**
     * 构造函数
     *
     * @param string $alg 加密算法
     * @param string $typ 令牌类型
     */
    public function __construct($alg = 'HS256', $typ = 'JWT')
    {
        $this->alg = $alg;
        $this->typ = $typ;
    }

    /**
     * @return string
     */
    public function getAlg()
    {
        return $this->alg;
    }

    /**
     * @return string
     */
    public function getTyp()
    {
        return $this->typ;
    }

    /**
     * @param string $alg
     */
    public function setAlg($alg)
    {
        $this->alg = $alg;
    }

    /**
     * @param string $typ
     */
    public function setTyp($typ)
    {
        $this->typ = $typ;
    }

    /**
     * 解析Base64字符串
     *
     * @param string $base64 Base64字符串
     * @return Header
     */
    public static function parse($base64)
    {
        $header = json_decode(Base64::decode($base64));

        return new self($header->alg, $header->typ);
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
        return json_encode(['alg' => $this->alg, 'typ' => $this->typ]);
    }

    /**
     * 返回字符串
     */
    public function __toString()
    {
        return $this->toBase64String();
    }
}