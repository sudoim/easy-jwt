<?php

namespace sudoim\jwt;

use sudoim\jwt\components\Header;
use sudoim\jwt\components\Payload;
use sudoim\jwt\components\Signature;

class Builder
{
    private $header;
    private $payload;
    private $signature;
    private $secretKey;
    private $privateKey;
    private $publicKey;

    public function __construct()
    {
        $this->header = new Header();
        $this->payload = new Payload();
    }

    /**
     * 签发人
     *
     * @param string $iss
     * @return Builder
     */
    public function iss($iss)
    {
        $this->payload->addClaim('iss', $iss);
        return $this;
    }

    /**
     * 主题
     *
     * @param string $sub
     * @return Builder
     */
    public function sub($sub)
    {
        $this->payload->addClaim('sub', $sub);
        return $this;
    }

    /**
     * 接收者
     *
     * @param string $aud
     * @return Builder
     */
    public function aud($aud)
    {
        $this->payload->addClaim('aud', $aud);
        return $this;
    }

    /**
     * 过期时间
     *
     * @param integer $exp
     * @return Builder
     */
    public function exp($exp)
    {
        $this->payload->addClaim('exp', $exp);
        return $this;
    }

    /**
     * 生效时间
     *
     * @param integer $nbf
     * @return Builder
     */
    public function nbf($nbf)
    {
        $this->payload->addClaim('nbf', $nbf);
        return $this;
    }

    /**
     * 签发时间
     *
     * @param integer $iat
     * @return Builder
     */
    public function iat($iat)
    {
        $this->payload->addClaim('iat', $iat);
        return $this;
    }

    /**
     * 唯一标识
     *
     * @param string $jti
     * @return Builder
     */
    public function jti($jti)
    {
        $this->payload->addClaim('jti', $jti);
        return $this;
    }

    /**
     * 构建Token字符串
     */
    public function build()
    {
        $this->signature = new Signature($this->header, $this->payload);

        return $this->__toString();
    }

    /**
     * 返回字符串
     */
    public function __toString()
    {
        return $this->header . '.' . $this->payload . '.' . $this->signature;
    }
}