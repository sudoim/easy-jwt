<?php

namespace sudoim\jwt;

use sudoim\jwt\components\Header;
use sudoim\jwt\components\Payload;
use sudoim\jwt\components\Signature;
use sudoim\jwt\util\BlackList;
use sudoim\jwt\util\Cache;

/**
 * Token类
 *
 */
class Token
{
    /**
     * @var array 配置
     */
    protected $config = [
        // 加密字符串
        'key'       => 'Thanks for your use so much!',
        // 加密方式
        'algorithm' => 'HS256',
        // Token有效时间(秒) 0表示永久有效,默认2小时
        'expire'    => 7200,
    ];

    /**
     * @var Header 头部信息
     */
    protected $header;

    /**
     * @var Payload 载荷
     */
    protected $payload;

    /**
     * @var Signature 签名
     */
    protected $signature;

    /**
     * @var string 错误信息
     */
    protected $error = '';

    /**
     * 构造函数
     *
     * @param array $options 配置
     */
    public function __construct($options = [])
    {
        $this->config  = array_merge($this->config, $options);
        $this->header  = new Header($this->config['algorithm']);
        $this->payload = new Payload();
    }

    /**
     * 根据Token字符串初始化
     *
     * @param string $token   Token字符串
     * @param array  $options 配置
     * @return Token|bool
     */
    private static function init($token, $options = [])
    {
        $components = explode('.', $token);

        $token = new self($options);

        if (count($components) != 3) {
            return $token->setError('Token struct is wrong');
        }

        $token->header    = Header::parse($components[0]);
        $token->payload   = Payload::parse($components[1]);
        $token->signature = Signature::parse($token->header, $token->payload, $components[2], $token->config['key']);

        if ($token->signature === false) {
            return $token->setError('Token is invalid');
        }

        return $token;
    }

    /**
     * 签发人
     *
     * @param string $iss
     * @return Token
     */
    public function iss($iss)
    {
        $this->payload->setClaim('iss', $iss);

        return $this;
    }

    /**
     * 主题
     *
     * @param string $sub
     * @return Token
     */
    public function sub($sub)
    {
        $this->payload->setClaim('sub', $sub);

        return $this;
    }

    /**
     * 接收者
     *
     * @param string $aud
     * @return Token
     */
    public function aud($aud)
    {
        $this->payload->setClaim('aud', $aud);

        return $this;
    }

    /**
     * 过期时间
     *
     * @param integer $exp
     * @return Token
     */
    public function exp($exp)
    {
        $this->payload->setClaim('exp', $exp);

        return $this;
    }

    /**
     * 生效时间
     *
     * @param integer $nbf
     * @return Token
     */
    public function nbf($nbf)
    {
        $this->payload->setClaim('nbf', $nbf);

        return $this;
    }

    /**
     * 签发时间
     *
     * @param integer $iat
     * @return Token
     */
    public function iat($iat)
    {
        $this->payload->setClaim('iat', $iat);

        return $this;
    }

    /**
     * 唯一标识
     *
     * @param string $jti
     * @return Token
     */
    public function jti($jti)
    {
        $this->payload->setClaim('jti', $jti);

        return $this;
    }

    /**
     * 自定义数据
     *
     * @param string $name
     * @param string $value
     * @return Token
     */
    public function claim($name, $value)
    {
        $this->payload->setClaim($name, $value);

        return $this;
    }

    /**
     * 构建Token
     *
     */
    public function build()
    {
        if ($expire = $this->config['expire']) {
            $this->payload->setClaim('exp', time() + intval($expire));
        }

        $this->signature = new Signature($this->header, $this->payload, $this->config['key']);

        return $this->__toString();
    }

    /**
     * 生成Token
     *
     * @param array $payload 自定义数据
     * @param array $options 配置
     * @return string
     */
    public static function set($payload, $options = [])
    {
        $token = new self($options);

        $token->payload = new Payload($payload);

        return $token->build();
    }

    /**
     * 获取数据
     *
     * @param string $token   Token字符串
     * @param array  $options 配置
     * @return array
     */
    public static function get($token, $options = [])
    {
        $token = Token::init($token, $options);

        if (!$token->error) {
            return $token->payload->claims();
        }

        return [];
    }

    /**
     * 验证Token是否有效
     *
     * @param string $token Token字符串
     * @return boolean
     */
    public static function verify($token)
    {
        $token = Token::init($token);

        // 判断是否有错误信息
        if ($token->error) {
            return false;
        }

        // 判断是否在生效时间
        if (!$token->isNotBefore()) {
            return false;
        }

        // 判断是否在黑名单中
        $jti = $token->payload->getClaim('jti', $token);
        if (BlackList::has($jti)) {
            return false;
        }

        // 判断是否过期
        if ($token->isExpired()) {
            return false;
        }

        return true;
    }

    /**
     * 刷新有效期
     *
     * @param string $token Token字符串
     * @return string|boolean
     */
    public static function refresh($token)
    {
        $token = self::block($token);

        return self::set($token->payload->claims());
    }

    /**
     * 添加Token到黑名单,并返回其Token对象
     *
     * @param string $token
     * @return Token
     */
    public static function block($token)
    {
        $token = Token::init($token);

        // 获取唯一标识
        $jti = $token->payload->getClaim('jti', $token);

        // 获取过期时间
        $exp = $token->payload->getClaim('exp', time());

        // 加入黑名单
        BlackList::add($jti, $exp - time());

        return $token;
    }

    /**
     * 是否过期
     *
     * @return boolean
     */
    public function isExpired()
    {
        $exp = $this->payload->getClaim('exp');

        if (!$exp) {
            return false;
        }

        return $exp < time();
    }

    /**
     * 是否生效
     *
     */
    public function isNotBefore()
    {
        $nbf = $this->payload->getClaim('nbf');

        if (!$nbf) {
            return true;
        }

        return $nbf > time();
    }

    /**
     * 设置错误信息
     *
     * @param string $error
     * @return Token
     */
    private function setError($error = '')
    {
        $this->error = $error;

        return $this;
    }

    /**
     * 获取错误信息
     *
     * @return string 错误信息
     */
    public function getError()
    {
        return $this->error;
    }

    public function __toString()
    {
        return $this->header . '.' . $this->payload . '.' . $this->signature;
    }
}
