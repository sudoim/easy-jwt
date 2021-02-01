#### 使用方式

```php
<?php

use simon\jwt\Token;

// 快速生成token字符串
$token = Token::set(['a' => 'b']);

// 快速获取原始数据
$data = Token::get($token);

// 加入黑名单
Token::block($token);

// 验证token是否有效
Token::verify($token);

// 刷新token
Token::refresh();

// 通过实例生成token字符串
$token = (new Token())
    ->iss("sifox")
    ->sub("写扩展的心得体会")
    ->aud("phper")
    ->exp(time() + 3600 * 2)
    ->nbf(time() + 3600 * 1)
    ->iat(time())
    ->jti(uniqid())
    ->claim("content", "简单，且用于学习，我会慢慢改进")
    ->build();
```

提示：这个扩展不包含权限认证，千万不要搞错了哦。