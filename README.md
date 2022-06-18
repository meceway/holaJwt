# holaJwt
==========================
一个简单的JWT库

# 安装方法
```bash
composer require firebase/php-jwt
```
## 示范
```php
use Hola\JWT\JWT
use Hola\JWT\KEY;

$key = 'secret';
$data = [
    'id' => 1
];

$jwt = new JWT();
$token = $jwt->expired('1week')->sign($data, [$key, 'HS256'], true, true);
```