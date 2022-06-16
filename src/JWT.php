<?php
    namespace Hola\JWT;

    use TypeError;
    use InvalidArgumentException;
    use Hola\JWT\KEY;

    class JWT
    {
        private int $expired = 7200;        //access_token过期时间
        private int $expired_r = 86400;     //refresh_token过期时间
        private string $iss;                //签发者
        private string $sub;                //JWT所面向的用户
        private string $aud;                //接收jwt的一方,是一个用户的id
        private string $nbf;                //在什么时候jwt开始生效，这里是一个Unix时间戳，在这之前是不可用的，默认是当前时间

        /**
         * sign方法返回的是两个token，一个是短时有效的，一个是长时有效的。
         * check方法返回的是一个token，只要是长时有效的就可以通过。
         * decode方法返回的是token的payload部分。
         */

        /**
         * @param int|string $exp   access token 过期时间
         * @return JWT
         */
        public function expired(int|string $exp): JWT
        {
            if (is_int($exp)) $this->expired = $exp;
            if (is_string($exp)) {
                switch ($exp) {
                    case '1day':
                        $this->expired = 86400;
                        break;
                    case '1week':
                        $this->expired = 604800;
                        break;
                    case '1month':
                        $this->expired = 2592000;
                        break;
                }
            }
            return $this;
        }

        /**
         * @param int|string $exp   refresh token 过期时间
         * @return JWT
         */
        public function expired_r(int|string $exp): JWT
        {
            if (is_int($exp)) $this->expired_r = $exp;
            if (is_string($exp)) {
                switch ($exp) {
                    case '1day':
                        $this->expired_r = 86400;
                        break;
                    case '1week':
                        $this->expired_r = 604800;
                        break;
                    case '1month':
                        $this->expired_r = 2592000;
                        break;
                }
            }
            return $this;
        }

        /**
         * @param string $iss  签发者
         * @return $this
         */
        public function iss(string $iss): JWT
        {
            $this->iss = $iss;
            return $this;
        }

        /**
         * @param string $sub  JWT所面向的用户
         * @return $this
         * @throws InvalidArgumentException
         */
        public function sub(string $sub): JWT
        {
            if (empty($sub)) throw new InvalidArgumentException('sub is empty');
            $this->sub = $sub;
            return $this;
        }

        /**
         * @return string   设定JWT唯一标识JTI，主要用来作为一次性token,从而回避重放攻击，用在相关敏感操作中
         */
        private function createJTI(): string
        {
            return md5(uniqid(rand(), true));
        }

        /**
         * @param string $aud   接收jwt的一方,是一个用户的id
         * @return $this
         */
        public function aud(string $aud): JWT
        {
            $this->aud = $aud;
            return $this;
        }

        /**
         * @param string $nbf   在什么时候jwt开始生效，这里是一个Unix时间戳，在这之前是不可用的，默认是当前时间
         * @return $this
         */
        public function nbf(string $nbf): JWT
        {
            $this->nbf = $nbf;
            return $this;
        }

        /**
         * @param array $data           附加数据
         * @param KEY $keyAndAlg        array(key, alg) key是秘钥，alg是算法
         * @param bool $refresh         是否为refresh token，默认不是
         * @param bool $important       是否重要数据，如果是重要数据，那么JWT中会附带JTI，默认不是重要数据
         * @return string               返回签名后的token
         * sign($data, [$key, $alg], false, false)
         */
        public function sign(array $data, KEY $keyAndAlg, bool $refresh = false, bool $important = false): string
        {
            $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => $keyAndAlg->getAlg()]));

            $iat = $this->iat ?? time();

            $payload = [
                'iat' => $iat,
                'data' => $data
            ];
            if (isset($this->iss)) $payload['iss'] = $this->iss;
            if (isset($this->sub)) $payload['sub'] = $this->sub;
            if (isset($this->aud)) $payload['aud'] = $this->aud;
            if ($important) $payload['jti'] = $this->createJTI();
            $payload['exp'] = $refresh ? $iat + $this->expired_r : $iat + $this->expired;
            if (isset($this->nbf)) $payload['nbf'] = $this->nbf;

            $payload = base64_encode(json_encode(array_merge($data, $payload)));

            $signature = $this->signature($header, $payload, $keyAndAlg->getKey(), $keyAndAlg->getAlg());
            return implode('.', [$header, $payload, $signature]);
        }

        /**
         * @param string $header    base64_encode后的header
         * @param string $payload   base64_encode后的payload
         * @param string $key       秘钥
         * @param string $alg       算法
         * @return string           返回签名后的signature部分
         */
        private function signature(string $header, string $payload, string $key, string $alg): string
        {
            $signature = $header . '.' . $payload;
            switch ($alg) {
                case 'HS256':
                    return hash_hmac('sha256', $signature, $key);
                case 'HS384':
                    return hash_hmac('sha384', $signature, $key);
                case 'HS512':
                    return hash_hmac('sha512', $signature, $key);
                default:
                    throw new TypeError('unsupported algorithm');
            }
        }

        // 判断token是否过期

        // 判断token是否合法
    }