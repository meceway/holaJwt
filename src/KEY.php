<?php
    namespace Hola\JWT;

    use TypeError;
    use InvalidArgumentException;

    class KEY
    {
        private string $key;
        private string $alg;

        public function __construct(array $keyAndAlg)
        {
            list($key, $alg) = $keyAndAlg;

            //  检查秘钥以及算法是否为空
            if (empty($key)) throw new InvalidArgumentException('key is empty');
            if (empty($alg)) throw new InvalidArgumentException('alg is empty');

            //  检查秘钥和算法是否合法
            if (!is_string($key)) throw new TypeError('key must be string');
            if (!is_string($alg)) throw new TypeError('alg must be string');

            $this->key = $key;
            $this->alg = $alg;
        }


        public function getKey(): string
        {
            return $this->key;
        }

        public function getAlg(): string
        {
            return $this->alg;
        }
    }