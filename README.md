# 收钱吧回调验签 POC

[![Go Test](https://github.com/yinheli/shouqianba-poc/actions/workflows/test.yaml/badge.svg)](https://github.com/yinheli/shouqianba-poc/actions/workflows/test.yaml)

## 生成密钥对

> 生成私钥和公钥，用于自测

```bash
openssl genpkey -algorithm RSA -out private.pem
openssl rsa -in private.pem -pubout -out public.pem
```

如果给的是 Java 的非 pem 格式公钥，需要转换一下

```bash
openssl rsa -pubin -in public.key -inform DER -out public.pem -outform PEM
```

## 测试

```bash
go test -v
```

## License

[MIT](LICENSE)
