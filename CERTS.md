# Some usefull commands to work with certificates

## RSA

To generate private key:

```BASH
openssl genrsa -out private.pem 2048
```

or encrypted one:

```BASH
openssl genrsa -des3 -out private.pem 2048
```

To save public key from it:

```BASH
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

## EC

To list available curves usable to generate the key:

```BASH
openssl ecparam -list_curves
```

To generate EC key to be used with ECDSA algorithm.

```BASH
openssl ecparam -name secp521r1 -genkey -noout -out eckey.pem
```

or encrypted private key protected with password:

```BASH
openssl ecparam -genkey -name secp256k1 | openssl ec -aes256 -out privatekey.pem
```

To show the key info:

```BASH
openssl ec -noout -text -in eckey.pem
```

To generate public key from the private one:

```BASH
openssl ec -in eckey.pem -pubout > eckey_pub.pem
```

To show public key info:

```BASH
openssl ec -noout -text -pubin -in eckey_pub.pem
```
