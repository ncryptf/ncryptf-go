# ncryptf Go

[![TravisCI](https://img.shields.io/travis/ncryptf/ncryptf-go.svg?style=flat-square "TravisCI")](https://travis-ci.com/ncryptf/ncryptf-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/ncryptf/ncryptf-go)](https://goreportcard.com/report/github.com/ncryptf/ncryptf-go)
[![License](https://img.shields.io/badge/license-BSD-orange.svg?style=flat-square "License")](https://github.com/ncryptf/ncryptf-go/blob/master/LICENSE.md)

<center>
    <img src="https://github.com/ncryptf/ncryptf-go/blob/master/logo.png?raw=true" alt="ncryptf logo" width="400px"/>
</center>

A library for facilitating hashed based KDF signature authentication, and end-to-end encrypted communication with compatible API's.

## Installing

1. Enable Go11 Modules by setting the `GO111MODULE` environment variable
```
GO111MODULE=on
```
2. Install normally
```
go get github.com/ncryptf/ncryptf-go
```

## Testing

```
go test ./...
```

## Documentation


## HMAC+HKDF Authentication

HMAC+HKDF Authentication is an Authentication method that allows ensures the request is not tampered with in transit. This provides resiliance not only against network layer manipulation, but also man-in-the-middle attacks.

At a high level, an HMAC signature is created based upon the raw request body, the HTTP method, the URI (with query parameters, if present), and the current date. In addition to ensuring the request cannot be manipulated in transit, it also ensures that the request is timeboxed, effectively preventing replay attacks.

The library itself is made available by importing the following struct:

Supporting API's will return the following payload containing at minimum the following information.

```json
{
    "access_token": "7XF56VIP7ZQQOLGHM6MRIK56S2QS363ULNB5UKNFMJRQVYHQH7IA",
    "refresh_token": "MA2JX5FXWS57DHW4OIHHQDCJVGS3ZKKFCL7XM4GNOB567I6ER4LQ",
    "ikm": "bDEyECRvKKE8w81fX4hz/52cvHsFPMGeJ+a9fGaVvWM=",
    "signing": "7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==",
    "expires_at": 1472678411
}
```

After extracting the elements, we can create signed request by doing the following:

```go
```

A trivial full example is shown as follows:

```go
```

The `payload` parameter should be a JSON serializable string.

### Version 2 HMAC Header

The Version 2 HMAC header, for API's that support it can be retrieved by calling:

```go
```

### Version 1 HMAC Header

For API's using version 1 of the HMAC header, call `Authorization` with the optional `version` parameter set to `1` for the 6th parameter.

```go
```

This string can be used in the `Authorization` Header

#### Date Header

The Version 1 HMAC header requires an additional `X-Date` header. The `X-Date` header can be retrieved by calling `auth.GetDateString()`

## Encrypted Requests & Responses

This library enables clients to establish and trusted encrypted session on top of a TLS layer, while simultaniously (and independently) providing the ability authenticate and identify a client via HMAC+HKDF style authentication.

The rationale for this functionality includes but is not limited to:

1. Necessity for extra layer of security
2. Lack of trust in the network or TLS itself (see https://blog.cloudflare.com/incident-report-on-memory-leak-caused-by-cloudflare-parser-bug/)
3. Need to ensure confidentiality of the Initial Key Material (IKM) provided by the server for HMAC+HKDF authentication
4. Need to ensure confidentiality of user submitted credentials to the API for authentication

The primary reason you may want to establish an encrypted session with the API itself is to ensure confidentiality of the IKM to prevent data leakages over untrusted networks to avoid information being exposed in a Cloudflare like incident (or any man-in-the-middle attack). Encrypted sessions enable you to utilize a service like Cloudflare should a memory leak occur again with confidence that the IKM and other secure data would not be exposed.

To encrypt, decrypt, sign, and verify messages, you'll need to be able to generate the appropriate keys. Internally, this library uses [lazysodium-java](https://github.com/terl/lazysodium-java) to perform all necessary cryptography functions, though any libsodium implementation for Java would suffice.

#### Encryption Keys

Encryption uses a sodium crypto box. A keypair can be generated as follows when using `lazy-sodium`.

```go
import "ncryptf"

func GetKeypair() *Keypair {
    return ncryptf.GenerateKeypair()
}
```

#### Signing Keys

Encryption uses a sodium signature. A keypair for signing can be generated as follows using `lazy-sodium`:

```go
import "ncryptf"

func GenerateSigningKeypair() *Keypair {
    return ncryptf.GenerateKeypair()
}
```

### Encrypted Request Body

Payloads can be encrypted as follows:

```go
```


> Note that you need to have a pre-bootstrapped public key to encrypt data. For the v1 API, this is typically this is returned by `/api/v1/server/otk`.

### Decrypting Responses

Responses from the server can be decrypted as follows:

```go
```


### V2 Encrypted Payload

Verison 2 works identical to the version 1 payload, with the exception that all components needed to decrypt the message are bundled within the payload itself, rather than broken out into separate headers. This alleviates developer concerns with needing to manage multiple headers.

The version 2 payload is described as follows. Each component is concatanated together.

| Segment | Length |
|---------|--------|
| 4 byte header `DE259002` in binary format | 4 BYTES |
| Nonce | 24 BYTES |
| The public key associated to the private key | 32 BYTES |
| Encrypted Body | X BYTES |
| Signature Public Key | 32 BYTES |
| Signature or raw request body | 64 BYTES |
| Checksum of prior elements concatonated together | 64 BYTES |
