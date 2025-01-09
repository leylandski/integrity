# Integrity
_**File integrity checking/tamper-proofing using JWTs**_

## Overview
Integrity is a very small library and set of tools for creating signed digital tokens that can be used to verify the integrity of a file or arbitrary data, ensuring the contents have not been tampered with. The token is signed using RS512 to ensure it cannot be spoofed (provided the private key is kept secure).

Much of the heavy lifting is done by https://github.com/golang-jwt/jwt.


## Prerequisites
### Install
```shell
go get -u github.com/leylandski/integrity
```

### Generate an RSA public/private key pair
Generating an RSA key pair can be done with two `openssl` commands:

#### Private Key
```shell
openssl genrsa -out private_key.pem 2048
```
As [this article](https://www.cerberauth.com/blog/rsa-key-pairs-openssl-jwt-signature/) very helpfully points out, 2048 is the recommended **minimum** key length for RS256. We are actually using RS512 but (see roadmap) there is a plan to make this controllable. RS512 provides more security due to using a larger hash, but takes longer to compute. As these tokens are intended to be long-lived, the delay is often an acceptable trade-off for the additional security.

#### Public Key
```shell
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

## Library Usage
### Creating tokens to later verify a file's integrity
The library functions `Sign` and `SignFile` can be used to generate a token containing a SHA256 digest of some data or the contents of a file, as well as issuer and subject information. The token is signed using an `*rsa.PrivateKey`.

#### Sign Example

```go
package my_signing_app

import (
	"crypto/rsa"
	"fmt"

	"github.com/leylandski/integrity"
)

func main() {
	var (
		issuer     = "example.issuer"
		subject    = "example.subject"
		dataToSign = []byte("Hello, I am some arbitrary data.")
		key        *rsa.PrivateKey
	)

	// TODO read in your private key from somewhere.

	token, err := integrity.Sign(issuer, subject, dataToSign, key)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Token: %s\n", string(token))
}
```

The resulting token should be a JWT signed with the private key with a payload consisting of the following claims:
* `iss` - The token issuer. This should be set to the name of the organisation, service, or machine that you intend to issue your tokens.
* `sub` - The token subject. This should be the name of the file or object that `dataToSign` represents in the above example.
* `iat` - The Unix timestamp the token was created at.
* `nbf` - The Unix timestamp that denotes the earliest time the token should be accepted. Should always be the same as `iat`.
* `digest` - A SHA256 digest of the data.

`SignFile` works similarly and can be used as a shortcut for reading the data manually:

```
integrity.SignFile(issuer, pathToFile, key)
```

### Verify Example

The example below shows how you can use Integrity to verify some data matches a corresponding token:

```go
package my_app

import (
	"crypto/rsa"
	
	"github.com/leylandski/integrity"
)

func main() {
	var (
		issuer  = "example.issuer"
		subject = "example.subject"
		data    = []byte("Hello, I am some arbitrary data.")
		token   = []byte("replace this with your token string")
		key     *rsa.PublicKey
	)
	
	// TODO read in your public key from somewhere

	if ok, err := integrity.Verify(issuer, subject, data, token, key); err != nil {
		panic(err)
	} else if !ok {
		panic("data does not match integrity token")
	}
}
```

### Verifying the integrity of a running golang program

TODO

## Using the command-line tools

### Roadmap
 * Make `digest` into `digests` and make it a map containing a manifest.
 * Need to have a `SignAll` and `VerifyAll` function for the above.
 * Make command line tools.
 * Add ability to use different key types.