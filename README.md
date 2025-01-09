# integrity
Signed digital manifests for tamper-proofing/integrity checking using JWTs.

## What is this?
Integrity is a very small golang package and command line tool for [verifying the integrity](https://en.wikipedia.org/wiki/Digital_signature) of one or more files, assuring they have not been manipulated or tampered with. It generates and stores a [JSON Web Token (JWT)](https://jwt.io/) containing a manifest of digital signatures (SHA256 hashes) which can later be compared to computed signatures of a given set of files.

The JWT contained within the integrity file is itself signed using RS512, signed with an RSA private key, and its authenticity and integrity can be verified by anyone who holds a corresponding public key. **Only** the party with the private key may generate a valid, authentic integrity file.

This package itself is very small, but mainly because it uses [github.com/golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt/v5) for a majority of the heavy lifting.

## Using the golang library
### Prerequisites
Install it:
```shell
go get -u github.com/leylandski/integrity
```

Making sure you have `openssl` installed, generate a public/private RSA key pair using [this helpful article](https://www.cerberauth.com/blog/rsa-key-pairs-openssl-jwt-signature/), or just use the following two commands:
```shell
openssl genrsa -out private_key.pem 2048
```

```shell
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

As mentioned in the article, 2048 is the currently recommended **minimum** key length for RS256. Integrity uses RS512 for additional strength (with the tradeoff of computation time), but the advice is much the same:
```
longer keys = more time/resources to factor
```

### Generating an integrity file

The code below will generate an integrity file from a collection of paths. It will fail if any of the paths provided do not resolve to actually existing files, or if the issuer is blank.
```go
package main

import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/leylandski/integrity"
)

func main() {
	issuer := "issuer_name"
	paths := []string{
		"path/to/file.1",
		"path/to/file.2",
		"path/to/file.3",
	}

	var privateKey *rsa.PrivateKey
	// TODO 
	//  Read in your private key from somewhere.
	//  github.com/golang-jwt/jwt/v5 has jwt.ParseRSAPrivateKeyFromPEM to do the parsing for you.

	manifestData, err := integrity.GenerateManifest(issuer, paths, privateKey)
	check(err)

	f, err := os.Create(".integrity")
	check(err)
	defer f.Close()
	
	_, err = f.Write(manifestData)
	check(err)
	
	fmt.Printf("Successfully generated integrity file!")
}

func check(err error) {
	if err != nil {
		fmt.Printf("Failed to generate manifest: %s.\n", err.Error())
		os.Exit(1)
    }
}
```

### Validating an integrity file

The code below demonstrates how to verify files have not been altered or manipulated using a pre-generated integrity file. You may optionally specify a root directory to prefix with when looking for files.

```go
package main

import (
	"crypto/rsa"
	"fmt"
	"github.com/leylandski/integrity"
	"os"
)

func main() {
	issuer := "issuer_name"
	manifestPath := "path/to/.integrity"
	root := "base/" 
	// The file will be looked for at ./base/path/to/.integrity
	// Files contained in the manifest will be looked for at ./base/<name in manifest>

	var publicKey *rsa.PublicKey
	// TODO
	//  Read in your public key from somewhere.
	//  As above, github.com/golang-jwt/jwt/v5 has jwt.ParseRSAPublicKeyFromPEM to do the parsing for you.
	
	_, err := integrity.VerifyManifest(issuer, manifestPath, root, publicKey)
	if err != nil {
		fmt.Printf("Unable to successfully verify the integrity of one or more files!\n")
		os.Exit(1)
    }
}
```

## Using the command-line tools
TODO