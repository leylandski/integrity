// Package integrity provides methods for creating and verifying signed JWTs containing a map of SHA256 digests.
// These can be used to verify files have not been tampered with.
package integrity

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Make time.Now overridable for testing purposes.
var now = time.Now

type tokenClaims struct {
	jwt.RegisteredClaims
	Manifest map[string]string `json:"manifest"`
}

func GenerateManifest(issuer string, paths []string, key *rsa.PrivateKey) ([]byte, error) {
	if issuer == "" {
		return nil, errors.New("issuer cannot be blank")
	}
	if len(paths) < 1 {
		return nil, errors.New("must specify at least one path")
	}
	if key == nil {
		return nil, errors.New("key cannot be blank")
	}

	paths = deduplicate(paths)

	digests := make(map[string]string)
	for i := range paths {
		digest, err := generateDigestForFile(paths[i])
		if err != nil {
			return nil, err
		}
		digests[paths[i]] = hex.EncodeToString(digest[:])
	}

	n := now()
	claims := tokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   issuer,
			IssuedAt: jwt.NewNumericDate(n),
		},
		Manifest: digests,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	tokenStr, err := token.SignedString(key)
	if err != nil {
		return nil, err
	}

	return []byte(tokenStr), nil
}

func VerifyManifest(issuer, manifestPath, root string, key *rsa.PublicKey) (bool, error) {
	if issuer == "" {
		return false, errors.New("issuer cannot be blank")
	}
	if manifestPath == "" {
		return false, errors.New("manifest path cannot be blank")
	}
	if key == nil {
		return false, errors.New("key cannot be nil")
	}

	token, err := readDataFromFile(path.Join(root, manifestPath))
	if err != nil {
		return false, err
	}

	claims := tokenClaims{}
	_, err = jwt.ParseWithClaims(string(token), &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return key, nil
	}, jwt.WithIssuer(issuer), jwt.WithIssuedAt(), jwt.WithLeeway(time.Second*10))

	if err != nil {
		return false, err
	}

	for k := range claims.Manifest {
		var claimDigest [32]byte
		n, hexErr := hex.Decode(claimDigest[:], []byte(claims.Manifest[k]))
		if hexErr != nil {
			return false, hexErr
		} else if n != 32 {
			return false, errors.New("did not decode expected number of bytes from hex digest string")
		}

		digest, dErr := generateDigestForFile(k)
		if dErr != nil {
			return false, dErr
		}

		for i := 0; i < 32; i++ {
			if digest[i] != claimDigest[i] {
				return false, fmt.Errorf("digests do not match for %s", k)
			}
		}
	}

	return true, nil
}

// WithNowFunc overrides the function to get the current time. Call this with a function that returns a static time for
// testing purposes.
// Do not call this function during normal operating circumstances.
func WithNowFunc(nowFunc func() time.Time) {
	now = nowFunc
}

// Read in file data with a deferred close.
func readDataFromFile(path string) ([]byte, error) {
	mf, err := os.OpenFile(path, os.O_RDONLY, 0444)
	if err != nil {
		return nil, err
	}
	defer mf.Close()

	return io.ReadAll(mf)
}

// Generate a SHA256 digest for a file located at path.
func generateDigestForFile(path string) ([32]byte, error) {
	b, err := readDataFromFile(path)
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(b), nil
}

// Returns a new slice containing only unique occurrences in l.
func deduplicate(l []string) []string {
	ll := make([]string, 0)
	for i := range l {
		alreadyFound := false
		for j := range ll {
			if l[i] == ll[j] {
				alreadyFound = true
				break
			}
		}
		if !alreadyFound {
			ll = append(ll, l[i])
		}
	}
	return ll
}
