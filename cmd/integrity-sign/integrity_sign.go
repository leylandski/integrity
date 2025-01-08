package main

import (
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/leylandski/integrity"
)

const startupMessage = `
File integrity token generator (integrity-sign)
2024 © Adam Leyland (github.com/leylandski)
`

var (
	flgInPath  = flag.String("in", "", "Input file name")
	flgOutPath = flag.String("out", ".integrity", "Output file name (defaults to \".integrity\")")
	flgKeyPath = flag.String("key", "", "Path to PEM-encoded signing key file (PKCS8/RSA)")
	flgIssuer  = flag.String("issuer", "", "Integrity file issuer")
)

func main() {
	start := time.Now()

	fmt.Println(startupMessage)

	flag.Parse()

	if flgInPath == nil || *flgInPath == "" {
		closeWithError(errors.New("must specify a valid path to an input file"))
	}
	if flgOutPath == nil || *flgOutPath == "" {
		closeWithError(errors.New("must specify a valid path to an output file"))
	}
	if flgKeyPath == nil || *flgKeyPath == "" {
		closeWithError(errors.New("must specify a valid path to a PEM-encoded PKCS8/RSA private key file"))
	}
	if flgIssuer == nil || *flgIssuer == "" {
		closeWithError(errors.New("must specify a non-empty issuer name"))
	}

	key, err := loadSigningKey(*flgKeyPath)
	if err != nil {
		closeWithError(err)
	}

	fmt.Printf("Generating integrity file for %s\n", *flgInPath)
	token, err := integrity.SignFile(*flgIssuer, *flgInPath, key)
	if err != nil {
		closeWithError(err)
	}

	if err = writeTokenToFile(*flgOutPath, token); err != nil {
		closeWithError(err)
	}

	finish := time.Now()
	timeTaken := finish.Sub(start)
	fmt.Printf("Finished generating %s in %s\n", *flgOutPath, timeTaken.String())
}

func closeWithError(err error) {
	fmt.Printf("Error: %s.\n", err.Error())
	os.Exit(1)
}

func loadSigningKey(path string) (*rsa.PrivateKey, error) {
	keyFile, err := os.OpenFile(path, os.O_RDONLY, 0444)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	keyBytes, err := io.ReadAll(keyFile)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
}

func writeTokenToFile(path string, token []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if n, err := f.Write(token); err != nil {
		return err
	} else if n != len(token) {
		return errors.New("did not write the entire token to the given path")
	}

	return nil
}
