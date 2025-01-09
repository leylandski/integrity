package integrity_test

import (
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/leylandski/integrity"
)

const (
	testIssuer        = "test_issuer"
	testSubject       = "test_subject"
	testFilePath      = "test.temp"
	testIntegrityPath = "test_integrity.temp"
)

var (
	testFileData      = []byte("Hello, I am some test file data.")
	testFileDigest    = sha256.Sum256(testFileData) // Should be 15c416d7bd9890f5cbcc875122837ad3f14a2589d1d163b0a685c86870082270
	testIntegrityData = []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsInN1YiI6InRlc3QudGVtcCIsIm5iZiI6MTczNjM0OTQzMCwiaWF0IjoxNzM2MzQ5NDMwLCJkaWdlc3QiOiIxNWM0MTZkN2JkOTg5MGY1Y2JjYzg3NTEyMjgzN2FkM2YxNGEyNTg5ZDFkMTYzYjBhNjg1Yzg2ODcwMDgyMjcwIn0.QIPjoKqt2kZ2iW4evv28CkodLZd0sKrZM7_qAK_-gLRRLXwDh_eNYzpfXXlggmcNwmlxTrGJsVOv2F4UdLUKMrImbgNICXGNFQxa7BWzFxMKtEOZ12Du8aH5Nka08FHt9GbliZ21yldswXaVM6OtDiGWJcDoX6KQFDgBNQCSlU0Si3E7Y4jyiyWwT_NgMUP_8X1v-fQr3249FmSHR4kllbUKY2OaNU5FCi9XefEIcHHWAZtzIynmFQjZFwHRDXMT9cg87xJxwig-rkoqncHRESczQdU0fvhjH7ARfC7VjKEBMGu0uvLSPjpEN0oV-NXRzh7uKMFgnaG1-_LlJRm60Q")
)

// If you change these keys have fun regenerating all the test data.
var (
	publicKeyData = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm4jcJXuPpUdBXvjzfF7C
bFzTY5o+2qMCsO4kDpWefbiyTiL44XP2cZo1GWPZRw7EXtOksR+Bi5KHPad6NQdD
vHd0WF8G/EdV5n9WtVOzZ/uYlAg/Q78sGWeysCO8FyJdNg85nlgNZqVMcX9P2pJ/
AhiFelTY90lPguW6KbFKrCQQnxrSXhkrlxbQ9Tx2b2nc50R/WgQfTW1hai15/eZP
Tq6h6qZnRQJWJv1MnkE/ii7fEfK4pjzKm+cWMTH4NT3snMJdEiyM9cpAyAUzHWYa
/RV2zJqc/0kdbMaJ+EF4Xs2SWDGTOpFBShba3E6cTxY3JeQ1TroZNTWr+vqHbhJc
gwIDAQAB
-----END PUBLIC KEY-----
`)

	privateKeyData = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAm4jcJXuPpUdBXvjzfF7CbFzTY5o+2qMCsO4kDpWefbiyTiL4
4XP2cZo1GWPZRw7EXtOksR+Bi5KHPad6NQdDvHd0WF8G/EdV5n9WtVOzZ/uYlAg/
Q78sGWeysCO8FyJdNg85nlgNZqVMcX9P2pJ/AhiFelTY90lPguW6KbFKrCQQnxrS
XhkrlxbQ9Tx2b2nc50R/WgQfTW1hai15/eZPTq6h6qZnRQJWJv1MnkE/ii7fEfK4
pjzKm+cWMTH4NT3snMJdEiyM9cpAyAUzHWYa/RV2zJqc/0kdbMaJ+EF4Xs2SWDGT
OpFBShba3E6cTxY3JeQ1TroZNTWr+vqHbhJcgwIDAQABAoIBAC84YOX8WoMqW/1y
hbHXrx1pHUCbHsQQQ4vl8QqAgErZHUE9uuPv6f1ZfQ+FUf0RzaqghNrFnvX5+ZdN
VnvtBbKdbbQ6vYswOTMuq+uHSuuh5hPjYRm3W7Mm2YhCgSNg6n20J6EcSI1GWCwJ
I/xPB8JiIXwfcHO7TSmHh3qK+gnCvB9YspslcVJwwOrVRy5eLLV5IIw0ku3Ib+Ei
fR6MU2QCBIk/sc40W/wNZpFXV+D6qdQehgfkdZSYUJZTni5mMSg2NncKsu8Whixu
L44vlZVR7+/DXyu3miPANV2GH1440bYhOpAzqk1M080fXhgucmqoKVEtNptvJQkK
sCnjY/kCgYEAysMf+yOzfI5Dc9OgjLFlmuYuyD6Ikoh6t8Ab/WA5yyhIZgt4ddLW
Atc5elh1wnse+RaAytmKcax+DMndPelcg/Y20BJbr+TPhGTlBRIdImVYy1jugMqA
M2rp8byk2n5O9XWKG66lTL0N88c8whLoftTmvePzti4IkjbA8a6DzNUCgYEAxF9I
SIsUtdeceMKt4xUDgraUExV/jLACgWYARLlySMfg6Bvnvn80XUped0KRDBAsq3gg
oASHqfdZoitb0sfa4OFt4qWOk64OxzVUfofXbeVJwgKgGAybPZ7dPInYYcLmV2vL
4egKi3Wxl0YGEG7+TNSNlPDY8VimBkwlzo7qT/cCgYAihKdsJL7IpJt9G3kImqa2
gRtTwbmUYKGrqIvbTcdo+5mfrbI7NMJ0R1mkp2ycyEMUmq0gW3qDMZ9f4/nDMXgr
iv333Dg5sJVXb6nBfDzzfxdnvuMTj+XVWw0qtzfFbp1YkkMJxWiksMawSqngTEHC
XdJOX4E88YdKBQJB4rjTZQKBgQCK8/lMC8491jHMacVtmCMBzXv9/QpiXPGI6spp
1ud9hKIq3AQiEhTVppgtv5aveIqDUt+TG2F77aEpVZEGF5FT63A8HnZDHbkrURtW
5XyVMNf+RqlOGy2GbvGRsuDAXI9tcMO2OOGtSTy/FDeaTU/4wbblm3+HV/kzH5Lp
FMvMhQKBgQDEk3+Y7KLpaqNncAeEr67ZzGLxKqxifuc6w8FCY2I6Y9Yhfkatjw9W
KeoODaVrgjiBurr8QzngY0U2N/k2WUEB036mHFOu13lE2Iff+Gs3LszjR92bBnez
Dw7YaJjb7we/vdEAAoth5aMxNybWVOg4iIT/SWsTix7woZqAXrRPVQ==
-----END RSA PRIVATE KEY-----
`)
)

var now = time.Unix(1736349430, 0)

func getTestPublicKey() *rsa.PublicKey {
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
	if err != nil {
		panic("unable to parse public key: " + err.Error())
	}
	return key
}

func getTestPrivateKey() *rsa.PrivateKey {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		panic("unable to parse private key: " + err.Error())
	}
	return key
}

func createTestDataFile() {
	testFile, err := os.Create(testFilePath)
	if err != nil {
		panic("unable to create temporary test data file")
	}
	defer testFile.Close()

	if n, err := testFile.Write(testFileData); err != nil {
		panic("unable to write test data to file: " + err.Error())
	} else if n != len(testFileData) {
		panic("did not write the expected number of bytes to the test data file")
	}
}

func deleteTestDataFile() {
	if err := os.Remove(testFilePath); err != nil {
		panic("failed to clean up test file: " + err.Error())
	}
}

func createTestIntegrityFile() {
	testFile, err := os.Create(testIntegrityPath)
	if err != nil {
		panic("unable to create temporary test integrity file")
	}
	defer testFile.Close()

	if n, err := testFile.Write(testIntegrityData); err != nil {
		panic("unable to write test integrity file: " + err.Error())
	} else if n != len(testIntegrityData) {
		panic("did not write the expected number of bytes to the test data file")
	}
}

func deleteTestIntegrityFile() {
	if err := os.Remove(testIntegrityPath); err != nil {
		panic("failed to clean up test integrity file: " + err.Error())
	}
}

func TestSign(t *testing.T) {
	integrity.WithNowFunc(func() time.Time {
		return now
	})
	var privateKey = getTestPrivateKey()

	type args struct {
		issuer  string
		subject string
		data    []byte
		key     *rsa.PrivateKey
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    testFileData,
				key:     privateKey,
			},
			want:    []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsInN1YiI6InRlc3Rfc3ViamVjdCIsIm5iZiI6MTczNjM0OTQzMCwiaWF0IjoxNzM2MzQ5NDMwLCJkaWdlc3QiOiIxNWM0MTZkN2JkOTg5MGY1Y2JjYzg3NTEyMjgzN2FkM2YxNGEyNTg5ZDFkMTYzYjBhNjg1Yzg2ODcwMDgyMjcwIn0.RmVuxnCntd6DVeFjTNE0-s47i5tALJ0vHgmimTPQSNoTWLM-kn8fipytFfR-yKzAPc5AwpVAE5Z3YNJ-D6C-nphnCSOch6_YDIWTVASvIbtYkCby9QMBQvemFMtq07AIIbe59O4krrp5obKmhjtyIFTm7dJiTGC9jj1JCtcR144h_egiDUdkvt3ISpii_BgbhCfVJ4xomPg_0GjknUaKeZZEs1rqZT44rH8-1DicD_eomqp7NZVTMLIiYL9RpbjlyYKbTuODqvRnkzrGhuVjCTiujgCWDVGOaBZE_ExD2XYhMhY14p5ezv3Tehp2eqvqPhZ1CHGt4cVCdcmNcAzBIw"),
			wantErr: false,
		},
		{
			name: "EmptyIssuer",
			args: args{
				issuer:  "",
				subject: testSubject,
				data:    testFileData,
				key:     privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "EmptySubject",
			args: args{
				issuer:  testIssuer,
				subject: "",
				data:    testFileData,
				key:     privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "EmptyData",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    []byte{},
				key:     privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "NilData",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    nil,
				key:     privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "NilKey",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    testFileData,
				key:     nil,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := integrity.Sign(tt.args.issuer, tt.args.subject, tt.args.data, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sign() got = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}

func TestSignFile(t *testing.T) {
	integrity.WithNowFunc(func() time.Time {
		return now
	})
	var privateKey = getTestPrivateKey()

	createTestDataFile()
	defer deleteTestDataFile()

	type args struct {
		issuer string
		path   string
		key    *rsa.PrivateKey
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				issuer: testIssuer,
				path:   testFilePath,
				key:    privateKey,
			},
			want:    []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsInN1YiI6InRlc3QudGVtcCIsIm5iZiI6MTczNjM0OTQzMCwiaWF0IjoxNzM2MzQ5NDMwLCJkaWdlc3QiOiIxNWM0MTZkN2JkOTg5MGY1Y2JjYzg3NTEyMjgzN2FkM2YxNGEyNTg5ZDFkMTYzYjBhNjg1Yzg2ODcwMDgyMjcwIn0.QIPjoKqt2kZ2iW4evv28CkodLZd0sKrZM7_qAK_-gLRRLXwDh_eNYzpfXXlggmcNwmlxTrGJsVOv2F4UdLUKMrImbgNICXGNFQxa7BWzFxMKtEOZ12Du8aH5Nka08FHt9GbliZ21yldswXaVM6OtDiGWJcDoX6KQFDgBNQCSlU0Si3E7Y4jyiyWwT_NgMUP_8X1v-fQr3249FmSHR4kllbUKY2OaNU5FCi9XefEIcHHWAZtzIynmFQjZFwHRDXMT9cg87xJxwig-rkoqncHRESczQdU0fvhjH7ARfC7VjKEBMGu0uvLSPjpEN0oV-NXRzh7uKMFgnaG1-_LlJRm60Q"),
			wantErr: false,
		},
		{
			name: "EmptyIssuer",
			args: args{
				issuer: "",
				path:   testFilePath,
				key:    privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "EmptyPath",
			args: args{
				issuer: testIssuer,
				path:   "",
				key:    privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "WrongPath",
			args: args{
				issuer: testIssuer,
				path:   "there_is_no_file_here.incomprehensible", // Try not to name a file this, if you can help it.
				key:    privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "InvalidPath",
			args: args{
				issuer: testIssuer,
				path:   "invalid/\nfile#path*$£!!()*&)_-+=][{}#'/?.,>,<,",
				key:    privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "NilKey",
			args: args{
				issuer: testIssuer,
				path:   testFilePath,
				key:    nil,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := integrity.SignFile(tt.args.issuer, tt.args.path, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SignFile() got = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}

func TestVerify(t *testing.T) {
	integrity.WithNowFunc(func() time.Time {
		return now
	})
	var publicKey = getTestPublicKey()

	type args struct {
		issuer  string
		subject string
		data    []byte
		token   []byte
		key     *rsa.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    testFileData,
				token:   []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsInN1YiI6InRlc3Rfc3ViamVjdCIsIm5iZiI6MTczNjM0OTQzMCwiaWF0IjoxNzM2MzQ5NDMwLCJkaWdlc3QiOiIxNWM0MTZkN2JkOTg5MGY1Y2JjYzg3NTEyMjgzN2FkM2YxNGEyNTg5ZDFkMTYzYjBhNjg1Yzg2ODcwMDgyMjcwIn0.RmVuxnCntd6DVeFjTNE0-s47i5tALJ0vHgmimTPQSNoTWLM-kn8fipytFfR-yKzAPc5AwpVAE5Z3YNJ-D6C-nphnCSOch6_YDIWTVASvIbtYkCby9QMBQvemFMtq07AIIbe59O4krrp5obKmhjtyIFTm7dJiTGC9jj1JCtcR144h_egiDUdkvt3ISpii_BgbhCfVJ4xomPg_0GjknUaKeZZEs1rqZT44rH8-1DicD_eomqp7NZVTMLIiYL9RpbjlyYKbTuODqvRnkzrGhuVjCTiujgCWDVGOaBZE_ExD2XYhMhY14p5ezv3Tehp2eqvqPhZ1CHGt4cVCdcmNcAzBIw"),
				key:     publicKey,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "EmptyIssuer",
			args: args{
				issuer:  "",
				subject: testSubject,
				data:    testFileData,
				token:   []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsInN1YiI6InRlc3Rfc3ViamVjdCIsIm5iZiI6MTczNjM0OTQzMCwiaWF0IjoxNzM2MzQ5NDMwLCJkaWdlc3QiOiIxNWM0MTZkN2JkOTg5MGY1Y2JjYzg3NTEyMjgzN2FkM2YxNGEyNTg5ZDFkMTYzYjBhNjg1Yzg2ODcwMDgyMjcwIn0.RmVuxnCntd6DVeFjTNE0-s47i5tALJ0vHgmimTPQSNoTWLM-kn8fipytFfR-yKzAPc5AwpVAE5Z3YNJ-D6C-nphnCSOch6_YDIWTVASvIbtYkCby9QMBQvemFMtq07AIIbe59O4krrp5obKmhjtyIFTm7dJiTGC9jj1JCtcR144h_egiDUdkvt3ISpii_BgbhCfVJ4xomPg_0GjknUaKeZZEs1rqZT44rH8-1DicD_eomqp7NZVTMLIiYL9RpbjlyYKbTuODqvRnkzrGhuVjCTiujgCWDVGOaBZE_ExD2XYhMhY14p5ezv3Tehp2eqvqPhZ1CHGt4cVCdcmNcAzBIw"),
				key:     publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "EmptySubject",
			args: args{
				issuer:  testIssuer,
				subject: "",
				data:    testFileData,
				token:   []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsInN1YiI6InRlc3Rfc3ViamVjdCIsIm5iZiI6MTczNjM0OTQzMCwiaWF0IjoxNzM2MzQ5NDMwLCJkaWdlc3QiOiIxNWM0MTZkN2JkOTg5MGY1Y2JjYzg3NTEyMjgzN2FkM2YxNGEyNTg5ZDFkMTYzYjBhNjg1Yzg2ODcwMDgyMjcwIn0.RmVuxnCntd6DVeFjTNE0-s47i5tALJ0vHgmimTPQSNoTWLM-kn8fipytFfR-yKzAPc5AwpVAE5Z3YNJ-D6C-nphnCSOch6_YDIWTVASvIbtYkCby9QMBQvemFMtq07AIIbe59O4krrp5obKmhjtyIFTm7dJiTGC9jj1JCtcR144h_egiDUdkvt3ISpii_BgbhCfVJ4xomPg_0GjknUaKeZZEs1rqZT44rH8-1DicD_eomqp7NZVTMLIiYL9RpbjlyYKbTuODqvRnkzrGhuVjCTiujgCWDVGOaBZE_ExD2XYhMhY14p5ezv3Tehp2eqvqPhZ1CHGt4cVCdcmNcAzBIw"),
				key:     publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "EmptyData",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    []byte{},
				token:   []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsInN1YiI6InRlc3Rfc3ViamVjdCIsIm5iZiI6MTczNjM0OTQzMCwiaWF0IjoxNzM2MzQ5NDMwLCJkaWdlc3QiOiIxNWM0MTZkN2JkOTg5MGY1Y2JjYzg3NTEyMjgzN2FkM2YxNGEyNTg5ZDFkMTYzYjBhNjg1Yzg2ODcwMDgyMjcwIn0.RmVuxnCntd6DVeFjTNE0-s47i5tALJ0vHgmimTPQSNoTWLM-kn8fipytFfR-yKzAPc5AwpVAE5Z3YNJ-D6C-nphnCSOch6_YDIWTVASvIbtYkCby9QMBQvemFMtq07AIIbe59O4krrp5obKmhjtyIFTm7dJiTGC9jj1JCtcR144h_egiDUdkvt3ISpii_BgbhCfVJ4xomPg_0GjknUaKeZZEs1rqZT44rH8-1DicD_eomqp7NZVTMLIiYL9RpbjlyYKbTuODqvRnkzrGhuVjCTiujgCWDVGOaBZE_ExD2XYhMhY14p5ezv3Tehp2eqvqPhZ1CHGt4cVCdcmNcAzBIw"),
				key:     publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "InvalidData",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    []byte("invalid data"),
				token:   []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsInN1YiI6InRlc3Rfc3ViamVjdCIsIm5iZiI6MTczNjM0OTQzMCwiaWF0IjoxNzM2MzQ5NDMwLCJkaWdlc3QiOiIxNWM0MTZkN2JkOTg5MGY1Y2JjYzg3NTEyMjgzN2FkM2YxNGEyNTg5ZDFkMTYzYjBhNjg1Yzg2ODcwMDgyMjcwIn0.RmVuxnCntd6DVeFjTNE0-s47i5tALJ0vHgmimTPQSNoTWLM-kn8fipytFfR-yKzAPc5AwpVAE5Z3YNJ-D6C-nphnCSOch6_YDIWTVASvIbtYkCby9QMBQvemFMtq07AIIbe59O4krrp5obKmhjtyIFTm7dJiTGC9jj1JCtcR144h_egiDUdkvt3ISpii_BgbhCfVJ4xomPg_0GjknUaKeZZEs1rqZT44rH8-1DicD_eomqp7NZVTMLIiYL9RpbjlyYKbTuODqvRnkzrGhuVjCTiujgCWDVGOaBZE_ExD2XYhMhY14p5ezv3Tehp2eqvqPhZ1CHGt4cVCdcmNcAzBIw"),
				key:     publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "NilData",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    nil,
				token:   []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsInN1YiI6InRlc3Rfc3ViamVjdCIsIm5iZiI6MTczNjM0OTQzMCwiaWF0IjoxNzM2MzQ5NDMwLCJkaWdlc3QiOiIxNWM0MTZkN2JkOTg5MGY1Y2JjYzg3NTEyMjgzN2FkM2YxNGEyNTg5ZDFkMTYzYjBhNjg1Yzg2ODcwMDgyMjcwIn0.RmVuxnCntd6DVeFjTNE0-s47i5tALJ0vHgmimTPQSNoTWLM-kn8fipytFfR-yKzAPc5AwpVAE5Z3YNJ-D6C-nphnCSOch6_YDIWTVASvIbtYkCby9QMBQvemFMtq07AIIbe59O4krrp5obKmhjtyIFTm7dJiTGC9jj1JCtcR144h_egiDUdkvt3ISpii_BgbhCfVJ4xomPg_0GjknUaKeZZEs1rqZT44rH8-1DicD_eomqp7NZVTMLIiYL9RpbjlyYKbTuODqvRnkzrGhuVjCTiujgCWDVGOaBZE_ExD2XYhMhY14p5ezv3Tehp2eqvqPhZ1CHGt4cVCdcmNcAzBIw"),
				key:     publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "EmptyToken",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    testFileData,
				token:   []byte{},
				key:     publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "InvalidToken",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    testFileData,
				token:   []byte("this is not a JWT"),
				key:     publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "NilToken",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    testFileData,
				token:   nil,
				key:     publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "NilKey",
			args: args{
				issuer:  testIssuer,
				subject: testSubject,
				data:    testFileData,
				token:   []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0X2lzc3VlciIsInN1YiI6InRlc3Rfc3ViamVjdCIsIm5iZiI6MTczNjM0OTQzMCwiaWF0IjoxNzM2MzQ5NDMwLCJkaWdlc3QiOiIxNWM0MTZkN2JkOTg5MGY1Y2JjYzg3NTEyMjgzN2FkM2YxNGEyNTg5ZDFkMTYzYjBhNjg1Yzg2ODcwMDgyMjcwIn0.RmVuxnCntd6DVeFjTNE0-s47i5tALJ0vHgmimTPQSNoTWLM-kn8fipytFfR-yKzAPc5AwpVAE5Z3YNJ-D6C-nphnCSOch6_YDIWTVASvIbtYkCby9QMBQvemFMtq07AIIbe59O4krrp5obKmhjtyIFTm7dJiTGC9jj1JCtcR144h_egiDUdkvt3ISpii_BgbhCfVJ4xomPg_0GjknUaKeZZEs1rqZT44rH8-1DicD_eomqp7NZVTMLIiYL9RpbjlyYKbTuODqvRnkzrGhuVjCTiujgCWDVGOaBZE_ExD2XYhMhY14p5ezv3Tehp2eqvqPhZ1CHGt4cVCdcmNcAzBIw"),
				key:     nil,
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := integrity.Verify(tt.args.issuer, tt.args.subject, tt.args.data, tt.args.token, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verify() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyFile(t *testing.T) {
	integrity.WithNowFunc(func() time.Time {
		return now
	})
	var publicKey = getTestPublicKey()

	createTestDataFile()
	defer deleteTestDataFile()

	createTestIntegrityFile()
	defer deleteTestIntegrityFile()

	type args struct {
		issuer        string
		path          string
		integrityPath string
		key           *rsa.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				issuer:        testIssuer,
				path:          testFilePath,
				integrityPath: testIntegrityPath,
				key:           publicKey,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "EmptyIssuer",
			args: args{
				issuer:        "",
				path:          testFilePath,
				integrityPath: testIntegrityPath,
				key:           publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "EmptyPath",
			args: args{
				issuer:        testIssuer,
				path:          "",
				integrityPath: testIntegrityPath,
				key:           publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "InvalidPath",
			args: args{
				issuer:        testIssuer,
				path:          "invalid?path6&&^&9))&&%^&(~@}{@#['#}{@~\\/.<>???<<>><dajk,;s./,a1!",
				integrityPath: testIntegrityPath,
				key:           publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "WrongPath",
			args: args{
				issuer:        testIssuer,
				path:          "this_file_does_not_exist.dontcallitthis",
				integrityPath: testIntegrityPath,
				key:           publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "EmptyIntegrityPath",
			args: args{
				issuer:        testIssuer,
				path:          testFilePath,
				integrityPath: "",
				key:           publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "InvalidIntegrityPath",
			args: args{
				issuer:        testIssuer,
				path:          testFilePath,
				integrityPath: "invalid?9834r9*&^*&Y*£)(U(*U(O£ORKJR#'[;4r#[;4r[][}{{@~}{@@?@>@?>.,.?><>/",
				key:           publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "WrongIntegrityPath",
			args: args{
				issuer:        testIssuer,
				path:          testFilePath,
				integrityPath: "this_file_does_not_exist_either.teeeeeeeeeeeesssssttttttt",
				key:           publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "NilKey",
			args: args{
				issuer:        testIssuer,
				path:          testFilePath,
				integrityPath: testIntegrityPath,
				key:           nil,
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := integrity.VerifyFile(tt.args.issuer, tt.args.path, tt.args.integrityPath, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyFile() got = %v, want %v", got, tt.want)
			}
		})
	}
}
