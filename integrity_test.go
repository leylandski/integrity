package integrity_test

import (
	"crypto/rsa"
	"errors"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/leylandski/integrity"
)

const (
	testIssuer     = "test.issuer"
	testFolderName = "_test"
)

var (
	testFileData = map[string]string{
		"test.1": "1234567890",
		"test.2": "abcdefghijklmnopqrstuvwxyz",
		"test.3": "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii",
	}
	testManifestData = map[string]string{
		"valid.integrity":             "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Lmlzc3VlciIsImlhdCI6MTczNjM0OTQzMCwibWFuaWZlc3QiOnsiX3Rlc3QvdGVzdC4xIjoiYzc3NWU3Yjc1N2VkZTYzMGNkMGFhMTExM2JkMTAyNjYxYWIzODgyOWNhNTJhNjQyMmFiNzgyODYyZjI2ODY0NiIsIl90ZXN0L3Rlc3QuMiI6IjcxYzQ4MGRmOTNkNmFlMmYxZWZhZDE0NDdjNjZjOTUyNWUzMTYyMThjZjUxZmM4ZDllZDgzMmYyZGFmMThiNzMiLCJfdGVzdC90ZXN0LjMiOiJiMWI0N2Y1ZGU3YTM4MjRmN2I0NGQyMDFlY2I3YjU3NzBiZDQwNzEwMGQ0NDdmNGQ4Nzk5YzAxZDQzNDdhNjBkIn19.fBbTLr9J_UNmnb_Ef9HpcEuhARB-4IV3FjwMElx5L-VavEIPPCcYSqyRlJJBhpg3Z1dQvFnVBk3O7mm9A4J5WZM1wdjiqj_8BTQdFgh5-ARADUBqQpDfdoa_amBi_sXO1PDftN7a-4JkdkFhj4bkRrqdzx_N_KIIODzx9sdNjY9UgQ3sCuIro7nVPTmA123pErmqfsUT8XuyZP_p20Qt40sVs7omZr3zU_LAdzpcnurpC0fWUPywD8f7bR_Ox81C8SXUV8P2Z7dlkelDYDV2ltAqmgLl4YPtwS-imK9ZgzaqMUiB927NRTeQWaq-I-ZHX5mvKro03W5zEZihrbUG7w",
		"invalid_signature.integrity": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Lmlzc3VlciIsImlhdCI6MTczNjM0OTQzMCwibWFuaWZlc3QiOnsiX3Rlc3QvdGVzdC4xIjoiYzc3NWU3Yjc1N2VkZTYzMGNkMGFhMTExM2JkMTAyNjYxYWIzODgyOWNhNTJhNjQyMmFiNzgyODYyZjI2ODY0NiIsIl90ZXN0L3Rlc3QuMiI6IjcxYzQ4MGRmOTNkNmFlMmYxZWZhZDE0NDdjNjZjOTUyNWUzMTYyMThjZjUxZmM4ZDllZDgzMmYyZGFmMThiNzMiLCJfdGVzdC90ZXN0LjMiOiJiMWI0N2Y1ZGU3YTM4MjRmN2I0NGQyMDFlY2I3YjU3NzBiZDQwNzEwMGQ0NDdmNGQ4Nzk5YzAxZDQzNDdhNjBkIn19.fBbTLr9J_UNmnb_Ef9HpcEuhARB-4IV3FjwMElx5L-VavEIPPCcYSqyRlJJBhpg3Z1dQvFnVBk3O7mm9A4J5WZM1wdjiqj_8BTQdFgh5-ARADUBqQpDfdoa_amBi_sXO1PDftN7a-4JkdkFhj4bkRrqdzx_N_KIIODzx9sdjY9UgQ3sCuIro7nVPTmA123pErmqfsUT8XuyZP_p20Qt40sVs7omZr3zU_LAdzpcnurpC0fWUPywD8f7bR_Ox81C8SXUV8P2Z7dlkelDYDV2ltAqmgLl4YPtwS-imK9ZgzaqMUiB927NRTeQWaq-I-ZHX5mvKro03W5zEZihrbUG7w",
		"invalid_digest.integrity":    "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Lmlzc3VlciIsImlhdCI6MTczNjM0OTQzMCwibWFuaWZlc3QiOnsiX3Rlc3QvdGVzdC4xIjoiYzc3NWU3Yjc1N2UzMGNkMGFhMTExM2JkMTAyNjYxYWIzODgyOWNhNTJhNjQyMmFiNzgyODYyZjI2ODY0NiIsIl90ZXN0L3Rlc3QuMiI6IjcxYzQ4MGRmOTNkNmFlMmYxZWZhZDE0NDdjNjZjOTUyNWUzMTYyMThjZjUxZmM4ZDllZDgzMmYyZGFmMThiNzMiLCJfdGVzdC90ZXN0LjMiOiJiMWI0N2Y1ZGU3YTM4MjRmN2I0NGQyMDFlY2I3YjU3NzBiZDQwNzEwMGQ0NDdmNGQ4Nzk5YzAxZDQzNDdhNjBkIn19.jL_3_YOEC1Z5M1mQzlKv1sMzCw8400Zd3Q0XJBSgXArajLSSbpkMe1OcWiaPx1KCwuumtMhDDlm7kxQVHRT68_btlrSabRKWOlvYyL2J2t_HBd8Q48chHoRIGRXq8oM1l3CoqMkVIsLlCoFeSzjxvVHCHxnkaqBvrngg2LbFYh-ssblFV8AOeEzyQqZSC_6moZbnQnrH25654NWHheHDYWxFByZOOD5B7W53aMtgeGtJ1q3P_5QZxOJXZPus71RZReXnJaGH5UzOP5dTS_OCeiX0UvaK-MvNiK7AbtAUMKRhFdsABJUkuP_hwXFm_cbmTm1STQzeAvAKg6TEhs_avw",
	}

	// Obviously don't use these keys for anything else.
	publicKeyData = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm4jcJXuPpUdBXvjzfF7C
bFzTY5o+2qMCsO4kDpWefbiyTiL44XP2cZo1GWPZRw7EXtOksR+Bi5KHPad6NQdD
vHd0WF8G/EdV5n9WtVOzZ/uYlAg/Q78sGWeysCO8FyJdNg85nlgNZqVMcX9P2pJ/
AhiFelTY90lPguW6KbFKrCQQnxrSXhkrlxbQ9Tx2b2nc50R/WgQfTW1hai15/eZP
Tq6h6qZnRQJWJv1MnkE/ii7fEfK4pjzKm+cWMTH4NT3snMJdEiyM9cpAyAUzHWYa
/RV2zJqc/0kdbMaJ+EF4Xs2SWDGTOpFBShba3E6cTxY3JeQ1TroZNTWr+vqHbhJc
gwIDAQAB
-----END PUBLIC KEY-----`)

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
-----END RSA PRIVATE KEY-----`)
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

func generateTestDataFiles() {
	err := os.Mkdir(testFolderName, 0755)
	if err != nil && !os.IsExist(err) {
		panic(err)
	}

	genFile := func(name string, data []byte) error {
		f, err := os.Create(path.Join(testFolderName, name))
		if err != nil {
			return err
		}
		defer f.Close()

		if n, err := f.Write(data); err != nil {
			return err
		} else if n != len(data) {
			return errors.New("did not write the expected number of bytes to the test data file")
		}

		return nil
	}

	for k := range testFileData {
		if err = genFile(k, []byte(testFileData[k])); err != nil {
			removeTestDataFiles()
			panic(err)
		}
	}

	for k := range testManifestData {
		if err = genFile(k, []byte(testManifestData[k])); err != nil {
			removeTestDataFiles()
			panic(err)
		}
	}
}

func removeTestDataFiles() {
	for k := range testFileData {
		os.Remove(path.Join(testFolderName, k))
	}
	for k := range testManifestData {
		os.Remove(path.Join(testFolderName, k))
	}
	os.Remove(testFolderName + string(os.PathSeparator))
}

func TestGenerateManifest(t *testing.T) {
	integrity.WithNowFunc(func() time.Time {
		return now
	})
	var privateKey = getTestPrivateKey()

	generateTestDataFiles()
	defer removeTestDataFiles()

	type args struct {
		issuer string
		paths  []string
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
				paths: []string{
					"_test/test.1",
					"_test/test.2",
					"_test/test.3",
				},
				key: privateKey,
			},
			want:    []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Lmlzc3VlciIsImlhdCI6MTczNjM0OTQzMCwibWFuaWZlc3QiOnsiX3Rlc3QvdGVzdC4xIjoiYzc3NWU3Yjc1N2VkZTYzMGNkMGFhMTExM2JkMTAyNjYxYWIzODgyOWNhNTJhNjQyMmFiNzgyODYyZjI2ODY0NiIsIl90ZXN0L3Rlc3QuMiI6IjcxYzQ4MGRmOTNkNmFlMmYxZWZhZDE0NDdjNjZjOTUyNWUzMTYyMThjZjUxZmM4ZDllZDgzMmYyZGFmMThiNzMiLCJfdGVzdC90ZXN0LjMiOiJiMWI0N2Y1ZGU3YTM4MjRmN2I0NGQyMDFlY2I3YjU3NzBiZDQwNzEwMGQ0NDdmNGQ4Nzk5YzAxZDQzNDdhNjBkIn19.fBbTLr9J_UNmnb_Ef9HpcEuhARB-4IV3FjwMElx5L-VavEIPPCcYSqyRlJJBhpg3Z1dQvFnVBk3O7mm9A4J5WZM1wdjiqj_8BTQdFgh5-ARADUBqQpDfdoa_amBi_sXO1PDftN7a-4JkdkFhj4bkRrqdzx_N_KIIODzx9sdNjY9UgQ3sCuIro7nVPTmA123pErmqfsUT8XuyZP_p20Qt40sVs7omZr3zU_LAdzpcnurpC0fWUPywD8f7bR_Ox81C8SXUV8P2Z7dlkelDYDV2ltAqmgLl4YPtwS-imK9ZgzaqMUiB927NRTeQWaq-I-ZHX5mvKro03W5zEZihrbUG7w"),
			wantErr: false,
		},
		{
			name: "EmptyIssuer",
			args: args{
				issuer: "",
				paths: []string{
					"_test/test.1",
					"_test/test.2",
					"_test/test.3",
				},
				key: privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "NilPaths",
			args: args{
				issuer: testIssuer,
				paths:  nil,
				key:    privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "EmptyPaths",
			args: args{
				issuer: testIssuer,
				paths:  []string{},
				key:    privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "InvalidPaths",
			args: args{
				issuer: testIssuer,
				paths: []string{
					"_test/test.4",
					"_test/test.5",
					"_test/test.6",
				},
				key: privateKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "DuplicatePaths",
			args: args{
				issuer: testIssuer,
				paths: []string{
					"_test/test.1",
					"_test/test.1",
					"_test/test.1",
				},
				key: privateKey,
			},
			want:    []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Lmlzc3VlciIsImlhdCI6MTczNjM0OTQzMCwibWFuaWZlc3QiOnsiX3Rlc3QvdGVzdC4xIjoiYzc3NWU3Yjc1N2VkZTYzMGNkMGFhMTExM2JkMTAyNjYxYWIzODgyOWNhNTJhNjQyMmFiNzgyODYyZjI2ODY0NiJ9fQ.lsQhNJ6fkxIW56N1XcIHKDBFFp0G608A9fI-LZ3PcJ24vj8hJy0rgj30XZMR5538mv9QXqXDhbndlKan7OF0xphrbTMxEXQiQ8C266oA72XgmWtDDsoKXYK0_Aj1ifl15uAezOH1HJC_ehdeIrBpXHbivmAlopJEIfjoCBBomKTnEY-013XYFmMz5cYdGLBvXZWuVz1pnbgK38XTdWfIo5ijklVUEqTjVIJBk-WzTsPiIK3PgSHQtR_p9Bwyg3KXTB5Oo12gV7QCfKT_DRvwEBCnOEtr9ufpmHwFDfuNsCzt5DUBrc1Uqojb-8dCcBoSByJmArGv-JDlC42BYYSNFQ"),
			wantErr: false,
		},
		{
			name: "NilKey",
			args: args{
				issuer: testIssuer,
				paths: []string{
					"_test/test.1",
					"_test/test.2",
					"_test/test.3",
				},
				key: nil,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := integrity.GenerateManifest(tt.args.issuer, tt.args.paths, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateManifest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateManifest() got = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}

func TestVerifyManifest(t *testing.T) {
	integrity.WithNowFunc(func() time.Time {
		return now
	})
	var publicKey = getTestPublicKey()

	generateTestDataFiles()
	defer removeTestDataFiles()

	type args struct {
		issuer       string
		manifestPath string
		root         string
		key          *rsa.PublicKey
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
				issuer:       testIssuer,
				manifestPath: "_test/valid.integrity",
				root:         "",
				key:          publicKey,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "SuccessWithRoot",
			args: args{
				issuer:       testIssuer,
				manifestPath: "valid.integrity",
				root:         "_test",
				key:          publicKey,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "SuccessWithRootSlash",
			args: args{
				issuer:       testIssuer,
				manifestPath: "valid.integrity",
				root:         "_test/",
				key:          publicKey,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "EmptyIssuer",
			args: args{
				issuer:       "",
				manifestPath: "_test/valid.integrity",
				root:         "",
				key:          publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "InvalidIssuer",
			args: args{
				issuer:       "invalid",
				manifestPath: "_test/valid.integrity",
				root:         "",
				key:          publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "EmptyManifestPath",
			args: args{
				issuer:       testIssuer,
				manifestPath: "",
				root:         "",
				key:          publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "InvalidManifestPath",
			args: args{
				issuer:       testIssuer,
				manifestPath: "_test/missing",
				root:         "",
				key:          publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "NilKey",
			args: args{
				issuer:       testIssuer,
				manifestPath: "_test/valid.integrity",
				root:         "",
				key:          nil,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "InvalidSignature",
			args: args{
				issuer:       testIssuer,
				manifestPath: "_test/invalid_signature.integrity",
				root:         "",
				key:          publicKey,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "InvalidDigest",
			args: args{
				issuer:       testIssuer,
				manifestPath: "_test/invalid_digest.integrity",
				root:         "",
				key:          publicKey,
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := integrity.VerifyManifest(tt.args.issuer, tt.args.manifestPath, tt.args.root, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyManifest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyManifest() got = %v, want %v", got, tt.want)
			}
		})
	}
}
