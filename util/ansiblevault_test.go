package util

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAnsibleVaultRoundTrip(t *testing.T) {
	plaintext := []byte("---\nprod_db_password: \"S3cr3t\"\nflag: \"FLAG{x}\"\n")
	const password = "Wint3r-Rot@t3-2026"

	out, err := AnsibleVaultEncrypt(plaintext, password, "", testSalt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	header, _, _ := strings.Cut(string(out), "\n")
	if header != "$ANSIBLE_VAULT;1.1;AES256" {
		t.Errorf("header = %q, want $ANSIBLE_VAULT;1.1;AES256", header)
	}

	got, err := AnsibleVaultDecrypt(out, password)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip = %q, want %q", got, plaintext)
	}
}

func TestAnsibleVaultWrongPasswordFails(t *testing.T) {
	out, err := AnsibleVaultEncrypt([]byte("secret"), "correct", "", testSalt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := AnsibleVaultDecrypt(out, "wrong"); err == nil {
		t.Fatal("decrypt with the wrong password should fail")
	}
}

func TestAnsibleVaultIDSelectsVersion12(t *testing.T) {
	out, err := AnsibleVaultEncrypt([]byte("secret"), "pw", "prod", testSalt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	header, _, _ := strings.Cut(string(out), "\n")
	if header != "$ANSIBLE_VAULT;1.2;AES256;prod" {
		t.Errorf("header = %q, want the 1.2 form with the vault id", header)
	}
}

// A pinned salt must give byte-identical output, which is what makes vault
// artifacts reproducible independently of PRNG draw order.
func TestAnsibleVaultPinnedSaltIsReproducible(t *testing.T) {
	salt := hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32))

	first, err := AnsibleVaultEncrypt([]byte("secret"), "pw", "", salt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	second, err := AnsibleVaultEncrypt([]byte("secret"), "pw", "", salt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("pinned salt produced different output across seeds")
	}
}

func TestAnsibleVaultRejectsBadSalt(t *testing.T) {
	if _, err := AnsibleVaultEncrypt([]byte("x"), "pw", "", "not-hex"); err == nil {
		t.Error("a non-hex salt should be rejected")
	}
	if _, err := AnsibleVaultEncrypt([]byte("x"), "pw", "", "abcd"); err == nil {
		t.Error("a salt of the wrong length should be rejected")
	}
}

func TestAnsibleVaultLineWrapping(t *testing.T) {
	out, err := AnsibleVaultEncrypt(bytes.Repeat([]byte("A"), 500), "pw", "", testSalt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected the payload to wrap over several lines, got %d", len(lines))
	}
	for i, l := range lines[1:] {
		if len(l) > vaultLineLen {
			t.Errorf("payload line %d is %d chars, want <= %d", i+1, len(l), vaultLineLen)
		}
	}
}

func TestParseFileMode(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    uint32
		wantOK  bool
		wantErr bool
	}{
		{"", 0, false, false},
		{"0600", 0o600, true, false},
		{"755", 0o755, true, false},
		{"0640", 0o640, true, false},
		{"999", 0, false, true},
		{"rwx", 0, false, true},
	} {
		mode, ok, err := ParseFileMode(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseFileMode(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if ok != tc.wantOK || (tc.wantOK && uint32(mode) != tc.want) {
			t.Errorf("ParseFileMode(%q) = %o, %v; want %o, %v", tc.in, mode, ok, tc.want, tc.wantOK)
		}
	}
}

// testSalt pins the salt; fsagen draws one from the operation's own random
// stream when the scenario gives none.
var testSalt = strings.Repeat("5a", 32)

func TestVaultNeedsSalt(t *testing.T) {
	if _, err := AnsibleVaultEncrypt([]byte("x"), "pw", "", ""); err == nil {
		t.Fatal("an empty salt was accepted")
	}
}
