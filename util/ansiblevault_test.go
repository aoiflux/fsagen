package util

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAnsibleVaultRoundTrip(t *testing.T) {
	Seed(1)
	plaintext := []byte("---\nprod_db_password: \"S3cr3t\"\nflag: \"FLAG{x}\"\n")
	const password = "Wint3r-Rot@t3-2026"

	out, err := AnsibleVaultEncrypt(plaintext, password, "", "")
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
	Seed(1)
	out, err := AnsibleVaultEncrypt([]byte("secret"), "correct", "", "")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := AnsibleVaultDecrypt(out, "wrong"); err == nil {
		t.Fatal("decrypt with the wrong password should fail")
	}
}

func TestAnsibleVaultIDSelectsVersion12(t *testing.T) {
	Seed(1)
	out, err := AnsibleVaultEncrypt([]byte("secret"), "pw", "prod", "")
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

	Seed(1)
	first, err := AnsibleVaultEncrypt([]byte("secret"), "pw", "", salt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	Seed(99) // a different seed must not matter once the salt is pinned
	second, err := AnsibleVaultEncrypt([]byte("secret"), "pw", "", salt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("pinned salt produced different output across seeds")
	}
}

func TestAnsibleVaultRejectsBadSalt(t *testing.T) {
	Seed(1)
	if _, err := AnsibleVaultEncrypt([]byte("x"), "pw", "", "not-hex"); err == nil {
		t.Error("a non-hex salt should be rejected")
	}
	if _, err := AnsibleVaultEncrypt([]byte("x"), "pw", "", "abcd"); err == nil {
		t.Error("a salt of the wrong length should be rejected")
	}
}

func TestAnsibleVaultLineWrapping(t *testing.T) {
	Seed(1)
	out, err := AnsibleVaultEncrypt(bytes.Repeat([]byte("A"), 500), "pw", "", "")
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

func TestGetRandomHexIsHexAndDeterministic(t *testing.T) {
	Seed(7)
	a := GetRandomHex(32)
	Seed(7)
	b := GetRandomHex(32)

	if a != b {
		t.Errorf("same seed produced %q and %q", a, b)
	}
	if len(a) != 32 {
		t.Errorf("length = %d, want 32", len(a))
	}
	if strings.Trim(a, "0123456789abcdef") != "" {
		t.Errorf("%q contains non-hex characters", a)
	}
}

func TestGetRandomUUIDIsWellFormed(t *testing.T) {
	Seed(3)
	got := GetRandomUUID()

	parts := strings.Split(got, "-")
	if len(parts) != 5 {
		t.Fatalf("%q does not have 5 dash-separated groups", got)
	}
	for i, want := range []int{8, 4, 4, 4, 12} {
		if len(parts[i]) != want {
			t.Errorf("group %d of %q is %d chars, want %d", i, got, len(parts[i]), want)
		}
	}
	if parts[2][0] != '4' {
		t.Errorf("version nibble of %q = %c, want 4", got, parts[2][0])
	}
	if !strings.ContainsRune("89ab", rune(parts[3][0])) {
		t.Errorf("variant nibble of %q = %c, want one of 8,9,a,b", got, parts[3][0])
	}
}
