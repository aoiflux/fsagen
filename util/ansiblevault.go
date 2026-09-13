package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Ansible's VaultAES256 parameters. These are fixed by the on-disk format, not
// choices we get to make: changing any of them yields a file the real
// ansible-vault cannot open.
const (
	vaultHeader     = "$ANSIBLE_VAULT"
	vaultCipher     = "AES256"
	vaultIterations = 10000
	vaultSaltLen    = 32
	vaultKeyLen     = 32
	vaultIVLen      = 16
	vaultLineLen    = 80
)

// AnsibleVaultEncrypt produces a genuine $ANSIBLE_VAULT;1.1;AES256 payload:
// PBKDF2-HMAC-SHA256 key derivation, AES-256-CTR encryption and an
// HMAC-SHA256 tag, hex-encoded twice exactly as Ansible layers it.
//
// A non-empty vaultID selects the 1.2 header form. saltHex pins the salt for
// reproducible output; when empty the salt is drawn from the seeded PRNG, which
// is deterministic for a given --seed.
func AnsibleVaultEncrypt(plaintext []byte, password, vaultID, saltHex string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("ansible-vault requires a password")
	}

	salt, err := vaultSalt(saltHex)
	if err != nil {
		return nil, err
	}

	cipherKey, hmacKey, iv, err := vaultDeriveKeys(password, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, padded)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(ciphertext)

	// Ansible joins the three already-hex-encoded fields with newlines, then
	// hex-encodes that whole blob a second time.
	inner := strings.Join([]string{
		hex.EncodeToString(salt),
		hex.EncodeToString(mac.Sum(nil)),
		hex.EncodeToString(ciphertext),
	}, "\n")
	payload := hex.EncodeToString([]byte(inner))

	version := "1.1"
	header := strings.Join([]string{vaultHeader, version, vaultCipher}, ";")
	if vaultID = strings.TrimSpace(vaultID); vaultID != "" {
		version = "1.2"
		header = strings.Join([]string{vaultHeader, version, vaultCipher, vaultID}, ";")
	}

	var out bytes.Buffer
	out.WriteString(header)
	out.WriteByte('\n')
	for len(payload) > vaultLineLen {
		out.WriteString(payload[:vaultLineLen])
		out.WriteByte('\n')
		payload = payload[vaultLineLen:]
	}
	out.WriteString(payload)
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// AnsibleVaultDecrypt reverses AnsibleVaultEncrypt. It exists so tests can
// round-trip without requiring Ansible to be installed; verifying against the
// real ansible-vault binary is still the authoritative check.
func AnsibleVaultDecrypt(vaulttext []byte, password string) ([]byte, error) {
	lines := strings.Split(strings.ReplaceAll(string(vaulttext), "\r\n", "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], vaultHeader) {
		return nil, errors.New("not an ansible-vault file")
	}

	outer, err := hex.DecodeString(strings.Join(lines[1:], ""))
	if err != nil {
		return nil, fmt.Errorf("decode vault envelope: %w", err)
	}
	fields := strings.Split(string(outer), "\n")
	if len(fields) != 3 {
		return nil, fmt.Errorf("expected 3 vault fields, got %d", len(fields))
	}

	salt, err := hex.DecodeString(fields[0])
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	wantMAC, err := hex.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("decode hmac: %w", err)
	}
	ciphertext, err := hex.DecodeString(fields[2])
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	cipherKey, hmacKey, iv, err := vaultDeriveKeys(password, salt)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(ciphertext)
	if !hmac.Equal(mac.Sum(nil), wantMAC) {
		return nil, errors.New("vault HMAC mismatch (wrong password or corrupt file)")
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	padded := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(padded, ciphertext)
	return pkcs7Unpad(padded, aes.BlockSize)
}

func vaultDeriveKeys(password string, salt []byte) (cipherKey, hmacKey, iv []byte, err error) {
	km, err := pbkdf2.Key(sha256.New, password, salt, vaultIterations, 2*vaultKeyLen+vaultIVLen)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive vault key: %w", err)
	}
	return km[:vaultKeyLen], km[vaultKeyLen : 2*vaultKeyLen], km[2*vaultKeyLen:], nil
}

func vaultSalt(saltHex string) ([]byte, error) {
	saltHex = strings.TrimSpace(saltHex)
	if saltHex == "" {
		return GetRandomBytes(vaultSaltLen), nil
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("vault salt must be hex: %w", err)
	}
	if len(salt) != vaultSaltLen {
		return nil, fmt.Errorf("vault salt must be %d bytes (%d hex chars), got %d", vaultSaltLen, vaultSaltLen*2, len(salt))
	}
	return salt, nil
}

// Ansible PKCS7-pads before AES-CTR even though a stream mode does not need it.
func pkcs7Pad(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	return append(append([]byte{}, b...), bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, errors.New("vault plaintext is not block-aligned")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, errors.New("invalid vault padding")
	}
	return b[:len(b)-n], nil
}
