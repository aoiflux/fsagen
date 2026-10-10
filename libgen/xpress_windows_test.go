//go:build windows

package libgen

import (
	"bytes"
	"syscall"
	"testing"
	"unsafe"
)

// compressionFormatXpressHuff is COMPRESSION_FORMAT_XPRESS_HUFF.
const compressionFormatXpressHuff = 4

// TestXpressDecodedByWindows: Windows' own decompressor, the one that reads
// prefetch files, turns what the encoder writes back into its input. The
// decoder in xpress_test.go is written from the specification; this one is
// the implementation the specification describes.
func TestXpressDecodedByWindows(t *testing.T) {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	decompress := ntdll.NewProc("RtlDecompressBufferEx")
	workspaceSize := ntdll.NewProc("RtlGetCompressionWorkSpaceSize")
	if decompress.Find() != nil || workspaceSize.Find() != nil {
		t.Skip("ntdll has no RtlDecompressBufferEx")
	}
	var bufferWS, fragmentWS uint32
	if st, _, _ := workspaceSize.Call(compressionFormatXpressHuff, uintptr(unsafe.Pointer(&bufferWS)), uintptr(unsafe.Pointer(&fragmentWS))); st != 0 {
		t.Fatalf("RtlGetCompressionWorkSpaceSize: NTSTATUS %#x", st)
	}
	workspace := make([]byte, max(bufferWS, fragmentWS, 1))

	for name, in := range xpressInputs() {
		if len(in) == 0 {
			continue // the API takes no empty buffer
		}
		t.Run(name, func(t *testing.T) {
			c := XpressHuffman(in)
			out := make([]byte, len(in))
			var final uint32
			st, _, _ := decompress.Call(compressionFormatXpressHuff,
				uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
				uintptr(unsafe.Pointer(&c[0])), uintptr(len(c)),
				uintptr(unsafe.Pointer(&final)), uintptr(unsafe.Pointer(&workspace[0])))
			if st != 0 {
				t.Fatalf("Windows refused the stream: NTSTATUS %#x", st)
			}
			if int(final) != len(in) || !bytes.Equal(out, in) {
				t.Fatalf("Windows decoded %d bytes, not the %d given", final, len(in))
			}
		})
	}
}
