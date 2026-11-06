package traffic

import (
	"bytes"
	"fmt"
	"testing"
)

// Measures only credential scanning, excluding DB reads, TLS, proxying and capture.
func BenchmarkCredentialScan(b *testing.B) {
	keys := make([]string, 8)
	for i := range keys {
		keys[i] = fmt.Sprintf("isolated-platform-key-%02d-abcdefghijklmnopqrstuvwxyz", i)
	}
	for _, size := range []int{1024, 64 * 1024, maxGuardBody} {
		for _, hit := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/tail_match=%t", size, hit), func(b *testing.B) {
				body := bytes.Repeat([]byte("x"), size)
				if hit {
					copy(body[len(body)-len(keys[7]):], keys[7])
				}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if containsSecret(body, keys) != hit {
						b.Fatal("incorrect scan result")
					}
				}
			})
		}
	}
}
