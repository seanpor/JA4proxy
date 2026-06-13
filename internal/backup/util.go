package backup

import (
	"fmt"
	"io"
)

// maxDecompressedBytes bounds the decompressed snapshot to defend against a
// decompression bomb. The artifact is GCM-authenticated (so a bomb would need
// our own key), but bounding the read is cheap defence-in-depth. 1 GiB is far
// above any realistic security-state snapshot.
const maxDecompressedBytes = 1 << 30

// readAllLimited reads from r up to maxDecompressedBytes, erroring if exceeded.
func readAllLimited(r io.Reader) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxDecompressedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxDecompressedBytes {
		return nil, fmt.Errorf("backup: decompressed snapshot exceeds %d bytes", maxDecompressedBytes)
	}
	return out, nil
}
