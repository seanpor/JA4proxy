package tlsfixture

// GREASE values per RFC 8701
var GREASE = [16]uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

// WithGREASE returns a new Spec with the specified GREASE value injected.
func WithGREASE(s Spec, g uint16) Spec {
	newSpec := s
	newSpec.Ciphers = append([]uint16{g}, s.Ciphers...)
	newSpec.Extensions = append([]Extension{{Type: g, Data: []byte{0x00}}}, s.Extensions...)
	return newSpec
}

// ShuffleExtensions returns a new Spec with extensions permuted deterministically using LCG.
func ShuffleExtensions(s Spec, seed int64) Spec {
	newSpec := s
	if len(s.Extensions) <= 1 {
		return newSpec
	}
	exts := make([]Extension, len(s.Extensions))
	copy(exts, s.Extensions)
	state := uint64(seed) // #nosec G115 -- seed bit pattern used as LCG state
	for i := len(exts) - 1; i > 0; i-- {
		state = state*6364136223846793005 + 1442695040888963407
		j := int(state % uint64(i+1)) // #nosec G115 -- index bounded by i+1
		exts[i], exts[j] = exts[j], exts[i]
	}
	newSpec.Extensions = exts
	return newSpec
}
