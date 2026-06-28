package tap

import (
	"testing"

	"golang.org/x/net/bpf"
)

func TestParsePortList_Empty_ReturnsNil(t *testing.T) {
	t.Parallel()
	got, err := ParsePortList("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestParsePortList_SinglePort(t *testing.T) {
	t.Parallel()
	got, err := ParsePortList("443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != 443 {
		t.Fatalf("expected [443], got %v", got)
	}
}

func TestParsePortList_MultiplePorts(t *testing.T) {
	t.Parallel()
	got, err := ParsePortList("443,8443,80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 || got[0] != 443 || got[1] != 8443 || got[2] != 80 {
		t.Fatalf("expected [443 8443 80], got %v", got)
	}
}

func TestParsePortList_WhitespaceAroundPorts_OK(t *testing.T) {
	t.Parallel()
	got, err := ParsePortList(" 443 , 8443 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != 443 || got[1] != 8443 {
		t.Fatalf("expected [443 8443], got %v", got)
	}
}

func TestParsePortList_InvalidPort_Error(t *testing.T) {
	t.Parallel()
	_, err := ParsePortList("abc")
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestParsePortList_OutOfRange_Error(t *testing.T) {
	t.Parallel()
	_, err := ParsePortList("99999")
	if err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}

func TestCompilePortBPF_Empty_ReturnsNil(t *testing.T) {
	t.Parallel()
	got, err := CompilePortBPF()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestCompilePortBPF_SinglePort_ProducesValidInstructions(t *testing.T) {
	t.Parallel()
	insts, err := CompilePortBPF(443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Structure: EtherType(2) + IP(2) + port(2) + KEEP/DROP(2) = 8
	if len(insts) != 8 {
		t.Fatalf("expected 8 instructions for 1 port, got %d", len(insts))
	}
}

func TestCompilePortBPF_MultiplePorts(t *testing.T) {
	t.Parallel()
	ports := []uint16{443, 8443, 80}
	insts, err := CompilePortBPF(ports...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 (EtherType) + 2 (IP) + 2*3 (port checks) + 2 (KEEP/DROP) = 10
	expected := 2 + 2 + 2*len(ports) + 2
	if len(insts) != expected {
		t.Fatalf("expected %d instructions for %d ports, got %d", expected, len(ports), len(insts))
	}
}

func TestCompilePortBPF_MultiPort_FiltersCorrectly(t *testing.T) {
	t.Parallel()
	// Build the filter for 3 ports and verify it with the BPF VM by feeding
	// synthetic Ethernet+IPv4+TCP packets to each configured port.
	raw, err := CompilePortBPF(443, 8443, 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Assemble and disassemble to get back Instruction form for the VM.
	insts := make([]bpf.Instruction, len(raw))
	for i, ri := range raw {
		insts[i] = ri.Disassemble()
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}

	// Build a minimal Ethernet+IPv4+TCP packet to a given dstPort.
	makePkt := func(dstPort uint16) []byte {
		// Ethernet header: dst(6) + src(6) + EtherType(2) = 14 bytes
		pkt := make([]byte, 14+20+20)
		// EtherType = 0x0800 (IPv4)
		pkt[12] = 0x08
		pkt[13] = 0x00
		// IPv4: ver=4, IHL=5 (20 bytes), total length=40, proto=6 (TCP)
		pkt[14] = 0x45
		pkt[16] = 0x00
		pkt[17] = 40 // total length
		pkt[23] = 6  // protocol = TCP
		// TCP header: srcPort=0, dstPort at offset 36 (14 Eth + 20 IP + 2 src)
		pkt[36] = byte(dstPort >> 8)
		pkt[37] = byte(dstPort)
		return pkt
	}

	for _, port := range []uint16{443, 8443, 80} {
		got, err := vm.Run(makePkt(port))
		if err != nil {
			t.Fatalf("VM Run(port %d): %v", port, err)
		}
		if got == 0 {
			t.Fatalf("port %d: packet DROPPED, expected KEEP", port)
		}
	}

	// Port not in list should be dropped.
	got, err := vm.Run(makePkt(8080))
	if err != nil {
		t.Fatalf("VM Run(port 8080): %v", err)
	}
	if got != 0 {
		t.Fatalf("port 8080: packet KEPT (len=%d), expected DROP", got)
	}
}

func TestCompilePortBPF_NonTCP_Dropped(t *testing.T) {
	t.Parallel()
	raw, err := CompilePortBPF(443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	insts := make([]bpf.Instruction, len(raw))
	for i, ri := range raw {
		insts[i] = ri.Disassemble()
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}

	// UDP packet to port 443 — should be dropped (proto=17, not TCP=6).
	pkt := make([]byte, 14+20+8) // Eth + IP + UDP
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45
	pkt[16] = 0x00
	pkt[17] = 28 // total length
	pkt[23] = 17 // UDP
	// UDP dst port at offset 36 (14 Eth + 20 IP + 2 src port)
	pkt[36] = 0x01
	pkt[37] = 0xBB // port 443
	got, err := vm.Run(pkt)
	if err != nil {
		t.Fatalf("VM Run(UDP): %v", err)
	}
	if got != 0 {
		t.Fatalf("UDP packet to port 443 was KEPT (len=%d), expected DROP", got)
	}
}

func TestCompilePortBPF_TooManyPorts_Error(t *testing.T) {
	t.Parallel()
	ports := make([]uint16, 128)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	_, err := CompilePortBPF(ports...)
	if err == nil {
		t.Fatal("expected error for >127 ports")
	}
}

func TestCompilePortBPF_SinglePort_MatchAccepted(t *testing.T) {
	t.Parallel()
	raw, err := CompilePortBPF(443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	insts := make([]bpf.Instruction, len(raw))
	for i, ri := range raw {
		insts[i] = ri.Disassemble()
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}

	pkt := make([]byte, 14+20+20)
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45
	pkt[16] = 0x00
	pkt[17] = 40
	pkt[23] = 6
	pkt[36] = 0x01 // dst port 443 at offset 36
	pkt[37] = 0xBB
	got, err := vm.Run(pkt)
	if err != nil {
		t.Fatalf("VM Run: %v", err)
	}
	if got == 0 {
		t.Fatal("TCP packet to port 443 DROPPED, expected KEEP")
	}
}
