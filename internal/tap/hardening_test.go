package tap

import (
	"encoding/json"
	"testing"
)

func TestApplySeccompProfile_ValidProfile(t *testing.T) {
	profile := seccompProfile{
		DefaultAction:   "SCMP_ACT_ERRNO",
		DefaultErrnoRet: 1,
		Syscalls: []seccompRule{
			{
				Names:  []string{"read", "write", "close"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}

	filter := buildBPFFilter(map[int]bool{0: true, 1: true, 3: true}, 1)
	if len(filter) == 0 {
		t.Fatal("expected non-empty filter")
	}
	_ = data
}

func TestBuildBPFFilter_DeniedSyscall(t *testing.T) {
	allowed := map[int]bool{
		0: true, // read
		1: true, // write
	}
	filter := buildBPFFilter(allowed, 1)

	if len(filter) < 5 {
		t.Fatalf("expected at least 5 instructions, got %d", len(filter))
	}

	// Last instruction should be the ERRNO return
	last := filter[len(filter)-1]
	if last.Code != 0x06 {
		t.Errorf("last instruction should be BPF_RET, got code %d", last.Code)
	}
	expectedRet := seccompRetErrno | 1
	if last.K != uint32(expectedRet) {
		t.Errorf("last instruction K should be 0x%x, got 0x%x", expectedRet, last.K)
	}
}

func TestBuildBPFFilter_AllowedSyscall(t *testing.T) {
	allowed := map[int]bool{
		0: true, // read
		1: true, // write
	}
	filter := buildBPFFilter(allowed, 1)

	// Find the RET_ALLOW instructions (code 0x06, K = 0x00000000)
	allowCount := 0
	for _, f := range filter {
		if f.Code == 0x06 && f.K == seccompRetAllow {
			allowCount++
		}
	}
	if allowCount != 2 {
		t.Errorf("expected 2 RET_ALLOW instructions, got %d", allowCount)
	}
}

func TestBuildBPFFilter_ArchCheck(t *testing.T) {
	allowed := map[int]bool{0: true}
	filter := buildBPFFilter(allowed, 1)

	// Second instruction should check architecture
	if len(filter) < 2 {
		t.Fatal("filter too short")
	}
	archCheck := filter[1]
	if archCheck.Code != 0x15 {
		t.Errorf("expected BPF_JMP|BPF_JEQ, got code %d", archCheck.Code)
	}
	if archCheck.K != auditArchX86_64 {
		t.Errorf("expected AUDIT_ARCH_X86_64 (0x%x), got 0x%x", auditArchX86_64, archCheck.K)
	}
}

func TestBuildBPFFilter_EmptyAllowlist(t *testing.T) {
	allowed := map[int]bool{}
	filter := buildBPFFilter(allowed, 1)

	// Should still have arch check + nr load + ERRNO return
	if len(filter) < 3 {
		t.Fatalf("expected at least 3 instructions for empty allowlist, got %d", len(filter))
	}
}

func TestSyscallToNumber(t *testing.T) {
	tests := []struct {
		name string
		want int
		ok   bool
	}{
		{"read", 0, true},
		{"write", 1, true},
		{"socket", 41, true},
		{"epoll_create1", 291, true},
		{"nonexistent", 0, false},
	}
	for _, tt := range tests {
		got, ok := syscallToNumber(tt.name)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("syscallToNumber(%q) = %d, %v; want %d, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

func TestApplySeccompProfile_BadDefaultAction(t *testing.T) {
	profile := seccompProfile{
		DefaultAction: "SCMP_ACT_KILL",
		Syscalls:      []seccompRule{},
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	err = applySeccompProfile(data)
	if err == nil {
		t.Error("expected error for unsupported default action")
	}
}

func TestApplySeccompProfile_UnknownSyscall(t *testing.T) {
	profile := seccompProfile{
		DefaultAction:   "SCMP_ACT_ERRNO",
		DefaultErrnoRet: 1,
		Syscalls: []seccompRule{
			{
				Names:  []string{"totally_fake_syscall_9999"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	err = applySeccompProfile(data)
	if err == nil {
		t.Error("expected error for unknown syscall")
	}
}

func TestApplySeccompProfile_InvalidJSON(t *testing.T) {
	err := applySeccompProfile([]byte("{invalid"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDefaultProfileValid(t *testing.T) {
	var profile seccompProfile
	if err := json.Unmarshal(defaultSeccompProfile, &profile); err != nil {
		t.Fatalf("embedded profile is invalid JSON: %v", err)
	}
	if profile.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("expected SCMP_ACT_ERRNO, got %s", profile.DefaultAction)
	}
	if len(profile.Syscalls) == 0 {
		t.Error("expected at least one syscall rule")
	}
	for _, rule := range profile.Syscalls {
		for _, name := range rule.Names {
			if _, ok := syscallToNumber(name); !ok {
				t.Errorf("embedded profile references unknown syscall: %s", name)
			}
		}
	}
}
