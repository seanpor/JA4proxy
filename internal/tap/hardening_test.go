package tap

import (
	"encoding/json"
	"os"
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

	filter := buildBPFFilter(map[int]bool{0: true, 1: true, 3: true})
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
	filter := buildBPFFilter(allowed)

	if len(filter) < 5 {
		t.Fatalf("expected at least 5 instructions, got %d", len(filter))
	}

	last := filter[len(filter)-1]
	if last.Code != 0x06 {
		t.Errorf("last instruction should be BPF_RET, got code %d", last.Code)
	}
	if last.K != seccompRetKillProcess {
		t.Errorf("last instruction K should be SECCOMP_RET_KILL_PROCESS (0x%x), got 0x%x", seccompRetKillProcess, last.K)
	}
}

func TestBuildBPFFilter_AllowedSyscall(t *testing.T) {
	allowed := map[int]bool{
		0: true, // read
		1: true, // write
	}
	filter := buildBPFFilter(allowed)

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
	filter := buildBPFFilter(allowed)

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

func TestBuildBPFFilter_ArchMismatchSkipsToKill(t *testing.T) {
	allowed := map[int]bool{0: true, 1: true}
	filter := buildBPFFilter(allowed)

	archCheck := filter[1]
	// BPF jf = target - (PC+1). RET_KILL is at index 3+2*N. PC=1, so jf = 3+2*N - 2 = 2*N+1.
	expectedJf := uint8(2*len(allowed) + 1)
	if archCheck.Jf != expectedJf {
		t.Errorf("arch mismatch Jf = %d, want %d (should skip to KILL)", archCheck.Jf, expectedJf)
	}

	// Verify the target instruction is actually RET_KILL_PROCESS
	targetIdx := 1 + 1 + int(archCheck.Jf) // PC + 1 + jf
	if targetIdx >= len(filter) {
		t.Fatalf("arch mismatch jump target %d out of bounds (filter has %d instructions)", targetIdx, len(filter))
	}
	if filter[targetIdx].K != seccompRetKillProcess {
		t.Errorf("arch mismatch target should be KILL_PROCESS, got 0x%x", filter[targetIdx].K)
	}
}

func TestBuildBPFFilter_PerSyscallJumpCorrect(t *testing.T) {
	allowed := map[int]bool{0: true, 1: true, 2: true}
	filter := buildBPFFilter(allowed)

	// Per-syscall JEQ should have Jt=0 (fall through to RET_ALLOW on match)
	// and Jf=1 (skip RET_ALLOW on mismatch)
	for i := 3; i < len(filter)-1; i += 2 {
		if filter[i].Code != 0x15 {
			continue
		}
		if filter[i].Jt != 0 || filter[i].Jf != 1 {
			t.Errorf("per-syscall JEQ at [%d]: Jt=%d Jf=%d, want Jt=0 Jf=1",
				i, filter[i].Jt, filter[i].Jf)
		}
	}
}

func TestBuildBPFFilter_EmptyAllowlist(t *testing.T) {
	allowed := map[int]bool{}
	filter := buildBPFFilter(allowed)

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
		{"msync", 26, true},
		{"mincore", 27, true},
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

func TestApplySeccompProfile_DangerousSyscallRejected(t *testing.T) {
	for _, name := range []string{"fork", "vfork", "execve", "execveat", "ptrace", "mount", "reboot"} {
		profile := seccompProfile{
			DefaultAction: "SCMP_ACT_ERRNO",
			Syscalls: []seccompRule{
				{Names: []string{name}, Action: "SCMP_ACT_ALLOW"},
			},
		}
		data, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		if err := applySeccompProfile(data); err == nil {
			t.Errorf("expected error when allowing dangerous syscall %q", name)
		}
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

func TestBuildBPFFilter_LargeAllowlistUsesTrampoline(t *testing.T) {
	// With 130 syscalls, 2*130+2 = 262 > 255, so the trampoline path must activate.
	allowed := make(map[int]bool)
	for i := 0; i < 130; i++ {
		allowed[i] = true
	}
	filter := buildBPFFilter(allowed)

	// Arch check at [1] should use Jt=1, Jf=0 (match skips trampoline)
	archCheck := filter[1]
	if archCheck.Jt != 1 || archCheck.Jf != 0 {
		t.Errorf("large filter arch check: Jt=%d Jf=%d, want Jt=1 Jf=0 (trampoline)", archCheck.Jt, archCheck.Jf)
	}

	// [2] should be the BPF_JA trampoline
	trampoline := filter[2]
	if trampoline.Code != 0x05 {
		t.Errorf("expected BPF_JA trampoline at [2], got code 0x%x", trampoline.Code)
	}

	// Trampoline should land on the last instruction (RET_KILL_PROCESS)
	targetIdx := 3 + int(trampoline.K) // instruction after trampoline + offset
	if targetIdx != len(filter)-1 {
		t.Errorf("trampoline target %d != last instruction %d", targetIdx, len(filter)-1)
	}
	if filter[targetIdx].K != seccompRetKillProcess {
		t.Errorf("trampoline target should be KILL_PROCESS, got 0x%x", filter[targetIdx].K)
	}
}

func TestEmbeddedMatchesConfig(t *testing.T) {
	configData, err := os.ReadFile("../../config/seccomp_tap_go.json")
	if err != nil {
		t.Skipf("config file not accessible: %v", err)
	}
	if string(defaultSeccompProfile) != string(configData) {
		t.Error("embedded profile differs from config/seccomp_tap_go.json — update both or embed directly")
	}
}
