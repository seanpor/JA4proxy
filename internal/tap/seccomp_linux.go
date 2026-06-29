//go:build linux

package tap

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"syscall"
	"unsafe"
)

type seccompProfile struct {
	DefaultAction   string        `json:"defaultAction"`
	DefaultErrnoRet int           `json:"defaultErrnoRet"`
	Syscalls        []seccompRule `json:"syscalls"`
}

type seccompRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

func loadSeccompProfile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read seccomp profile %s: %w", path, err)
	}
	return applySeccompProfile(data)
}

func applySeccompProfile(data []byte) error {
	var profile seccompProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("parse seccomp profile: %w", err)
	}

	if profile.DefaultAction != "SCMP_ACT_ERRNO" {
		return fmt.Errorf("unsupported default action: %s", profile.DefaultAction)
	}

	allow := make(map[int]bool)
	for _, rule := range profile.Syscalls {
		if rule.Action != "SCMP_ACT_ALLOW" {
			continue
		}
		for _, name := range rule.Names {
			if _, blocked := dangerousSyscalls[name]; blocked {
				return fmt.Errorf("syscall %q is blocked for TAP sensor security", name)
			}
			nr, ok := syscallToNumber(name)
			if !ok {
				return fmt.Errorf("unknown syscall: %s", name)
			}
			allow[nr] = true
		}
	}

	return loadBPF(allow)
}

const (
	seccompSetModeFilter  = 1
	seccompRetAllow       = 0x00000000
	seccompRetKillProcess = 0x80000000
	auditArchX86_64       = 0xC000003E
)

func loadBPF(allow map[int]bool) error {
	sockFilter := buildBPFFilter(allow)
	prog := [2]uintptr{
		uintptr(len(sockFilter)),
		uintptr(unsafe.Pointer(&sockFilter[0])), //nolint:gosec // required for seccomp(2) syscall interface
	}

	_, _, errnoSys := syscall.RawSyscall(
		317, // SYS_SECCOMP (x86_64)
		seccompSetModeFilter,
		0,
		uintptr(unsafe.Pointer(&prog[0])), //nolint:gosec // required for seccomp(2) syscall interface
	)
	runtime.KeepAlive(sockFilter)
	if errnoSys != 0 {
		return fmt.Errorf("seccomp load: %w", errnoSys)
	}

	log.Printf("seccomp profile loaded: %d syscalls allowed", len(allow))
	return nil
}

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

func buildBPFFilter(allow map[int]bool) []sockFilter {
	sorted := make([]int, 0, len(allow))
	for nr := range allow {
		sorted = append(sorted, nr)
	}
	sort.Ints(sorted)

	if len(sorted) > 4000 {
		panic("seccomp: too many allowed syscalls for BPF jump encoding")
	}

	// Layout: [0] LOAD_ARCH, [1] JNE→KILL, [2] LOAD_NR, [3..] N×(JEQ+RET_ALLOW), [last] RET_KILL
	// Total instructions after arch check: 1 (load_nr) + 2*N (jeq+ret pairs) + 1 (default ret) = 2*N+2
	// BPF jt/jf fields are uint8 (max 255), so for large N we chain through
	// intermediate jumps. But since we use jf=1 per check (skip one RET_ALLOW),
	// only the arch-mismatch jump needs to span the full filter.
	//
	// For arch mismatch we use JNE (jt=far, jf=0) so the "true" branch (not-equal)
	// jumps to KILL. jt can be up to 255, so we need intermediate trampolines
	// if 2*N+2 > 255.

	var filter []sockFilter

	// [0] Load architecture
	filter = append(filter, sockFilter{
		Code: 0x20, // BPF_LD | BPF_W | BPF_ABS
		K:    4,    // offsetof(seccomp_data, arch)
	})

	// [1] Check arch — on mismatch, jump to KILL.
	// RET_KILL is the last instruction. From [1], the next instruction is [2] (LOAD_NR).
	// RET_KILL is at index 2 + 2*N + 1 = 3 + 2*N (load_nr, N pairs, default).
	// BPF jf offset = target_index - (current_index + 1) = (3 + 2*N) - 2 = 2*N + 1.
	archJmpOffset := 2*len(sorted) + 1
	if archJmpOffset <= 255 {
		filter = append(filter, sockFilter{
			Code: 0x15,                        // BPF_JMP | BPF_JEQ | BPF_K
			Jt:   0, Jf: uint8(archJmpOffset), //nolint:gosec // bounds-checked above
			K: auditArchX86_64,
		})
	} else {
		// Arch match: skip the trampoline. Mismatch: fall through to trampoline.
		filter = append(filter, sockFilter{
			Code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
			Jt:   1, Jf: 0,
			K: auditArchX86_64,
		})
		// Trampoline: unconditional jump to KILL. From [2] (this instruction),
		// KILL is at [3 + 2*N + 1] = [4 + 2*N] (extra instruction from trampoline).
		// BPF_JA offset = (4 + 2*N) - (2 + 1) = 2*N + 1.
		filter = append(filter, sockFilter{
			Code: 0x05,                      // BPF_JMP | BPF_JA
			K:    uint32(2*len(sorted) + 1), //nolint:gosec // BPF offset, bounded by filter size
		})
	}

	// Load syscall number
	filter = append(filter, sockFilter{
		Code: 0x20, // BPF_LD | BPF_W | BPF_ABS
		K:    0,    // offsetof(seccomp_data, nr)
	})

	// Per-syscall checks: on match, fall through to RET_ALLOW;
	// on mismatch, skip RET_ALLOW to next check.
	for _, nr := range sorted {
		filter = append(filter, sockFilter{
			Code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
			Jt:   0, Jf: 1,
			K: uint32(nr), //nolint:gosec // syscall numbers are positive ints
		})
		filter = append(filter, sockFilter{
			Code: 0x06, // BPF_RET | BPF_K
			K:    seccompRetAllow,
		})
	}

	// Default: KILL the process
	filter = append(filter, sockFilter{
		Code: 0x06, // BPF_RET | BPF_K
		K:    seccompRetKillProcess,
	})

	return filter
}

// dangerousSyscalls that a TAP sensor must never be allowed, even via custom profiles.
var dangerousSyscalls = map[string]struct{}{
	"fork":          {},
	"vfork":         {},
	"execve":        {},
	"execveat":      {},
	"ptrace":        {},
	"mount":         {},
	"umount2":       {},
	"pivot_root":    {},
	"reboot":        {},
	"kexec_load":    {},
	"init_module":   {},
	"delete_module": {},
	"finit_module":  {},
}

func syscallToNumber(name string) (int, bool) {
	nr, ok := x86_64Syscalls[name]
	return nr, ok
}

var x86_64Syscalls = map[string]int{
	"read":                   0,
	"write":                  1,
	"open":                   2,
	"close":                  3,
	"stat":                   4,
	"fstat":                  5,
	"lstat":                  6,
	"poll":                   7,
	"lseek":                  8,
	"mmap":                   9,
	"mprotect":               10,
	"munmap":                 11,
	"brk":                    12,
	"rt_sigaction":           13,
	"rt_sigprocmask":         14,
	"rt_sigreturn":           15,
	"ioctl":                  16,
	"pread64":                17,
	"pwrite64":               18,
	"readv":                  19,
	"writev":                 20,
	"access":                 21,
	"pipe":                   22,
	"select":                 23,
	"sched_yield":            24,
	"mremap":                 25,
	"msync":                  26,
	"mincore":                27,
	"madvise":                28,
	"dup":                    32,
	"dup2":                   33,
	"nanosleep":              35,
	"getitimer":              36,
	"setitimer":              38,
	"getpid":                 39,
	"socket":                 41,
	"connect":                42,
	"accept":                 43,
	"sendto":                 44,
	"recvfrom":               45,
	"sendmsg":                46,
	"recvmsg":                47,
	"shutdown":               48,
	"bind":                   49,
	"listen":                 50,
	"getsockname":            51,
	"getpeername":            52,
	"socketpair":             53,
	"setsockopt":             54,
	"getsockopt":             55,
	"clone":                  56,
	"fork":                   57,
	"vfork":                  58,
	"execve":                 59,
	"exit":                   60,
	"wait4":                  61,
	"kill":                   62,
	"uname":                  63,
	"fcntl":                  72,
	"flock":                  73,
	"fsync":                  74,
	"fdatasync":              75,
	"truncate":               76,
	"ftruncate":              77,
	"getdents":               78,
	"getcwd":                 79,
	"chdir":                  80,
	"fchdir":                 81,
	"rename":                 82,
	"mkdir":                  83,
	"rmdir":                  84,
	"link":                   86,
	"unlink":                 87,
	"symlink":                88,
	"readlink":               89,
	"chmod":                  90,
	"fchmod":                 91,
	"chown":                  92,
	"fchown":                 93,
	"lchown":                 94,
	"gettimeofday":           96,
	"getrlimit":              97,
	"getrusage":              98,
	"sysinfo":                99,
	"times":                  100,
	"getuid":                 102,
	"getgid":                 104,
	"setuid":                 105,
	"setgid":                 106,
	"geteuid":                107,
	"getegid":                108,
	"setpgid":                109,
	"getppid":                110,
	"getpgrp":                111,
	"setsid":                 112,
	"setreuid":               113,
	"setregid":               114,
	"getgroups":              115,
	"setgroups":              116,
	"setresuid":              117,
	"getresuid":              118,
	"setresgid":              119,
	"getresgid":              120,
	"getpgid":                121,
	"setfsuid":               122,
	"setfsgid":               123,
	"getsid":                 124,
	"capget":                 125,
	"capset":                 126,
	"rt_sigpending":          127,
	"rt_sigtimedwait":        128,
	"rt_sigqueueinfo":        129,
	"rt_sigsuspend":          130,
	"sigaltstack":            131,
	"mknod":                  133,
	"personality":            135,
	"statfs":                 137,
	"fstatfs":                138,
	"getpriority":            140,
	"setpriority":            141,
	"sched_setparam":         142,
	"sched_getparam":         143,
	"sched_setscheduler":     144,
	"sched_getscheduler":     145,
	"sched_get_priority_max": 146,
	"sched_get_priority_min": 147,
	"sched_rr_get_interval":  148,
	"mlock":                  149,
	"munlock":                150,
	"mlockall":               151,
	"munlockall":             152,
	"vhangup":                153,
	"pivot_root":             155,
	"prctl":                  157,
	"arch_prctl":             158,
	"setrlimit":              160,
	"sync":                   162,
	"settimeofday":           164,
	"mount":                  165,
	"umount2":                166,
	"reboot":                 169,
	"sethostname":            170,
	"setdomainname":          171,
	"iopl":                   172,
	"ioperm":                 173,
	"init_module":            175,
	"delete_module":          176,
	"quotactl":               179,
	"gettid":                 186,
	"setxattr":               188,
	"lsetxattr":              189,
	"fsetxattr":              190,
	"getxattr":               191,
	"lgetxattr":              192,
	"fgetxattr":              193,
	"listxattr":              194,
	"llistxattr":             195,
	"flistxattr":             196,
	"removexattr":            197,
	"lremovexattr":           198,
	"fremovexattr":           199,
	"tkill":                  200,
	"time":                   201,
	"futex":                  202,
	"sched_setaffinity":      203,
	"sched_getaffinity":      204,
	"io_setup":               206,
	"io_destroy":             207,
	"io_getevents":           208,
	"io_submit":              209,
	"io_cancel":              210,
	"epoll_create":           213,
	"remap_file_pages":       216,
	"getdents64":             217,
	"set_tid_address":        218,
	"restart_syscall":        219,
	"fadvise64":              221,
	"timer_create":           222,
	"timer_settime":          223,
	"timer_gettime":          224,
	"timer_getoverrun":       225,
	"timer_delete":           226,
	"clock_settime":          227,
	"clock_gettime":          228,
	"clock_getres":           229,
	"clock_nanosleep":        230,
	"exit_group":             231,
	"epoll_wait":             232,
	"epoll_ctl":              233,
	"tgkill":                 234,
	"mbind":                  237,
	"set_mempolicy":          238,
	"get_mempolicy":          239,
	"kexec_load":             246,
	"waitid":                 247,
	"ioprio_set":             251,
	"ioprio_get":             252,
	"inotify_add_watch":      254,
	"inotify_rm_watch":       255,
	"openat":                 257,
	"mkdirat":                258,
	"mknodat":                259,
	"fchownat":               260,
	"futimesat":              261,
	"newfstatat":             262,
	"unlinkat":               263,
	"renameat":               264,
	"linkat":                 265,
	"symlinkat":              266,
	"readlinkat":             267,
	"fchmodat":               268,
	"faccessat":              269,
	"pselect6":               270,
	"ppoll":                  271,
	"set_robust_list":        273,
	"get_robust_list":        274,
	"splice":                 275,
	"tee":                    276,
	"sync_file_range":        277,
	"vmsplice":               278,
	"utimensat":              280,
	"epoll_pwait":            281,
	"signalfd":               282,
	"timerfd_create":         283,
	"eventfd":                284,
	"fallocate":              285,
	"timerfd_settime":        286,
	"timerfd_gettime":        287,
	"accept4":                288,
	"signalfd4":              289,
	"eventfd2":               290,
	"epoll_create1":          291,
	"dup3":                   292,
	"pipe2":                  293,
	"inotify_init1":          294,
	"preadv":                 295,
	"pwritev":                296,
	"recvmmsg":               299,
	"fanotify_init":          300,
	"fanotify_mark":          301,
	"prlimit64":              302,
	"clock_adjtime":          305,
	"syncfs":                 306,
	"sendmmsg":               307,
	"setns":                  308,
	"getcpu":                 309,
	"process_vm_readv":       310,
	"process_vm_writev":      311,
	"finit_module":           313,
	"sched_setattr":          314,
	"sched_getattr":          315,
	"renameat2":              316,
	"seccomp":                317,
	"getrandom":              318,
	"memfd_create":           319,
	"bpf":                    321,
	"execveat":               322,
	"userfaultfd":            323,
	"membarrier":             324,
	"mlock2":                 325,
	"copy_file_range":        326,
	"preadv2":                327,
	"pwritev2":               328,
	"statx":                  332,
	"rseq":                   334,
}
