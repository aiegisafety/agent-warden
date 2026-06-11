//go:build windows

// Windows T2-a/T2-b confinement (AW-INT-v0.1 §2; AW-T2B-v0.1):
//   - Job Object: blast-radius bound, kill-on-close, process cap, no breakaway.
//   - Suspended launch: the agent is jailed before it runs any instruction.
//   - Egress lockdown (T2-b B1): OS firewall blocks non-loopback outbound.
//   - Child-process restriction (T2-b B1 step 1, opt-in via AgentSpec.NoChildProcesses):
//     CHILD_PROCESS_RESTRICTED so the agent cannot spawn ANY child — closing the
//     "drop a helper exe to evade the per-binary egress rule" bypass.
//
// Two launch paths: the proven exec-based one (default) and a CreateProcessW +
// STARTUPINFOEX one (used when NoChildProcesses is set, since the child-process
// mitigation can only be applied at creation via a proc-thread attribute list).
//
// Stdlib only (ADR-0002): kernel32 via syscall.NewLazyDLL.
//
// Licensed under the Apache License 2.0.
package enforce

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW           = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObj       = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObj      = kernel32.NewProc("AssignProcessToJobObject")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procCreateToolhelp32Snapshot   = kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First              = kernel32.NewProc("Thread32First")
	procThread32Next               = kernel32.NewProc("Thread32Next")
	procOpenThread                 = kernel32.NewProc("OpenThread")
	procResumeThread               = kernel32.NewProc("ResumeThread")
	procCreateProcessW             = kernel32.NewProc("CreateProcessW")
	procInitializeProcThreadAttrs  = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute  = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttrList   = kernel32.NewProc("DeleteProcThreadAttributeList")
	procWaitForSingleObject        = kernel32.NewProc("WaitForSingleObject")
	procGetExitCodeProcess         = kernel32.NewProc("GetExitCodeProcess")
	procTerminateProcess           = kernel32.NewProc("TerminateProcess")
	procSetHandleInformation       = kernel32.NewProc("SetHandleInformation")
)

const (
	jobObjectExtendedLimitInformation     = 9
	jobLimitKillOnJobClose                = 0x00002000
	jobLimitActiveProcess                 = 0x00000008
	jobLimitDieOnUnhandledException       = 0x00000400
	processAllAccess                      = 0x1F0FFF
	createSuspended                       = 0x00000004
	createUnicodeEnvironment              = 0x00000400
	extendedStartupInfoPresent            = 0x00080000
	startfUseStdHandles                   = 0x00000100
	th32csSnapThread                      = 0x00000004
	threadSuspendResume                   = 0x0002
	procThreadAttrChildProcessPolicy      = 0x0002000E
	childProcessRestricted                = 0x00000001
	handleFlagInherit                     = 0x00000001
	infinite                       uint32 = 0xFFFFFFFF
	invalidHandleValue            uintptr = ^uintptr(0)
)

type jobobjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobobjectExtendedLimitInformation struct {
	BasicLimitInformation jobobjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type threadEntry32 struct {
	Size           uint32
	CntUsage       uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

type startupInfoEx struct {
	StartupInfo   syscall.StartupInfo
	AttributeList *byte
}

// confined is a started-but-suspended agent, with path-specific lifecycle hooks.
type confined struct {
	process uintptr        // process handle (for AssignProcessToJobObject)
	resume  func() error   // resume execution
	wait    func() error   // block until exit
	kill    func()         // terminate
	closeUp func()         // release handles
}

type jobInterceptor struct{ onEffect EffectFunc }

func NewInterceptor() Interceptor { return &jobInterceptor{} }

func Platform() string { return "windows/jobobject(T2-a + T2-b B1)" }

func (j *jobInterceptor) OnEffect(f EffectFunc) { j.onEffect = f }

// Launch confines and runs the agent, blocking until it exits.
func (j *jobInterceptor) Launch(ctx context.Context, spec AgentSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	if j.onEffect == nil {
		return fmt.Errorf("enforce(windows): no mediator registered (fail-closed)")
	}

	// Gate the launch itself through the broker.
	launchAction := awspec.Action{
		AgentID:   "confined-agent",
		Substrate: awspec.SubProc,
		Class:     "process.launch",
		Params:    map[string]string{"exe": spec.Exe, "workdir": spec.WorkDir},
		Source:    "enforce.windows",
		Tier:      2,
		Tool:      "os.launch",
	}
	if v := j.onEffect(launchAction); v != awspec.Allow {
		return fmt.Errorf("enforce(windows): launch %s by broker", v)
	}

	// Create and limit the Job Object.
	hJob, _, callErr := procCreateJobObjectW.Call(0, 0)
	if hJob == 0 {
		return fmt.Errorf("CreateJobObjectW failed: %v", callErr)
	}
	defer syscall.CloseHandle(syscall.Handle(hJob))
	var info jobobjectExtendedLimitInformation
	info.BasicLimitInformation.LimitFlags = jobLimitKillOnJobClose | jobLimitActiveProcess | jobLimitDieOnUnhandledException
	info.BasicLimitInformation.ActiveProcessLimit = 64
	if r, _, e := procSetInformationJobObj.Call(hJob, uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r == 0 {
		return fmt.Errorf("SetInformationJobObject failed: %v", e)
	}

	// Start the agent suspended, by the chosen path.
	var (
		c   *confined
		err error
	)
	if spec.NoChildProcesses || spec.LowIntegrity {
		c, err = startViaCreateProcess(spec, spec.NoChildProcesses)
	} else {
		c, err = startExecSuspended(ctx, spec)
	}
	if err != nil {
		return err
	}
	defer c.closeUp()

	// B2: while still suspended, drop the agent's token to Low integrity and label
	// its workspace Low — the OS then lets it write only its sandbox, not your files.
	if spec.LowIntegrity {
		if lerr := labelDirLowIntegrity(spec.WorkDir); lerr != nil {
			fmt.Fprintf(os.Stderr, "[enforce] low-integrity workspace labeling failed (%v) — the agent may be unable to write its workspace\n", lerr)
		}
		if lerr := lowerProcessIntegrity(c.process); lerr != nil {
			c.kill()
			return fmt.Errorf("lower agent integrity: %w", lerr)
		}
	}

	// Jail it while still suspended.
	if r, _, e := procAssignProcessToJobObj.Call(hJob, c.process); r == 0 {
		c.kill()
		return fmt.Errorf("AssignProcessToJobObject failed: %v", e)
	}

	// T2-b B1: OS-enforced egress lockdown (best-effort; needs admin).
	if cleanup, nfErr := newNetFilter().Lock(spec.Exe); nfErr != nil {
		fmt.Fprintf(os.Stderr, "[enforce] egress lockdown NOT applied (%v)\n", nfErr)
		fmt.Fprintln(os.Stderr, "[enforce] running with Job-Object containment only — run as Administrator for the T2-b egress lockdown")
	} else {
		defer cleanup()
		fmt.Fprintln(os.Stderr, "[enforce] egress lockdown active: agent's only network path is the broker proxy")
	}
	if spec.NoChildProcesses {
		fmt.Fprintln(os.Stderr, "[enforce] child-process creation blocked: the agent cannot spawn a helper to evade the lockdown")
	}
	if spec.LowIntegrity {
		fmt.Fprintln(os.Stderr, "[enforce] low-integrity: the agent can write only its sandbox workspace, not your files or system dirs")
	}

	if err := c.resume(); err != nil {
		c.kill()
		return fmt.Errorf("resume confined agent: %w", err)
	}
	return c.wait()
}

// startExecSuspended is the proven os/exec path (no child-process restriction).
func startExecSuspended(ctx context.Context, spec AgentSpec) (*confined, error) {
	cmd := exec.CommandContext(ctx, spec.Exe, spec.Args...)
	cmd.Dir = spec.WorkDir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createSuspended}
	cmd.Env = egressEnv(spec.EgressProxy)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start confined agent: %w", err)
	}
	hProc, _, _ := procOpenProcess.Call(uintptr(processAllAccess), 0, uintptr(cmd.Process.Pid))
	if hProc == 0 {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("OpenProcess failed for confined agent")
	}
	pid := uint32(cmd.Process.Pid)
	return &confined{
		process: hProc,
		resume:  func() error { return resumeProcessThreads(pid) },
		wait:    func() error { return cmd.Wait() },
		kill:    func() { _ = cmd.Process.Kill() },
		closeUp: func() { syscall.CloseHandle(syscall.Handle(hProc)) },
	}, nil
}

// startRestrictedSuspended is the CreateProcessW path with CHILD_PROCESS_RESTRICTED.
func startViaCreateProcess(spec AgentSpec, childRestrict bool) (*confined, error) {
	appName, err := syscall.UTF16PtrFromString(spec.Exe)
	if err != nil {
		return nil, err
	}
	cmdline, err := syscall.UTF16FromString(commandLine(spec.Exe, spec.Args))
	if err != nil {
		return nil, err
	}
	workDir, err := syscall.UTF16PtrFromString(spec.WorkDir)
	if err != nil {
		return nil, err
	}
	env := buildEnvBlock(egressEnv(spec.EgressProxy))

	// Inheritable std handles so the agent shares our console.
	for _, h := range []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()} {
		procSetHandleInformation.Call(h, handleFlagInherit, handleFlagInherit)
	}

	// Build a proc-thread attribute list holding the child-process policy.
	var size uintptr
	procInitializeProcThreadAttrs.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	attrBuf := make([]byte, size)
	if r, _, e := procInitializeProcThreadAttrs.Call(uintptr(unsafe.Pointer(&attrBuf[0])), 1, 0,
		uintptr(unsafe.Pointer(&size))); r == 0 {
		return nil, fmt.Errorf("InitializeProcThreadAttributeList failed: %v", e)
	}
	policy := uint32(childProcessRestricted)
	if childRestrict {
		if r, _, e := procUpdateProcThreadAttribute.Call(uintptr(unsafe.Pointer(&attrBuf[0])), 0,
			uintptr(procThreadAttrChildProcessPolicy), uintptr(unsafe.Pointer(&policy)),
			unsafe.Sizeof(policy), 0, 0); r == 0 {
			procDeleteProcThreadAttrList.Call(uintptr(unsafe.Pointer(&attrBuf[0])))
			return nil, fmt.Errorf("UpdateProcThreadAttribute failed: %v", e)
		}
	}

	var siex startupInfoEx
	siex.StartupInfo.Cb = uint32(unsafe.Sizeof(siex))
	siex.StartupInfo.Flags = startfUseStdHandles
	siex.StartupInfo.StdInput = syscall.Handle(os.Stdin.Fd())
	siex.StartupInfo.StdOutput = syscall.Handle(os.Stdout.Fd())
	siex.StartupInfo.StdErr = syscall.Handle(os.Stderr.Fd())
	siex.AttributeList = &attrBuf[0]

	var pi syscall.ProcessInformation
	flags := uintptr(createSuspended | extendedStartupInfoPresent | createUnicodeEnvironment)
	r, _, e := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(&cmdline[0])),
		0, 0, 1, flags,
		uintptr(unsafe.Pointer(&env[0])),
		uintptr(unsafe.Pointer(workDir)),
		uintptr(unsafe.Pointer(&siex)),
		uintptr(unsafe.Pointer(&pi)),
	)
	// Keep the attribute-list backing and the policy value alive across the call:
	// the list holds an internal pointer to `policy`, referenced only indirectly.
	runtime.KeepAlive(policy)
	runtime.KeepAlive(attrBuf)
	procDeleteProcThreadAttrList.Call(uintptr(unsafe.Pointer(&attrBuf[0])))
	if r == 0 {
		return nil, fmt.Errorf("CreateProcess failed: %v", e)
	}

	return &confined{
		process: uintptr(pi.Process),
		resume: func() error {
			procResumeThread.Call(uintptr(pi.Thread))
			syscall.CloseHandle(pi.Thread)
			return nil
		},
		wait:    func() error { return waitProcess(uintptr(pi.Process)) },
		kill:    func() { procTerminateProcess.Call(uintptr(pi.Process), 1) },
		closeUp: func() { syscall.CloseHandle(pi.Process) },
	}, nil
}

// waitProcess blocks until the process exits and reports a non-zero exit as error.
func waitProcess(hProcess uintptr) error {
	procWaitForSingleObject.Call(hProcess, uintptr(infinite))
	var code uint32
	procGetExitCodeProcess.Call(hProcess, uintptr(unsafe.Pointer(&code)))
	if code != 0 {
		return fmt.Errorf("confined agent exited with code %d", code)
	}
	return nil
}

// egressEnv returns the parent environment with egress pinned to the proxy and
// NO_PROXY cleared, as a []string (for os/exec).
func egressEnv(proxy string) []string {
	env := os.Environ()
	if proxy != "" {
		env = append(env,
			"HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "ALL_PROXY="+proxy,
			"NO_PROXY=", "no_proxy=")
	}
	return env
}

// buildEnvBlock turns a []string environment into a UTF-16, double-null-terminated
// block for CreateProcessW (last value wins on duplicate keys).
func buildEnvBlock(env []string) []uint16 {
	m := map[string]string{}
	for _, e := range env {
		if i := strings.IndexByte(e, '='); i > 0 {
			m[e[:i]] = e[i+1:]
		}
	}
	var buf []uint16
	for k, v := range m {
		if u, err := syscall.UTF16FromString(k + "=" + v); err == nil {
			buf = append(buf, u...)
		}
	}
	buf = append(buf, 0) // block terminator
	return buf
}

// commandLine builds a quoted command line from exe + args.
func commandLine(exe string, args []string) string {
	parts := []string{`"` + exe + `"`}
	for _, a := range args {
		parts = append(parts, `"`+a+`"`)
	}
	return strings.Join(parts, " ")
}

// resumeProcessThreads resumes every thread owned by pid (exec path, no thread handle).
func resumeProcessThreads(pid uint32) error {
	snap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(th32csSnapThread), 0)
	if snap == 0 || snap == invalidHandleValue {
		return fmt.Errorf("CreateToolhelp32Snapshot failed")
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var te threadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	ret, _, _ := procThread32First.Call(snap, uintptr(unsafe.Pointer(&te)))
	resumed := 0
	for ret != 0 {
		if te.OwnerProcessID == pid {
			hThread, _, _ := procOpenThread.Call(uintptr(threadSuspendResume), 0, uintptr(te.ThreadID))
			if hThread != 0 {
				procResumeThread.Call(hThread)
				syscall.CloseHandle(syscall.Handle(hThread))
				resumed++
			}
		}
		ret, _, _ = procThread32Next.Call(snap, uintptr(unsafe.Pointer(&te)))
	}
	if resumed == 0 {
		return fmt.Errorf("no threads resumed for pid %d", pid)
	}
	return nil
}
