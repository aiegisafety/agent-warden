//go:build windows

// Windows Low-integrity filesystem containment (AW-T2B-v0.1 Phase B2).
//
// We lower the SUSPENDED agent process's token to **Low** integrity (before it
// runs any code) and label its workspace Low. Windows Mandatory Integrity Control
// then permits the agent to write its (Low-labeled) workspace but DENIES writes to
// normal medium/high-integrity objects — the user's files, system directories,
// startup folders — at the OS level, with no kernel driver. A Low-integrity
// process can still read system DLLs and make the loopback proxy connection, so the
// agent runs normally; it just cannot persist anything outside its sandbox.
//
// Lowering the child's own token (which we just created) needs no special
// privilege — unlike CreateProcessAsUser, which an interactive admin usually
// cannot call. This reuses the working CreateProcessW launch.
//
// Stdlib only: advapi32 + kernel32 via syscall.NewLazyDLL.
//
// Licensed under the Apache License 2.0.
package enforce

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	advapi32                   = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken       = advapi32.NewProc("OpenProcessToken")
	procSetTokenInformation    = advapi32.NewProc("SetTokenInformation")
	procConvertStringSidToSidW = advapi32.NewProc("ConvertStringSidToSidW")
	procLocalFree              = kernel32.NewProc("LocalFree")
)

const (
	tokenAdjustDefault    = 0x0080
	tokenQuery            = 0x0008
	tokenIntegrityLevel   = 25
	seGroupIntegrity      = 0x00000020
	lowIntegritySidString = "S-1-16-4096"
)

type sidAndAttributes struct {
	Sid        uintptr
	Attributes uint32
}

type tokenMandatoryLabel struct {
	Label sidAndAttributes
}

// lowerProcessIntegrity sets the (suspended) process's primary token to Low
// integrity. Lowering — never raising — is permitted on a token we own.
func lowerProcessIntegrity(hProcess uintptr) error {
	var hToken uintptr
	if r, _, e := procOpenProcessToken.Call(hProcess, tokenAdjustDefault|tokenQuery,
		uintptr(unsafe.Pointer(&hToken))); r == 0 {
		return fmt.Errorf("OpenProcessToken(child): %v", e)
	}
	defer syscall.CloseHandle(syscall.Handle(hToken))

	lowSid, err := syscall.UTF16PtrFromString(lowIntegritySidString)
	if err != nil {
		return err
	}
	var pSid uintptr
	if r, _, e := procConvertStringSidToSidW.Call(uintptr(unsafe.Pointer(lowSid)),
		uintptr(unsafe.Pointer(&pSid))); r == 0 {
		return fmt.Errorf("ConvertStringSidToSid: %v", e)
	}
	defer procLocalFree.Call(pSid)

	til := tokenMandatoryLabel{Label: sidAndAttributes{Sid: pSid, Attributes: seGroupIntegrity}}
	if r, _, e := procSetTokenInformation.Call(hToken, tokenIntegrityLevel,
		uintptr(unsafe.Pointer(&til)), unsafe.Sizeof(til)); r == 0 {
		return fmt.Errorf("SetTokenInformation(integrity): %v", e)
	}
	return nil
}

// labelDirLowIntegrity marks dir (and its tree, inherited) as Low integrity so a
// Low-integrity process may write inside it. Uses icacls (needs admin/ownership).
func labelDirLowIntegrity(dir string) error {
	out, err := exec.Command("icacls", dir, "/setintegritylevel", "(OI)(CI)Low").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls setintegritylevel failed: %v: %s", err, out)
	}
	return nil
}
