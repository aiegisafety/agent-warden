// AwClient — newline-JSON transport to the Go bridge (aw-openclaw-bridge).
// One long-lived child process; requests are correlated by a monotonic id.
// No policy here: this only moves bytes and fails closed on transport errors.
//
// Reliability contract (AW Tier-1 dependability):
//   * Every failure path resolves a fail-closed `deny` — a tool call is NEVER
//     allowed because the bridge was unreachable, slow, crashed, or missing.
//   * A crashed bridge is transparently respawned on the next call, with bounded
//     exponential backoff so a permanently-broken binary cannot spin the CPU.
//   * The child's `error` event is handled (an unhandled 'error' on a Node
//     ChildProcess throws and would take down the Gateway plugin host). This was
//     the main Tier-1 flakiness: a missing/!x bridge binary crashing the host.
//   * Diagnostics go to stderr with an `[agent-warden]` prefix so the cause of a
//     fail-closed state is visible in the Gateway log.
//
// Licensed under the Apache License 2.0.

import { spawn, ChildProcessWithoutNullStreams } from "node:child_process";
import * as readline from "node:readline";

export interface ToolCall {
  tool: string;
  params: Record<string, string>;
  ctx: Record<string, string>;
}

export interface ApprovalSpec {
  title: string;
  description: string;
  severity: string;
  timeoutMs: number;
  timeoutBehavior: string;
}

export interface ToolVerdict {
  id: number;
  decision: "allow" | "deny" | "escalate" | "sandbox";
  blockReason?: string;
  decoyParams?: Record<string, string>;
  approval?: ApprovalSpec;
  simulated?: boolean;
  ledgerNote?: string;
  error?: string;
}

function log(msg: string): void {
  try {
    process.stderr.write(`[agent-warden] ${msg}\n`);
  } catch {
    /* stderr may be closed during shutdown; never throw from logging */
  }
}

// Backoff bounds for respawning a dead bridge. After a crash we refuse to respawn
// until COOLDOWN_MS has elapsed (growing up to MAX_COOLDOWN_MS), so a broken
// binary fails closed cheaply instead of fork-bombing the host.
const BASE_COOLDOWN_MS = 500;
const MAX_COOLDOWN_MS = 30_000;

export class AwClient {
  private proc: ChildProcessWithoutNullStreams | null = null;
  private rl: readline.Interface | null = null;
  private nextId = 1;
  private pending = new Map<number, (v: ToolVerdict) => void>();

  // Spawn health / backoff state.
  private spawnFailures = 0;
  private nextSpawnAllowedAt = 0; // epoch ms; 0 = spawn allowed now
  private closed = false; // set by close() on gateway_stop — stop respawning

  constructor(private bin: string, private args: string[]) {}

  // ensure() returns a live child, or null if we are in a fail-closed cooldown
  // (recently crashed) or permanently closed. Callers MUST treat null as deny.
  private ensure(): ChildProcessWithoutNullStreams | null {
    if (this.proc) return this.proc;
    if (this.closed) return null;
    if (Date.now() < this.nextSpawnAllowedAt) return null; // in cooldown → fail closed

    let proc: ChildProcessWithoutNullStreams;
    try {
      proc = spawn(this.bin, this.args, { stdio: ["pipe", "pipe", "inherit"] });
    } catch (err) {
      // Synchronous spawn failure (rare; most surface via the 'error' event).
      this.onSpawnFailure(`spawn threw: ${String(err)}`);
      return null;
    }

    // CRITICAL: a ChildProcess 'error' event with no listener throws and would
    // crash the Gateway plugin host. Handle it → fail closed + schedule backoff.
    proc.on("error", (err) => {
      this.onSpawnFailure(`bridge process error: ${String(err)} (bin=${this.bin})`);
      this.failAllPending("bridge process error (fail-closed)");
      this.teardown(proc);
    });

    this.rl = readline.createInterface({ input: proc.stdout });
    this.rl.on("line", (line) => {
      let v: ToolVerdict;
      try {
        v = JSON.parse(line);
      } catch {
        return; // ignore non-JSON (e.g. a stray log line on stdout)
      }
      const cb = this.pending.get(v.id);
      if (cb) {
        this.pending.delete(v.id);
        cb(v);
      }
    });

    proc.on("exit", (code, signal) => {
      // Distinguish a clean close() from an unexpected crash for diagnostics.
      if (!this.closed) {
        log(`bridge exited (code=${code} signal=${signal}); calls fail closed until respawn`);
        // Treat an unexpected exit as a (mild) failure for backoff accounting so a
        // crash-looping bridge backs off, but a single restart recovers instantly.
        if (code !== 0) this.onSpawnFailure(`bridge exited code=${code}`);
      }
      this.failAllPending("bridge exited (fail-closed)");
      this.teardown(proc);
    });

    // Successful spawn: reset failure accounting once we actually get bytes back
    // is ideal, but a clean spawn is a good-enough signal to relax the cooldown.
    this.spawnFailures = 0;
    this.nextSpawnAllowedAt = 0;
    this.proc = proc;
    log(`bridge spawned (bin=${this.bin}${this.args.length ? " " + this.args.join(" ") : ""})`);
    return proc;
  }

  private onSpawnFailure(reason: string): void {
    this.spawnFailures++;
    const cooldown = Math.min(BASE_COOLDOWN_MS * 2 ** (this.spawnFailures - 1), MAX_COOLDOWN_MS);
    this.nextSpawnAllowedAt = Date.now() + cooldown;
    log(`FAIL-CLOSED: ${reason}; backing off ${cooldown}ms (failure #${this.spawnFailures})`);
  }

  private failAllPending(reason: string): void {
    for (const [id, cb] of this.pending) {
      cb({ id, decision: "deny", blockReason: reason });
    }
    this.pending.clear();
  }

  private teardown(proc: ChildProcessWithoutNullStreams): void {
    if (this.proc === proc) {
      this.proc = null;
      this.rl?.close();
      this.rl = null;
    }
  }

  mediate(call: ToolCall, timeoutMs = 10_000): Promise<ToolVerdict> {
    const proc = this.ensure();
    const id = this.nextId++;
    if (!proc) {
      // No live bridge (missing binary, crash cooldown, or closed) → fail closed.
      return Promise.resolve({
        id,
        decision: "deny",
        blockReason: "Agent Warden bridge unavailable (fail-closed)",
      });
    }
    return new Promise<ToolVerdict>((resolve) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) {
          resolve({ id, decision: "deny", blockReason: "Agent Warden timeout (fail-closed)" });
        }
      }, timeoutMs);
      this.pending.set(id, (v) => {
        clearTimeout(timer);
        resolve(v);
      });
      try {
        proc.stdin.write(JSON.stringify({ id, tool: call.tool, params: call.params, ctx: call.ctx }) + "\n");
      } catch (err) {
        // Write after the pipe closed (EPIPE) → fail closed for this call.
        if (this.pending.delete(id)) {
          clearTimeout(timer);
          resolve({ id, decision: "deny", blockReason: `Agent Warden bridge write failed (fail-closed): ${String(err)}` });
        }
      }
    });
  }

  // Fire-and-forget observation (no response expected from the bridge today).
  observe(_tool: string, _outcome: string): void {
    /* reserved for after_tool_call → ledger enrichment */
  }

  close(): void {
    this.closed = true;
    this.failAllPending("gateway stopping (fail-closed)");
    try {
      this.rl?.close();
      this.proc?.stdin.end();
      this.proc?.kill();
    } catch {
      /* best-effort shutdown */
    }
    this.rl = null;
    this.proc = null;
  }
}
