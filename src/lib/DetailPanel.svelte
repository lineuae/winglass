<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { X, Skull, ShieldCheck, Shield, ShieldOff, ShieldAlert } from "lucide-svelte";
  import Sparkline from "./Sparkline.svelte";
  import { fmtBytes, fmtMbps, fmtDuration } from "./format";
  import type { ProcessDetail, SigInfo, ThreadInfo, HandleInfo } from "./types";

  interface Props {
    pid: number;
    netMonitorActive: boolean;
    onClose: () => void;
    onKilled: (name: string) => void;
  }

  let { pid, netMonitorActive, onClose, onKilled }: Props = $props();

  let detail = $state<ProcessDetail | null>(null);
  let loading = $state(true);
  let killPrompt = $state(false);
  let killError = $state<string | null>(null);
  let intervalId: ReturnType<typeof setInterval> | null = null;

  async function fetchDetail() {
    try {
      const d = await invoke<ProcessDetail | null>("get_process_detail", { pid });
      if (d) detail = d;
      loading = false;
    } catch {
      loading = false;
    }
  }

  $effect(() => {
    void pid;
    detail = null;
    loading = true;
    killPrompt = false;
    killError = null;
    fetchDetail();
    if (intervalId !== null) clearInterval(intervalId);
    intervalId = setInterval(fetchDetail, 1000);
    return () => {
      if (intervalId !== null) clearInterval(intervalId);
    };
  });

  async function doKill() {
    if (!detail) return;
    const name = detail.name;
    try {
      await invoke("kill_process", { pid });
      killPrompt = false;
      onKilled(name);
      onClose();
    } catch (e) {
      killError = String(e);
    }
  }

  function handleKey(e: KeyboardEvent) {
    const t = e.target as HTMLElement | null;
    if (t?.tagName === "INPUT" || t?.tagName === "TEXTAREA") return;

    if (e.key === "k" && !killPrompt) {
      killPrompt = true;
      killError = null;
      e.preventDefault();
    } else if (e.key === "Enter" && killPrompt) {
      void doKill();
      e.preventDefault();
    }
  }

  function sigChip(sig: SigInfo) {
    if (sig.status === "valid" && sig.is_ms_windows)
      return { label: `Windows OS  ${sig.signer ?? ""}`, color: "var(--color-ok)", Icon: ShieldCheck };
    if (sig.status === "valid")
      return { label: `Signed  ${sig.signer ?? ""}`, color: "var(--color-fg-muted)", Icon: Shield };
    if (sig.status === "unsigned")
      return { label: "Unsigned", color: "var(--color-danger)", Icon: ShieldOff };
    if (sig.status === "failed")
      return {
        label: `Verify failed  0x${sig.error_code?.toString(16).toUpperCase()}`,
        color: "var(--color-warn)",
        Icon: ShieldAlert,
      };
    return { label: "verifying...", color: "var(--color-fg-dim)", Icon: Shield };
  }

  function dllColor(sig: SigInfo): string {
    if (sig.status === "valid" && sig.is_ms_windows) return "var(--color-ok)";
    if (sig.status === "valid") return "var(--color-fg-muted)";
    if (sig.status === "unsigned") return "var(--color-danger)";
    if (sig.status === "failed") return "var(--color-warn)";
    return "var(--color-fg-dim)";
  }

  let envOpen = $state(false);
  let threadsOpen = $state(false);
  let handlesOpen = $state(false);

  function handleTypeHistogram(all: HandleInfo[]): Array<[string, number]> {
    const m = new Map<string, number>();
    for (const h of all) {
      const t = h.type_name || "?";
      m.set(t, (m.get(t) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }

  function fmtHandle(v: number): string {
    return "0x" + v.toString(16).toUpperCase().padStart(4, "0");
  }

  function fmtCpuSeconds(hundredNs: number): string {
    // 100-ns ticks → seconds
    const s = hundredNs / 1e7;
    if (s < 0.001) return "0";
    if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
    if (s < 60) return `${s.toFixed(1)} s`;
    const m = Math.floor(s / 60);
    const rem = s - m * 60;
    return `${m}m ${rem.toFixed(0)}s`;
  }

  function threadStateColor(state: string): string {
    switch (state) {
      case "Running": return "var(--color-ok)";
      case "Ready":
      case "Standby":
      case "DeferredReady": return "var(--color-warn)";
      case "Terminated": return "var(--color-danger)";
      case "Waiting":
      case "Transition":
      case "Initialized":
      default: return "var(--color-fg-dim)";
    }
  }

  function sortThreads(arr: ThreadInfo[]): ThreadInfo[] {
    // Show Running first, then Ready/Standby, then everything else. TID ascending as tiebreaker.
    const rank = (s: string) =>
      s === "Running" ? 0 : s === "Ready" || s === "Standby" ? 1 : 2;
    return [...arr].sort((a, b) => rank(a.state) - rank(b.state) || a.tid - b.tid);
  }

  const publicRemotes = $derived(
    detail
      ? new Set(detail.connections.filter((c) => c.remote_ip).map((c) => c.remote_ip!))
      : new Set<string>()
  );
  const resolvedCount = $derived(
    detail ? detail.connections.filter((c) => c.hostname).length : 0
  );
</script>

<svelte:window onkeydown={handleKey} />

<aside
  class="flex flex-col h-full border-l border-[var(--color-border)] bg-[var(--color-bg)] overflow-hidden"
>
  {#if loading && !detail}
    <div class="flex-1 flex items-center justify-center text-[var(--color-fg-muted)] text-xs">
      Loading detail...
    </div>
  {:else if !detail}
    <div class="flex-1 flex items-center justify-center text-[var(--color-fg-muted)] text-xs">
      Process gone.
    </div>
  {:else}
    {@const chip = sigChip(detail.sig)}
    {@const ChipIcon = chip.Icon}
    <!-- Header -->
    <header class="px-5 pt-4 pb-3 border-b border-[var(--color-border)] shrink-0">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0 flex-1">
          <div class="flex items-baseline gap-3">
            <h2
              class="text-[15px] font-medium truncate"
              class:text-[var(--color-ok)]={detail.sig.status === "valid" && detail.sig.is_ms_windows}
            >
              {detail.name}
            </h2>
            <span class="text-[var(--color-accent)] tabular text-sm">PID {detail.pid}</span>
          </div>
          <div class="flex items-center gap-1.5 mt-1 text-xs" style:color={chip.color}>
            <ChipIcon size={12} />
            <span class="truncate">{chip.label}</span>
          </div>
        </div>
        <div class="flex items-center gap-1 shrink-0">
          <button
            type="button"
            title="Kill process (k)"
            onclick={() => (killPrompt = true)}
            class="w-8 h-8 rounded-md flex items-center justify-center text-[var(--color-fg-muted)] hover:text-[var(--color-danger)] hover:bg-[var(--color-surface)] transition-colors"
          >
            <Skull size={14} />
          </button>
          <button
            type="button"
            title="Close (Esc)"
            onclick={onClose}
            class="w-8 h-8 rounded-md flex items-center justify-center text-[var(--color-fg-muted)] hover:text-[var(--color-fg)] hover:bg-[var(--color-surface)] transition-colors"
          >
            <X size={16} />
          </button>
        </div>
      </div>

      {#if killPrompt}
        <div class="mt-3 p-3 rounded-md bg-[var(--color-surface)] border border-[var(--color-danger)]/40">
          <p class="text-xs text-[var(--color-fg)] mb-2">
            Kill <span class="text-[var(--color-danger)]">{detail.name}</span>
            <span class="text-[var(--color-fg-muted)]">(PID {detail.pid})</span> ?
          </p>
          {#if killError}
            <p class="text-xs text-[var(--color-danger)] mb-2">{killError}</p>
          {/if}
          <div class="flex gap-2">
            <button
              type="button"
              onclick={doKill}
              class="px-3 py-1 text-xs rounded bg-[var(--color-danger)]/20 text-[var(--color-danger)] hover:bg-[var(--color-danger)]/30 transition-colors"
            >
              Kill
            </button>
            <button
              type="button"
              onclick={() => (killPrompt = false)}
              class="px-3 py-1 text-xs rounded text-[var(--color-fg-muted)] hover:text-[var(--color-fg)] transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      {/if}
    </header>

    <div class="flex-1 overflow-y-auto px-5 py-4 space-y-5">
      <!-- Stat tiles -->
      <div class="grid grid-cols-2 gap-3">
        <div class="rounded-md bg-[var(--color-surface)] border border-[var(--color-border)] p-3">
          <div class="flex items-baseline justify-between mb-1">
            <span class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">CPU</span>
            <span class="tabular text-sm">
              {detail.cpu.toFixed(1)}<span class="text-[var(--color-fg-muted)]">%</span>
            </span>
          </div>
          <Sparkline data={detail.cpu_history} max={100} color="var(--color-accent)" />
        </div>
        <div class="rounded-md bg-[var(--color-surface)] border border-[var(--color-border)] p-3">
          <div class="flex items-baseline justify-between mb-1">
            <span class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">Memory</span>
            <span class="tabular text-sm">
              {detail.mem_mb.toFixed(1)}<span class="text-[var(--color-fg-muted)]"> MB</span>
            </span>
          </div>
          <Sparkline data={detail.mem_history} color="var(--color-warn)" />
        </div>
      </div>

      <!-- Metadata -->
      <div class="space-y-2 text-xs">
        <div class="grid grid-cols-[80px_1fr] gap-3 items-baseline">
          <span class="text-[var(--color-fg-muted)] text-[11px]">Executable</span>
          <span class="selectable break-all">
            {detail.exe_path ?? "(unavailable)"}
          </span>
        </div>
        {#if detail.exe_sha256}
          <div class="grid grid-cols-[80px_1fr] gap-3 items-baseline">
            <span class="text-[var(--color-fg-muted)] text-[11px]">SHA-256</span>
            <span class="selectable font-mono text-[11px] text-[var(--color-fg-muted)] break-all">
              {detail.exe_sha256}
            </span>
          </div>
        {/if}
        <div class="grid grid-cols-[80px_1fr] gap-3 items-baseline">
          <span class="text-[var(--color-fg-muted)] text-[11px]">Command</span>
          <span class="selectable text-[var(--color-fg-muted)] break-all">
            {detail.cmd.length ? detail.cmd.join(" ") : "(none)"}
          </span>
        </div>
        <div class="grid grid-cols-[80px_1fr_80px_1fr] gap-x-3 gap-y-1 items-baseline">
          <span class="text-[var(--color-fg-muted)] text-[11px]">User</span>
          <span>{detail.user ?? "(unknown)"}</span>
          <span class="text-[var(--color-fg-muted)] text-[11px]">Uptime</span>
          <span class="tabular">{fmtDuration(detail.uptime_seconds)}</span>
        </div>
        {#if detail.parent_chain.length}
          <div class="grid grid-cols-[80px_1fr] gap-3 items-baseline">
            <span class="text-[var(--color-fg-muted)] text-[11px]">Parent</span>
            <span class="text-[var(--color-fg-muted)]">
              {#each detail.parent_chain as p, i}
                {p.name}
                <span class="text-[var(--color-fg-dim)] tabular">({p.pid})</span>
                {#if i < detail.parent_chain.length - 1}
                  <span class="text-[var(--color-fg-dim)] mx-1">←</span>
                {/if}
              {/each}
            </span>
          </div>
        {/if}
      </div>

      <!-- IO -->
      <section>
        <div class="flex items-baseline justify-between mb-2 pb-1 border-b border-[var(--color-border)]/50">
          <h3 class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">I/O</h3>
        </div>
        <div class="grid grid-cols-3 gap-3 text-xs">
          <div>
            <div class="text-[var(--color-fg-muted)] text-[10px]">Read</div>
            <div class="tabular">{fmtMbps(detail.io_read_bps, true)} MB/s</div>
            <div class="text-[var(--color-fg-dim)] text-[10px] tabular">total {fmtBytes(detail.io_read_total)}</div>
          </div>
          <div>
            <div class="text-[var(--color-fg-muted)] text-[10px]">Write</div>
            <div class="tabular">{fmtMbps(detail.io_write_bps, true)} MB/s</div>
            <div class="text-[var(--color-fg-dim)] text-[10px] tabular">total {fmtBytes(detail.io_write_total)}</div>
          </div>
          <div>
            <div class="text-[var(--color-fg-muted)] text-[10px]">Other</div>
            <div class="tabular">{fmtMbps(detail.io_other_bps, true)} MB/s</div>
            <div class="text-[var(--color-fg-dim)] text-[10px] tabular">total {fmtBytes(detail.io_other_total)}</div>
          </div>
        </div>
      </section>

      <!-- Network -->
      <section>
        <div class="flex items-baseline justify-between mb-2 pb-1 border-b border-[var(--color-border)]/50">
          <h3 class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">Network</h3>
          <span class="text-[10px] text-[var(--color-fg-dim)] tabular">
            {#if detail.connections.length === 0}
              no open sockets
            {:else if publicRemotes.size === 0}
              {detail.connections.length} sockets · local only
            {:else}
              {detail.connections.length} sockets · {resolvedCount}/{publicRemotes.size} resolved
            {/if}
          </span>
        </div>
        {#if netMonitorActive}
          <div class="grid grid-cols-[1fr_1fr_96px] gap-3 items-end mb-3 text-xs">
            <div>
              <div class="text-[var(--color-fg-muted)] text-[10px] tabular">↓ Down</div>
              <div class="tabular">{fmtMbps(detail.net_rx_bps, true)} MB/s</div>
              <div class="text-[var(--color-fg-dim)] text-[10px] tabular">
                total {fmtBytes(detail.net_rx_total)}
              </div>
            </div>
            <div>
              <div class="text-[var(--color-fg-muted)] text-[10px] tabular">↑ Up</div>
              <div class="tabular">{fmtMbps(detail.net_tx_bps, true)} MB/s</div>
              <div class="text-[var(--color-fg-dim)] text-[10px] tabular">
                total {fmtBytes(detail.net_tx_total)}
              </div>
            </div>
            <Sparkline data={detail.net_history} color="var(--color-remote)" />
          </div>
        {:else}
          <div class="mb-3 px-2.5 py-1.5 text-[11px] text-[var(--color-fg-dim)] border border-dashed border-[var(--color-border)] rounded">
            Per-process throughput needs winglass launched as Administrator (ETW).
          </div>
        {/if}
        {#if detail.connections.length}
          <div class="space-y-0.5 font-mono text-[11px]">
            {#each detail.connections as c}
              <div class="flex items-baseline gap-2 py-0.5 selectable">
                <span class="text-[var(--color-accent)] w-10 shrink-0">{c.proto}</span>
                <span class="text-[var(--color-fg-muted)]">{c.local}</span>
                {#if c.remote}
                  <span class="text-[var(--color-fg-dim)]">→</span>
                  {#if c.hostname}
                    <span class="text-[var(--color-remote)]">
                      {c.hostname}:{c.remote.split(":").pop()}
                    </span>
                    <span class="text-[var(--color-fg-dim)]">({c.remote_ip})</span>
                  {:else}
                    <span class="text-[var(--color-fg-muted)]">{c.remote}</span>
                  {/if}
                  {#if c.country}
                    <span
                      class="text-[10px] px-1 rounded border border-[var(--color-border)] text-[var(--color-fg-muted)] tabular"
                      title="{c.country}"
                    >
                      {c.country}
                    </span>
                  {/if}
                {/if}
                {#if c.state}
                  <span
                    class="ml-auto text-[10px] uppercase tracking-wide"
                    class:text-[var(--color-ok)]={c.state === "ESTABLISHED"}
                    class:text-[var(--color-warn)]={c.state === "LISTEN"}
                    class:text-[var(--color-fg-dim)]={c.state !== "ESTABLISHED" && c.state !== "LISTEN"}
                  >
                    {c.state}
                  </span>
                {/if}
              </div>
            {/each}
          </div>
        {/if}
      </section>

      <!-- Threads -->
      <section>
        {#if "Error" in detail.threads}
          <div class="flex items-baseline justify-between mb-2 pb-1 border-b border-[var(--color-border)]/50">
            <h3 class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">Threads</h3>
            <span class="text-[10px] tabular" style:color="var(--color-warn)">{detail.threads.Error}</span>
          </div>
        {:else}
          {@const all = detail.threads.Ok}
          {@const running = all.filter((t) => t.state === "Running").length}
          {@const waiting = all.filter((t) => t.state === "Waiting").length}
          <button
            type="button"
            onclick={() => (threadsOpen = !threadsOpen)}
            class="w-full flex items-baseline justify-between mb-2 pb-1 border-b border-[var(--color-border)]/50 hover:text-[var(--color-fg)] transition-colors text-left cursor-pointer"
          >
            <h3 class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">Threads</h3>
            <span class="text-[10px] text-[var(--color-fg-dim)] tabular">
              {all.length} total · {running} running · {waiting} waiting · click to {threadsOpen ? "hide" : "show"}
            </span>
          </button>
          {#if threadsOpen}
            <div class="font-mono text-[11px] max-h-64 overflow-y-auto">
              <div class="grid grid-cols-[70px_82px_1fr_60px_60px] gap-2 pb-1 text-[10px] uppercase tracking-wider text-[var(--color-fg-dim)]">
                <span>TID</span>
                <span>State</span>
                <span>Wait reason</span>
                <span class="text-right">CPU</span>
                <span class="text-right">Ctx sw</span>
              </div>
              {#each sortThreads(all) as t (t.tid)}
                <div class="grid grid-cols-[70px_82px_1fr_60px_60px] gap-2 py-0.5 selectable">
                  <span class="text-[var(--color-accent)] tabular">{t.tid}</span>
                  <span style:color={threadStateColor(t.state)}>{t.state}</span>
                  <span class="text-[var(--color-fg-muted)] truncate">{t.wait_reason}</span>
                  <span class="text-[var(--color-fg-muted)] tabular text-right">
                    {fmtCpuSeconds(t.user_time_100ns + t.kernel_time_100ns)}
                  </span>
                  <span class="text-[var(--color-fg-dim)] tabular text-right">{t.context_switches.toLocaleString()}</span>
                </div>
              {/each}
            </div>
          {/if}
        {/if}
      </section>

      <!-- Environment -->
      {#if detail.environ.length > 0}
        <section>
          <button
            type="button"
            onclick={() => (envOpen = !envOpen)}
            class="w-full flex items-baseline justify-between mb-2 pb-1 border-b border-[var(--color-border)]/50 hover:text-[var(--color-fg)] transition-colors text-left cursor-pointer"
          >
            <h3 class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">
              Environment
            </h3>
            <span class="text-[10px] text-[var(--color-fg-dim)] tabular">
              {detail.environ.length} vars · click to {envOpen ? "hide" : "show"}
            </span>
          </button>
          {#if envOpen}
            <div class="space-y-0.5 font-mono text-[11px] max-h-64 overflow-y-auto">
              {#each detail.environ as e}
                <div class="flex items-baseline gap-2 py-0.5 selectable">
                  <span class="text-[var(--color-accent)] shrink-0">{e.key}</span>
                  <span class="text-[var(--color-fg-dim)]">=</span>
                  <span class="text-[var(--color-fg-muted)] break-all">{e.value}</span>
                </div>
              {/each}
            </div>
          {/if}
        </section>
      {/if}

      <!-- DLLs -->
      <section>
        {#if "Denied" in detail.dlls}
          <div class="flex items-baseline justify-between mb-2 pb-1 border-b border-[var(--color-border)]/50">
            <h3 class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">DLLs</h3>
            <span class="text-[10px] tabular" style:color="var(--color-warn)">{detail.dlls.Denied}</span>
          </div>
        {:else}
          {@const entries = detail.dlls.Ok.entries}
          {@const unsigned = detail.dlls.Ok.unsigned_count}
          <div class="flex items-baseline justify-between mb-2 pb-1 border-b border-[var(--color-border)]/50">
            <h3 class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">DLLs</h3>
            <span
              class="text-[10px] tabular"
              class:text-[var(--color-danger)]={unsigned > 0}
              class:text-[var(--color-fg-dim)]={unsigned === 0}
            >
              {#if unsigned}
                {entries.length} loaded · {unsigned} unsigned
              {:else}
                {entries.length} loaded
              {/if}
            </span>
          </div>
          <div class="space-y-0.5 font-mono text-[11px]">
            {#each entries as d}
              <div class="flex items-center gap-2 py-0.5 min-w-0">
                <span
                  class="w-1 h-1 rounded-full shrink-0"
                  style:background-color={dllColor(d.sig)}
                ></span>
                <span
                  class="shrink-0"
                  class:text-[var(--color-ok)]={d.sig.status === "valid" && d.sig.is_ms_windows}
                  class:text-[var(--color-danger)]={d.sig.status === "unsigned"}
                >
                  {d.name}
                </span>
                <span class="text-[var(--color-fg-dim)] truncate">
                  {d.sig.status === "valid"
                    ? d.sig.signer
                    : d.sig.status === "unsigned"
                    ? "unsigned"
                    : d.sig.status === "failed"
                    ? "verify failed"
                    : ""}
                </span>
              </div>
            {/each}
          </div>
        {/if}
      </section>

      <!-- Handles -->
      <section>
        {#if "Error" in detail.handles}
          <div class="flex items-baseline justify-between mb-2 pb-1 border-b border-[var(--color-border)]/50">
            <h3 class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">Handles</h3>
            <span class="text-[10px] tabular" style:color="var(--color-warn)">{detail.handles.Error}</span>
          </div>
        {:else}
          {@const handleList = detail.handles.Ok}
          {@const histogram = handleTypeHistogram(handleList)}
          {@const unresolved = handleList.filter((h) => !h.type_name).length}
          {@const named = handleList.filter((h) => h.name).length}
          <button
            type="button"
            onclick={() => (handlesOpen = !handlesOpen)}
            class="w-full flex items-baseline justify-between mb-2 pb-1 border-b border-[var(--color-border)]/50 hover:text-[var(--color-fg)] transition-colors text-left cursor-pointer"
          >
            <h3 class="text-[10px] uppercase tracking-wider text-[var(--color-fg-muted)]">Handles</h3>
            <span class="text-[10px] text-[var(--color-fg-dim)] tabular">
              {handleList.length} open · {histogram.length} types · {named} named{#if unresolved > 0} · {unresolved} unresolved{/if} · click to {handlesOpen ? "hide" : "show"}
            </span>
          </button>
          {#if handlesOpen}
            <div class="grid grid-cols-2 gap-x-6 gap-y-0.5 font-mono text-[11px] mb-3">
              {#each histogram as [type, count]}
                <div class="flex items-baseline justify-between">
                  <span
                    class:text-[var(--color-fg-dim)]={type === "?"}
                    class:text-[var(--color-fg)]={type !== "?"}
                  >
                    {type}
                  </span>
                  <span class="text-[var(--color-fg-muted)] tabular">{count}</span>
                </div>
              {/each}
            </div>
            <div class="font-mono text-[11px] max-h-64 overflow-y-auto border-t border-[var(--color-border)]/40 pt-2">
              <div class="grid grid-cols-[90px_1fr_60px_70px] gap-2 pb-1 text-[10px] uppercase tracking-wider text-[var(--color-fg-dim)]">
                <span>Type</span>
                <span>Name</span>
                <span class="text-right">Handle</span>
                <span class="text-right">Access</span>
              </div>
              {#each handleList as h (h.value)}
                <div class="grid grid-cols-[90px_1fr_60px_70px] gap-2 py-0.5 selectable">
                  <span class:text-[var(--color-fg-dim)]={!h.type_name}>
                    {h.type_name || "?"}
                  </span>
                  <span
                    class="truncate"
                    class:text-[var(--color-fg)]={h.name}
                    class:text-[var(--color-fg-dim)]={!h.name}
                    title={h.name ?? ""}
                  >
                    {h.name ?? "—"}
                  </span>
                  <span class="text-[var(--color-accent)] tabular text-right">{fmtHandle(h.value)}</span>
                  <span class="text-[var(--color-fg-muted)] tabular text-right">
                    0x{h.granted_access.toString(16).toUpperCase().padStart(6, "0")}
                  </span>
                </div>
              {/each}
            </div>
          {/if}
        {/if}
      </section>
    </div>
  {/if}
</aside>
