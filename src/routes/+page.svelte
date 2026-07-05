<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount, onDestroy } from "svelte";
  import {
    Search,
    ShieldCheck,
    ShieldOff,
    Loader2,
    ArrowUp,
    ArrowDown,
  } from "lucide-svelte";
  import DetailPanel from "$lib/DetailPanel.svelte";
  import type { ProcessInfo, SigInfo } from "$lib/types";

  type SortKey = "pid" | "cpu" | "mem_mb" | "io_bps" | "name";

  let procs = $state<ProcessInfo[]>([]);
  let filter = $state("");
  let sortKey = $state<SortKey>("cpu");
  let sortDesc = $state(true);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let selectedPid = $state<number | null>(null);
  let toast = $state<{ msg: string; kind: "ok" | "err" } | null>(null);
  let intervalId: ReturnType<typeof setInterval> | null = null;
  let filterInput = $state<HTMLInputElement | null>(null);
  let tableContainer = $state<HTMLDivElement | null>(null);
  let toastTimer: ReturnType<typeof setTimeout> | null = null;

  async function refresh() {
    try {
      procs = await invoke<ProcessInfo[]>("list_processes");
      loading = false;
      error = null;
    } catch (e) {
      error = String(e);
      loading = false;
    }
  }

  onMount(() => {
    refresh();
    intervalId = setInterval(refresh, 1000);
  });

  onDestroy(() => {
    if (intervalId !== null) clearInterval(intervalId);
    if (toastTimer !== null) clearTimeout(toastTimer);
  });

  function showToast(msg: string, kind: "ok" | "err" = "ok") {
    toast = { msg, kind };
    if (toastTimer !== null) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toast = null), 3000);
  }

  function toggleSort(key: SortKey) {
    if (sortKey === key) sortDesc = !sortDesc;
    else {
      sortKey = key;
      sortDesc = key !== "name";
    }
  }

  const view = $derived.by(() => {
    const needle = filter.toLowerCase();
    const filtered = needle
      ? procs.filter((p) => p.name.toLowerCase().includes(needle))
      : procs;
    const cmp = (a: ProcessInfo, b: ProcessInfo): number => {
      switch (sortKey) {
        case "pid": return a.pid - b.pid;
        case "cpu": return a.cpu - b.cpu;
        case "mem_mb": return a.mem_mb - b.mem_mb;
        case "io_bps": return a.io_bps - b.io_bps;
        case "name":
          return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
      }
    };
    return [...filtered].sort((a, b) => (sortDesc ? cmp(b, a) : cmp(a, b)));
  });

  const stats = $derived({
    totalCpu: procs.reduce((s, p) => s + p.cpu, 0),
    totalMemGb: procs.reduce((s, p) => s + p.mem_mb, 0) / 1024,
    totalProcs: procs.length,
    unsigned: procs.filter((p) => p.sig.status === "unsigned").length,
  });

  const MEBI = 1024 * 1024;
  function fmtMbps(bps: number): string {
    const mb = bps / MEBI;
    if (mb < 0.05) return "";
    return mb.toFixed(1);
  }

  function sigColor(sig: SigInfo): string {
    if (sig.status === "valid" && sig.is_ms_windows) return "var(--color-ok)";
    if (sig.status === "valid") return "var(--color-fg-muted)";
    if (sig.status === "unsigned") return "var(--color-danger)";
    if (sig.status === "failed") return "var(--color-warn)";
    return "var(--color-fg-dim)";
  }

  function sigTitle(sig: SigInfo): string {
    if (sig.status === "valid" && sig.is_ms_windows)
      return `Signed by ${sig.signer} (Windows OS)`;
    if (sig.status === "valid") return `Signed by ${sig.signer}`;
    if (sig.status === "unsigned") return "Unsigned";
    if (sig.status === "failed")
      return `Verify failed (0x${sig.error_code?.toString(16).toUpperCase()})`;
    return "Verifying...";
  }

  const sortableColumns: {
    key: SortKey; label: string; align: "left" | "right"; widthClass: string;
  }[] = [
    { key: "pid",    label: "PID",    align: "right", widthClass: "w-20" },
    { key: "cpu",    label: "CPU %",  align: "right", widthClass: "w-28" },
    { key: "mem_mb", label: "Memory", align: "right", widthClass: "w-24" },
    { key: "io_bps", label: "I/O",    align: "right", widthClass: "w-24" },
    { key: "name",   label: "Name",   align: "left",  widthClass: "w-auto" },
  ];

  // Keyboard shortcuts
  function handleKey(e: KeyboardEvent) {
    const t = e.target as HTMLElement | null;
    const inInput = t?.tagName === "INPUT" || t?.tagName === "TEXTAREA";

    if (e.key === "Escape") {
      if (inInput) {
        (t as HTMLInputElement).blur();
        e.preventDefault();
      } else if (selectedPid !== null) {
        selectedPid = null;
        e.preventDefault();
      }
      return;
    }
    if (inInput) return;

    if (e.key === "/") {
      filterInput?.focus();
      e.preventDefault();
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      if (view.length === 0) return;
      const idx = selectedPid !== null ? view.findIndex((p) => p.pid === selectedPid) : -1;
      const delta = e.key === "ArrowDown" ? 1 : -1;
      const next = idx === -1
        ? (delta === 1 ? 0 : view.length - 1)
        : Math.max(0, Math.min(view.length - 1, idx + delta));
      selectedPid = view[next].pid;
      e.preventDefault();
      // Scroll into view
      queueMicrotask(() => {
        const row = tableContainer?.querySelector<HTMLTableRowElement>(
          `tr[data-pid="${selectedPid}"]`
        );
        row?.scrollIntoView({ block: "nearest" });
      });
    }
  }
</script>

<svelte:window onkeydown={handleKey} />

<div class="flex flex-col h-screen w-screen bg-[var(--color-bg)]">
  <!-- Top bar -->
  <header
    class="flex items-center gap-4 h-12 px-4 border-b border-[var(--color-border)] shrink-0"
  >
    <div class="flex items-center gap-2">
      <ShieldCheck size={16} color="var(--color-ok)" />
      <span class="text-[var(--color-fg)] font-medium tracking-tight">winglass</span>
    </div>

    <div class="flex-1 max-w-md relative">
      <Search
        size={14}
        class="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
        color="var(--color-fg-dim)"
      />
      <input
        type="text"
        placeholder="Filter processes...  (press /)"
        bind:value={filter}
        bind:this={filterInput}
        class="w-full h-8 pl-9 pr-3 rounded-md bg-[var(--color-surface)] border border-[var(--color-border)] text-[var(--color-fg)] placeholder:text-[var(--color-fg-dim)] outline-none focus:border-[var(--color-border-strong)] transition-colors selectable"
      />
    </div>

    <div class="flex items-center gap-5 text-[var(--color-fg-muted)] text-xs tabular">
      <span>
        <span class="text-[var(--color-fg)] tabular">{stats.totalProcs}</span>
        procs
      </span>
      <span>
        <span class="text-[var(--color-fg)] tabular">{stats.totalCpu.toFixed(1)}</span>
        % CPU
      </span>
      <span>
        <span class="text-[var(--color-fg)] tabular">{stats.totalMemGb.toFixed(1)}</span>
        GB
      </span>
      {#if stats.unsigned > 0}
        <span class="flex items-center gap-1 text-[var(--color-danger)]">
          <ShieldOff size={12} />
          <span class="tabular">{stats.unsigned}</span>
          unsigned
        </span>
      {/if}
    </div>
  </header>

  <!-- Body: table + optional detail panel -->
  <main class="flex-1 overflow-hidden flex">
    <div class="flex-1 min-w-0 overflow-hidden">
      {#if loading}
        <div class="flex items-center justify-center h-full text-[var(--color-fg-muted)]">
          <Loader2 size={16} class="animate-spin mr-2" />
          Loading processes...
        </div>
      {:else if error}
        <div class="flex flex-col items-center justify-center h-full text-[var(--color-danger)]">
          <p>Failed to load: {error}</p>
        </div>
      {:else}
        <div class="h-full overflow-y-auto" bind:this={tableContainer}>
          <table class="w-full text-[13px]">
            <thead class="sticky top-0 bg-[var(--color-bg)] z-10">
              <tr
                class="text-[var(--color-fg-muted)] text-[11px] uppercase tracking-wider border-b border-[var(--color-border)]"
              >
                {#each sortableColumns as col}
                  <th
                    class="{col.widthClass} px-3 py-2 font-medium cursor-pointer select-none hover:text-[var(--color-fg)] transition-colors"
                    class:text-right={col.align === "right"}
                    class:text-left={col.align === "left"}
                    onclick={() => toggleSort(col.key)}
                  >
                    <span class="inline-flex items-center gap-1">
                      {col.label}
                      {#if sortKey === col.key}
                        {#if sortDesc}
                          <ArrowDown size={11} class="text-[var(--color-accent)]" />
                        {:else}
                          <ArrowUp size={11} class="text-[var(--color-accent)]" />
                        {/if}
                      {/if}
                    </span>
                  </th>
                {/each}
                <th class="text-left px-3 py-2 font-medium">Signer</th>
              </tr>
            </thead>
            <tbody>
              {#each view as p (p.pid)}
                {@const ioText = fmtMbps(p.io_bps)}
                <tr
                  data-pid={p.pid}
                  class="border-b border-[var(--color-border)]/40 hover:bg-[var(--color-surface-hover)] transition-colors cursor-default"
                  class:bg-[var(--color-surface)]={selectedPid === p.pid}
                  onclick={() => (selectedPid = p.pid)}
                >
                  <td class="text-right px-3 py-1.5 text-[var(--color-accent)] tabular">
                    {p.pid}
                  </td>
                  <td class="text-right px-3 py-1.5 tabular">
                    <div class="flex items-center justify-end gap-2">
                      <div class="w-8 h-1 rounded-full bg-[var(--color-border)] overflow-hidden">
                        <div
                          class="h-full bg-[var(--color-accent)]"
                          style:width="{Math.min(100, p.cpu)}%"
                        ></div>
                      </div>
                      <span class="w-10 text-right">{p.cpu.toFixed(1)}</span>
                    </div>
                  </td>
                  <td class="text-right px-3 py-1.5 tabular text-[var(--color-fg)]">
                    {p.mem_mb.toFixed(1)}
                  </td>
                  <td
                    class="text-right px-3 py-1.5 tabular"
                    class:text-[var(--color-fg)]={!!ioText}
                    class:text-[var(--color-fg-dim)]={!ioText}
                  >
                    {ioText || "—"}
                  </td>
                  <td class="px-3 py-1.5">
                    <div class="flex items-center gap-2">
                      <span
                        class="w-1.5 h-1.5 rounded-full shrink-0"
                        style:background-color={sigColor(p.sig)}
                        title={sigTitle(p.sig)}
                      ></span>
                      <span
                        class="truncate"
                        class:text-[var(--color-ok)]={p.sig.status === "valid" && p.sig.is_ms_windows}
                      >
                        {p.name}
                      </span>
                    </div>
                  </td>
                  <td class="px-3 py-1.5 text-[var(--color-fg-muted)] truncate max-w-xs">
                    {#if p.sig.status === "pending"}
                      <span class="text-[var(--color-fg-dim)]">verifying...</span>
                    {:else if p.sig.status === "unsigned"}
                      <span class="text-[var(--color-danger)]">unsigned</span>
                    {:else if p.sig.status === "failed"}
                      <span class="text-[var(--color-warn)]">
                        failed (0x{p.sig.error_code?.toString(16).toUpperCase()})
                      </span>
                    {:else}
                      {p.sig.signer}
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>

    {#if selectedPid !== null}
      <div class="w-[46%] max-w-[720px] min-w-[400px]">
        <DetailPanel
          pid={selectedPid}
          onClose={() => (selectedPid = null)}
          onKilled={(name) => showToast(`Killed ${name}`, "ok")}
        />
      </div>
    {/if}
  </main>

  <!-- Footer / shortcuts hint -->
  <footer
    class="h-7 px-4 flex items-center justify-between text-[10px] text-[var(--color-fg-dim)] border-t border-[var(--color-border)] shrink-0 tabular"
  >
    <div class="flex items-center gap-4">
      <span><kbd class="text-[var(--color-fg-muted)]">↑ ↓</kbd> select</span>
      <span><kbd class="text-[var(--color-fg-muted)]">Enter</kbd>/click open</span>
      <span><kbd class="text-[var(--color-fg-muted)]">/</kbd> filter</span>
      <span><kbd class="text-[var(--color-fg-muted)]">Esc</kbd> close</span>
    </div>
    <div>winglass · click column headers to sort</div>
  </footer>

  <!-- Toast -->
  {#if toast}
    <div
      class="fixed bottom-10 right-6 px-4 py-2 rounded-md shadow-lg text-xs bg-[var(--color-surface)] border transition-opacity"
      class:border-[var(--color-ok)]={toast.kind === "ok"}
      class:border-[var(--color-danger)]={toast.kind === "err"}
    >
      {toast.msg}
    </div>
  {/if}
</div>
