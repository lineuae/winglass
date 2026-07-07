<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount, onDestroy } from "svelte";
  import { SvelteSet } from "svelte/reactivity";
  import {
    Search,
    ShieldCheck,
    ShieldOff,
    Loader2,
    ArrowUp,
    ArrowDown,
    Info,
    Activity,
    ListTree,
    ChevronRight,
    ChevronDown,
  } from "lucide-svelte";
  import DetailPanel from "$lib/DetailPanel.svelte";
  import Sparkline from "$lib/Sparkline.svelte";
  import { fmtMbps } from "$lib/format";
  import { sigKind, sigColor } from "$lib/sig";
  import type { ProcessInfo, SigInfo } from "$lib/types";

  type SortKey = "pid" | "cpu" | "mem_mb" | "io_bps" | "net_bps" | "name";

  let procs = $state<ProcessInfo[]>([]);
  let filter = $state("");
  let active = $state<Record<FilterKey, boolean>>({
    unsigned: false,
    msWindows: false,
    net: false,
  });
  let sortKey = $state<SortKey>("cpu");
  let sortDesc = $state(true);
  let treeView = $state(false);
  let collapsed = new SvelteSet<number>();
  let loading = $state(true);
  let error = $state<string | null>(null);
  let selectedPid = $state<number | null>(null);
  let toast = $state<{ msg: string; kind: "ok" | "err" } | null>(null);
  // Assume available until proven otherwise so we don't flash the "needs admin"
  // hint on every startup before the capability probe resolves.
  let netMonitorActive = $state(true);
  let intervalId: ReturnType<typeof setInterval> | null = null;
  let filterInput = $state<HTMLInputElement | null>(null);
  let tableContainer = $state<HTMLDivElement | null>(null);
  let toastTimer: ReturnType<typeof setTimeout> | null = null;

  type FilterKey = "unsigned" | "msWindows" | "net";
  type FilterDef = {
    key: FilterKey;
    Icon: typeof ShieldOff;
    label: string;
    cssVar: string;
    shortcut: string;
    tip: string;
    predicate: (p: ProcessInfo) => boolean;
    disabled?: () => boolean;
    disabledTip?: string;
  };
  const filters: FilterDef[] = [
    {
      key: "unsigned",
      Icon: ShieldOff,
      label: "Unsigned",
      cssVar: "--color-danger",
      shortcut: "u",
      tip: "Show only unsigned processes",
      predicate: (p) => sigKind(p.sig) === "unsigned",
    },
    {
      key: "msWindows",
      Icon: ShieldCheck,
      label: "Windows OS",
      cssVar: "--color-ok",
      shortcut: "w",
      tip: "Show only Microsoft Windows-signed processes",
      predicate: (p) => sigKind(p.sig) === "os",
    },
    {
      key: "net",
      Icon: Activity,
      label: "Network",
      cssVar: "--color-accent",
      shortcut: "n",
      tip: "Show only processes with current network activity",
      predicate: (p) => p.net_bps > 0,
      disabled: () => !netMonitorActive,
      disabledTip: "Network monitoring needs admin — filter unavailable",
    },
  ];

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
    invoke<boolean>("net_monitor_active")
      .then((v) => (netMonitorActive = v))
      .catch(() => (netMonitorActive = false));
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

  type Row = {
    p: ProcessInfo;
    depth: number;
    hasChildren: boolean;
    isMatch: boolean;
  };

  const view = $derived.by<Row[]>(() => {
    const needle = filter.toLowerCase();
    const matches = (p: ProcessInfo): boolean => {
      if (needle && !p.name.toLowerCase().includes(needle)) return false;
      for (const f of filters) {
        if (active[f.key] && !f.predicate(p)) return false;
      }
      return true;
    };
    const cmp = (a: ProcessInfo, b: ProcessInfo): number => {
      switch (sortKey) {
        case "pid": return a.pid - b.pid;
        case "cpu": return a.cpu - b.cpu;
        case "mem_mb": return a.mem_mb - b.mem_mb;
        case "io_bps": return a.io_bps - b.io_bps;
        case "net_bps": return a.net_bps - b.net_bps;
        case "name":
          return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
      }
    };
    const sortSiblings = (arr: ProcessInfo[]) =>
      [...arr].sort((a, b) => (sortDesc ? cmp(b, a) : cmp(a, b)));

    if (!treeView) {
      return sortSiblings(procs.filter(matches)).map((p) => ({
        p,
        depth: 0,
        hasChildren: false,
        isMatch: true,
      }));
    }

    // Tree mode. Build a parent → children index, keep only processes whose
    // parent is also in the current list — the rest become roots.
    const byPid = new Map<number, ProcessInfo>();
    for (const p of procs) byPid.set(p.pid, p);
    const childrenOf = new Map<number, ProcessInfo[]>();
    for (const p of procs) {
      const ppid = p.parent_pid;
      if (ppid !== null && byPid.has(ppid)) {
        let arr = childrenOf.get(ppid);
        if (!arr) {
          arr = [];
          childrenOf.set(ppid, arr);
        }
        arr.push(p);
      }
    }

    // matched = directly satisfies the filter/search predicate.
    // keep = matched ∪ every ancestor of a matched node, so the hierarchy
    // stays legible when the user filters. Non-matched ancestors are dimmed
    // at render time via row.isMatch.
    const matched = new Set<number>();
    for (const p of procs) if (matches(p)) matched.add(p.pid);
    const keep = new Set<number>(matched);
    for (const pid of matched) {
      let cur = byPid.get(pid);
      while (cur) {
        const ppid = cur.parent_pid;
        // Stop at a root, or once we reach a pid already kept — the latter
        // both prunes redundant work and breaks parent cycles (a self-parent
        // or a PID-reuse loop) that would otherwise spin forever.
        if (ppid === null || !byPid.has(ppid) || keep.has(ppid)) break;
        keep.add(ppid);
        cur = byPid.get(ppid);
      }
    }

    const roots = procs.filter(
      (p) => keep.has(p.pid) && (p.parent_pid === null || !byPid.has(p.parent_pid))
    );

    const out: Row[] = [];
    const walk = (nodes: ProcessInfo[], depth: number) => {
      for (const p of sortSiblings(nodes.filter((n) => keep.has(n.pid)))) {
        const kids = (childrenOf.get(p.pid) ?? []).filter((c) => keep.has(c.pid));
        const hasChildren = kids.length > 0;
        out.push({ p, depth, hasChildren, isMatch: matched.has(p.pid) });
        if (hasChildren && !collapsed.has(p.pid)) walk(kids, depth + 1);
      }
    };
    walk(roots, 0);
    return out;
  });

  const stats = $derived({
    totalCpu: procs.reduce((s, p) => s + p.cpu, 0),
    totalMemGb: procs.reduce((s, p) => s + p.mem_mb, 0) / 1024,
    totalProcs: procs.length,
    unsigned: procs.filter((p) => sigKind(p.sig) === "unsigned").length,
  });

  const MEBI = 1024 * 1024;

  function sigTitle(sig: SigInfo): string {
    switch (sigKind(sig)) {
      case "os": return `Signed by ${sig.signer} (Windows OS)`;
      case "signed": return `Signed by ${sig.signer}`;
      case "unsigned": return "Unsigned";
      case "failed":
        return `Verify failed (0x${sig.error_code?.toString(16).toUpperCase()})`;
      case "pending": return "Verifying...";
    }
  }

  const sortableColumns: {
    key: SortKey; label: string; align: "left" | "right"; widthClass: string;
  }[] = [
    { key: "pid",     label: "PID",    align: "right", widthClass: "w-20" },
    { key: "cpu",     label: "CPU %",  align: "right", widthClass: "w-28" },
    { key: "mem_mb",  label: "Memory", align: "right", widthClass: "w-24" },
    { key: "io_bps",  label: "I/O",    align: "right", widthClass: "w-24" },
    { key: "net_bps", label: "Net",    align: "right", widthClass: "w-24" },
    { key: "name",    label: "Name",   align: "left",  widthClass: "w-auto" },
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
    const preset = filters.find((f) => f.shortcut === e.key);
    if (preset && !preset.disabled?.()) {
      active[preset.key] = !active[preset.key];
      e.preventDefault();
      return;
    }
    if (e.key === "t") {
      treeView = !treeView;
      e.preventDefault();
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      if (view.length === 0) return;
      const idx = selectedPid !== null ? view.findIndex((r) => r.p.pid === selectedPid) : -1;
      const delta = e.key === "ArrowDown" ? 1 : -1;
      const next = idx === -1
        ? (delta === 1 ? 0 : view.length - 1)
        : Math.max(0, Math.min(view.length - 1, idx + delta));
      selectedPid = view[next].p.pid;
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

    <div class="flex-1 max-w-sm relative">
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

    <div class="flex items-center gap-1.5">
      {#each filters as f (f.key)}
        {@const isDisabled = f.disabled?.() ?? false}
        {@const state = isDisabled ? "disabled" : active[f.key] ? "on" : "off"}
        {@const Icon = f.Icon}
        <button
          onclick={() => (active[f.key] = !active[f.key])}
          disabled={isDisabled}
          title={isDisabled
            ? (f.disabledTip ?? f.tip)
            : `${f.tip}  (press ${f.shortcut})`}
          class="flex items-center gap-1.5 h-7 px-2.5 rounded-md border text-xs whitespace-nowrap transition-colors disabled:cursor-not-allowed"
          style:color={state === "on"
            ? `var(${f.cssVar})`
            : state === "disabled"
              ? "var(--color-fg-dim)"
              : "var(--color-fg-muted)"}
          style:border-color={state === "on"
            ? `color-mix(in oklch, var(${f.cssVar}) 40%, transparent)`
            : "var(--color-border)"}
          style:background-color={state === "on"
            ? `color-mix(in oklch, var(${f.cssVar}) 12%, transparent)`
            : "transparent"}
        >
          <Icon size={12} />
          {f.label}
        </button>
      {/each}
    </div>

    <div class="w-px h-5 bg-[var(--color-border)]"></div>

    <button
      onclick={() => (treeView = !treeView)}
      title="Toggle process tree view  (press t)"
      class="flex items-center gap-1.5 h-7 px-2.5 rounded-md border text-xs whitespace-nowrap transition-colors"
      style:color={treeView ? "var(--color-fg)" : "var(--color-fg-muted)"}
      style:border-color={treeView ? "var(--color-border-strong)" : "var(--color-border)"}
      style:background-color={treeView ? "var(--color-surface)" : "transparent"}
    >
      <ListTree size={12} />
      Tree
    </button>

    <div class="flex items-center gap-5 text-[var(--color-fg-muted)] text-xs tabular ml-auto">
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
      {#if !netMonitorActive}
        <span
          class="flex items-center gap-1 text-[var(--color-fg-dim)]"
          title="Per-process network throughput uses ETW, which requires running winglass as Administrator (or as a member of the Performance Log Users group). The Net column will stay empty until then."
        >
          <Info size={12} />
          Net: needs admin
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
              {#each view as { p, depth, hasChildren, isMatch } (p.pid)}
                {@const ioText = fmtMbps(p.io_bps)}
                {@const netText = fmtMbps(p.net_bps)}
                <tr
                  data-pid={p.pid}
                  class="border-b border-[var(--color-border)]/40 hover:bg-[var(--color-surface-hover)] transition-colors cursor-default"
                  class:bg-[var(--color-surface)]={selectedPid === p.pid}
                  class:opacity-50={!isMatch}
                  onclick={() => (selectedPid = p.pid)}
                >
                  <td class="text-right px-3 py-1.5 text-[var(--color-accent)] tabular">
                    {p.pid}
                  </td>
                  <td class="text-right px-3 py-1.5 tabular">
                    <div class="flex items-center justify-end gap-2">
                      <div class="w-10 shrink-0 opacity-80">
                        <Sparkline data={p.cpu_history} height={14} />
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
                  <td
                    class="text-right px-3 py-1.5 tabular"
                    class:text-[var(--color-fg)]={!!netText}
                    class:text-[var(--color-fg-dim)]={!netText}
                    title={netText
                      ? `${(p.net_rx_bps / MEBI).toFixed(2)} MB/s ↓   ${(p.net_tx_bps / MEBI).toFixed(2)} MB/s ↑`
                      : ""}
                  >
                    {netText || "—"}
                  </td>
                  <td class="px-3 py-1.5">
                    <div class="flex items-center gap-2" style:padding-left="{depth * 14}px">
                      {#if treeView}
                        {#if hasChildren}
                          <button
                            class="flex items-center justify-center w-4 h-4 -ml-0.5 text-[var(--color-fg-muted)] hover:text-[var(--color-fg)] shrink-0"
                            onclick={(e) => {
                              e.stopPropagation();
                              if (collapsed.has(p.pid)) collapsed.delete(p.pid);
                              else collapsed.add(p.pid);
                            }}
                            title={collapsed.has(p.pid) ? "Expand" : "Collapse"}
                          >
                            {#if collapsed.has(p.pid)}
                              <ChevronRight size={12} />
                            {:else}
                              <ChevronDown size={12} />
                            {/if}
                          </button>
                        {:else}
                          <span class="w-4 shrink-0"></span>
                        {/if}
                      {/if}
                      <span
                        class="w-1.5 h-1.5 rounded-full shrink-0"
                        style:background-color={sigColor(p.sig)}
                        title={sigTitle(p.sig)}
                      ></span>
                      <span
                        class="truncate"
                        class:text-[var(--color-ok)]={sigKind(p.sig) === "os"}
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
          {netMonitorActive}
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
      <span>
        <kbd class="text-[var(--color-fg-muted)]">u</kbd>
        <kbd class="text-[var(--color-fg-muted)]">w</kbd>
        <kbd class="text-[var(--color-fg-muted)]">n</kbd>
        presets
      </span>
      <span><kbd class="text-[var(--color-fg-muted)]">t</kbd> tree</span>
      <span><kbd class="text-[var(--color-fg-muted)]">k</kbd> kill</span>
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
