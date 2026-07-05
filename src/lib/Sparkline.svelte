<script lang="ts">
  interface Props {
    data: number[];
    max?: number;
    color?: string;
    height?: number;
  }

  let {
    data,
    max,
    color = "var(--color-accent)",
    height = 28,
  }: Props = $props();

  const width = 160;

  const geom = $derived.by(() => {
    if (data.length === 0) return { line: "", area: "" };
    const cap = max ?? Math.max(...data, 0.001);
    const step = width / Math.max(1, data.length - 1);
    const pad = 2;
    const usable = height - pad * 2;
    const points = data.map((v, i) => {
      const clamped = Math.max(0, Math.min(cap, v));
      const y = height - pad - (clamped / cap) * usable;
      return [i * step, y] as const;
    });
    const line = points
      .map(([x, y], i) => `${i === 0 ? "M" : "L"} ${x.toFixed(2)},${y.toFixed(2)}`)
      .join(" ");
    const area =
      points.length > 0
        ? `M 0,${height} L ${points[0][0].toFixed(2)},${points[0][1].toFixed(2)} ` +
          points
            .slice(1)
            .map(([x, y]) => `L ${x.toFixed(2)},${y.toFixed(2)}`)
            .join(" ") +
          ` L ${width},${height} Z`
        : "";
    return { line, area };
  });
</script>

<svg
  viewBox="0 0 {width} {height}"
  preserveAspectRatio="none"
  class="block w-full"
  style:height="{height}px"
>
  <path d={geom.area} fill={color} opacity="0.15" />
  <path
    d={geom.line}
    fill="none"
    stroke={color}
    stroke-width="1.2"
    stroke-linejoin="round"
    stroke-linecap="round"
  />
</svg>
