"""Report figures from benchmarks/results/evaluation.json (light mode, print-ready PNGs)."""
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

repo = Path(sys.argv[1])
out = repo / "docs" / "figures"
out.mkdir(parents=True, exist_ok=True)
r = json.loads((repo / "benchmarks" / "results" / "evaluation.json").read_text())

SURFACE, INK, INK2, MUTED, GRID, AXIS = "#ffffff", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
OURS, BASE = "#2a78d6", "#eb6834"          # categorical slots 1 and 2 (validated)

plt.rcParams.update({
    "font.family": ["Segoe UI", "DejaVu Sans"], "font.size": 10, "text.color": INK,
    "axes.edgecolor": AXIS, "axes.labelcolor": INK2, "axes.facecolor": SURFACE, "figure.facecolor": SURFACE,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.titlesize": 12, "axes.titleweight": "semibold",
    "axes.titlelocation": "left", "axes.titlepad": 12,
})


def tidy(ax, grid_axis="y"):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.spines["left" if grid_axis == "x" else "bottom"].set_color(AXIS)
    ax.spines["bottom" if grid_axis == "x" else "left"].set_visible(False)
    ax.grid(axis=grid_axis, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)


def save(fig, name):
    fig.tight_layout()
    fig.savefig(out / name, dpi=200)
    plt.close(fig)
    print("wrote", out / name)


# 1. Rules per tier ---------------------------------------------------------------------------
f = r["fidelity"]
dist, lat = f["tier_distribution"], f["latency_ms"]
labels = ["Tier 1\nFeature artefacts", "Tier 2\nSummaries", "Tier 3\nIndex-guided restore"]
vals = [dist["1"], dist["2"], dist["3"]]
fig, ax = plt.subplots(figsize=(6.4, 3.8))
bars = ax.bar(labels, vals, width=0.5, color=OURS)
for b, v, t in zip(bars, vals, ("1", "2", "3")):
    ax.text(b.get_x() + b.get_width() / 2, v + 0.3, f"{v} rules", ha="center", va="bottom", color=INK, fontsize=10)
ax.set_ylim(0, 14)
ax.set_ylabel("Number of rules")
ax.set_title(f"Rules answered per tier ({f['tier_hit_rate']*100:.1f}% without raw data)")
tidy(ax)
save(fig, "fig1_rules_per_tier.png")

# 2. Total cost vs hunts per year (5-year hunts) ----------------------------------------------
fy = r["cost"]["five_year"]["for_n_hunts"]
n = sorted(int(k) for k in fy)
base = [fy[str(k)]["baseline"] for k in n]
ours = [fy[str(k)]["ours"] for k in n]
fig, ax = plt.subplots(figsize=(6.4, 3.8))
ax.plot(n, base, color=BASE, linewidth=2, marker="o", markersize=6, label="Full rehydration")
ax.plot(n, ours, color=OURS, linewidth=2, marker="o", markersize=6, label="This design")
ax.text(n[-1] + 2, base[-1], f"{base[-1]/1000:,.0f}K", va="center", color=INK2, fontsize=9)
ax.text(n[-1] + 2, ours[-1], f"{ours[-1]/1000:,.0f}K", va="center", color=INK2, fontsize=9)
ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v/1000:,.0f}K"))
ax.set_xlim(0, 112)
ax.set_xlabel("Five-year hunts per year")
ax.set_ylabel("Total modelled cost (USD)")
ax.set_title("Yearly cost of five-year hunts")
ax.legend(frameon=False, loc="upper left", labelcolor=INK)
tidy(ax)
save(fig, "fig2_cost_vs_hunts.png")

# 3. Cost per hunt: two ranges, small multiples ----------------------------------------------
c = r["cost"]
panels = [("7-day range (mean)", c["mean_cost_per_hunt"]["baseline_full_rehydration"], c["mean_cost_per_hunt"]["ours"]),
          ("5-year range", c["five_year"]["baseline_per_hunt"], c["five_year"]["ours_per_hunt"])]
fig, axes = plt.subplots(1, 2, figsize=(6.8, 3.6))
for ax, (title, b, o) in zip(axes, panels):
    bars = ax.bar(["Full\nrehydration", "This\ndesign"], [b, o], width=0.55, color=[BASE, OURS])
    for bar, v in zip(bars, (b, o)):
        ax.text(bar.get_x() + bar.get_width() / 2, v * 1.02, f"{v:,.2f} USD", ha="center", va="bottom", fontsize=9)
    ax.set_ylim(0, b * 1.18)
    ax.set_title(f"{title}: {(1 - o / b) * 100:.0f}% cheaper", fontsize=10.5)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
    tidy(ax)
axes[0].set_ylabel("Modelled cost per hunt (USD)")
fig.suptitle("Cost per hunt", x=0.02, ha="left", fontsize=12, fontweight="semibold")
save(fig, "fig3_cost_per_hunt.png")

# 4. Derived storage relative to raw ---------------------------------------------------------
s = r["storage"]
layers = [("Feature artefacts", s["artefacts_to_raw"]), ("Summary tables", s["summary_to_raw"]),
          ("Index (bloom + BM25)", s["index_to_raw"])]
fig, ax = plt.subplots(figsize=(6.4, 3.0))
y = range(len(layers))
ax.barh(list(y), [v * 100 for _, v in layers], height=0.5, color=OURS)
for i, (_, v) in enumerate(layers):
    ax.text(v * 100 + 0.8, i, f"{v*100:.1f}%", va="center", fontsize=9)
ax.set_yticks(list(y), [k for k, _ in layers], color=INK2)
ax.set_xlim(0, 70)
ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:.0f}%"))
ax.set_xlabel("Size relative to raw data")
ax.set_title(f"Derived-layer storage ({s['derived_to_raw']*100:.1f}% of raw in total)")
tidy(ax, grid_axis="x")
save(fig, "fig4_storage_layers.png")

# 5. Tier-3 restore volume vs a full scan ----------------------------------------------------
t3 = [x for x in f["per_rule"] if 3 in (x.get("tiers") or [])]
full = max(x["bytes_restored"] for x in t3)   # the /24 range scan restores the whole 7-day range
t3.sort(key=lambda x: x["bytes_restored"])
fig, ax = plt.subplots(figsize=(6.6, 3.4))
pct = [x["bytes_restored"] / full * 100 for x in t3]
ax.barh(range(len(t3)), pct, height=0.5, color=OURS)
for i, (x, p) in enumerate(zip(t3, pct)):
    ax.text(p * 1.15, i, f"{p:.2f}%  ({x['bytes_restored']/1e6:.2f} MB)" if p < 1 else f"{p:.0f}%  ({x['bytes_restored']/1e6:.2f} MB)", va="center", fontsize=9)
ax.set_xscale("log")
ax.set_xlim(0.1, 400)
ax.set_xticks([0.1, 1, 10, 100])
ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}%"))
ax.set_yticks(range(len(t3)), [x["rule"] for x in t3], color=INK2, fontsize=9)
ax.set_xlabel("Raw data restored, % of a full 7-day scan (log scale)")
ax.set_title("Tier-3 rules restore only what they need")
tidy(ax, grid_axis="x")
save(fig, "fig5_tier3_restore.png")
