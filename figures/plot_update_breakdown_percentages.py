import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[1]
CRITERION_DIR = ROOT_DIR / "target" / "criterion"
OUT_IMG = ROOT_DIR / "figures" / "images" / "update_breakdown_percentage_bars.png"
OUT_CSV = ROOT_DIR / "data_for_latex" / "update_breakdown_percentages.csv"
OUT_TIKZ = ROOT_DIR / "figures" / "update_breakdown.tikz"

BILINEAR_MEM_SIZE = 64

CONTEXTS = [
    {
        "label": f"Mem Bilinear (n={BILINEAR_MEM_SIZE})",
        "group": "mem_update_breakdown_bilinear",
        "full": "full_update",
        "nizk": "nizk_proving",
        "exp": "exponentiations",
        "hash": "hashing_fs",
        "size": BILINEAR_MEM_SIZE,
    },
    {
        "label": "Mem RSA",
        "group": "mem_update_breakdown_rsa",
        "full": "full_update",
        "nizk": "nizk_proving",
        "exp": "exponentiations",
        "hash": "hashing_fs",
        "size": None,
    },
    {
        "label": "Mem Class",
        "group": "mem_update_breakdown_class_group",
        "full": "full_update",
        "nizk": "nizk_proving",
        "exp": "exponentiations",
        "hash": "hashing_fs",
        "size": None,
    },
    {
        "label": "NonMem Bilinear",
        "group": "non_mem_update_breakdown_bilinear",
        "full": "full_update",
        "nizk": "nizk_proving",
        "exp": "exponentiations",
        "hash": None,
        "size": None,
    },
    {
        "label": "NonMem RSA",
        "group": "non_mem_update_breakdown_rsa",
        "full": "full_update",
        "nizk": None,
        "exp": "exponentiations",
        "hash": None,
        "size": None,
    },
    {
        "label": "NonMem Class",
        "group": "non_mem_update_breakdown_class_group",
        "full": "full_update",
        "nizk": None,
        "exp": "exponentiations",
        "hash": None,
        "size": None,
    },
]

TIKZ_X_COORDS = ["m0", "m1", "m2", "n0", "n1", "n2"]
TIKZ_XTICK_LABELS = [
    r"\shortstack{Mem\\Bilinear}",
    r"\shortstack{Mem\\RSA}",
    r"\shortstack{Mem\\Class}",
    r"\shortstack{NonMem\\Bilinear}",
    r"\shortstack{NonMem\\RSA}",
    r"\shortstack{NonMem\\Class}",
]


def estimate_path(group: str, bench: str, size: int | None) -> Path:
    if size is None:
        return CRITERION_DIR / group / bench / "new" / "estimates.json"
    return CRITERION_DIR / group / bench / str(size) / "new" / "estimates.json"


def load_mean_ms(path: Path) -> float:
    with path.open("r", encoding="utf-8") as f:
        content = json.load(f)
    return float(content["mean"]["point_estimate"]) / 1_000_000.0


def resolve_mean_ms(group: str, bench: str, size: int | None) -> float:
    path = estimate_path(group, bench, size)
    if not path.exists():
        raise FileNotFoundError(f"Missing estimates file: {path}")
    return load_mean_ms(path)


def collect_rows() -> list[dict]:
    rows: list[dict] = []

    for ctx in CONTEXTS:
        full_ms = resolve_mean_ms(ctx["group"], ctx["full"], ctx["size"])
        exp_ms = resolve_mean_ms(ctx["group"], ctx["exp"], ctx["size"])

        if ctx["hash"] is None:
            hash_ms = 0.0
        else:
            hash_ms = resolve_mean_ms(ctx["group"], ctx["hash"], ctx["size"])

        if ctx["nizk"] is None:
            nizk_total_ms = 0.0
            nizk_only_ms = 0.0
        else:
            nizk_total_ms = resolve_mean_ms(ctx["group"], ctx["nizk"], ctx["size"])
            nizk_only_ms = max(nizk_total_ms - hash_ms, 0.0)

        other_ms = max(full_ms - exp_ms - hash_ms - nizk_only_ms, 0.0)
        
        denom_ms = exp_ms + hash_ms + nizk_only_ms #+ # other_ms
        if denom_ms <= 0:
            continue

        rows.append(
            {
                "label": ctx["label"],
                "full_ms": full_ms,
                "nizk_total_ms": nizk_total_ms,
                "nizk_only_ms": nizk_only_ms,
                "exp_ms": exp_ms,
                "hash_ms": hash_ms,
                "other_ms": other_ms,
                "nizk_pct": (nizk_only_ms / denom_ms) * 100.0,
                "exp_pct": (exp_ms / denom_ms) * 100.0,
                "hash_pct": (hash_ms / denom_ms) * 100.0,
            }
        )

    return rows


def write_csv(rows: list[dict]) -> None:
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "label",
        "full_ms",
        "nizk_total_ms",
        "nizk_only_ms",
        "exp_ms",
        "hash_ms",
        "other_ms",
        "nizk_pct",
        "exp_pct",
        "hash_pct",
    ]

    with OUT_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: f"{v:.8f}" if isinstance(v, float) else v for k, v in row.items()})


def _tikz_coordinates(values: np.ndarray) -> str:
    return " ".join(
        f"({x_label},{value:.2f})" for x_label, value in zip(TIKZ_X_COORDS, values, strict=True)
    )


def write_tikz(rows: list[dict]) -> None:
    if not rows:
        raise RuntimeError("No benchmark rows loaded. Run the benchmark first.")

    exp = np.array([r["exp_pct"] for r in rows])
    hsh = np.array([r["hash_pct"] for r in rows])
    nizk = np.array([r["nizk_pct"] for r in rows])

    tikz_lines = [
        "% Requires in LaTeX preamble: \\usepackage{pgfplots}",
        "% Optional: \\pgfplotsset{compat=1.18}",
        r"\begin{tikzpicture}",
        r"\begin{axis}[",
        r"    ybar stacked,",
        r"    bar width=10pt,",
        r"    width=0.98\linewidth,",
        r"    height=0.52\linewidth,",
        r"    ymin=0,",
        r"    ymax=100,",
        r"    ytick={0,20,40,60,80,100},",
        r"    ylabel={Share of measured update time (\%)},",
        r"    symbolic x coords={" + ",".join(TIKZ_X_COORDS) + r"},",
        r"    xtick=data,",
        r"    xticklabels={" + ",".join("{" + label + "}" for label in TIKZ_XTICK_LABELS) + r"},",
        r"    x tick label style={font=\footnotesize, rotate=40, anchor=east, align=right},",
        r"    y tick label style={font=\footnotesize},",
        r"    ylabel style={font=\footnotesize},",
        r"    ymajorgrids,",
        r"    grid style={dashed, gray!35},",
        r"    axis line style={black!70},",
        r"    tick style={black!70},",
        r"    legend columns=3,",
        r"    legend style={font=\footnotesize, draw=none, fill=none, at={(0.5,1.02)}, anchor=south},",
        r"]",
        r"\addplot+[draw=none, fill={rgb,255:red,78;green,121;blue,167}] coordinates {"
        + _tikz_coordinates(exp)
        + r"};",
        r"\addplot+[draw=none, fill={rgb,255:red,242;green,142;blue,43}] coordinates {"
        + _tikz_coordinates(hsh)
        + r"};",
        r"\addplot+[draw=none, fill={rgb,255:red,89;green,161;blue,79}] coordinates {"
        + _tikz_coordinates(nizk)
        + r"};",
        r"\legend{Exponentiation,Hashing,NIZK}",
        r"\end{axis}",
        r"\end{tikzpicture}",
        "",
    ]

    OUT_TIKZ.parent.mkdir(parents=True, exist_ok=True)
    OUT_TIKZ.write_text("\n".join(tikz_lines), encoding="utf-8")


def plot(rows: list[dict]) -> None:
    if not rows:
        raise RuntimeError("No benchmark rows loaded. Run the benchmark first.")

    labels = ["Mem\nBilinear", "Mem\nRSA", "Mem\nClass", "NonMem\nBilinear", "NonMem\nRSA", "NonMem\nClass"]
    nizk = np.array([r["nizk_pct"] for r in rows])
    exp = np.array([r["exp_pct"] for r in rows])
    hsh = np.array([r["hash_pct"] for r in rows])
    #other = np.array([r["other_pct"] for r in rows])

    x = np.arange(len(labels))
    width = 0.72

    fig, ax = plt.subplots(figsize=(12.0, 6.5))

    ax.bar(x, exp, width, label="Exponentiation", color="#1f77b4")
    ax.bar(x, hsh, width, bottom=exp, label="Hashing", color="#ff7f0e")
    ax.bar(x, nizk, width, bottom=exp + hsh, label="NIZK", color="#9467bd")
    # ax.bar(x, other, width, bottom=exp + hsh + nizk, label="Other", color="#2ca02c")

    # for i, row in enumerate(rows):
    #     top = exp[i] + hsh[i] + nizk[i]
    #     ax.text(i, top + 1.0, f"{row['full_ms']:.2f} ms", ha="center", va="bottom", fontsize=9)

    ax.set_ylim(0, 105)
    ax.set_ylabel("Share of measured update time (%)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=40, ha="right")
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.legend(loc="lower right", frameon=True)

    OUT_IMG.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(OUT_IMG, format="png", dpi=300, bbox_inches="tight")
    fig.savefig(OUT_IMG.with_suffix(".pdf"), format="pdf", bbox_inches="tight")
    plt.close(fig)



if __name__ == "__main__":
    rows = collect_rows()
    write_csv(rows)
    plot(rows)
    write_tikz(rows)
    print(f"Saved chart: {OUT_IMG}")
    print(f"Saved tikz: {OUT_TIKZ}")
    print(f"Saved csv: {OUT_CSV}")
