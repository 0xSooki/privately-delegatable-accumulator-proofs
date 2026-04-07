import json
import os
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends import backend_pgf as mpl_backend_pgf
from matplotlib.legend import Legend

if not hasattr(mpl_backend_pgf, "common_texification"):
    # Compatibility shim for tikzplotlib with newer Matplotlib versions.
    mpl_backend_pgf.common_texification = mpl_backend_pgf._tex_escape

if not hasattr(Legend, "legendHandles"):
    # Compatibility shim for tikzplotlib with newer Matplotlib versions.
    Legend.legendHandles = property(lambda self: self.legend_handles)

if not hasattr(Legend, "_ncol"):
    # Compatibility shim for tikzplotlib with newer Matplotlib versions.
    Legend._ncol = property(lambda self: self._ncols)

if not hasattr(np, "float_"):
    # Compatibility shim for tikzplotlib with NumPy 2.x.
    np.float_ = np.float64

import tikzplotlib

BASE_DIR = Path("target/criterion/bilinear_vs_class_vs_rsa_trapdoorless")
OUT_IMG = Path("figures/images/bilinear_vs_class_vs_rsa_trapdoorless.png")
OUT_TIKZ = Path("figures/images/bilinear_vs_class_vs_rsa_trapdoorless.tex")
OUT_CSV_DIR = Path("data_for_latex")

FAMILIES = [
    (
        "Blind Membership Proof Update",
        [
            (
                "rsa_trapdoored_mem_blind_proof_upd",
                "RSA trapdoored",
                "#ff7f0e",
                "^",
            ),
            (
                "rsa_trapdoorless_mem_blind_proof_upd",
                "RSA trapdoorless",
                "#1f77b4",
                "o",
            ),
            ("class_mem_blind_proof_upd", "Class group", "#d62728", "s"),
            ("bilinear_mem_blind_proof_upd", "Bilinear", "#2ca02c", "D"),
        ],
    ),
    (
        "Blind Membership Update Overhead",
        [
            (
                (
                    "rsa_trapdoored_mem_blind_proof_upd",
                    "rsa_trapdoored_mem_proof_create",
                ),
                "RSA trapdoored",
                "#ff7f0e",
                "^",
            ),
            (
                (
                    "rsa_trapdoorless_mem_blind_proof_upd",
                    "rsa_trapdoorless_mem_proof_create",
                ),
                "RSA trapdoorless",
                "#1f77b4",
                "o",
            ),
            (
                ("class_mem_blind_proof_upd", "class_mem_proof_create"),
                "Class group",
                "#d62728",
                "s",
            ),
            (
                ("bilinear_mem_blind_proof_upd", "bilinear_mem_proof_create"),
                "Bilinear",
                "#2ca02c",
                "D",
            ),
        ],
    ),
    (
        "Blind Non-Membership Proof Update",
        [
            (
                "rsa_trapdoored_non_mem_blind_proof_upd",
                "RSA trapdoored",
                "#ff7f0e",
                "^",
            ),
            (
                "rsa_trapdoorless_non_mem_blind_proof_upd",
                "RSA trapdoorless",
                "#1f77b4",
                "o",
            ),
            ("class_non_mem_blind_proof_upd", "Class group", "#d62728", "s"),
            ("bilinear_non_mem_blind_proof_upd", "Bilinear", "#2ca02c", "D"),
        ],
    ),
    (
        "Blind Non-Membership Update Overhead",
        [
            (
                (
                    "rsa_trapdoored_non_mem_blind_proof_upd",
                    "rsa_trapdoored_non_mem_proof_create",
                ),
                "RSA trapdoored",
                "#ff7f0e",
                "^",
            ),
            (
                (
                    "rsa_trapdoorless_non_mem_blind_proof_upd",
                    "rsa_trapdoorless_non_mem_proof_create",
                ),
                "RSA trapdoorless",
                "#1f77b4",
                "o",
            ),
            (
                ("class_non_mem_blind_proof_upd", "class_non_mem_proof_create"),
                "Class group",
                "#d62728",
                "s",
            ),
            (
                (
                    "bilinear_non_mem_blind_proof_upd",
                    "bilinear_non_mem_proof_create",
                ),
                "Bilinear",
                "#2ca02c",
                "D",
            ),
        ],
    ),
]


def load_mean_ms(estimates_path: Path) -> float:
    with estimates_path.open("r", encoding="utf-8") as f:
        content = json.load(f)
    mean_ns = content["mean"]["point_estimate"]
    return mean_ns / 1_000_000.0


def load_series(bench_id: str):
    bench_dir = BASE_DIR / bench_id
    if not bench_dir.exists():
        return []

    rows = []
    for child in bench_dir.iterdir():
        if not child.is_dir() or not child.name.isdigit():
            continue
        n = int(child.name)

        base_est = child / "base" / "estimates.json"
        new_est = child / "new" / "estimates.json"

        est_path = base_est if base_est.exists() else new_est if new_est.exists() else None
        if est_path is None:
            continue

        rows.append((n, load_mean_ms(est_path)))

    rows.sort(key=lambda x: x[0])
    return rows


def build_overhead_series(update_bench_id: str, create_bench_id: str):
    upd_rows = dict(load_series(update_bench_id))
    create_rows = dict(load_series(create_bench_id))
    common_n = sorted(set(upd_rows) & set(create_rows))

    rows = []
    for n in common_n:
        create_ms = create_rows[n]
        if create_ms <= 0:
            continue
        rows.append((n, upd_rows[n] / create_ms))
    return rows


def export_csv(bench_id: str, rows, y_label: str = "Time (ms)"):
    OUT_CSV_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_CSV_DIR / f"{bench_id}.csv"
    with out_path.open("w", encoding="utf-8") as f:
        f.write(f"Elements,{y_label}\n")
        for n, value in rows:
            f.write(f"{n},{value}\n")


def main():
    if not BASE_DIR.exists():
        raise FileNotFoundError(f"Missing benchmark directory: {BASE_DIR}")

    fig, axes = plt.subplots(1, 4, figsize=(24, 5))

    for panel_idx, (ax, (title, families)) in enumerate(zip(axes, FAMILIES)):
        is_overhead_panel = panel_idx in (1, 3)

        for bench_ref, label, color, marker in families:
            if is_overhead_panel:
                update_bench_id, create_bench_id = bench_ref
                rows = build_overhead_series(update_bench_id, create_bench_id)
                export_id = f"{update_bench_id}_over_create"
                y_axis_label = "Overhead (x)"
            else:
                bench_id = bench_ref
                rows = load_series(bench_id)
                export_id = bench_id
                y_axis_label = "Time (ms)"

            if not rows:
                continue

            x = [r[0] for r in rows]
            y = [r[1] for r in rows]
            ax.plot(
                x,
                y,
                marker=marker,
                linewidth=2.2,
                markersize=6,
                markerfacecolor="white",
                markeredgecolor="black",
                markeredgewidth=1.2,
                color=color,
                label=label,
            )

            export_csv(export_id, rows, y_axis_label)
            print(f"Loaded {export_id}: {len(rows)} points -> {x}")

        ax.set_title(title)
        ax.set_xscale("log", base=2)
        ax.set_yscale("log", base=10)
        ax.set_xlabel("Number of inserted elements (k)")
        ax.set_ylabel("Overhead (x)" if is_overhead_panel else "Time (ms)")
        ax.grid(True, which="both", linestyle="--", alpha=0.5)
        ax.legend()

    plt.tight_layout()

    OUT_IMG.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUT_IMG, dpi=300)
    print(f"Saved plot: {OUT_IMG}")

    OUT_TIKZ.parent.mkdir(parents=True, exist_ok=True)
    tikzplotlib.save(OUT_TIKZ)
    print(f"Saved TikZ: {OUT_TIKZ}")


if __name__ == "__main__":
    main()
