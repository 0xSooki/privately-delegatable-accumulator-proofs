import json
import os
from pathlib import Path

import matplotlib.pyplot as plt

BASE_DIR = Path("target/criterion/bilinear_vs_class_vs_rsa_trapdoorless")
OUT_IMG = Path("figures/images/bilinear_vs_class_vs_rsa_trapdoorless.png")
OUT_CSV_DIR = Path("data_for_latex")

FAMILIES = [
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
        "Membership Proof Create",
        [
            ("rsa_trapdoored_mem_proof_create", "RSA trapdoored", "#ff7f0e", "^"),
            (
                "rsa_trapdoorless_mem_proof_create",
                "RSA trapdoorless",
                "#1f77b4",
                "o",
            ),
            ("class_mem_proof_create", "Class group", "#d62728", "s"),
            ("bilinear_mem_proof_create", "Bilinear", "#2ca02c", "D"),
        ],
    ),
    (
        "Non-Membership Proof Create",
        [
            (
                "rsa_trapdoored_non_mem_proof_create",
                "RSA trapdoored",
                "#ff7f0e",
                "^",
            ),
            (
                "rsa_trapdoorless_non_mem_proof_create",
                "RSA trapdoorless",
                "#1f77b4",
                "o",
            ),
            ("class_non_mem_proof_create", "Class group", "#d62728", "s"),
            ("bilinear_non_mem_proof_create", "Bilinear", "#2ca02c", "D"),
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


def export_csv(bench_id: str, rows):
    OUT_CSV_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_CSV_DIR / f"{bench_id}.csv"
    with out_path.open("w", encoding="utf-8") as f:
        f.write("Elements,Time (ms)\n")
        for n, ms in rows:
            f.write(f"{n},{ms}\n")


def main():
    if not BASE_DIR.exists():
        raise FileNotFoundError(f"Missing benchmark directory: {BASE_DIR}")

    fig, axes = plt.subplots(1, 4, figsize=(24, 5))

    for ax, (title, families) in zip(axes, FAMILIES):
        for bench_id, label, color, marker in families:
            rows = load_series(bench_id)
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

            export_csv(bench_id, rows)
            print(f"Loaded {bench_id}: {len(rows)} points -> {x}")

        ax.set_title(title)
        ax.set_xscale("log", base=2)
        ax.set_yscale("log", base=10)
        ax.set_xlabel("Elements")
        ax.set_ylabel("Time (ms)")
        ax.grid(True, which="both", linestyle="--", alpha=0.5)
        ax.legend()

    plt.tight_layout()

    OUT_IMG.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUT_IMG, dpi=300)
    print(f"Saved plot: {OUT_IMG}")


if __name__ == "__main__":
    main()
