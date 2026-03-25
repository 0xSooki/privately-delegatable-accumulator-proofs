import os
import json
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Configuration
BENCHMARKS_UPDATES = [
    {
        "label": "Blind Membership Proof Update",
        "base_dir": "target/criterion/membership_proofs",
        "bench_name": "blind_mem_proof_upd",
        "linestyle": "-"
    },
    {
        "label": "Blind Non-Membership Proof Update",
        "base_dir": "target/criterion/non_membership_proofs",
        "bench_name": "blind_non_mem_proof_upd",
        "linestyle": "--"
    }
]

BASE_DIR_COMPARE = "target/criterion/accumulator_compare"
BENCHMARKS_COMPARE = {
    "rsa_add_n": "RSA Add",
    "bilinear_add_n": "Bilinear Add",
    "rsa_mem_proof": "RSA Membership Proof",
    "bilinear_mem_proof": "Bilinear Membership Proof",
}

DIR_TRAPDOOR = "target/criterion/trapdoored_vs_trapdoorless_accumulator"
BENCHMARKS_TRAPDOOR = {
    "trapdoored_non_mem_blind_proof_upd": "Trapdoored Blind Non-Membership Proof Update",
    "trapdoorless_non_mem_blind_proof_upd": "Trapdoorless Blind Non-Membership Proof Update",
    "trapdoored_mem_proof_create": "Trapdoored Membership Proof Create",
    "trapdoorless_mem_proof_create": "Trapdoorless Membership Proof Create",
    "trapdoored_non_mem_proof_create": "Trapdoored Non-Membership Proof Create",
    "trapdoorless_non_mem_proof_create": "Trapdoorless Non-Membership Proof Create",
}

def load_criterion_data(base_dir, bench_name):

    data_rows = []

    bench_dir = os.path.join(base_dir, bench_name)

    if not os.path.exists(bench_dir):
        print(f"ERROR: Could not find {bench_dir}. Did you run 'cargo bench'?")
        return pd.DataFrame()
    
    for folder_name in os.listdir(bench_dir):
        folder_path = os.path.join(bench_dir, folder_name)

        if os.path.isdir(folder_path) and folder_name.isdigit():
            n_elements = int(folder_name)

            est_path = os.path.join(folder_path, "base", "estimates.json")

            if os.path.exists(est_path):
                with open(est_path, "r") as f:
                    content = json.load(f)

                    mean_ns = content["mean"]["point_estimate"]

                    mean_s = mean_ns / 1_000_000_000.0

                    data_rows.append({
                        "Elements": n_elements,
                        "Time (s)": mean_s,
                    })
    return pd.DataFrame(data_rows)


# Main Execution
print("Loading samples from Criterion..")
series = {}

for bench_name, label in BENCHMARKS_COMPARE.items():
    df = load_criterion_data(BASE_DIR_COMPARE, bench_name)
    if df.empty:
        continue
    df = df.sort_values("Elements")
    series[label] = df


for bench in BENCHMARKS_UPDATES:
    df = load_criterion_data(bench["base_dir"], bench["bench_name"])
    if not df.empty:
        df = df.sort_values("Elements")
        series[bench["label"]] = df


for bench_name, label in BENCHMARKS_TRAPDOOR.items():
    df = load_criterion_data(DIR_TRAPDOOR, bench_name)
    if df.empty:
        continue
    df = df.sort_values("Elements")
    series[label] = df


if not series:
    print(f"No data found. Check the {BASE_DIR_COMPARE} path")
    exit()

for label, df in series.items():
    print(f"Loaded {len(df)} data points for {label}")

# Visualization: Add scaling
plt.figure(figsize=(10, 6))
sns.set_theme(style="whitegrid")

for label in ["RSA Add", "Bilinear Add"]:
    if label not in series:
        continue
    df = series[label]
    plt.plot(
        df["Elements"],
        df["Time (s)"],
        marker="o",
        linestyle="-",
        linewidth="2.5",
        markersize=7,
        label=label,
    )

plt.xlabel("Number of elements", fontsize=12)
plt.ylabel("Time (seconds)", fontsize=12)
plt.title("Accumulator Add Scaling")
plt.grid(True, linestyle="--", alpha=0.7)
plt.legend()

output_file_add = "figures/images/accumulator_add_scaling.png"
plt.tight_layout()
plt.savefig(output_file_add, dpi=300)
print(f"\nSuccess! Chart saved to: {output_file_add}")

# Visualization: Membership proof scaling
plt.figure(figsize=(10, 6))
sns.set_theme(style="whitegrid")

for label in ["RSA Membership Proof", "Bilinear Membership Proof"]:
    if label not in series:
        continue
    df = series[label]
    plt.plot(
        df["Elements"],
        df["Time (s)"],
        marker="o",
        linestyle="-",
        linewidth="2.5",
        markersize=7,
        label=label,
    )

plt.xlabel("Number of elements", fontsize=12)
plt.ylabel("Time (seconds)", fontsize=12)
plt.title("Accumulator Membership Proof Scaling")
plt.grid(True, linestyle="--", alpha=0.7)
plt.legend()

output_file_mem = "figures/images/accumulator_mem_proof_scaling.png"
plt.tight_layout()
plt.savefig(output_file_mem, dpi=300)
print(f"\nSuccess! Chart saved to: {output_file_mem}")


# Visualization: Update Blind Proofs Scaling
plt.figure(figsize=(10, 6))
sns.set_theme(style="whitegrid")

for bench in BENCHMARKS_UPDATES:
    label = bench["label"]
    if label in series:
        df = series[label]
        
        plt.plot(
            df["Elements"], 
            df["Time (s)"], 
            marker="o", 
            linestyle=bench["linestyle"], 
            linewidth=2.5, 
            markersize=7, 
            label=label
        )



plt.xlabel("Number of elements", fontsize=12)
plt.ylabel("Time (seconds)", fontsize=12)
plt.title("Trapdoored RSA Accumulator Blind Update Proof Scaling")
plt.yscale('log', base=2)
plt.xscale('log', base=2)
plt.grid(True, linestyle="--", alpha=0.7)
plt.legend()
plt.tight_layout()
output_file_upd = "figures/images/trapdoorless_accumulator_blind_update_proof_scaling.png"
plt.savefig(output_file_upd, dpi=300)
print(f"\nSuccess! Chart saved to: {output_file_upd}")



# Visualization: Trapdoored vs Trapdoorless
plt.figure(figsize=(12, 7))
sns.set_theme(style="whitegrid")


styles = {
    "Trapdoorless": "-",
    "Trapdoored": "--"
}

colors = {
    "Membership Proof Create": "#2ecc71",
    "Non-Membership Proof Create": "#e74c3c",
    "Blind Non-Membership Proof Update": "#3498db"
}

for label in ["Trapdoored Blind Non-Membership Proof Update", "Trapdoorless Blind Non-Membership Proof Update", "Trapdoored Membership Proof Create", "Trapdoorless Membership Proof Create", "Trapdoored Non-Membership Proof Create", "Trapdoorless Non-Membership Proof Create"]:
    df = series[label]
    
    line_style = "-"
    for key, style in styles.items():
        if key in label:
            line_style = style
            
    line_color = None
    for key, color in colors.items():
        if key in label:
            line_color = color

    plt.plot(
        df["Elements"],
        df["Time (s)"],
        marker="o",
        linestyle=line_style,
        color=line_color,
        linewidth=2.5,
        markersize=6,
        label=label,
        alpha=0.8
    )

plt.xscale("log", base=2)
plt.yscale("log", base=2)

plt.xlabel("Number of elements", fontsize=12)
plt.ylabel("Time (seconds)", fontsize=12)
plt.title("Trapdoored vs Trapdoorless Accumulator Algorithms")
plt.grid(True, linestyle="--", alpha=0.7)
plt.legend(bbox_to_anchor=(-0.1, 1), loc='upper right', handlelength=3)

output_file_add = "figures/images/trapdoored_vs_trapdoorless.png"
plt.tight_layout()
plt.savefig(output_file_add, dpi=300)
print(f"\nSuccess! Chart saved to: {output_file_add}")

plt.show()