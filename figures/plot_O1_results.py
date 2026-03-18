import os
import json
import pandas as pd
import seaborn as sns
from brokenaxes import brokenaxes
import numpy as np
import matplotlib.pyplot as plt

# Configuration

BENCHMARK_MEM = "membership_proofs"
BENCHMARK_NON_MEM = "non_membership_proofs" 
BENCHMARKS = [
    {
        "name": "Blind Membership Proof",
        "path": f"target/criterion/{BENCHMARK_MEM}/blind_mem_proof/new/sample.json" 
    },
    {
        "name": "Unblind Membership Proof",
        "path": f"target/criterion/{BENCHMARK_MEM}/unblind_mem_proof/new/sample.json"
    },
    {
        "name": "Verify Blinded Membership Proof Update",
        "path": f"target/criterion/{BENCHMARK_MEM}/ver_blind_mem_proof_upd/new/sample.json"
    },
    {
        "name": "Blind Non-Membership Proof",
        "path": f"target/criterion/{BENCHMARK_NON_MEM}/blind_non_mem_proof/new/sample.json" 
    },
    {
        "name": "Unblind Non-Membership Proof",
        "path": f"target/criterion/{BENCHMARK_NON_MEM}/unblind_non_mem_proof/new/sample.json"
    },
    {
        "name": "Verify Blinded Non-Membership Proof Update",
        "path": f"target/criterion/{BENCHMARK_NON_MEM}/ver_blind_non_mem_proof_upd/new/sample.json"
    }
]

def load_criterion_data(file_path, operation_name):
    if not os.path.exists(file_path):
        print(f"ERROR: Could not find {file_path}. Did you run 'cargo bench'?")
        return pd.DataFrame()
    
    with open(file_path, "r") as f:
        content = json.load(f)

        times = content["times"]
        iters = content["iters"]

        data_rows = []

        for t, i in zip(times, iters):
            time_per_op_ns = t/i
            time_per_op_ms = time_per_op_ns / 1_000_000.0

            data_rows.append({
                "Operation": operation_name,
                "Time (ms)": time_per_op_ms
            })

    return pd.DataFrame(data_rows)


# Main Execution

print("Loading 100 samples from Criterion..")
all_dataframes = []

for bench in BENCHMARKS:
    df = load_criterion_data(bench["path"], bench["name"])
    if not df.empty:
        all_dataframes.append(df)

if not all_dataframes:
    print("ERROR: Could not load any data. Did you run 'cargo bench'?")
    exit()

df = pd.concat(all_dataframes, ignore_index=True)

print(f"Successfully loaded {len(df)} measurements.")

print("\n--- Statistical Summary ---")
print(df.groupby("Operation")["Time (ms)"].describe())

# Visualization
plt.figure(figsize=(12, 8))
sns.set_theme(style="whitegrid")

#plt.subplots_adjust(bottom=0.35)

bax = brokenaxes(
    ylims=((-0.1, 5.0), (10.0, 36.0)), 
    hspace=.1,
    bottom=0.30
)

op_names = df['Operation'].unique()
data_to_plot = [df[df['Operation'] == op]['Time (ms)'].values for op in op_names]

bplot = bax.boxplot(
    data_to_plot,
    widths=0.4,
    patch_artist=True,
    showmeans=True,
    showfliers=False,
    labels=op_names,
    meanprops={
        "marker": "o",
        "markerfacecolor": "white",
        "markeredgecolor": "black",
        "markersize": 5
    }
)

colors = sns.color_palette("Set2", n_colors=len(op_names))

for part in bplot: 
    for patch, color in zip(part['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.8)

#plt.xlabel("", fontsize=12)
bax.set_xticks(range(1, len(op_names) + 1)) 
bax.set_xticklabels(op_names, fontsize=10, rotation=45, ha='right')
bax.set_ylabel("Time (ms)", labelpad=40, fontsize=12, fontweight='bold')

output_file = "figures/images/membership_proofs_boxplot.png"
plt.tight_layout()
plt.savefig(output_file, dpi=300)
print(f"\nSuccess! Boxplot saved to: {output_file}")

plt.show()