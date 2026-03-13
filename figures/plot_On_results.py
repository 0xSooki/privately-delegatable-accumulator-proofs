import os
import json
import pandas as pd
import seaborn as sns
from brokenaxes import brokenaxes
import numpy as np
import matplotlib.pyplot as plt

# Configuration

BASE_DIR = "target/criterion/membership_proofs/blind_proof_upd"

input_size = [10, 200, 400, 600, 800, 1000]

def load_criterion_data(base_dir):

    data_rows = []

    if not os.path.exists(base_dir):
        print(f"ERROR: Could not find {base_dir}. Did you run 'cargo bench'?")
        return pd.DataFrame()
    
    for folder_name in os.listdir(base_dir):
        folder_path = os.path.join(base_dir, folder_name)

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
                        "Time (s)": mean_s
                    })
    return pd.DataFrame(data_rows)


# Main Execution
print("Loading 10 samples from Criterion..")
all_dataframes = []

df = load_criterion_data(BASE_DIR)

if df.empty:
    print(f"No data found. Check the {BASE_DIR} path")
    exit()

df = df.sort_values("Elements")

print(f"Loaded {len(df)} data points:")
print(df)



# Visualization
plt.figure(figsize=(10, 6))
sns.set_theme(style="whitegrid")


plt.plot(df["Elements"], df["Time (s)"],
         marker='o',
         linestyle='-',
         linewidth="2.5",
         markersize=9,
         color="#2980b9",
         label="Blind Proof Update")

plt.xlabel("Number of elements", fontsize=12)
plt.ylabel("Time (seconds)", fontsize=12)

plt.grid(True, linestyle='--', alpha=0.7)
plt.legend()

output_file = "figures/images/membership_proofs_scaling.png"
plt.tight_layout()
plt.savefig(output_file, dpi=300)
print(f"\nSuccess! Chart saved to: {output_file}")

plt.show()