import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configuration
BENCHMARK_GROUP = "rsa_add" 
SAMPLE_JSON_PATH = f"target/criterion/{BENCHMARK_GROUP}/add_one_element/new/sample.json"

def load_criterion_data(file_path):
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
                "Operation": "RSA Addition (1 element)",
                "Time (ms)": time_per_op_ms
            })
        
    return pd.DataFrame(data_rows)


# Main Execution
print("Loading 100 samples from Criterion..")
df = load_criterion_data(SAMPLE_JSON_PATH)

if df.empty:
    print("No data found.")
    exit()

print(f"Successfully loaded {len(df)} measurements.")

print("\n--- Statistical Summary ---")
print(df["Time (ms)"].describe())

# Visualization
plt.figure(figsize=(8, 6))
sns.set_theme(style="whitegrid")

ax = sns.boxplot(
    x="Operation",
    y="Time (ms)",
    data=df,
    width=0.4,
    color="#3498db",
    showmeans=True,
    meanprops={
        "marker": "o",
        "markerfacecolor": "white",
        "markeredgecolor": "black",
        "markersize": "10"
    }
)



plt.xlabel("", fontsize=12)
plt.ylabel("Execution Time (ms)", fontsize=12)

output_file = "benches/images/rsa_add_boxplot.png"
plt.tight_layout()
plt.savefig(output_file, dpi=300)
print(f"\nSuccess! Boxplot saved to: {output_file}")

plt.show()