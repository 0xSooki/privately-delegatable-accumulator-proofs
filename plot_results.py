import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configuration
BENCHMARK_GROUP = "rsa_add_scaling" 
BASE_DIR = f"target/criterion/{BENCHMARK_GROUP}"

def load_criterion_data(base_dir):
    data_rows = []
    
    if not os.path.exists(base_dir):
        print(f"ERROR: Directory not found: {base_dir}")
        return pd.DataFrame()

    for folder_name in os.listdir(base_dir):
        folder_path = os.path.join(base_dir, folder_name)
        
        if os.path.isdir(folder_path) and folder_name.isdigit():
            input_size = int(folder_name)
            
            est_path = os.path.join(folder_path, "base", "estimates.json")
            
            if os.path.exists(est_path):
                with open(est_path, "r") as f:
                    content = json.load(f)
                    
                    mean_ns = content["mean"]["point_estimate"]
                    
                    mean_ms = mean_ns / 1_000_000.0
                    
                    data_rows.append({
                        "Elements": input_size,
                        "Time (ms)": mean_ms
                    })
    
    return pd.DataFrame(data_rows)

# Main Execution
df = load_criterion_data(BASE_DIR)

if df.empty:
    print("No data found.")
    exit()

df = df.sort_values("Elements")

print(f"Loaded {len(df)} data points:")
print(df)

# Visualization
plt.figure(figsize=(10, 6))
sns.set_theme(style="whitegrid")

plt.plot(df["Elements"], df["Time (ms)"], 
         marker='o',
         linestyle='-',
         linewidth=2,         
         markersize=8,        
         color="#2c3e50",
         label="RSA Accumulator Addition")

plt.title("RSA Accumulator Scaling (Linear)", fontsize=16, fontweight='bold')
plt.xlabel("Number of Added Elements", fontsize=12)
plt.ylabel("Execution Time (ms)", fontsize=12)

plt.grid(True, linestyle='--', alpha=0.7)
plt.legend()

output_file = "benches/images/rsa_scaling_linear.png"
plt.tight_layout()
plt.savefig(output_file, dpi=300)
print(f"\nSuccess! Chart saved to: {output_file}")

plt.show()