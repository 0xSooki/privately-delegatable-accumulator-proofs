# 🔐 Private accumulator proof delegation

This repository contains code for privacy-preserving accumulator proof updates, that allows clients to outsource heavy proof updates to a server while using blinding techniques to keep the specific elements being updated hidden from that server.

## 🔍 What problem does this solve?

Imagine you need to prove "my item is in this set" or "my item is not in this set", where the set contains millions of elements and changes constantly. Storing the whole set yourself is impractical. Recomputing your proof from scratch every time the set changes is expensive. A cryptographic accumulator solves the storage problem: the entire set is compressed into a single 3072-bit value (the digest). Your proof is a single group element. Verification is one modular exponentiation. The remaining problem: keeping your proof current. Every time the set changes, your proof goes stale. You could delegate the update work to a server - but sending your proof to a server tells the server exactly which element you hold a proof for. In a privacy-sensitive setting, that is unacceptable. This library solves the delegation problem. The client blinds its proof before sending it, the server updates the blinded proof, and the client verifies and unblinds to recover a valid up-to- date proof. The server learns nothing about the underlying element.

## ❓ When would you use this?
- Stateless blockchains — clients hold only a digest of the UTXO set and must keep their spending witnesses current without revealing which coins they own.
- Anonymous credentials — proving set membership without linking multiple proof requests.
- Private allowlists / blocklists — a client proves membership or non-membership in a registry without revealing which entry it checked.
- Any setting where you need verifiable set operations on a compact digest, with delegation to an untrusted third party.

## 🧩 Features

- ⚡ **Efficient Proof Updates**: Optimized algorithms for fast proof updates, reducing computational overhead.
- 🕶️ **Blinding Techniques**: Advanced methods to ensure client data remains confidential during outsourcing.
- 📊 **Performance Analysis**: Integrated tools for visualizing and analyzing performance metrics.
- 🌍 **Cross-Platform Compatibility**: Works seamlessly across different operating systems and environments.
- 🧪 **Robust Testing Framework**: Ensures reliability and correctness of the implementation through extensive testing.


## ⚙️ How it works (in brief)

The digest of a set $\{x_1, \ldots, x_k\}$ is $\mathrm{Acc}(S) = g^{p_1 \cdots p_k} \bmod N$, where each $p_i$ is a prime hash of $x_i$. A membership witness for $x_j$ is $π_j = g^{\prod_{i \neq j} p_i}$ verification checks $\pi_j^{p_j} = \mathrm{Acc}(S)$.

**Blinding** randomises the witness $\pi \mapsto \pi \cdot g^r$ with a fresh secret $r$. The server updates the blinded witness and proves it did so correctly with discrete-log-equality (DLEq) proofs under the Fiat–Shamir transform. The client verifies the proofs, then divides out $g^r$ to recover the updated witness in the clear.

Non-membership works differently: the witness is a pair of Bézout coefficients $(a, g^b)$ satisfying $a \cdot y + b \cdot P = 1$, where $P$ is the product of all accumulated primes. Blinding here multiplies the element itself by a fresh prime rather than masking the group element.

An example of this can be found in the **examples** folder



## 🛠️ Installation

### 📋 Requirements

- 🦀 Rust (for the core implementation)
- 🐍 Python (for visualization and performance analysis)
- 📦 pip (for managing Python dependencies)

### 🚀 Quick start

To get started with the project, follow these steps:

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/glaszboti/privacy-preserving-accumulator-proofs
   cd privacy-preserving-accumulator-proofs
   ```

2. **Build the Rust Project**:

   ```bash
   cargo build --release
   ```

3. **Run the Application**:
   After building the Rust project, you can run the application using:

   ```bash
   cargo run
   ```

### 📊 Benchmarks

```bash
cargo bench
python plot_On_results.py    # requires: pip install pandas matplotlib seaborn
```


## </> API reference

Run `cargo doc --open` for the full API reference with inline examples.

