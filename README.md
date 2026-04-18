# Private accumulator proof delegation

This repository contains code for privacy-preserving accumulator proof updates, that allows clients to outsource heavy proof updates to a server while using blinding techniques to keep the specific elements being updated hidden from that server.

## Overview

Cryptographic accumulators are widely employed in blockchain systems to verify status of the set of elements; however updating these proofs can be computationally intensive for clients, especially when dealing with large datasets. This project implements a privacy-preserving approach to allow clients to outsource these updates to a server without revealing the specific elements being updated. This is implemented in Rust, leveraging its performance and safety features to ensure efficient and secure operations. The project includes Python's Matplotlib-based visualizations to analyze the performance of proof updates, evaluating the trade-off between the privacy-preserving blinded outsourcing protocol and the standard update mechanism.

## Features

- **Efficient Proof Updates**: Optimized algorithms for fast proof updates, reducing computational overhead.
- **Blinding Techniques**: Advanced methods to ensure client data remains confidential during outsourcing.
- **Performance Analysis**: Integrated tools for visualizing and analyzing performance metrics.
- **Cross-Platform Compatibility**: Works seamlessly across different operating systems and environments.
- **Robust Testing Framework**: Ensures reliability and correctness of the implementation through extensive testing.

## Installation

### Requirements

- Rust (for the core implementation)
- Python (for visualization and performance analysis)
- pip (for managing Python dependencies)

### Quick start

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

3. **Install Python Dependencies**:
   Make sure you have Python and pip installed, then run:

   ```bash
   pip install pandas matplotlib
   ```

4. **Run the Application**:
   After building the Rust project and installing the Python dependencies, you can run the application using:

   ```bash
   cargo run
   ```

5. **Visualize Performance**:
   To generate performance visualizations, execute the following Python script:
   ```bash
   python plot_On_results.py
   ```
