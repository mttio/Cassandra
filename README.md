# Cassandra Web Sanitizer

Cassandra is a high-performance web sanitization engine and parallel crawling pipeline written in Rust. It enforces strict security policies to protect systems against active threats, including cross-site scripting (XSS), XML bombs, IDN homograph confusion, Server-Side Request Forgery (SSRF), malicious stylesheet inputs, and active content inside binary files (PDFs).

---

## Getting Started

### Prerequisites

To build and run the application, ensure you have the following installed:

- [Rust](https://www.rust-lang.org/) (2024 edition)
- [Python 3](https://www.python.org/) with `matplotlib` and `numpy` (only required for running the plotting evaluation script)

---

## Running the CLI Application

The default run target of the workspace executes the `cli_application`. It processes directories, individual files, or remote URLs.

```bash
cassandra <inputs> [flags]
```

### CLI Arguments & Options

- `<inputs>`: One or more inputs, separated by spaces. Supported inputs include:
  - Local HTML, JS, CSS, or PDF files.
  - Directories (searched recursively).
  - Remote HTTP/HTTPS URLs (crawled safely under Anti-SSRF policies).
- `-p, --policy <FILE>`: Path to a custom TOML policy file. If omitted, the default embedded policy is used.
- `-o, --output-dir <DIR>`: Directory where sanitized outputs and JSON/log reports are written (default: `output`).
- `-w, --workers <N>`: Number of concurrent worker threads used by the Tokio runtime (default: `4`).
- `-v`: Verbosity level. Specify multiple times to increase details (e.g., `-v`, `-vv`, `-vvv`).
- `-g, --generate-policy`: Print the default TOML policy to stdout and exit.

### Examples

1. **Sanitize a directory tree using the default policy**:

   ```bash
   cassandra input_test_files/benign
   ```

2. **Generate and inspect the default policy**:

   ```bash
   cassandra --generate-policy > my_policy.toml
   ```

3. **Run with a custom policy and verbose logs**:
   ```bash
   cassandra input_test_files/malicious --policy my_policy.toml -vvv
   ```

## Running Tests

To run the complete test suite verifying the HTML tokenizer, resource sanitizers (PDF, CSS, JS, MIME), SSRF client, and logger loop:

```bash
cargo test
```

---

## Running the Experimental Evaluation Suite

Cassandra features an integrated benchmarking suite to measure correctness, performance, thread scalability, and memory usage.

### 1. Prerequisites for Plotting

Ensure Python 3 is installed along with the required libraries:

```bash
pip install matplotlib numpy
```

### 2. Run the Evaluation Runner

The evaluation binary runs correctness validations against a documented ground truth, benchmarks parsing throughput/latency across varying file sizes, measures thread speed-up scaling, and tracks peak memory usage:

```bash
cargo run --release --bin evaluation_runner
```

> [!NOTE]
> Running the evaluation runner in `--release` mode is highly recommended for accurate performance and scalability measurements.

_Outputs:_ Saves the raw metric data as a structured JSON file at `output_test/evaluation_results.json`.

### 3. Generate Plots and Reports

To render the visual charts (latency, throughput, and small/large workload scalability speed-up curves) and compile the critical discussion report:

```bash
python3 plot_results.py
```

_Outputs:_

- `output_test/perf_latency.png` (Latency scaling curve)
- `output_test/perf_throughput.png` (Throughput scaling curve)
- `output_test/scalability_small.png` (Speedup on 140 files)
- `output_test/scalability_large.png` (Speedup on 7000 files)
- `output_test/scalability.png` (Combined speedup comparison)

---

## Final Report

For a complete and comprehensive analysis of the project requirements, architecture, Rust systems programming features, evaluation results, and limitations assessment, refer to the [docs/REPORT.md](https://github.com/mttio/Cassandra/blob/main/docs/REPORT.pdf) final report.
