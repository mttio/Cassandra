use anyhow::{Context, Result};
use cassandra::InputSource;
use cassandra::policy::Policy;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

fn get_peak_rss() -> Result<u64> {
    unsafe {
        let mut usage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) == 0 {
            #[cfg(target_os = "macos")]
            {
                // macOS returns maxrss in bytes
                Ok(usage.ru_maxrss as u64)
            }
            #[cfg(not(target_os = "macos"))]
            {
                // Linux returns maxrss in kilobytes
                Ok((usage.ru_maxrss as u64) * 1024)
            }
        } else {
            Err(anyhow::anyhow!("getrusage failed"))
        }
    }
}

fn get_rule_type(err: &cassandra::errors::RuleError) -> String {
    match serde_json::to_value(err).unwrap() {
        serde_json::Value::Object(map) => map.get("type").unwrap().as_str().unwrap().to_owned(),
        _ => unreachable!(),
    }
}

fn run_sanitization(
    runtime: &tokio::runtime::Runtime,
    sources: Vec<InputSource>,
    policy: Arc<Policy>,
    output_dir: PathBuf,
) -> Result<(Vec<cassandra::log::SanitizationReport>, f64, f64)> {
    let (tx, rx) = std::sync::mpsc::channel();
    if output_dir.exists() {
        std::fs::remove_dir_all(&output_dir)?;
    }
    std::fs::create_dir_all(&output_dir)?;

    let output_dir_arc = Arc::new(output_dir);

    cassandra::library(
        runtime,
        sources.clone(),
        policy.clone(),
        output_dir_arc.clone(),
        tx,
    )
    .context("Failed to run cassandra::library")?;

    // Consume channel synchronously to wait for processing to finish
    let (_has_errors, parse_time, write_time) = cassandra::log::logging_thread(
        &output_dir_arc,
        cassandra::log::LogLevel::Error, // Console logging level
        cassandra::log::LogLevel::Trace, // File logging level
        &sources,
        *policy.resources.max_requests.value.as_ref(),
        rx,
    );

    // Read the generated JSON reports
    let mut reports = Vec::new();
    let report_path = output_dir_arc.join("report.json");
    if report_path.exists() {
        let content = std::fs::read_to_string(&report_path)?;
        reports = serde_json::from_str(&content)
            .context(format!("Failed to parse report {report_path:?}"))?;
    }

    Ok((reports, parse_time, write_time))
}

#[derive(serde::Serialize)]
struct CorrectnessResult {
    file: String,
    expected_verdict: String,
    actual_verdict: String,
    expected_rules: Vec<String>,
    actual_rules: Vec<String>,
    match_status: String,
}

#[derive(serde::Serialize)]
struct PerformanceMetric {
    size_name: String,
    size_bytes: usize,
    fetch_subresources: bool,
    avg_latency_ms: f64,
    throughput_ips: f64,
}

#[derive(serde::Serialize)]
struct ScalabilityMetric {
    threads: usize,
    small_duration_secs: f64,
    small_speedup: f64,
    small_parse_secs: f64,
    small_write_secs: f64,
    large_duration_secs: f64,
    large_speedup: f64,
    large_parse_secs: f64,
    large_write_secs: f64,
}

#[derive(serde::Serialize)]
struct EvaluationResults {
    correctness: Vec<CorrectnessResult>,
    correctness_summary: HashMap<String, f64>,
    performance: Vec<PerformanceMetric>,
    scalability: Vec<ScalabilityMetric>,
    peak_memory_mb: f64,
}

fn main() -> Result<()> {
    println!("=== Starting Cassandra Experimental Evaluation ===");

    let corpus_dir = Path::new("input_test_files");
    let ground_truth_path = corpus_dir.join("ground_truth.json");
    let output_test_dir = Path::new("output_test");

    // Load ground truth
    let ground_truth_content =
        std::fs::read_to_string(&ground_truth_path).context("Failed to read ground_truth.json")?;
    let ground_truth: HashMap<String, Vec<String>> =
        serde_json::from_str(&ground_truth_content).context("Failed to parse ground_truth.json")?;

    // Create runtime for single-threaded correctness and performance runs
    let single_thread_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;

    // 1. Correctness Phase
    println!("\n--- 1. Evaluating Correctness ---");
    let mut correctness_results = Vec::new();
    let mut tp = 0;
    let mut tn = 0;
    let mut fp = 0;
    let mut fn_count = 0;

    for (file_key, expected_rules) in &ground_truth {
        let file_path = corpus_dir.join(file_key);
        if !file_path.exists() {
            println!("Warning: test file {:?} not found", file_path);
            continue;
        }

        let sources = vec![InputSource::File(file_path.clone())];
        let policy = Arc::new(Policy::default());
        let (reports, _, _) = run_sanitization(
            &single_thread_rt,
            sources,
            policy,
            output_test_dir.join("correctness").join(file_key),
        )?;

        // Analyze report
        let mut actual_rules = Vec::new();
        if let Some(report) = reports.first() {
            for action in &report.actions {
                actual_rules.push(get_rule_type(&action.error).to_owned());
            }
        }
        actual_rules.sort();
        actual_rules.dedup();

        let is_expected_malicious = !expected_rules.is_empty();
        let is_actual_malicious = !actual_rules.is_empty();

        let (expected_verdict, actual_verdict, match_status) = if is_expected_malicious {
            let mut is_matched = true;
            for req_rule in expected_rules {
                if !actual_rules.contains(req_rule) {
                    is_matched = false;
                    break;
                }
            }

            if is_actual_malicious && is_matched {
                tp += 1;
                (
                    "malicious".to_owned(),
                    "malicious".to_owned(),
                    "MATCH (TP)".to_owned(),
                )
            } else {
                fn_count += 1;
                let actual_v = if is_actual_malicious {
                    "malicious (partial/incorrect rules)"
                } else {
                    "benign"
                };
                (
                    "malicious".to_owned(),
                    actual_v.to_owned(),
                    "MISMATCH (FN)".to_owned(),
                )
            }
        } else {
            if is_actual_malicious {
                fp += 1;
                (
                    "benign".to_owned(),
                    "malicious".to_owned(),
                    "MISMATCH (FP)".to_owned(),
                )
            } else {
                tn += 1;
                (
                    "benign".to_owned(),
                    "benign".to_owned(),
                    "MATCH (TN)".to_owned(),
                )
            }
        };

        println!(
            "File: {:<50} | Expected: {:<9} | Actual: {:<9} | Expected Rules: {:?} | Actual Rules: {:?}",
            file_key, expected_verdict, actual_verdict, expected_rules, actual_rules
        );

        correctness_results.push(CorrectnessResult {
            file: file_key.clone(),
            expected_verdict,
            actual_verdict,
            expected_rules: expected_rules.clone(),
            actual_rules,
            match_status,
        });
    }

    let total_malicious = tp + fn_count;
    let total_benign = tn + fp;
    let detection_rate = if total_malicious > 0 {
        tp as f64 / total_malicious as f64
    } else {
        0.0
    };
    let false_positive_rate = if total_benign > 0 {
        fp as f64 / total_benign as f64
    } else {
        0.0
    };

    println!("Correctness Summary:");
    println!("  TP: {}, TN: {}, FP: {}, FN: {}", tp, tn, fp, fn_count);
    println!(
        "  Detection Rate (Sensitivity): {:.2}%",
        detection_rate * 100.0
    );
    println!(
        "  False-Positive Rate:          {:.2}%",
        false_positive_rate * 100.0
    );

    let mut correctness_summary = HashMap::new();
    correctness_summary.insert("tp".to_owned(), tp as f64);
    correctness_summary.insert("tn".to_owned(), tn as f64);
    correctness_summary.insert("fp".to_owned(), fp as f64);
    correctness_summary.insert("fn".to_owned(), fn_count as f64);
    correctness_summary.insert("detection_rate".to_owned(), detection_rate);
    correctness_summary.insert("false_positive_rate".to_owned(), false_positive_rate);

    // 2. Performance Phase
    println!("\n--- 2. Evaluating Performance (Throughput & Latency) ---");
    let performance_files = vec![
        ("10KB", corpus_dir.join("benign/perf_10kb.html"), 10240, 100),
        (
            "100KB",
            corpus_dir.join("benign/perf_100kb.html"),
            102400,
            25,
        ),
        ("1MB", corpus_dir.join("benign/perf_1mb.html"), 1048576, 5),
        ("5MB", corpus_dir.join("benign/perf_5mb.html"), 5242880, 2),
    ];

    let mut performance_metrics = Vec::new();

    for (name, path, bytes, iterations) in &performance_files {
        if !path.exists() {
            println!("Warning: performance file {:?} not found", path);
            continue;
        }

        // Test with and without sub-resources
        for fetch_sub in &[false, true] {
            let mut policy = Policy::default();
            policy.resources.fetch_sub_resources = *fetch_sub;
            policy.resources.max_requests =
                serde_json::from_str("{\"value\": 100, \"level\": \"error\"}").unwrap();
            policy.resources.max_bytes =
                serde_json::from_str("{\"value\": 52428800, \"level\": \"error\"}").unwrap();
            let policy_arc = Arc::new(policy);

            println!(
                "Running performance test for {} (fetch_subresources={})...",
                name, fetch_sub
            );

            let start = Instant::now();
            for _ in 0..*iterations {
                let sources = vec![InputSource::File(path.clone())];
                let (_reports, _, _) = run_sanitization(
                    &single_thread_rt,
                    sources,
                    policy_arc.clone(),
                    output_test_dir.join("performance").join(name),
                )?;
            }
            let elapsed = start.elapsed();
            let avg_latency = elapsed.as_secs_f64() / (*iterations as f64) * 1000.0; // ms
            let throughput = (*iterations as f64) / elapsed.as_secs_f64(); // inputs/sec

            println!(
                "  Avg Latency: {:.2} ms | Throughput: {:.2} inputs/sec",
                avg_latency, throughput
            );

            performance_metrics.push(PerformanceMetric {
                size_name: name.to_string(),
                size_bytes: *bytes,
                fetch_subresources: *fetch_sub,
                avg_latency_ms: avg_latency,
                throughput_ips: throughput,
            });
        }
    }

    // 3. Scalability Phase
    println!("\n--- 3. Evaluating Scalability (Thread Speed-up) ---");
    let mut base_workload = Vec::new();
    for file_key in ground_truth.keys() {
        let file_path = corpus_dir.join(file_key);
        if file_path.exists() {
            base_workload.push(InputSource::File(file_path));
        }
    }

    // Create small workload (10x replication = 140 files)
    let mut small_workload = Vec::new();
    for _ in 0..10 {
        small_workload.extend(base_workload.clone());
    }

    // Create large workload (500x replication = 7000 files)
    let mut large_workload = Vec::new();
    for _ in 0..500 {
        large_workload.extend(base_workload.clone());
    }

    println!("Total inputs in small workload: {}", small_workload.len());
    println!("Total inputs in large workload: {}", large_workload.len());

    let thread_counts = vec![1, 2, 4, 8, 16];
    let mut scalability_metrics = Vec::new();
    let mut small_base_duration = 0.0;
    let mut large_base_duration = 0.0;

    for threads in thread_counts {
        println!(
            "Running scalability test with {} worker threads...",
            threads
        );

        let custom_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .enable_all()
            .build()?;

        let policy = Arc::new(Policy::default());

        // Run small workload
        let start_small = Instant::now();
        let (_reports_small, small_parse, small_write) = run_sanitization(
            &custom_rt,
            small_workload.clone(),
            policy.clone(),
            output_test_dir
                .join("scalability_small")
                .join(threads.to_string()),
        )?;
        let small_elapsed = start_small.elapsed().as_secs_f64();

        if threads == 1 {
            small_base_duration = small_elapsed;
        }
        let small_speedup = if small_elapsed > 0.0 {
            small_base_duration / small_elapsed
        } else {
            1.0
        };

        // Run large workload
        let start_large = Instant::now();
        let (_reports_large, large_parse, large_write) = run_sanitization(
            &custom_rt,
            large_workload.clone(),
            policy,
            output_test_dir
                .join("scalability_large")
                .join(threads.to_string()),
        )?;
        let large_elapsed = start_large.elapsed().as_secs_f64();

        if threads == 1 {
            large_base_duration = large_elapsed;
        }
        let large_speedup = if large_elapsed > 0.0 {
            large_base_duration / large_elapsed
        } else {
            1.0
        };

        println!(
            "  [Small] Duration: {:.3} s (Parse: {:.3}s, Write: {:.3}s) | Speedup: {:.2}x",
            small_elapsed, small_parse, small_write, small_speedup
        );
        println!(
            "  [Large] Duration: {:.3} s (Parse: {:.3}s, Write: {:.3}s) | Speedup: {:.2}x",
            large_elapsed, large_parse, large_write, large_speedup
        );

        scalability_metrics.push(ScalabilityMetric {
            threads,
            small_duration_secs: small_elapsed,
            small_speedup,
            small_parse_secs: small_parse,
            small_write_secs: small_write,
            large_duration_secs: large_elapsed,
            large_speedup,
            large_parse_secs: large_parse,
            large_write_secs: large_write,
        });
    }

    // 4. Memory/Resource Phase
    let peak_rss_bytes = get_peak_rss().unwrap_or(0);
    let peak_rss_mb = (peak_rss_bytes as f64) / (1024.0 * 1024.0);
    println!("\n--- 4. Resource Usage ---");
    println!("Peak Resident Set Size (RSS): {:.2} MB", peak_rss_mb);

    // Save all evaluation results to JSON
    let final_results = EvaluationResults {
        correctness: correctness_results,
        correctness_summary,
        performance: performance_metrics,
        scalability: scalability_metrics,
        peak_memory_mb: peak_rss_mb,
    };

    let results_path = output_test_dir.join("evaluation_results.json");
    if let Some(parent) = results_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let writer = std::fs::File::create(&results_path)?;
    serde_json::to_writer_pretty(writer, &final_results)?;
    println!(
        "\n[+] Evaluation completed! Results saved to {:?}",
        results_path
    );

    Ok(())
}
