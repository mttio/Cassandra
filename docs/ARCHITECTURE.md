# Cassandra Web Sanitizer: System Architecture

Cassandra Web Sanitizer is a defensive, high-performance system utility designed in Rust to inspect, neutralize, and rewrite web pages and embedded resources before they reach a client system. This document describes the modular architecture of the codebase, its components, implementation details, and design decisions.

---

## 1. Crate Workspace Structure

The project is structured as a multi-crate Cargo workspace to cleanly decouple the core sanitization engine from the command-line interface (CLI).

```
cassandra/ (Workspace Root)
├── Cargo.toml
├── policies/
│   └── default.toml
├── input_test_files/
├── output/
├── sanitizer_engine/ (Library Crate: cassandra)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── crawl_session.rs
│       ├── http_client.rs
│       ├── html.rs
│       ├── log.rs
│       ├── errors.rs
│       ├── policy.rs
│       ├── rules.rs
│       ├── url.rs
│       └── resources/
│           ├── mod.rs
│           ├── css.rs
│           ├── javascript.rs
│           └── mime.rs
└── cli_application/ (Binary Crate: cli_application)
    ├── Cargo.toml
    └── src/
        └── main.rs
```

- **`cassandra` (Library Crate)**: Contains the core sanitization, URL resolution, HTTP parsing, MIME sniffing, and recursive crawler logic. Exposes a programmatic API.
- **`cli_application` (Binary Crate)**: Wraps the library crate, parses command-line arguments using `clap` (supporting multiple inputs, custom TOML `--policy`, `--output-dir`, and multi-threaded `--workers`), maps input paths recursively, controls output verbosity via incremental `-v` flags, and exits with a non-zero exit code if any policy block/error occurs during sanitization.

---

## 2. Core Modules & Component Architecture

### 2.1 Orchestrator (`lib.rs`)
The `library` function acts as the entrypoint for the sanitization pipeline. It:
1. Instantiates a shared, thread-safe cache (`url_map` protected by an `Arc<Mutex<HashMap<Url, usize>>>`) to trace resolved URLs and prevent duplicate resource requests.
2. Initializes the safe HTTP client (`SanitizerHttpClient`).
3. Iterates over the target inputs (`sources`), constructs worker tasks (`CrawlSession`), and spawns them concurrently onto the multi-threaded Tokio runtime.

### 2.2 Worker Task & Crawler (`crawl_session.rs`)
`CrawlSession` processes a single root input source (file or URL) and handles sub-resource scheduling:
- **Files**: Inspects file extensions and dispatches processing to specialized parsers (HTML, PDF, CSS, JS).
- **URLs**: Fetches and parses remote HTML, enqueuing discovered sub-resources (`<img>`, `<script>`, `<audio>`, etc.).
- **Resource Constraints**: Strictly enforces resource consumption limits (`max_depth`, `max_bytes`, and `max_requests`) to prevent DoS attacks (e.g. infinite loops or large payload downloads).

### 2.3 SSRF-Safe HTTP Client (`http_client.rs`)
The client wrapper prevents Server-Side Request Forgery (SSRF) and DNS rebind attacks when crawling sub-resources:
- **IP Address Sanitization**: Intercepts resolved IPs and denies access to loopback (`127.0.0.0/8`, `::1`), private subnets (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), test networks, CGNAT ranges, multicast, and broadcast spaces.
- **Protocol Restrictions**: Restricts all outbound sub-resource fetches exclusively to `HTTPS`.
- **MIME Sniffing**: Prevents MIME-confusion exploits by checking response headers and verifying them using content-signature sniffing.

### 2.4 Streaming HTML Tokenizer & Rewriter (`html.rs`)
HTML parsing is built on top of `lol_html`, a fast, streaming CSS-selector-based rewriter. This design allows zero-copy manipulation without loading a heavy DOM structure into memory:
- **Inline Script and Event Handling**: Strips or normalizes event handlers (e.g. `onclick`, `onload`) and filters script blocks against hashing/origin allow-lists.
- **Origins and Redirects**: Validates iframe and object targets against the `allow_origins` policy, removing unauthorized content. Detects and completely strips `<meta http-equiv="refresh">` redirect tags.
- **Broadened Tag Extraction**: Automatically extracts and sanitizes resource references inside `form`, `area`, `audio`, `video`, `embed`, `track`, and `input` tags.
- **Flexible Action Policies**: If a URL rule returns an `Error`/Deny level, the rewriter catches the failure, blanks/strips the attribute, logs the error, and resumes parsing the document.

### 2.5 Resource-Specific Sanitizers (`resources/`)
- **MIME Sniffer (`mime.rs`)**: Inspects magic numbers at the beginning of fetched files to assert their real type (HTML, CSS, JS, JPEG, PNG, PDF) matching the server-declared type.
- **CSS Sanitizer (`css.rs`)**: Strips unsafe `url()` imports and expressions pointing to external or unapproved origins.
- **JS Sanitizer (`javascript.rs`)**: Inspects script contents for dangerous keywords (e.g. `eval`) and active script injection.
- **PDF Active Content Scanner (`mod.rs`)**: Scans PDF structure definitions for active elements (like internal `JavaScript`, `/JS`, or `/OpenAction` directives) that could trigger actions inside PDF viewers.
- **Image Metadata Stripper (`mod.rs`)**: Strips EXIF headers and chunks from JPEG and PNG files to block tracking vectors.

### 2.6 Declarative Policies (`policy.rs`, `rules.rs`, `url.rs`)
Declarative policies map rule enforcement behavior into:
- **`Ignore`**: Bypasses the rule check.
- **`Warn`**: Logs a warning but keeps the original value.
- **`Replace`**: Logs a warning and replaces the target with a safe placeholder.
- **`Error` (Deny/Remove)**: Blanks or strips the attribute and logs an audit error.

Implementations leverage the `Verify` trait, separating verification definitions (e.g., checking if a URL domain is IDN or on a blacklist) from policy actions.

### 2.7 Structured Reporting Loop (`log.rs`, `errors.rs`)
- **Channel-based Logging**: Individual workers log events asynchronously through an `mpsc::Sender` channel to a single sequential thread (`logging_thread`).
- **Audit JSON Report**: The logging thread records each mapped `RuleError` into a structured `SanitizationReport`. At the end of execution, it consolidates all reports and logs, writing a single pretty-printed audit JSON report (`report.json`) and a unified log file (`cassandra.log`) in the output directory. The report maps:
  - The input source path or URL.
  - A list of occurred sanitization actions containing the matched rule, the specific replacement, context, and byte offsets.

---

## 3. Rust System Programming Design Decisions

### 3.1 Concurrency Model
To process files and network feeds at scale, the engine utilizes **Tokio's multi-threaded runtime scheduler**. Workers operate concurrently, sharing data via atomic wrappers:
- **`Arc<Mutex<HashMap<Url, usize>>>`**: Used for the global URL request cache. The lock is held briefly to fetch/store items, avoiding task starvation.
- **`Arc<AtomicUsize>`**: Used to track total HTTP request budgets across threads without lock contention.
- **`mpsc::channel`**: Transports log entries from worker threads without locks, ensuring writing I/O bottleneck does not block worker threads.

### 3.2 Memory Safety and Zero-Copy Parsing
The engine processes untrusted, attacker-controlled byte arrays. To prevent memory bugs and maximize performance, the parser relies on:
- **Streaming Parsers (`lol_html`)**: Tokenizes the HTML document inside a moving window of data chunks, avoiding materializing a complete DOM tree.
- **Lifetimes & Borrowing**: Borrows string slices (`&str`) from source buffers rather than allocating new heap segments wherever practical.
- **Safe Rust**: The codebase is written entirely in safe Rust, relying on the compiler to guarantee memory safety.
