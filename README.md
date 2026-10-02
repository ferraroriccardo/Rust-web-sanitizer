# Rust Web Sanitizer

A command-line HTML sanitizer written in Rust. It takes local files, directories or URLs as input, applies a set of rules configured through a **TOML** file, and produces HTML cleaned of potentially dangerous content (scripts, iframes, `on*` handlers, `javascript:`/`data:` URIs, `<meta refresh>` redirects, links to suspicious hosts, etc.), along with a report of what was removed or replaced.

HTML parsing and rewriting are based on [`lol_html`](https://crates.io/crates/lol_html), a streaming rewriter: the HTML is never loaded into a full DOM, and the parser's memory usage is capped via configuration.

*Italian version: [README.it.md](README.it.md)*

---

## Features

- **Multiple input types**: single files, directories (recursive scan of `.html` / `.htm`) and `http://` / `https://` URLs, which can be mixed in the same invocation.
- **Declarative TOML rules** with `deny_unknown_fields`: a typo in a key or section name makes config loading fail instead of being silently ignored.
- **Two strategies per rule**: remove the attribute, or replace its value with `#` (for `iframe`, "replace" mode instead means *rejecting the whole document*, see below).
- **Bypass protections**: normalization of `javascript:` / `data:` (case-insensitive, whitespace and tabs ignored), case-insensitive `on*` handling, `srcdoc` on iframes, `http-equiv="refresh"` with odd casing/spacing.
- **Suspicious host detection** on links, forms, images and stylesheets: non-ASCII characters (IDN homographs), Punycode (`xn--`) and `%` in the host.
- **Resource limits**: parser memory, maximum file/download size, maximum number of files, maximum recursion depth, HTTP timeout.
- **Path traversal / cycle protection** while scanning directories (canonicalization, jail inside the root directory, visited-directories set).
- **Parallel processing** with a worker thread pool.
- **Reports** in text (quiet / default / verbose) and **JSON**.
- **Exit codes** suitable for CI pipelines (see [Exit codes](#exit-codes)).

---

## Project structure

```
.
├── Cargo.toml
├── config.toml              # default configuration (read when --config is not given)
└── src
    ├── main.rs              # entry point: reads arguments and runs run_sanitizer
    ├── lib.rs               # public re-exports + CustomError enum
    ├── cli.rs               # argument definitions (clap)
    ├── engine.rs            # orchestration: fetch, worker pool, reports, exit codes
    ├── input_analyzer.rs    # input analysis (file / directory / URL) with limits and jail
    └── sanitizer/
        ├── mod.rs           # get_rules, create_sanitizer_rules, sanitize_html (+ integration tests)
        ├── handlers.rs      # lol_html handlers for each rule (apply_rule, meta, script, ...)
        ├── rules.rs         # Rules / Fields / ActionMode structs (TOML deserialization)
        ├── security.rs      # suspicious_host(): suspicious host check
        └── status.rs        # ProcessedResult, ContentStatus, RemovedElement (JSON-serializable)
```

### Execution flow

```
CLI args ─► config.toml ─► Rules
                │
   analyze_input (file / dir / URL) ─► Vec<InputSource>
                │
        worker thread pool
   ┌────────────┴─────────────┐
   │  fetch (reqwest) / read  │   honors max_parser_memory and fetch_timeout_secs
   │  sanitize_html (lol_html)│
   └────────────┬─────────────┘
                │
   Result<ProcessedResult, CustomError>
                │
   sanitized HTML output + report (text / JSON) + exit code
```

---

## Requirements and build

- Rust (edition 2021 or later) and `cargo`.

```bash
cargo build --release
```

The binary is in `target/release/` (its name depends on the package `name`; the library is imported as `rust_web_sanitizer`).

### Main dependencies

| Crate           | Purpose                                              |
|-----------------|------------------------------------------------------|
| `lol_html`      | streaming HTML rewriting                             |
| `clap`          | CLI argument parsing (`derive` feature)              |
| `serde`, `toml` | configuration deserialization                        |
| `serde_json`    | JSON reports                                         |
| `reqwest`       | URL downloads (`blocking` feature)                   |
| `thiserror`     | `CustomError` definition                             |
| `tempfile`      | tests only (`dev-dependencies`)                      |

---

## Usage

```
rust_web_sanitizer [OPTIONS] <SRC>...
```

| Option                 | Description                                                            | Default       |
|------------------------|------------------------------------------------------------------------|---------------|
| `<SRC>...`             | one or more local files, directories or URLs to sanitize (required)    | —             |
| `-c, --config <PATH>`  | path to the TOML configuration file                                    | `config.toml` |
| `-o, --out-dir <DIR>`  | directory where sanitized HTML files are saved (created if missing)    | —             |
| `--json`               | enable the JSON report output                                          | off           |
| `-v, --verbose`        | detailed output (includes the reason for each removal)                 | —             |
| `-q, --quiet`          | no text report (conflicts with `--verbose`)                            | —             |
| `-h, --help` / `-V, --version` | help and version                                               | —             |

### Examples

```bash
# Sanitize a single file and print the text report
cargo run --release -- page.html

# Sanitize a whole directory, save the results and a JSON report next to each file
cargo run --release -- ./site --out-dir ./site_clean --json

# Sanitize a URL with a specific configuration, verbose output
cargo run --release -- https://example.com/page.html -c rules/strict.toml -v

# Quiet mode, handy in CI (only the exit code matters)
cargo run --release -- ./site -q
```

### Where the output goes

| Situation                    | Sanitized HTML                    | JSON report                                       |
|------------------------------|-----------------------------------|---------------------------------------------------|
| `--out-dir` **not given**    | not written                       | with `--json`, printed to stdout                  |
| `--out-dir` **given**        | `<out_dir>/<file_name>`           | with `--json`, `<out_dir>/<file_name>.report.json` |

For URLs the output file name is `url_resource_<index>`. The text report (`Final result length`, `Elements removed`, and with `-v` also `Reason`) is always printed to stdout, unless `--quiet` is set.

> **Warning:** files from a directory are written to `out_dir` using only the file name. If files with the same name exist in different subfolders, the last one overwrites the previous ones.

---

## Configuration (TOML)

Every key is optional: an empty file is valid and applies no rules. Unknown keys or sections cause a parse error.

### Global limits

| Key                    | Type    | Default | Notes                                                            |
|------------------------|---------|---------|------------------------------------------------------------------|
| `max_parser_memory`    | `usize` | 10 MiB  | maximum parser memory **and** maximum file / download size. If exceeded, the content is *rejected* (`memory limit exceeded`) |
| `max_files_allowed`    | `usize` | 1000    | maximum number of HTML files found in a scan. Absolute cap: 5000 |
| `max_recursion_depth`  | `usize` | 32      | maximum depth when scanning directories. Absolute cap: 64        |
| `fetch_timeout_secs`   | `u64`   | 10      | HTTP request timeout                                             |

Configured values for file count and depth are still clamped to the absolute caps.

### Per-tag/attribute rules

Each rule is a section with these fields (`Fields`):

| Field          | Type          | Default | Meaning                                                                    |
|----------------|---------------|---------|----------------------------------------------------------------------------|
| `filters`      | `Vec<String>` | —       | allow-list or block-list, depending on the rule (see table below)          |
| `need_replace` | `bool`        | `false` | `false` → remove the attribute; `true` → replace the value with `#` (for `iframe`: reject the document) |
| `active`       | `bool`        | `false` | present in the configuration struct but **not currently read by the handlers**: a rule is active if its section is present |

| Section            | Elements / attributes checked              | Filter type                    | Behavior                                                                   |
|--------------------|--------------------------------------------|--------------------------------|----------------------------------------------------------------------------|
| `[iframe]`         | `<iframe src>`, `srcdoc`                   | **allow-list** (exact match)   | values not in the list → removed; with `need_replace = true` the document is **rejected** |
| `[object]`         | `<object data>`                            | allow-list                     | values not in the list → removed / replaced with `#`                       |
| `[embed]`          | `<embed src>`                              | allow-list                     | same                                                                       |
| `[script]`         | `<script src>` and inline scripts          | allow-list                     | `src` not in the list → removed / `#`; inline script → tag removed (`false`) or content emptied (`true`) |
| `[links]`          | `<a href>`                                 | **block-list** (substring) + suspicious hosts | blocked URLs → removed / `#`                                 |
| `[forms]`          | `<form action>`                            | block-list + suspicious hosts  | same                                                                       |
| `[images]`         | `<img src>`                                | block-list + suspicious hosts  | same                                                                       |
| `[styles]`         | `<link href>`                              | block-list + suspicious hosts  | same                                                                       |
| `[javascript_uri]` | any attribute on any tag                   | —                              | neutralizes values containing `javascript:` (whitespace/tabs ignored, case-insensitive) |
| `[data_uri]`       | any attribute on any tag                   | allow-list                     | neutralizes `data:` values not in the list                                 |
| `[on_prefix]`      | any attribute starting with `on`           | —                              | removes / replaces inline event handlers (`onclick`, `onerror`, ...)       |
| `[meta]`           | `<meta http-equiv="refresh">`              | —                              | removes the tag (`false`) or turns it into a `<span>` (`true`)             |

**Notes on filters**

- *Allow-list*: if the section is present **without** `filters`, every value is considered disallowed (for `[script]`, however, without `filters` external scripts are left untouched, while inline ones are not).
- *Block-list*: a value is blocked if it contains one of the strings in `filters` **or** if the host is suspicious (non-ASCII characters, `xn--`, `%`). Relative links are never considered suspicious.
- Attribute values for `[iframe]`, `[object]`, `[embed]`, `[script]` and `[data_uri]` are compared against the list **exactly**, not by prefix.

### Example `config.toml`

```toml
# --- Limits ---
max_parser_memory   = 2097152   # 2 MiB
max_files_allowed   = 200
max_recursion_depth = 10
fetch_timeout_secs  = 15

# --- Inline events and dangerous URIs: always removed ---
[on_prefix]
need_replace = false

[javascript_uri]
need_replace = false

[data_uri]
need_replace = false
filters = ["data:image/png;base64,AAAA"]   # exact match on the attribute value

# --- Automatic redirects ---
[meta]
need_replace = false

# --- Scripts: only allow-listed sources, inline ones are removed ---
[script]
need_replace = false
filters = ["https://trusted.example.com/app.js"]

# --- Iframes: allow-list; with need_replace = true a disallowed iframe rejects the whole document ---
[iframe]
need_replace = false
filters = ["https://www.youtube.com/embed/abc123"]

# --- Block-lists for links, forms, images, stylesheets ---
[links]
need_replace = true
filters = ["malicious.example", "tracker.example"]

[forms]
need_replace = true
filters = ["malicious.example"]

[images]
need_replace = true
filters = ["tracker.example"]

[styles]
need_replace = true
filters = ["malicious.example"]
```

---

## Reports

### Text

```
Final result length: 1234 bytes
Elements removed:
  - Removed attribute onclick from tag a, which has value doSomething()
    Reason: Stripped inline event handler to prevent event-drive script execution
```

The `Reason` line only appears in `--verbose` mode.

### JSON (`--json`)

Serialization of `ProcessedResult`: it contains the final HTML (`final_html`) and the content status (`parts_removed`), which can be `Accepted([...])` with the list of removed elements and the reason, or `Empty`.

---

## Exit codes

| Code | Meaning                                                                                          |
|------|--------------------------------------------------------------------------------------------------|
| `0`  | all inputs were processed successfully                                                           |
| `1`  | at least one content item was **rejected** by policy (iframe with `need_replace = true`, parser memory limit exceeded), or a configuration / input error occurred |
| `2`  | at least one error occurred during sanitization (network, I/O, file too large, parsing, ...)     |

If both errors and rejections occur, code `2` wins. A rejected content item produces **no** output file.

---

## Using it as a library

The crate also exposes a public API:

```rust
use rust_web_sanitizer::{get_rules, sanitize_html};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rules = Arc::new(get_rules(r#"
        [on_prefix]
        need_replace = false
    "#)?);

    let html = br#"<p onclick="evil()">Hello</p>"#;
    let result = sanitize_html(rules, html)?;

    println!("{}", result.get_final_html()); // <p>Hello</p>
    Ok(())
}
```

Exported items: `Rules`, `get_rules`, `create_sanitizer_rules`, `sanitize_html`, `ProcessedResult`, `ContentStatus`, `RemovedElement`, `analyze_input`, `read_args`, `run_sanitizer`, `build_json_report`, `CliConfig`, `Verbosity`, `CustomError`.

`Rules` and `ProcessedResult` are `Send + Sync`, so they can be shared across threads via `Arc`.

---

## File scanning security

`input_analyzer` applies several defenses while walking directories:

- canonicalization of every directory and a check that it stays inside the root (`starts_with`) against path traversal;
- a `HashSet` of already visited paths to avoid cycles caused by symlinks;
- symlinks to files are resolved before being included;
- limits on depth and file count, with absolute caps that configuration cannot exceed;
- only `.html` / `.htm` extensions are considered.

---

## Tests

```bash
cargo test
```

The suite covers:

- configuration deserialization and validation (`rules.rs`);
- every sanitization rule, bypass cases (uppercase, spaces, tabs, `srcdoc`, IDN/Punycode), unchanged benign pages, empty, non-UTF-8 and hostile input (`sanitizer/mod.rs`);
- memory limits, thread safety and concurrent use of the rules;
- `suspicious_host` (`security.rs`);
- `ContentStatus` / `ProcessedResult` and JSON serialization (`status.rs`);
- input detection, extension filtering and the file count limit (`input_analyzer.rs`).

---

## Known limitations

- The parser works on individual attributes: `srcset`, inline `style`, `<style>` content and CSS `url(...)` are not analyzed.
- `[meta]` only acts on `http-equiv="refresh"`.
- `[styles]` checks any `<link href>`, not just those with `rel="stylesheet"`.
- The `active` field of the rules is defined but not yet used.
- Protocol-relative links (`//host/path`) are analyzed by `suspicious_host`, while relative URLs are considered safe.
- Output is written using only the file name: files with the same name in different subfolders overwrite each other.
- If the input is not valid UTF-8, the output is converted lossily.

---

## License

To be defined.
