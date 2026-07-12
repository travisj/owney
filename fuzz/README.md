# Fuzzing Infrastructure

Fuzzing suite for Owney, covering critical parsing paths that handle untrusted network input.

## Fuzz Targets

### `smtp_parse`
Fuzzes the SMTP protocol parser (inbound mail reception).
- **Input**: Arbitrary bytes sent to SMTP port
- **Goal**: Ensure parser never panics on malformed commands
- **Library**: `smtp-proto`

### `mime_parse`
Fuzzes the MIME message parser.
- **Input**: Arbitrary bytes as email message bodies
- **Goal**: Ensure MIME parser handles all inputs gracefully
- **Library**: `mail-parser`

### `pgp_parse`
Fuzzes the PGP certificate/key parser.
- **Input**: Arbitrary bytes as PGP keys/certificates
- **Goal**: Ensure Sequoia parser never panics on invalid keys
- **Library**: `sequoia-openpgp`

### `jmap_parse`
Fuzzes the JSON parser (JMAP protocol layer).
- **Input**: Arbitrary bytes as JSON
- **Goal**: Ensure JSON parsing is robust to malformed input
- **Library**: `serde_json`

## Running Locally

Install `cargo-fuzz`:
```bash
cargo install cargo-fuzz
```

Build all targets:
```bash
cargo fuzz build
```

Run a single target for 60 seconds:
```bash
cargo fuzz run smtp_parse -- -timeout=10 -max_len=4096
```

Run with artifacts (crashes/slow inputs are saved):
```bash
cargo fuzz run smtp_parse
# Results in fuzz/artifacts/smtp_parse/
```

## Continuous Fuzzing (CI)

The `.github/workflows/fuzz.yml` workflow runs on every push and nightly (2 AM UTC).
Each target fuzzes for 60 seconds with a 10-second timeout per input.

Crashes are treated as CI failures and block merges.

## Corpus Seeds

Initial corpus seeds for faster discovery are stored in:
- `fuzz/corpus/smtp_parse/` (example SMTP commands)
- `fuzz/corpus/mime_parse/` (example email messages)
- `fuzz/corpus/pgp_parse/` (example PGP keys)
- `fuzz/corpus/jmap_parse/` (example JMAP JSON)

To add a new seed:
```bash
echo "HELO example.com" > fuzz/corpus/smtp_parse/helo_cmd
```

## Interpreting Results

### No Crashes After 60s
✅ Target is robust. The fuzzer explores the input space but finds no panics or timeouts.

### Crash Detected
❌ A panic or unsafe behavior was triggered. Crash is saved to `fuzz/artifacts/` with:
- Input that triggered it (`*.raw`)
- Backtrace of the panic
- Regression test to prevent re-occurrence

### Slow Input Detected
⚠️ An input takes >10 seconds to process (DoS candidate). Saved to `fuzz/artifacts/` for analysis.

## Next Steps

After M7:
- Integrate AFL++ for parallel fuzzing (faster crash discovery)
- Add corpus from real-world mailservers (Postfix, Gmail)
- Fuzz the full ingest pipeline (SMTP → storage)
- AddressSanitizer memory fuzzing for buffer overflows
