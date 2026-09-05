# NIGHTSHIFT

[![Money Safety](https://img.shields.io/badge/money--safety-A%2B-3fb950?style=for-the-badge&logo=shield)](https://github.com/omshukla24/NightShift)
[![Tests](https://img.shields.io/badge/tests-130%20passed-3fb950?style=for-the-badge&logo=pytest)](https://github.com/omshukla24/NightShift)
[![Python](https://img.shields.io/badge/python-3.10+-3776ab?style=for-the-badge&logo=python)](https://github.com/omshukla24/NightShift)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Core Dependencies](https://img.shields.io/badge/core%20dependencies-0%20(stdlib)-brightgreen?style=for-the-badge)](pyproject.toml)

> **The security scanner you run against your Razorpay integration before you go live.**
> It fires eight real payment attacks at your webhook endpoint, grades you A+ to F, and writes the CVEs.

---

## The Problem

Every payments team has a 2 AM story: a webhook that shipped an order for a payment that never actually settled, a retried event that double-fulfilled inventory, or a concurrent burst that bypassed non-atomic deduplication.

Payment webhook endpoints are public HTTP endpoints. Anyone on the internet who discovers the URL can `POST` a spoofed `payment.captured` event. If your integration fails to cryptographically verify the signature, deduplicate atomically under concurrency, validate that the order was genuinely created on your account, or bound refunds, an attacker can extract free goods or drain settled balances.

Traditional unit tests only exercise the happy path with valid, sequential payloads. **NIGHTSHIFT attacks the payment and event layer under adversarial conditions before real money is on the line.**

---

## 30-Second Live Scan

Point NIGHTSHIFT at a running endpoint to red-team it in real time:

```bash
# 1. Start a bundled vulnerable payment target (or point at your own app)
python -m nightshift serve --port 8000

# 2. Fire the live red-team scan
python -m nightshift scan --url http://localhost:8000
```

```text
LIVE SCAN · http://localhost:8000
  grade: F   attacks landed: 7/8   exposure: Rs 17,249.00

  [HIT ] race             [CRITICAL]  6 parallel webhooks -> order fulfilled 6x (non-atomic dedupe)
  [HIT ] unsigned         [CRITICAL]  an unsigned webhook was accepted and fulfilled
  [HIT ] forged           [CRITICAL]  a forged webhook shipped an order
  [HIT ] idor             [CRITICAL]  fulfilled an order that was never created
  [HIT ] tamper           [HIGH    ]  booked Rs 20.00 for a Rs 2,000.00 order
  [HIT ] over_refund      [HIGH    ]  refunded Rs 800.00 against a Rs 500.00 capture
  [HIT ] stale            [MEDIUM  ]  a decades-old event was accepted (no freshness window)
  [safe] replay                       order fulfilled 1x on a replayed webhook
```

Now test against the hardened implementation:

```bash
# Start the hardened target and rescan
python -m nightshift serve --port 8001 --hardened
python -m nightshift scan --url http://localhost:8001

# LIVE SCAN · http://localhost:8001
#   grade: A+   attacks landed: 0/8   exposure: Rs 0.00
```

Generate vulnerability advisories for every security hole discovered:

```bash
python -m nightshift advisories --url http://localhost:8000 -o advisories.md
```

---

## Architecture

NIGHTSHIFT separates **empirical proof** from **vulnerability explanation**. Money-safety is decided exclusively by **deterministic ledger oracles**. The AI copilot never decides whether money is safe; an oracle mathematically proves the violation, and AI only generates the incident narrative and root-cause advisory grounded in the proven trace.

```mermaid
flowchart TD
    subgraph ATTACK_ENGINE["1. Attack Engine & Fuzzing Harness"]
        A1["Replay Attacks\n(Sequential duplicate events)"]
        A2["Concurrency Race\n(6x parallel barrier burst)"]
        A3["Cryptographic Spoofing\n(Unsigned / Forged secrets)"]
        A4["Payload Tampering\n(Price alteration / IDOR / Stale)"]
    end

    subgraph TARGET["2. Target Application Under Test"]
        T_REG["POST /register\n(Order initialization)"]
        T_WH["POST /webhook\n(Razorpay HMAC-SHA256 handler)"]
        T_ST["GET /state\n(Read-only ledger & fulfillments)"]
    end

    subgraph ORACLES["3. Deterministic Ledger Oracles"]
        O1["Idempotency Oracle"]
        O2["Conservation of Money"]
        O3["No Unpaid Fulfillment"]
        O4["Reconciliation Completeness"]
        O5["Signature Integrity"]
        O6["Terminal State Monotonicity"]
        O7["Refund Bounding"]
        O8["Currency Consistency"]
    end

    subgraph VERDICT["4. Verification & Security Artifacts"]
        V_GRADE["Money-Safety Grade\n(A+ down to F)"]
        V_EXP["Rupee Exposure\n(Calculated financial loss)"]
        V_ADV["CVE-Style Advisories\n(SARIF / Markdown / JSON / JUnit)"]
    end

    ATTACK_ENGINE -->|"Raw HTTP Malicious Webhooks\n(X-Razorpay-Signature)"| T_WH
    ATTACK_ENGINE -->|"Register Pending Orders"| T_REG
    T_ST -->|"Export State & Event History"| ORACLES
    ORACLES -->|"Prove Ledger Violations"| VERDICT
```

---

## The 8 Live Attack Vectors

NIGHTSHIFT fires eight distinct attack classes directly at the target's `/webhook` endpoint:

| Attack Key | Severity | CWE | Threat Mechanism | Vulnerable Outcome | Hardened Defense |
|:---|:---:|:---|:---|:---|:---|
| `replay` | **HIGH** | [CWE-799](https://cwe.mitre.org/data/definitions/799.html) | Sequential re-posting of identical valid `payment.captured` webhooks. | Order ships multiple times for a single payment. | Enforce idempotency on `event_id` or Razorpay `payment_id`. |
| `race` | **CRITICAL** | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) | Parallel burst of identical webhooks synchronized across threads. | Race window between check and record causes double fulfillment. | Atomic database lock (`SELECT FOR UPDATE`) or unique constraint. |
| `unsigned` | **CRITICAL** | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | `POST` payload without `X-Razorpay-Signature` header. | Unauthenticated requests trigger order fulfillment. | Strict cryptographic verification before parsing payload. |
| `forged` | **CRITICAL** | [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | Webhook payload signed with incorrect / guessed secret. | Attackers forge payment events without credentials. | Constant-time HMAC-SHA256 signature verification. |
| `tamper` | **HIGH** | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Payload amount modified (e.g., ₹20.00 for a ₹2,000.00 item). | Order fulfilled for a fraction of list price. | Reject invalid signatures and verify amount against order record. |
| `over_refund` | **HIGH** | [CWE-840](https://cwe.mitre.org/data/definitions/840.html) | Webhook triggers refund larger than captured payment amount. | Business logic error drains merchant balances. | Invariant check: $\sum \text{refunds} + \text{new\_refund} \le \text{captured}$. |
| `stale` | **MEDIUM** | [CWE-294](https://cwe.mitre.org/data/definitions/294.html) | Webhook replayed with timestamp from years in the past. | Expired or superseded events processed out of lifecycle. | Enforce timestamp freshness threshold (e.g., 300s window). |
| `idor` | **CRITICAL** | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | Webhook payment for an order ID belonging to another entity. | Merchant fulfills goods for untracked or arbitrary orders. | Verify order ownership against local DB & Razorpay API. |

---

## The 8 Money-Safety Invariants (Deterministic Oracles)

The evaluation suite validates the ledger state against mathematical money-safety invariants:

| Oracle | Mathematical Condition | Violation Caught |
|:---|:---|:---|
| **`idempotency`** | $\forall o \in \text{Orders}, \text{count}(\text{fulfillments}(o)) \le 1 \land \text{unique}(\text{event\_ids})$ | Duplicate delivery or retried webhook causes duplicate fulfillment. |
| **`conservation`** | $\forall (o, k, a), \text{booked}(o, k, a) \le \text{ground\_truth}(o, k, a)$ | Booking financial movements that do not exist in settlement history. |
| **`no_unpaid_fulfillment`** | $\forall o \in \text{fulfillments}, \exists \text{capture}(o) : \text{amount} \ge \text{order\_amount}(o)$ | Shipping goods or activating services without verified full payment. |
| **`reconciliation_completeness`**| $\forall o \in \text{legit\_captures}, o \in \text{fulfillments}$ | Webhook dropped in transit: money received, but order remains unfulfilled. |
| **`signature_integrity`** | $\text{ledger\_events} \cap \text{invalid\_signature\_events} = \emptyset$ | State mutated by unsigned, forged, or tampered webhook deliveries. |
| **`terminal_state_monotonicity`**| $\text{status}(o) \in \{\text{CREATED} \to \text{PAID} \to \text{REFUNDED}\}$ | Out-of-order event delivery reverts a refunded order back to paid. |
| **`no_over_refund`** | $\forall o, \sum \text{refunded}(o) \le \sum \text{captured}(o)$ | Refunding more capital than was captured on an order. |
| **`currency_consistency`** | $\forall e \in \text{ledger}(o), e.\text{currency} = o.\text{currency}$ | Cross-currency mismatch booked against an order (e.g., USD vs INR). |

---

## Target Contract (Scannable Interface)

Any payment integration (written in Python, Node.js, Go, Java, Ruby, PHP, etc.) can be scanned if it implements four endpoints:

| Endpoint | Method | Payload / Response Format | Purpose |
|:---|:---:|:---|:---|
| `/register` | `POST` | `{"order_id": "ord_123", "amount": 50000, "currency": "INR"}` | Registers a pending order in the merchant system. |
| `/webhook` | `POST` | Razorpay webhook payload + `X-Razorpay-Signature` header | Your actual payment webhook handler under test. |
| `/state` | `GET` | `{"fulfillments": ["ord_123"], "ledger": [{"event_id": "...", "order_id": "...", "kind": "capture", "amount": 50000, "currency": "INR"}]}` | Read-only telemetry for oracle verification. |
| `/health` | `GET` | `200 OK` | Liveness check before running test batteries. |

### Minimal Shim for Existing Applications

To test your existing Razorpay handler, add a lightweight `/state` shim:

```python
# Example: Flask / FastAPI shim
@app.route("/state", methods=["GET"])
def get_state():
    return {
        "fulfillments": db.get_fulfilled_order_ids(),
        "ledger": db.get_payment_ledger_entries(),
    }
```

---

## Interactive Live Dashboard & Exploit Proof

### 1. The Live Console

Launch a dual-pane live console that pairs an active storefront with a real-time red-team console:

```bash
python -m nightshift dashboard
```

- **Left Pane ("Acme Pay"):** Live store with active checkout, shopping cart, and order board.
- **Right Pane ("Attack Console"):** Real-time exploit triggers. Watch fraudulent orders populate the board and rupee exposure tick upward in real time.
- **Defense Switch:** Toggle from Naive to Hardened mode and watch incoming attacks immediately bounce.

### 2. Side-by-Side Proof (`nightshift prove`)

Verify exploit validity by inspecting state databases directly:

```bash
python -m nightshift prove
```

```text
NIGHTSHIFT PROVE · watching theft in each shop's own ledger

[1/8] replay: re-sends the same paid webhook 3x
  naive   : [THEFT] Rs 500.00 extra shipped (order fulfilled 2x)
  hardened: [SAFE ] rejected duplicate event

[2/8] race: fires 6 identical webhooks at once
  naive   : [THEFT] Rs 3,500.00 stolen (order fulfilled 6x via race window)
  hardened: [SAFE ] atomic lock rejected concurrent duplicates

[3/8] unsigned: sends a 'paid' webhook, no signature
  naive   : [THEFT] Rs 400.00 stolen (accepted unsigned payload)
  hardened: [SAFE ] rejected: invalid signature
```

---

## Real Razorpay Test-Mode Target

NIGHTSHIFT includes a fully functional merchant implementation using the official `razorpay` Python SDK:

```bash
# Run the vulnerable reference merchant
python -m nightshift merchant --port 5000 --open

# Run the hardened reference merchant
python -m nightshift merchant --port 5001 --hardened

# Scan against your live webhook secret
python -m nightshift --secret whsec_your_secret scan --url http://localhost:5000
```

---

## CLI Reference

```text
usage: nightshift [-h] [--secret SECRET] [--no-color]
                  {run,report,bench,fuzz,score,diff,list,scan,serve,advisories,cinema,badge,dashboard,merchant,prove} ...
```

| Command | Description | Example |
|:---|:---|:---|
| `dashboard` | Start the dual-pane interactive web console. | `python -m nightshift dashboard` |
| `scan` | Red-team a live HTTP payment endpoint. | `python -m nightshift scan --url http://localhost:5000 --fail-on-hit` |
| `prove` | Compare naive vs hardened state ledgers side-by-side. | `python -m nightshift prove --url http://localhost:5000` |
| `advisories` | Generate Markdown vulnerability advisories (mini-CVEs). | `python -m nightshift advisories --url http://localhost:5000 -o findings.md` |
| `merchant` | Run real Razorpay SDK merchant target. | `python -m nightshift merchant --port 5000 --open` |
| `serve` | Run bundled zero-dependency reference target. | `python -m nightshift serve --port 8000 --hardened` |
| `run` | Run scenario test battery against internal targets. | `python -m nightshift run --target naive` |
| `score` | Generate 0–100 reliability score and letter grade. | `python -m nightshift score --target fixed` |
| `diff` | View code diff showing exact security hardening patches. | `python -m nightshift diff` |
| `fuzz` | Run randomized fault campaign with shrinking. | `python -m nightshift fuzz --target naive --trials 300 --seed 1` |
| `bench` | Run precision/recall benchmark and mutation tests. | `python -m nightshift bench` |
| `report` | Export findings in SARIF, HTML, JUnit, JSON, or CSV. | `python -m nightshift report --target naive --format sarif -o scan.sarif` |
| `badge` | Generate SVG money-safety badge. | `python -m nightshift badge --grade A+ -o badge.svg` |
| `list` | List available scenarios or oracles. | `python -m nightshift list oracles` |

---

## CI/CD Integration (GitHub Actions)

Add continuous payment security scanning to your pull request workflows:

```yaml
# .github/workflows/nightshift-scan.yml
name: Payment Security Scan

on: [pull_request, workflow_dispatch]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install NIGHTSHIFT
        run: pip install -e .

      - name: Start Merchant Service
        env:
          NIGHTSHIFT_SECRET: ${{ secrets.RAZORPAY_WEBHOOK_SECRET }}
        run: |
          python -m nightshift serve --hardened --port 8000 &
          for i in $(seq 1 20); do curl -sf localhost:8000/health && break; sleep 0.5; done

      - name: Run Red-Team Scan (Blocks PR on Vulnerability)
        env:
          NIGHTSHIFT_SECRET: ${{ secrets.RAZORPAY_WEBHOOK_SECRET }}
        run: python -m nightshift scan --url http://localhost:8000 --fail-on-hit

      - name: Export Security Advisories
        if: always()
        env:
          NIGHTSHIFT_SECRET: ${{ secrets.RAZORPAY_WEBHOOK_SECRET }}
        run: python -m nightshift advisories --url http://localhost:8000 -o advisories.md

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: payment-security-advisories
          path: advisories.md
```

---

## Benchmarks & Mutation Testing

NIGHTSHIFT's oracle suite is validated with statistical benchmarks and mutation testing:

```bash
python -m nightshift bench
```

```text
DETECTION (labelled set)
  checks=160  TP=16 FP=0 FN=0 TN=144
  precision=1.000  recall=1.000  specificity=1.000  F1=1.000

MUTATION TESTING (each defense removed once)
  drop 'sig'           -> caught by signature_integrity            KILLED
  drop 'dedupe'        -> caught by idempotency                    KILLED
  drop 'amount'        -> caught by no_unpaid_fulfillment          KILLED
  drop 'reconcile'     -> caught by reconciliation_completeness    KILLED
  drop 'refund_bound'  -> caught by no_over_refund                 KILLED
  kill rate = 5/5 (100%)
```

- **Precision, Recall, Specificity = 1.000:** Zero false positives across 160 labeled test checks, including legitimate partial-refund control flows.
- **100% Mutation Kill Rate:** Disabling any defense toggle in `FixedHandler` is immediately detected and killed by its corresponding oracle.
- **Automated Shrinking:** Fuzz campaigns reduce complex multi-event failure traces to minimal reproducible sequences.

---

## Installation

NIGHTSHIFT core requires **Python $\ge$ 3.10** and has **zero third-party dependencies** (runs entirely on the standard library).

```bash
# Clone the repository
git clone https://github.com/omshukla24/NightShift.git
cd NightShift

# Install core CLI and development tools
pip install -e ".[dev]"

# Optional: Install with real Razorpay SDK merchant server
pip install -e ".[merchant,dev]"

# Optional: Install all extras (FastAPI live demo target, Gemini triage)
pip install -e ".[merchant,web,ai,dev]"
```

Run test suite:

```bash
pytest -q
# 130 passed in 0.82s
```

---

## Repository Structure

```text
nightshift/
├── cli.py            # Unified CLI entrypoint & subcommands
├── scanner.py        # Live HTTP red-team scanner & attack battery
├── oracles.py        # 8 deterministic money-safety ledger oracles
├── refserver.py      # Standard library HTTP reference target (naive & hardened)
├── merchant.py       # Real Razorpay SDK integration (Flask + test-mode orders)
├── dashboard.py      # Interactive dual-panel live web console
├── prove.py          # Side-by-side ledger exploit verification
├── advisories.py     # CVE-style advisory generator & CVSS scoring
├── report.py         # Multi-format report exporter (HTML, SARIF, JUnit, Markdown, CSV)
├── runner.py         # Scenario runner & trace evaluator
├── scenarios.py      # 10 built-in payment fault injection scenarios
├── faults.py         # Fault injection operators (drop, duplicate, delay, tamper, reorder)
├── campaign.py       # Property-based fuzz testing & trace shrinker
├── bench.py          # Precision/recall benchmarking & mutation testing
├── score.py          # 0–100 reliability scoring & grading engine
├── handlers/
│   ├── naive.py      # Vulnerable reference implementation (illustrates 6 common bugs)
│   └── fixed.py      # Hardened reference implementation (passes all oracles)
tests/                # 14 test suites verifying oracles, scanner, and handlers (130 tests)
examples/             # Drop-in CI/CD GitHub Actions workflows
targets/              # FastAPI live demo targets
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
