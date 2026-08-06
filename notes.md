## 21 July 2026 — Module 1

Built parser.py and fetcher.py. Checkpoint 1 reached: 60 real CVEs
retrieved from OSV across 5 test packages.

Errors hit:
- ImportError (parse_requirements not found) — parser.py hadn't saved
- ModuleNotFoundError (requests) — venv needed its own install; a global
  install isn't visible inside the virtual environment

Design decision: parser accepts only pinned "==" versions. Rejected
supporting ranges like ">=1.0" because contextual scoring requires one
deterministic version — a range could resolve to many versions with
different CVEs.

## 24 July — Module 4: Policy Loader (FR05)

Built policy.py. Loads and validates deployment policy JSON files.

Design decisions:
- Custom PolicyError inheriting ValueError, so callers can catch policy
  problems specifically while code unaware of the type still handles it.
- Error messages name the offending field and list permitted values. The
  developer reading them in a CI log cannot see the source code.
- Validation is semantic as well as structural: warn threshold must be lower
  than block threshold. A file can be valid JSON with every field present and
  still be logically incoherent.
- JSON nests thresholds for human readability; the Policy NamedTuple flattens
  them because the scoring engine consumes them directly. File format optimised
  for humans, object shape optimised for code.
- Sets rather than lists for the valid value constants — constant-time
  membership checks, and the three constants together form the visible schema.

Tested with policy-broken.json containing "produciton" (transposed letters).
Correctly raised: PolicyError: Invalid value for 'environment_tier':
'produciton'. Allowed: ['development', 'production', 'staging']

Kept the broken file as a future pytest fixture.

## 25 July — Module 6: Decision Engine (FR07, FR09)

Built decision.py. Compares scored vulnerabilities against policy thresholds,
produces the Allow/Warn/Block verdict and CI exit code.

Design decisions:
- Verdict(str, Enum): inherits str so it serialises straight to JSON and
  prints cleanly, while Enum catches typos at runtime that a bare string
  comparison would miss silently.
- Worst-case drives the verdict, not an average. A project's single highest
  contextual score determines the outcome, because averaging would let one
  critical finding hide behind many low ones — the opposite of what a
  security gate should do.
- WARN returns exit code 0, BLOCK returns 1. Keeping them distinct matters:
  if a warning failed the build, every advisory would halt delivery and the
  warn/block distinction would be meaningless.
- "contributing" list holds only the vulnerabilities that caused the verdict,
  sorted highest score first, not every finding scanned — a developer needs
  to know what to fix, not a full inventory.

Verified end to end: requests 2.19.0 (CVSS 7.5) -> ALLOW/exit 0 under dev
policy, BLOCK/exit 1 under production. Same vulnerability, same code, verdict
flips on policy alone.

## 25 July — Bug: Decimal vs float in severity extraction

TypeError: unsupported operand type(s) for *: 'decimal.Decimal' and 'float'

The cvss library returns base_score as decimal.Decimal, not float. Fixed by
converting at the extraction boundary (severity.py) rather than patching
scoring.py, so every downstream module only ever handles plain floats.

## 26 July — Deconfounding the evaluation

Identified that policy-dev.json and policy-prod.json vary
both contextual attributes AND thresholds simultaneously, making it impossible
to prove a decision change came from context rather than a stricter threshold.

Added policy-context-low.json and policy-context-high.json: identical
thresholds (warn 4.0, block 7.0), varying only environment tier, network
exposure and data sensitivity. This pair is now the RQ1/RQ2 evidence.
policy-dev.json/policy-prod.json remain as a separate demonstration of
threshold-based risk appetite, not used as RQ evidence.

Verified: LOW CONTEXT -> WARN, HIGH CONTEXT -> BLOCK, same thresholds in both.
Two of ten requests vulnerabilities (PYSEC-2018-28, PYSEC-2023-74) had no
parseable CVSS v3 vector and correctly floored the verdict at WARN via
unscored() rather than crashing or being silently dropped — first real-world
trigger of that path, not manufactured.

## 26 July- feedback taken from AI Tool

Ran the tool's output past ChatGPT for a second opinion and it caught a real
transparency bug: decide() discarded all non-blocking findings once BLOCK
fired, so a "BLOCK, 1 finding" report was silently hiding 7 warning-level
findings and 2 unscored ones from the same scan. Separated verdict logic
(worst-case wins) from reporting logic (show everything) — contributing now
always lists blocking + warning + unscored together.

Added a reconciliation count (N of M fetched records evaluated) so every
OSV record is provably accounted for, never silently dropped.

Verified: requests 2.19.0, all 10 fetched records accounted for under both
LOW CONTEXT (0 block, 0 warn, 2 unscored) and HIGH CONTEXT (1 block, 7 warn,
2 unscored).

Follow-up fix: the WARN summary omitted the count of findings that scored
clean (below the warn threshold) whenever unscored items were also present,
because the ALLOW-count logic had been added to the wrong branch — WARN
fires ahead of ALLOW whenever unscored items exist, even with zero actual
warning-range findings. Moved the count into the branch that actually
executes. Verified: LOW CONTEXT now reads "8 scored finding(s) below the

## 5 August — Module 9: Pytest Suite (NFR03)

41 tests across 8 files, 86% coverage. NFR03 required 70%.

Environment issue first: C: drive was completely full (0 bytes), which blocked
pip install and was also breaking File Explorer. Moved Downloads to D:,
recovered 21GB.

Import error on first run — pytest adds tests/ to the path, not the project
root, so `from verdikt.parser import ...` failed. Fixed properly with
pyproject.toml (PEP 621) rather than sys.path manipulation in each test file;
same file also makes the tool pip-installable later.

Coverage distribution is deliberate: parser, cache, scoring, severity at 100%,
decision 97%, policy 97%, orchestrator 94%. cli.py at 0% because it is a thin
entry point whose logic lives in the modules it calls, and whose behaviour is
verified end-to-end by the CI workflow.

Most important test: test_same_vulnerability_different_verdict_by_context in
test_orchestrator.py. It asserts the project's central hypothesis — identical
vulnerability, identical thresholds, different context, different verdict. If
the attenuation model breaks, that test fails immediately.

Regression tests added for both bugs found earlier: the Decimal/float
conversion in severity extraction, and the transparency bug where BLOCK
discarded non-blocking findings.