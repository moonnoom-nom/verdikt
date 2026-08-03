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

