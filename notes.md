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