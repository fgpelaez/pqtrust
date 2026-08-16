# Graph Report - pqtrust  (2026-08-16)

## Corpus Check
- 66 files · ~69,834 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 53 nodes · 50 edges · 7 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `c2dd7d79`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- pqtrust — Post-Quantum PKI-as-a-Service
- 2026-08-16-pqtrust-phase1.md
- File Structure
- 5. Cryptographic design
- 6. pqx509 package specification
- AGENTS.md
- 2. Goals and non-goals

## God Nodes (most connected - your core abstractions)
1. `pqtrust — Post-Quantum PKI-as-a-Service` - 14 edges
2. `File Structure` - 7 edges
3. `5. Cryptographic design` - 5 edges
4. `6. pqx509 package specification` - 4 edges
5. `Large third-party ACVP vectors; refetch with ./scripts/fetch-acvp.sh` - 3 edges
6. `pqtrust Phase 1 Implementation Plan` - 3 edges
7. `2. Goals and non-goals` - 3 edges
8. `11. Deployment, licensing & commercialization path` - 2 edges
9. `Where the code actually is` - 1 edges
10. `Sources of truth` - 1 edges

## Surprising Connections (you probably didn't know these)
- None detected - all connections are within the same source files.

## Communities (7 total, 0 thin omitted)

### Community 0 - "pqtrust — Post-Quantum PKI-as-a-Service"
Cohesion: 0.15
Nodes (12): 10. Testing strategy, 11.1 Open-core boundary (future, not built now), 11. Deployment, licensing & commercialization path, 12. Phasing, 13. Success criteria, 1. Overview, 3. Technology choices, 4. Architecture (+4 more)

### Community 1 - "2026-08-16-pqtrust-phase1.md"
Cohesion: 0.17
Nodes (11): ACVP test vectors, certificate chain issued by pqtrust. Run locally or from CI., Downloads the NIST ACVP ML-DSA sigVer vectors used by internal/pqx509/acvp_test.go., Large third-party ACVP vectors; refetch with ./scripts/fetch-acvp.sh, ... paste and run every command from the README demo ..., pqtrust daemon configuration. Every key can be overridden by an environment, Proves third-party interoperability: OpenSSL 3.5+ must parse and verify a, Split the returned chain into leaf, intermediate and root PEM files. (+3 more)

### Community 2 - "File Structure"
Cohesion: 0.22
Nodes (9): File Structure, Global Constraints, pqtrust Phase 1 Implementation Plan, Task 0: Toolchain and repository bootstrap, Task 1: pqx509 algorithms, keys and SPKI encoding, Task 2: Distinguished names and RFC 5280 time encoding, Task 3: Certificate extensions, Task 4: CreateCertificate and ParseCertificate (+1 more)

### Community 3 - "5. Cryptographic design"
Cohesion: 0.40
Nodes (5): 5.1 Algorithms and OIDs, 5.2 Hierarchy and constraints, 5.3 Key storage, 5.4 Transport, 5. Cryptographic design

### Community 4 - "6. pqx509 package specification"
Cohesion: 0.50
Nodes (4): 6.1 Surface (Phase 1), 6.2 Supported extensions, 6.3 Path validation scope, 6. pqx509 package specification

### Community 5 - "AGENTS.md"
Cohesion: 0.29
Nodes (5): Architecture, Commands (run in the worktree), Crypto / X.509 conventions (hard rules, enforced in tests), Sources of truth, Where the code actually is

### Community 6 - "2. Goals and non-goals"
Cohesion: 0.67
Nodes (3): 2. Goals and non-goals, Goals, Non-goals (YAGNI)

## Knowledge Gaps
- **41 isolated node(s):** `Where the code actually is`, `Sources of truth`, `Commands (run in the worktree)`, `Architecture`, `Crypto / X.509 conventions (hard rules, enforced in tests)` (+36 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `pqtrust — Post-Quantum PKI-as-a-Service` connect `pqtrust — Post-Quantum PKI-as-a-Service` to `5. Cryptographic design`, `6. pqx509 package specification`, `2. Goals and non-goals`?**
  _High betweenness centrality (0.193) - this node is a cross-community bridge._
- **Why does `pqtrust Phase 1 Implementation Plan` connect `File Structure` to `2026-08-16-pqtrust-phase1.md`?**
  _High betweenness centrality (0.078) - this node is a cross-community bridge._
- **What connects `Where the code actually is`, `Sources of truth`, `Commands (run in the worktree)` to the rest of the system?**
  _41 weakly-connected nodes found - possible documentation gaps or missing edges._