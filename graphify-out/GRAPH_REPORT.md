# Graph Report - pqtrust  (2026-08-16)

## Corpus Check
- 2 files · ~37,496 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 46 nodes · 44 edges · 8 communities (7 shown, 1 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `0f939a34`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- pqtrust — Post-Quantum PKI-as-a-Service
- 2026-08-16-pqtrust-phase1.md
- File Structure
- 5. Cryptographic design
- 6. pqx509 package specification
- Large third-party ACVP vectors; refetch with ./scripts/fetch-acvp.sh
- 2. Goals and non-goals
- 11. Deployment, licensing & commercialization path

## God Nodes (most connected - your core abstractions)
1. `pqtrust — Post-Quantum PKI-as-a-Service` - 14 edges
2. `File Structure` - 7 edges
3. `5. Cryptographic design` - 5 edges
4. `6. pqx509 package specification` - 4 edges
5. `pqtrust Phase 1 Implementation Plan` - 3 edges
6. `Large third-party ACVP vectors; refetch with ./scripts/fetch-acvp.sh` - 3 edges
7. `2. Goals and non-goals` - 3 edges
8. `11. Deployment, licensing & commercialization path` - 2 edges
9. `Global Constraints` - 1 edges
10. `Task 0: Toolchain and repository bootstrap` - 1 edges

## Surprising Connections (you probably didn't know these)
- None detected - all connections are within the same source files.

## Communities (8 total, 1 thin omitted)

### Community 0 - "pqtrust — Post-Quantum PKI-as-a-Service"
Cohesion: 0.18
Nodes (10): 10. Testing strategy, 12. Phasing, 13. Success criteria, 1. Overview, 3. Technology choices, 4. Architecture, 7. REST API, 8. Data model (SQLite) (+2 more)

### Community 1 - "2026-08-16-pqtrust-phase1.md"
Cohesion: 0.22
Nodes (8): ACVP test vectors, certificate chain issued by pqtrust. Run locally or from CI., Downloads the NIST ACVP ML-DSA sigVer vectors used by internal/pqx509/acvp_test.go., ... paste and run every command from the README demo ..., pqtrust daemon configuration. Every key can be overridden by an environment, Proves third-party interoperability: OpenSSL 3.5+ must parse and verify a, Split the returned chain into leaf, intermediate and root PEM files., variable; see the table in README.md.

### Community 2 - "File Structure"
Cohesion: 0.22
Nodes (9): File Structure, Global Constraints, pqtrust Phase 1 Implementation Plan, Task 0: Toolchain and repository bootstrap, Task 1: pqx509 algorithms, keys and SPKI encoding, Task 2: Distinguished names and RFC 5280 time encoding, Task 3: Certificate extensions, Task 4: CreateCertificate and ParseCertificate (+1 more)

### Community 3 - "5. Cryptographic design"
Cohesion: 0.40
Nodes (5): 5.1 Algorithms and OIDs, 5.2 Hierarchy and constraints, 5.3 Key storage, 5.4 Transport, 5. Cryptographic design

### Community 4 - "6. pqx509 package specification"
Cohesion: 0.50
Nodes (4): 6.1 Surface (Phase 1), 6.2 Supported extensions, 6.3 Path validation scope, 6. pqx509 package specification

### Community 5 - "Large third-party ACVP vectors; refetch with ./scripts/fetch-acvp.sh"
Cohesion: 0.67
Nodes (3): Large third-party ACVP vectors; refetch with ./scripts/fetch-acvp.sh, Task 11: ca — issuance profiles, hierarchy and CRL, Task 9: store — SQLite persistence

### Community 6 - "2. Goals and non-goals"
Cohesion: 0.67
Nodes (3): 2. Goals and non-goals, Goals, Non-goals (YAGNI)

## Knowledge Gaps
- **36 isolated node(s):** `Global Constraints`, `Task 0: Toolchain and repository bootstrap`, `Task 1: pqx509 algorithms, keys and SPKI encoding`, `Task 2: Distinguished names and RFC 5280 time encoding`, `Task 3: Certificate extensions` (+31 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `pqtrust — Post-Quantum PKI-as-a-Service` connect `pqtrust — Post-Quantum PKI-as-a-Service` to `5. Cryptographic design`, `6. pqx509 package specification`, `2. Goals and non-goals`, `11. Deployment, licensing & commercialization path`?**
  _High betweenness centrality (0.259) - this node is a cross-community bridge._
- **Why does `pqtrust Phase 1 Implementation Plan` connect `File Structure` to `2026-08-16-pqtrust-phase1.md`?**
  _High betweenness centrality (0.104) - this node is a cross-community bridge._
- **What connects `Global Constraints`, `Task 0: Toolchain and repository bootstrap`, `Task 1: pqx509 algorithms, keys and SPKI encoding` to the rest of the system?**
  _36 weakly-connected nodes found - possible documentation gaps or missing edges._