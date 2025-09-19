# Demo Walkthrough

The following session (≤10s) demonstrates Real Tracker X scanning a mixed repository. The GIF in `docs/assets/demo.gif` was generated from this script.

```text
$ rtx scan --path examples/mixed
 Detecting manifests... done
 Resolving dependency graph... done (312 nodes, 587 edges)
 Querying advisories... done (OSV, GitHub, ecosystem feeds)
 Computing trust scores... warnings detected

Summary
───────
High Risk   : 2
Medium Risk : 5
Low Risk    : 305

Top Findings
────────────
1. npm:coa@2.0.4          CVE-2021-3757 (critical)
2. pypi:requests@2.19.0   Abandoned (last release 2018-06-22)

Exit status: 2
Report saved to reports/rtx-latest.json & reports/rtx-latest.html
```
