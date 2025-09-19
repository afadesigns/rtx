# Governance Policy

Real Tracker X is authored and stewarded by **Andreas Fahl**. This document explains how decisions are made, how maintainers are added, and how the community collaborates.

## Roles
- **Lead Maintainer (Andreas Fahl):** Sets roadmap, finalizes releases, arbitrates disputes.
- **Maintainers:** Trusted contributors with merge rights for designated areas (scanners, core engine, docs). Must demonstrate security competency.
- **Reviewers:** Experienced contributors who provide code review feedback but do not merge.
- **Contributors:** Anyone participating in issues, discussions, docs, or code.

## Decision Process
1. **Everyday Changes.** Maintainers may merge approved PRs after two reviews (one maintainer, one reviewer). Security-impacting changes require unanimous maintainer approval.
2. **Roadmap Updates.** Proposed in GitHub Discussions; formalized during monthly roadmap calls chaired by Andreas Fahl.
3. **Policy Changes.** Governance, security, or Code of Conduct updates undergo a public RFC lasting at least seven days.
4. **Dispute Resolution.** The Lead Maintainer mediates. Appeals escalate to a Steering Committee (three maintainers elected annually).

## Adding Maintainers
- Demonstrate sustained, high-quality contributions across code and security topics.
- Sign the maintainer agreement (adds to CODEOWNERS).
- Majority vote from existing maintainers plus approval from Andreas Fahl.

## Removing Maintainers
- Voluntary resignation.
- Inactivity >6 months without notice.
- Breach of Code of Conduct, security policy, or trust. Removal decided by majority vote including Andreas Fahl.

## Release Cadence
- **Stable Releases:** Monthly (first Tuesday) with signed wheels and SBOMs.
- **Security Releases:** As needed, within 24 hours of confirmed vulnerability.
- **Long-Term Support:** The two most recent minor versions receive patches.

## Transparency
- Quarterly transparency reports summarizing incidents, CVE triage outcomes, and governance changes.
- Public backlog labeled “good first issue” to welcome new contributors.

## Amendments
Changes to this policy require an RFC and approval from Andreas Fahl plus ≥2 maintainers. Updates are documented in CHANGELOG.md and communicated via Discussions.
