# CloudSecOps Live

An AWS-first security engineering portfolio and training environment, designed around one traceable workflow:

**Actual AWS event → trusted ingestion → preserved evidence → tested detection → analyst investigation → reviewed response recommendation → independently verified outcome.**

## Current status: Phase 0 design review

This repository contains architecture and a read-only reuse audit. **It does not yet contain a working platform.** No AWS resources were provisioned, paid services enabled, credentials configured, integrations activated, or deployments performed for Phase 0. There are no runtime tests or CI workflows in this repository yet.

The design targets enterprise engineering practices in a small, independently testable lab. It is not evidence of production SOC experience, detection efficacy against real adversaries, or authority to respond to operational incidents.

## Proposed direction

- Python and FastAPI in one application, with a separate worker process from the same package; PostgreSQL for cases, decisions, jobs and audit records.
- Terraform for a dedicated AWS sandbox. Initial runtime roles read only; provisioning and teardown use a separate, manually authorized role.
- CloudTrail management events delivered to private, versioned S3 storage, with raw-file provenance and explicit digest-validation status.
- Deterministic Python detections and correlation, linked to an analyst case. A local Wazuh deployment supplies a real SIEM integration after its resource gate passes.
- A small server-rendered investigation workspace first. Next.js is deferred until workflow needs justify a second application.
- Human review before response decisions; independent verification before closing an investigation. Cloud-changing response and optional AI assistance are later milestones.

These are recommendations for review, not implemented capabilities or approved cloud expenditure.

## Design and delivery documents

| Document | Purpose |
| --- | --- |
| [System design](docs/architecture/SYSTEM_DESIGN.md) | Architecture, contracts, trust boundaries, stack decisions and first vertical slice |
| [Reuse audit](docs/architecture/REUSE_AUDIT.md) | Six repository snapshots, source evidence, gaps and license boundaries |
| [Threat model](docs/architecture/THREAT_MODEL.md) | Abuse cases, controls, failure behavior and residual risk |
| [Cloud cost and safety](docs/architecture/CLOUD_COST_AND_SAFETY.md) | Cost assumptions, IAM, safe exercises, retention and teardown |
| [Delivery roadmap](docs/DELIVERY_ROADMAP.md) | Acceptance tests, dependencies and stop/go gates |
| [Interview mastery](docs/INTERVIEW_MASTERY.md) | Practical exercises and evidence-based assessment |

## First implementation candidate

Phase 1 would build one complete workflow: three authorized `DescribeInstances` calls in an isolated account; authenticated collection of their CloudTrail logs; digest-backed evidence; a tested inventory-burst rule; a searchable Wazuh alert and investigation case; human review of a **no-action / authorized exercise** recommendation; and separately recorded read-only verification. No resource needs to be attacked, exposed or remediated to demonstrate this path.

CloudTrail delivery and digest timing make this an eventual, evidence-first workflow, not a real-time response claim. A no-action exercise does not demonstrate containment or remediation; those require later gates.

## Safety and contribution boundary

Do not commit cloud evidence, account identifiers, private names, Terraform state or plans, credentials, tokens, or unsanitized screenshots. Public fixtures must be explicitly synthetic. Source-project tests were inspected during the audit; they were not executed by this Phase 0 review. No source code was copied. This repository has no project license yet; choose one before code reuse or distribution beyond this documentation review.

Phase 0 ends with a review PR against `main`. Phase 1 requires owner approval of the scope and gates in the roadmap. Do not merge or deploy as part of Phase 0.
