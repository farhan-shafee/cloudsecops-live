# Guarded AWS transport implementation plan

The owner's Phase1B-AWS-1 specification authorizes offline implementation and publication.
PR#6 was verified at `5a08dab7c99f8ad356ed1a806267d113a89bbe90`, 45files,
nine passing exact-head jobs, resolved P2 and fresh no-findings review. Normal merge
`da8fcbcde05a4e7a7e66e9c8efb26e892211d465` preserves reviewed tree
`7520b34f32bf50806040a04897c681cd2f05199c`. Work starts from that main on
`codex/phase1b-aws1-guarded-transport`. No checks are represented as branch-protection
requirements: the repository had no protected-main required checks configured.

## Design and implementation sequence

1. Independently author negative SDK and receipt tests before production logic. Separate
   test authors own expected responses and failure outcomes. Review actual SDK/CLI source.
2. Add `integrations/aws_sdk/transport.py` implementing the existing `ReadTransport`
   protocol with injected clients only. The old `aws_cloudtrail` package retains its
   static prohibition on SDK/network/subprocess imports. No client factory, live command
   or automatic credential resolver is supplied. Boto3/botocore1.43.123 are reviewed
   Apache-2.0 dependencies, hash-locked with their transitives.
3. Validate short-lived explicit credential/client bindings, lease, exact role identity,
   regional HTTPS, TLS verification, bounded retries and approved source requests.
   Preserve complete version/delete-marker pagination and bounded streamed reads.
4. Add a pure offline parser for the fixed AWS CLI2.37.11 verbose-output contract.
   Separate original-location membership, controlled chain observations, retained
   content/archive hashes and version continuity. Every result remains unauthenticated;
   no receipt can enter synthetic findings or reviewed closure.
5. Document unresolved owner decisions, four separate live permissions, cost/retention
   reconciliation and a no-AI practical lab. Preserve Wazuh NO-GO and PostgreSQL risk.
6. Add credential-free CI tests and separate >=85% branch gates for the new security
   modules. Preserve all old gates, native Terraform and sequential PostgreSQL suites.
7. Run complete acceptance, independent adversarial review, fix material defects, commit,
   publish an unmerged PR and verify its remote tree, fresh CI and same-head review.

## Boundaries and alternatives

Accepting arbitrary boto3 sessions would enable ambient credential discovery and regional
redirects. Constructing a default session is deliberately absent. Injected SDK clients
are checked against pinned botocore implementation details; upgrades require fresh
compatibility tests. A caller capable of replacing Python objects remains in the trusted
local operator boundary. These checks cannot establish AWS authorization or authenticity.

CLI output is human text and omits critical source metadata; `--output json` does not
create a signed receipt. A strict local wrapper plus separately controlled observations
can test consistency only. Neither SDK success nor CLI exit0 authenticates a log. No
migration or synthetic-workflow bridge is justified. Migrations001–003 remain unchanged.

No real credentials, AWS APIs, live CLI, Terraform plan/apply, infrastructure, Wazuh or
resource-stress reproduction belongs to any implementation or validation command.
