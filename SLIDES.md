# Sentinel Edge — Presentation Slide Deck Outline (8 Slides)

1. **Slide 1 (Title):** Sentinel Edge: Local-First, Privacy-Preserving AIOps Observability — *Raw Stays Local, Metadata Goes Global*.
2. **Slide 2 (The Problem):** Traditional observability forces you to stream raw logs, private IPs, and customer credentials into centralized cloud data lakes.
3. **Slide 3 (The Solution):** Two-tier architecture with an uncompromised customer trust boundary: host-level analysis, pre-egress allow-listing, and metadata-only transit.
4. **Slide 4 (Privacy Engine):** Dual allow-list gate and 13-pattern secret scanner strip credentials, drop unknown fields, and hash host identities (`h_xxxxxxxx`).
5. **Slide 5 (Resilience):** Store-and-forward SQLite outbox queues telemetry during cloud outages, delivering zero data loss (`lost=0, duplicates=0`).
6. **Slide 6 (AIOps Intelligence):** Sliding-window topological correlation collapses multi-signal alert cascades into single explainable incidents with confidence scores.
7. **Slide 7 (Governed Remediation):** Human-in-the-loop state machine validates actions against policy, stores pre-execution rollback plans, and audits every UTC transition.
8. **Slide 8 (Sovereignty & Scale):** Multi-region pinning rejects cross-border traffic (HTTP 421), reducing cloud bandwidth by 92% to scale seamlessly across 10,000+ tenants.
