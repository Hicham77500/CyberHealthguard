# TRELLO_SYNC

> Généré automatiquement le 2026-05-29 13:40:37Z via `scripts/trello_update.py`.

## Résumé rapide
| Liste | Tickets |
| --- | --- |
| Backlog | 0 |
| À Faire | 1 |
| In Progress | 0 |
| En Revue | 0 |
| Terminé | 13 |
| Total | 14 |

## Backlog

| Ticket ID | Task | Assignee | Due | Status | Link GitHub | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| - | Aucun ticket | - | - | - | - | - |

## À Faire

| Ticket ID | Task | Assignee | Due | Status | Link GitHub | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| CHG-1 | CHG-001 — Dockeriser l'API Zero Trust | alice | 2026-06-15T10:00:00.000Z | 🟡 | https://github.com/Hicham77500/CyberHealthguard/issues/1 | Security, Sprint-4 |

## In Progress

| Ticket ID | Task | Assignee | Due | Status | Link GitHub | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| - | Aucun ticket | - | - | - | - | - |

## En Revue

| Ticket ID | Task | Assignee | Due | Status | Link GitHub | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| - | Aucun ticket | - | - | - | - | - |

## Terminé

| Ticket ID | Task | Assignee | Due | Status | Link GitHub | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| CHG-10 | CHG-10 - Bootstraper le repo Zero Trust | alice | 2026-03-05T09:00:00.000Z | 🟢 | https://github.com/org/CyberHealthGuard/issues/10 | Foundation |
| CHG-11 | CHG-11 - Automatiser sync Trello | bob | 2026-03-08T12:00:00.000Z | 🟢 | https://github.com/org/CyberHealthGuard/issues/11 | Automation |
| CHG-12 | CHG-12 - Corriger CI (Node cache) | alice | 2026-03-09T08:00:00.000Z | 🟢 | https://github.com/org/CyberHealthGuard/issues/12 | CI |
| CHG-21 | CHG-021 — Log Collector (log_generator.py) | alice | 2026-03-09T18:00:00.000Z | 🟢 | https://github.com/Hicham77500/CyberHealthguard/commit/648a222 | Collector, Sprint-2 |
| CHG-22 | CHG-022 — Dataset Validator (dataset_validator.py) | alice | 2026-05-29T18:00:00.000Z | 🟢 | https://github.com/Hicham77500/CyberHealthguard/commit/08eaedf | Validator, Sprint-2 |
| CHG-23 | CHG-023 — Feature Engineering Pipeline (feature_engineering.py) | bob | 2026-05-29T18:00:00.000Z | 🟢 | https://github.com/Hicham77500/CyberHealthguard/commit/08eaedf | ML, Sprint-2 |
| CHG-24 | CHG-024 — Risk Scoring Engine (risk_scoring.py) | alice | 2026-05-29T20:00:00.000Z | 🟢 | https://github.com/Hicham77500/CyberHealthguard | Scoring, Sprint-3 |
| CHG-25 | CHG-025 — Alert Manager (alert_manager.py) | bob | 2026-05-29T20:00:00.000Z | 🟢 | https://github.com/Hicham77500/CyberHealthguard | Alerting, Sprint-3 |
| CHG-26 | CHG-026 — Experiment Tracker (experiment_tracker.py) | alice | 2026-05-29T20:00:00.000Z | 🟢 | https://github.com/Hicham77500/CyberHealthguard | MLOps, Sprint-3 |
| CHG-29 | CHG-029 — NIS2 / PGSSI-S Incident Reporter | alice | 2026-05-29T20:00:00.000Z | 🟢 | https://github.com/Hicham77500/CyberHealthguard/commit/3180fb1 | Compliance, Sprint-5 |
| CHG-30 | CHG-030 — Audit Trail SHA-256 (append-only) | alice | 2026-05-29T20:00:00.000Z | 🟢 | https://github.com/Hicham77500/CyberHealthguard/commit/3180fb1 | Compliance, Sprint-5 |
| CHG-27 | CHG-027 — Dashboard / Reporting (Sprint 4) | alice | 2026-05-30T18:00:00.000Z | 🟢 | https://github.com/Hicham77500/CyberHealthguard/commit/23fda01 | Dashboard, Sprint-4 |
| CHG-28 | CHG-028 — Tests pytest pipeline complet (Sprint 4) | alice | 2026-05-30T18:00:00.000Z | 🟢 | https://github.com/Hicham77500/CyberHealthguard/commit/23fda01 | Tests, Sprint-4 |

## Procédure
1. Exporter le board en JSON (ou utiliser l'API avec `--board-id`).
2. `python scripts/trello_update.py --input board.json`.
3. Commit + push pour déclencher la sync GitHub Actions.
