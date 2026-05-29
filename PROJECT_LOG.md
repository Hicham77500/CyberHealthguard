# PROJECT_LOG

Tracer toutes les décisions produit/sécurité/tech. Ajouter une ligne par décision ou incident.

| Date | Fichier / Zone | Décision | Statut |
| --- | --- | --- | --- |
| 2026-03-09 | README.md | Initialisation POC + instructions Trello/Zero Trust | Adopté |

> Statut possibles : Proposé, En discussion, Adopté, Rejeté, À surveiller.
| 2026-03-09 | scripts/anti_dup.py | Implémentation scanner doublons + plan JSON | Adopté |
| 2026-03-09 | scripts/trello_update.py | Export JSON Trello → Markdown + check mode | Adopté |
| 2026-03-09 | .githooks/pre-commit | Hook tests/doublons/logs obligatoire | Adopté |
| 2026-03-09 | .github/workflows | CI + sync Trello automatisés | En cours |
| 2026-03-09 | src/ml/anomaly_demo.py | PoC IsolationForest pour logs santé | En cours |
| 2026-05-29 | src/ml/anomaly_demo.py | Suppression imports morts (math, os) | Adopté |
| 2026-05-29 | scripts/trello_update.py | Suppression constantes mortes TABLE_HEADER/TABLE_DIVIDER + renommage token→word | Adopté |
| 2026-05-29 | scripts/anti_dup.py | Suppression bloc code mort iter_candidate_files | Adopté |
| 2026-05-29 | src/collector/log_generator.py | Harmonisation pattern __main__ (raise SystemExit) | Adopté |
| 2026-05-29 | README.md | Correction commande --fix inexistante → --strict | Adopté |
| 2026-05-29 | src/validator/dataset_validator.py | CHG-022 — Implémentation Dataset Validator (schéma, types, plages, doublons) | Adopté |
| 2026-05-29 | src/features/feature_engineering.py | CHG-023 — Pipeline Feature Engineering (11 features temporelles/catégorielles/comportementales) | Adopté |
| 2026-05-29 | src/ml/anomaly_demo.py | Auto-détection colonnes features (rétro-compatible --generate) | Adopté |
| 2026-05-29 | src/scoring/risk_scoring.py | CHG-024 — Risk Scoring Engine (score 0-100, 4 niveaux Low/Medium/High/Critical) | Adopté |
| 2026-05-29 | src/alerts/alert_manager.py | CHG-025 — Alert Manager (alertes JSON structurées, 6 types d'anomalies) | Adopté |
| 2026-05-29 | src/tracking/experiment_tracker.py | CHG-026 — Experiment Tracker JSON (precision/recall/F1/AUC-ROC) | Adopté |
| 2026-05-29 | data/trello_sample.json + TRELLO_SYNC.md | Mise à jour tickets CHG-021–028, sync pipeline réel | Adopté |
| 2026-05-30 | tests/ (4 fichiers) | CHG-028 — Suite pytest 67 tests (validator, feature_engineering, risk_scoring, alert_manager) | Adopté |
| 2026-05-30 | src/reporting/report_generator.py | CHG-027 — Dashboard HTML auto-généré (dark theme, inline CSS, 7 sections) | Adopté |
| 2026-05-30 | scripts/run_pipeline.py | Orchestrateur pipeline 7 étapes — validation → features → ML → scoring → alertes → tracking → dashboard | Adopté |
| 2026-05-30 | requirements.txt | Ajout pytest>=8.0.0 | Adopté |
| 2026-05-30 | data/trello_sample.json | CHG-027 + CHG-028 déplacés en list_done | Adopté |
