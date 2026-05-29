# CHANGELOG

Format suivant [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et SemVer.

## [Unreleased]
### Ajouté
- `src/compliance/nis2_reporter.py` (CHG-029) : rapport d'incident NIS2 Art.23 — champs obligatoires ANSSI/CERT Santé, classification Significant/Non-significant, délais 24h/72h automatiques, mapping PGSSI-S, export JSON + HTML PDF-ready, signature SHA-256.
- `src/compliance/audit_trail.py` (CHG-030) : piste d'audit append-only JSONL chainé SHA-256 (tamper-evident). Vérification d'intégrité de la chaîne, mapping PGSSI-S v2, export HTML, CLI avec sous-commandes `log`/`verify`/`export`/`stats`.
- `tests/test_nis2_reporter.py` : 22 tests (build_report, sign_report, HTML, intégration fichier).
- `tests/test_audit_trail.py` : 17 tests (log, chaîne, tampering, verify, stats).
- `scripts/run_pipeline.py` : étendu à 9 étapes (+ NIS2 Report step 8 + Audit Trail step 9). Nouveaux args `--org` et `--contact`.
- **Total tests** : 106/106 verts en 0.65 s.
- `src/reporting/report_generator.py` (CHG-027) : dashboard HTML auto-généré (dark navy theme, inline CSS), 4 stat cards (Events/Alerts/Critical/AUC-ROC), barres de distribution des risques, top-20 alertes, historique d'expériences, statut des 7 étapes pipeline.
- `scripts/run_pipeline.py` : orchestrateur pipeline complet 7 étapes avec affichage coloré ✅/❌, temps d'exécution, génération automatique du dashboard. Exécution de bout en bout en < 0.5 s sur 12 000 événements.
- `tests/test_alert_manager.py` (CHG-028) : 14 tests pour `_infer_alert_type` (6 types + priorités) et `generate_alerts` (threshold, tri, structure, edge cases).
- `tests/test_risk_scoring.py` (CHG-028) : 16 tests pour `risk_level`, `compute_scores`, `summary`, dégradation gracieuse.
- `tests/test_feature_engineering.py` (CHG-028) : 21 tests couvrant le schéma, les mappings risk, le z-score, les agrégats UEBA.
- `tests/test_validator.py` (CHG-028) : 17 tests couvrant schéma, types, plages, ISO 8601, doublons, warnings IP.
- `conftest.py` : ajout au sys.path pour que `src.*` soit importable dans pytest sans installation.
- `requirements.txt` : ajout de `pytest>=8.0.0`.
- **Résultat global CHG-028** : 67/67 tests passent en 3.44 s.
- `src/scoring/risk_scoring.py` (CHG-024) : score composite 0–100 par 6 facteurs pondérés (is_off_hours, severity, category_risk, role_risk_score, status_risk, bytes_zscore) ; niveaux Low/Medium/High/Critical. Résultat : 9 Critical, 1589 High sur 12 000 événements réels.
- `src/alerts/alert_manager.py` (CHG-025) : générateur d'alertes JSON structurées (alert_id, severity, alert_type, risk_score, details) ; 6 types inférés (off_hours_patient_access, mass_data_exfiltration, privilege_abuse, suspicious_network_activity, repeated_login_failure, anomalous_activity).
- `src/tracking/experiment_tracker.py` (CHG-026) : tracker JSONL sans dépendance externe ; métriques precision/recall/F1/AUC-ROC, historique des runs, sous-commandes `record`/`list`. AUC-ROC = 0.8057 (objectif Sprint 2 ≥ 0.80 atteint).
- `data/trello_sample.json` : fixture mise à jour avec tickets CHG-021 à CHG-028 (statuts réels, liens commits).
- `TRELLO_SYNC.md` : régénéré — 9 tickets Terminé, 1 À Faire, 2 Backlog. : validateur JSONL — contrôle schéma, types, plages severity, format ISO 8601, doublons event_id, rapport JSON exportable.
- `src/features/feature_engineering.py` (CHG-023) : pipeline feature engineering — 11 features (temporelles, risk scores catégoriels, z-score volume, agrégats comportementaux UEBA par utilisateur), sortie CSV compatible IsolationForest.

### Modifié
- `src/ml/anomaly_demo.py` : auto-détection des colonnes de features via `_feature_cols()` ; supporte désormais les CSV issus de `feature_engineering.py` en plus du dataset synthétique (rétro-compatible `--generate`).
- `src/ml/anomaly_demo.py` : suppression des imports inutilisés `math` et `os`.
- `scripts/trello_update.py` : suppression des constantes mortes `TABLE_HEADER`/`TABLE_DIVIDER` (jamais utilisées, incohérentes avec le rendu réel) ; renommage `token` → `word` dans `pick_github_link`.
- `scripts/anti_dup.py` : suppression du bloc `for child in dir_path.iterdir(): break` inopérant dans `iter_candidate_files`.
- `src/collector/log_generator.py` : `main()` retourne désormais `int`, point d'entrée harmonisé en `raise SystemExit(main())`.
- `README.md` : correction de la commande `--fix` inexistante remplacée par `--strict`.

### Ajouté
- Documentation initiale (README, PROJECT_LOG template, TRELLO_SYNC live table).
- Scripts `anti_dup.py`, `trello_update.py`, hook pre-commit unifié.
- Workflows GitHub Actions `ci.yml` et `trello-sync.yml`.
- Exemple ML IsolationForest + Docker compose + checklist sprint + template board Trello.
