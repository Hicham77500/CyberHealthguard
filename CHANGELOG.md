# CHANGELOG

Format suivant [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et SemVer.

## [Unreleased]
### Ajouté
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
