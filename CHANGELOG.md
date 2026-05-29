# CHANGELOG

Format suivant [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et SemVer.

## [Unreleased]
### Ajouté
- `src/validator/dataset_validator.py` (CHG-022) : validateur JSONL — contrôle schéma, types, plages severity, format ISO 8601, doublons event_id, rapport JSON exportable.
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
