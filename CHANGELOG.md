# CHANGELOG

Format suivant [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et SemVer.

## [Unreleased]
### Modifié
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
