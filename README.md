# CyberHealthGuard

POC d'intelligence artificielle appliquée à la cybersécurité santé. Le dépôt fournit une base prêt-clone pour auditer les flux médicaux, détecter les anomalies/ransomware et synchroniser automatiquement les tâches Trello ↔ GitHub.

## Architecture & Stack
- **Frontend** : Next.js/React (Zero Trust-ready, SSR ou static export).
- **Backend** : Node.js (API Zero Trust), Python services (ML, détection ransomware) packagés Docker.
- **Automations** : Scripts `anti_dup.py`, `trello_update.py`, git hooks, GitHub Actions CI/CD + sync Trello.
- **Observabilité** : logs unifiés, CHANGELOG/PROJECT_LOG, Trello table `TRELLO_SYNC.md`.

```
CyberHealthGuard/
├── README.md
├── PROJECT_LOG.md
├── CHANGELOG.md
├── TRELLO_SYNC.md
├── scripts/
│   ├── anti_dup.py
│   └── trello_update.py
├── src/
│   └── ml/
│       └── anomaly_demo.py
└── .github/workflows/
    ├── ci.yml
    └── trello-sync.yml
```

## Prérequis
- Node.js 20+, npm 10+
- Python 3.11+, pipx/pipenv/uv optionnel
- Docker Engine 25+ (tests ML container)
- Accès Trello (API key + token) et GitHub PAT si besoin workflows

## Mise en route
1. **Cloner** : `git clone git@github.com:<org>/CyberHealthGuard.git && cd CyberHealthGuard`
2. **Node** : `npm install` (ou `pnpm`, `yarn`).
3. **Python** : `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt` (ajustez selon outil ML).
4. **Hooks** : `git config core.hooksPath .githooks`.
5. **Anti-doublons** : `python scripts/anti_dup.py --fix` avant PR.
6. **Trello sync** : configurer `.env.trello` (cf. plus bas) puis `python scripts/trello_update.py --board-id <ID>`.
7. **Docker** : `docker compose up anomaly-demo` (exemple ML).

## Trello ↔ GitHub
- Board : `https://trello.com/b/<board-id>/CyberHealthGuard` (mettre l'URL réelle ici).
- Power-ups requis : *GitHub* + *Importer JSON/CSV*.
- Flux recommandé :
  1. Exporter le board Trello (`... > Plus > Imprimer et exporter > JSON`).
  2. `python scripts/trello_update.py --input trello-board.json` → met à jour `TRELLO_SYNC.md`.
  3. Commit/push. GitHub Action `trello-sync.yml` rejoue `trello_update.py` via API (cron + workflow_dispatch) et ouvre PR automatisée si drift.
  4. Depuis GitHub Project ou Trello, utiliser le power-up JSON Importer pour réappliquer le template mis à jour.
  **Instruction standard** : `Export JSON board → trello_update.py → push Git → import JSON GitHub Project`.

## Roadmap MVP (4 sprints)
| Sprint | Objectif clé | Livrables | Mesure de succès |
| --- | --- | --- | --- |
| Sprint 1 | Setup Zero Trust scaffold | Authz API Next.js/Node, scripts sync, logging initial | Hook + workflows verts, Trello table remplie |
| Sprint 2 | Détection ML basique | Pipeline IsolationForest (logs), dataset anonymisé, tests | AUC ≥ 0.80 sur dataset synthétique |
| Sprint 3 | Intégration Docker/Zero Trust | Compose services API+ML, tests charge, RBAC | 0 vulnérabilité critique scan SAST/DAST |
| Sprint 4 | Observabilité & automation | Alerting, Trello↔GitHub auto, runbooks | MTTD < 5 min sur scénarios ransom|

## Conventions anti-régression
- **Logs** : chaque commit/PR suit `[YYYY-MM-DD][FICHIER][CHANGE][TESTS]`.
- **Doublons** : `scripts/anti_dup.py` empêche fichiers identiques/refactor à l'identique.
- **PROJECT_LOG.md** : décisions clés par date + statut.
- **CHANGELOG.md** : changelog semantique (Keep a Changelog) enrichi par hook.
- **TRELLO_SYNC.md** : table unique des tickets Trello avec liens GitHub.

## Tests & QA
- `npm run lint`, `npm run test` (frontend/backend)
- `pytest` (services Python)
- `python scripts/anti_dup.py --strict`
- `docker compose run anomaly-demo pytest`

## Observabilité & Alerting
- Branche `main` protégée + CI obligatoire
- GitHub Actions `ci.yml` : lint/test anti-dup/Trello diff
- `trello-sync.yml` : cron `0 */6 * * *` + dispatch manuel, crée issue si échec

## Artefacts & Templates
- `SPRINT_CHECKLIST.md` : Definition of Ready/Done + revue sprint.
- `trello_board_template.json` : import JSON/CSV power-up → lists Backlog/ToDo/In Progress/Done pré-remplies.
- `data/trello_sample.json` : fixture pour tester `trello_update.py`.
- `docker-compose.yml` + `docker/anomaly-demo/Dockerfile` : exécution rapide du PoC ML.

## Ressources complémentaires
- [Trello API](https://developer.atlassian.com/cloud/trello/)
- [GitHub Projects JSON import](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/importing-data-into-projects)
- [Zero Trust Reference](https://cloud.google.com/zero-trust)
