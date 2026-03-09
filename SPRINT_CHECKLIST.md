# Sprint Checklist CyberHealthGuard

## Definition of Ready
- [ ] User story liée à un ticket Trello + GitHub issue (ID aligné)
- [ ] Critères d'acceptation / tests documentés
- [ ] Risques sécurité évalués (Zero Trust, PHI)
- [ ] Logs attendus définis (PROJECT_LOG + CHANGELOG entries)

## Definition of Done
- [ ] Code + tests automatisés verts
- [ ] `scripts/anti_dup.py --strict` sans findings
- [ ] `PROJECT_LOG.md` + `CHANGELOG.md` mis à jour
- [ ] `TRELLO_SYNC.md` régénéré (workflow ou script)
- [ ] Ticket Trello déplacé vers "Done" + GitHub issue fermée
- [ ] Checklist runbook / alerting mise à jour

## Revue sprint
- [ ] Export JSON board Trello pour archive
- [ ] Générer rapport `trello_update.py --check`
- [ ] Mettre à jour roadmap `README.md`
- [ ] Retrospective action items ajoutés au Backlog
