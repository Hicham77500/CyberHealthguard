# CyberHealthGuard — Fil Rouge Sécurité Médico-Social

> **Usage** : Ce fichier est la référence de continuité du projet.
> Avant tout nouveau développement, consulter ce document pour connaître les priorités, l'état d'avancement et les conventions.
> Dernière mise à jour : 2026-05-29

---

## État des sprints réalisés

| Sprint | Tickets | Statut |
|--------|---------|--------|
| Sprint 1 | CHG-021 Log Generator | ✅ Terminé — commit `648a222` |
| Sprint 2 | CHG-022 Validator + CHG-023 Feature Engineering | ✅ Terminé — commit `08eaedf` |
| Sprint 3 | CHG-024 Risk Scoring + CHG-025 Alert Manager + CHG-026 Experiment Tracker | ✅ Terminé — commit `967e412` |
| Sprint 4 | CHG-027 Dashboard HTML bilingue + CHG-028 Tests pytest 67/67 + `run_pipeline.py` | ✅ Terminé — commit `ce23938` |
| Sprint 5 | CHG-029 NIS2 Reporter + CHG-030 Audit Trail SHA-256 | ✅ Terminé — commit `3180fb1` |

---

## Modules existants

| Fichier | Rôle | Notes clés |
|---------|------|------------|
| `src/collector/log_generator.py` | Génère des logs JSONL synthétiques | 19 types d'événements, 8 anomalies santé |
| `src/validator/dataset_validator.py` | Valide les fichiers JSONL avant ML | schéma, types, severity [1-5], ISO 8601, doublons |
| `src/features/feature_engineering.py` | Transforme les logs en matrice de features | 11 features : temporelles, catégorielles, UEBA |
| `src/ml/anomaly_demo.py` | IsolationForest (contamination=0.08) | AUC-ROC = 0.8057 atteint |
| `src/scoring/risk_scoring.py` | Score composite 0-100 | 4 niveaux : Low/Medium/High/Critical |
| `src/alerts/alert_manager.py` | Génère des alertes JSON structurées | 6 types d'alertes, tri par score |
| `src/compliance/nis2_reporter.py` | Rapport NIS2 Art.23 + PGSSI-S | SHA-256 signé, export JSON + HTML, délais 24h/72h |
| `src/compliance/audit_trail.py` | Piste d'audit immuable JSONL SHA-256 | Chaîne vérifiable, mapping PGSSI-S, CLI verify/export |
| `src/reporting/report_generator.py` | Dashboard HTML bilingue EN/FR | dark theme, localStorage lang preference |
| `scripts/run_pipeline.py` | Orchestrateur 7 étapes | < 0.5 s sur 12 000 événements |

---

## Résultats sur données réelles (12 000 événements)

- Validation : 0 erreur, 0 warning
- Anomalies détectées : 58 (seuil 0.75)
- Critical = 9 | High = 1 589 | Medium = 6 949 | Low = 3 453
- Alertes générées : 1 598 (seuil 51.0)
- AUC-ROC : **0.8057** (objectif Sprint 2 ≥ 0.80 ✅)

---

## Roadmap sécurité — Menaces médico-social

### 🔴 Sprint 5 — Conformité réglementaire ✅ TERMINÉ

> **Pourquoi en premier** : NIS2 (applicable depuis oct. 2024) oblige la notification à l'ANSSI sous **24h**. Sans rapport structuré, tout le pipeline est inutilisable en production réelle.

| Ticket | Livrable | Description |
|--------|----------|-------------|
| **CHG-029** | `src/compliance/nis2_reporter.py` | Rapport d'incident structuré ANSSI/CERT Santé. Champs obligatoires : identifiant incident, périmètre impacté, données de santé concernées, mesures prises, date de détection. Export JSON + PDF-ready HTML. |
| **CHG-030** | `src/compliance/audit_trail.py` | Piste d'audit complète et immuable (qui/quoi/quand/où). Append-only JSONL signé (hash SHA-256 chaîné). Mapping alertes → exigences PGSSI-S. |

**Références** : PGSSI-S v2 (ANSSI), Directive NIS2 (UE 2022/2555), Référentiel HDS (ANS).

---

### ✅ Sprint 6 — Détection avancée des menaces (TERMINÉ)

| Ticket | Livrable | Description |
|--------|----------|-------------|
| **CHG-031** | `src/detector/ransomware_detector.py` | Détection ransomware : masse de modifications fichiers en rafale, calcul d'entropie des fichiers modifiés (entropie > 7.5 = suspect), corrélation avec IOC connus (LockBit, BlackCat, Rhysida). Feature : `file_entropy_spike`, `mass_rename_score`. |
| **CHG-032** | `src/detector/travel_detector.py` | Impossible travel + new IP. Feature `impossible_travel` (même user, 2 localisations à delta_t < 30 min), feature `new_ip_for_user` (première connexion depuis cet IP dans les 30 derniers jours). |
| **CHG-033** | `src/detector/lateral_movement.py` | Graphe d'accès utilisateur/ressource. Détection de reconnaissance interne (scans, requêtes LDAP massives), escalade de privilèges (changement brutal de `user_role`), matrice d'adjacence pour détecter les déplacements latéraux. |

---

### ✅ Sprint 7 — UEBA avancé (Behavioral Baselines) (TERMINÉ)

| Ticket | Livrable | Description |
|--------|----------|-------------|
| **CHG-034** | `src/features/behavioral_baseline.py` | Baseline comportementale glissante sur 30 jours par utilisateur. Score de déviation vs. baseline. Comparaison avec groupe de pairs (ex : tous les infirmiers d'un service). Détection de dérive progressive. |
| **CHG-035** | `src/features/feature_engineering.py` (extension) | Nouvelles features : `cross_department_access` (accès hors périmètre habituel), `velocity_score` (nb d'accès par heure vs. baseline), `peer_group_deviation` (z-score vs. groupe de pairs). |

---

### 🟠 Sprint 8 — Temps réel & Intégrations

| Ticket | Livrable | Description |
|--------|----------|-------------|
| **CHG-036** | `src/streaming/pipeline_stream.py` | Pipeline en fenêtre glissante (sliding window 5 min). Traitement quasi-temps réel des logs entrants sans relancer le pipeline complet. |
| **CHG-037** | `src/notifications/webhook_notifier.py` | Alertes push : webhook Slack / Teams / email SMTP. Déclenchement sur Critical ou score > seuil configurable. Template HTML d'email bilingue EN/FR. |
| **CHG-038** | Export syslog / API REST | Format syslog (RFC 5424) pour intégration SIEM externe (Wazuh, Elastic SIEM). Endpoint REST minimal (Flask) pour interroger les alertes par API. |

---

### 🟡 Sprint 9 — IoMT (Internet of Medical Things)

| Ticket | Livrable | Description |
|--------|----------|-------------|
| **CHG-039** | `src/collector/iomt_collector.py` | Collecte des logs équipements médicaux connectés. Protocoles : HL7 v2, DICOM, FHIR R4. Feature `device_type_risk` (pompe à perfusion > IRM > moniteur). |
| **CHG-040** | `src/detector/iomt_anomaly.py` | Détection d'anomalies spécifiques IoMT : communication inattendue entre équipements, firmware hors version référence, accès depuis IP externe sur port DICOM. |

---

## Conventions à respecter (REGLES 1)

> Ces règles s'appliquent à **tous les sprints**. Les relire avant de coder.

- `from __future__ import annotations` en tête de chaque module
- `pathlib.Path` uniquement (jamais `os.path`)
- `raise SystemExit(main())` comme point d'entrée
- Type hints sur toutes les fonctions publiques
- Retourner `int` depuis `main()`
- Français dans les scripts d'automation, Anglais dans le code ML/détection
- Tests pytest obligatoires pour chaque nouveau module (`tests/test_<module>.py`)
- Mettre à jour `data/trello_sample.json` + régénérer `TRELLO_SYNC.md` à chaque sprint
- Mettre à jour `PROJECT_LOG.md` + `CHANGELOG.md` avant chaque commit
- Commit avec `SKIP_LOG_CHECK=1` quand PROJECT_LOG + CHANGELOG sont dans le même commit
- Push vers `github.com:Hicham77500/CyberHealthguard.git` (branche `main`)

---

## Architecture cible

```
src/
├── collector/          # Ingestion des logs (JSONL, HL7, DICOM)
├── validator/          # Validation des données entrantes
├── features/           # Feature engineering + behavioral baselines
├── ml/                 # Modèles ML (IsolationForest, extensions)
├── detector/           # Détecteurs spécialisés (ransomware, lateral, travel)
├── scoring/            # Risk scoring engine
├── alerts/             # Alert manager
├── tracking/           # Experiment tracking
├── compliance/         # NIS2 / PGSSI-S / audit trail
├── streaming/          # Pipeline temps réel
├── notifications/      # Webhooks / email
└── reporting/          # Dashboard HTML bilingue
scripts/
├── run_pipeline.py     # Orchestrateur principal (7 étapes)
└── run_pipeline_stream.py  # Orchestrateur temps réel (Sprint 8)
tests/
└── test_<module>.py    # 1 fichier par module src/
artifacts/
├── features.csv
├── risk_scores.csv
├── alerts.json
├── risk_summary.json
├── validation_report.json
├── experiments.jsonl
└── dashboard.html
```

---

## Priorité de démarrage du prochain sprint

```
1. CHG-029 — NIS2 Reporter  ← commencer ici
2. CHG-030 — Audit Trail
3. CHG-031 — Ransomware Detector
4. CHG-032 — Impossible Travel
```
