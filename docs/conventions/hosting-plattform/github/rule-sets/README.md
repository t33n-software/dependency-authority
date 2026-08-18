# Hosting-Plattform: GitHub — Rule-Sets
[INTENT: REFERENZ]

## Kanonische Quelle

Die GitHub-Rule-Sets für die Organisation `t33n-software` werden einmalig und
zentral im Repository
[`git-governance`](https://github.com/t33n-software/git-governance) unter
`rulesets/github/` definiert und verwaltet. Dieses Repository ist die
kanonische Quelle der Wahrheit für die JSON-Definitionen: Es erklärt die
Architektur, setzt die Definitionen und liefert die versionierten,
importierbaren Artefakte.

Eine lokale Kopie, Neudefinition oder Abweichung in diesem Repository ist ein
Anti-Pattern und verboten (Redundanz- und Drift-Verbot). Erlaubt sind
ausschließlich benannte, auditierbare Repository-Ausnahmen, die restriktiver
als die Organisations-Grundlage sind, niemals schwächer.

## Verwendete Familie

Dieses Projekt (`dependency-authority`) verwendet die Familie
**`quality-gates=linux-only`**:

- Die Quality Gates laufen ausschließlich für **Linux**.
- Architektonische Begründung: Dieses Projekt liefert reine
  Linux-/Container-/CI-/CD-Artefakte; die fünf Lane-Controller werden
  ausschließlich für Linux/AMD64 gebaut und verifiziert. Es existieren keine
  betriebssystemspezifischen Binaries, daher ergeben Windows-/macOS-Gates
  keinen Kontrollwert.

## Gebundene Rule-Sets

| Rule-Set | Klasse |
|---|---|
| `push-protections: secret artifact boundary` | klassenlos (private/interne Sichtbarkeit) |
| `branch-governance: ticket working branches` | klassenlos (`~ALL`) |
| `branch-governance: develop shared line (quality-gates=linux-only)` | linux-only |
| `branch-governance: main shared line (quality-gates=linux-only)` | linux-only |
| `branch-governance: release shared lines (quality-gates=linux-only)` | linux-only |
| `branch-governance: support shared lines (quality-gates=linux-only)` | linux-only |

## Verwaltung

- Verwaltungsebene: die **Organisation** (`t33n-software`), niemals die
  einzelne Repository-Ebene.
- Klassenmitgliedschaft dieses Repositorys: Custom Property
  `quality-gates=linux-only`.
- Änderungen an den Rule-Sets erfolgen ausschließlich im kanonischen
  Repository und werden danach auf Organisationsebene re-importiert
  (Organisation Settings → Repository → Rulesets).
