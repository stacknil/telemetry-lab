# v0.6.0 Reviewer Pack Manifest

This pack is a small, sanitized reviewer artifact set for `config-change-investigation-demo`.

It is intended for release attachment or offline review. The files are portable, contain no secrets or machine-specific paths, and are representative non-production examples aligned with the demo's public portfolio story.

| File | Path Proven | Source Type | What It Proves |
| --- | --- | --- | --- |
| `benign-change-example.json` | benign change with no investigation | representative sanitized example aligned with committed sample semantics | A benign config change remains normalized input and does not become an investigation |
| `risky-change-with-evidence-example.json` | risky change with nearby evidence | representative sanitized example aligned with committed artifact semantics | A risky config change becomes an explicit investigation with bounded supporting evidence |
| `bounded-case-no-evidence-example.json` | risky change with bounded case but no nearby evidence | representative sanitized example aligned with committed artifact semantics | A risky config change still produces a visible investigation even when bounded correlation finds zero nearby evidence |
| `investigation-summary-example.json` | reduced summary path | representative sanitized example aligned with committed artifact semantics | The reduced summary preserves deterministic counts and the same bounded-correlation explanation |
