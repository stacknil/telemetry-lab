# Sample Output

The committed sample artifacts are intended to be reproducible from the bundled inputs and configs.

## Default Sample

Running `python -m telemetry_window_demo.cli run --config configs/default.yaml` produces:

- a window feature table at `data/processed/features.csv`
- an alert table at `data/processed/alerts.csv`
- a machine-readable summary at `data/processed/summary.json`
- three timeline plots under `data/processed/`

On the bundled default sample dataset, the current repo state produces:

- `41` normalized events
- `24` sliding windows
- `12` alerts after a `60` second cooldown

The default summary currently reports these triggered rule counts:

- `high_error_rate`: `3`
- `persistent_high_error`: `3`
- `high_severity_spike`: `2`
- `login_fail_burst`: `2`
- `source_spread_spike`: `1`
- `rare_event_repeat_malware_alert`: `1`

## Richer Sample

Running `python -m telemetry_window_demo.cli run --config configs/richer_sample.yaml` produces:

- a window feature table at `data/processed/richer_sample/features.csv`
- an alert table at `data/processed/richer_sample/alerts.csv`
- a machine-readable summary at `data/processed/richer_sample/summary.json`
- three timeline plots under `data/processed/richer_sample/`

On the richer bundled sample dataset, the current repo state produces:

- `28` normalized events
- `24` sliding windows
- `8` alerts after a `120` second cooldown

Representative alert categories across the bundled samples:

- elevated error rate during the login failure burst
- repeated high-severity events around `malware_alert`
- sudden source spread as the number of distinct sources increases in the default sample
- repeated rare-event alerts for both `malware_alert` and `policy_denied` in the richer sample

See the committed PNGs under `data/processed/` and `data/processed/richer_sample/` for GitHub-visible output snapshots.
