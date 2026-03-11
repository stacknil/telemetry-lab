# Sample Output

Running the default pipeline produces:

- a window feature table at `data/processed/features.csv`
- an alert table at `data/processed/alerts.csv`
- three timeline plots under `data/processed/`

On the bundled sample dataset, the default config produces:

- `41` input events
- `24` sliding windows
- `53` alerts across rule categories

The sample is intentionally bursty so the plots and alerts are visually obvious in a portfolio setting.

Representative alert categories in the sample dataset:

- elevated error rate during the login failure burst
- repeated high-severity events around `malware_alert`
- sudden source spread as the number of distinct sources increases

See the generated assets in `assets/` for README-friendly screenshots.
