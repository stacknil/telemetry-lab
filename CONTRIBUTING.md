# Contributing

Thanks for the interest. This is a solo-maintainer portfolio repository, so the most helpful contributions are small, scoped, and easy to review.

## Good Contributions

- bug reports with exact commands, configs, and sample inputs
- docs fixes when README behavior drifts from the actual CLI
- small tests around time parsing, window boundaries, and alert thresholds
- narrowly scoped pull requests that keep the repository local and file-based

## Before Opening A Pull Request

- keep the project boundary honest: this is not a production monitoring system
- prefer fixing or clarifying existing behavior over adding large new subsystems
- update README or docs if a user-visible command, output, or artifact changes
- run:

  ```bash
  python -m pip install -e .
  pytest
  ```

If you want to propose a larger demo or roadmap item, opening an issue first is the easiest path.
