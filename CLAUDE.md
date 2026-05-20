# CLAUDE.md

Guide for AI assistants working in this repository.

## Project Overview

`backup-tool` is a single-file Python 3.7+ CLI for orchestrating backups across multiple targets. It supports two modes — **pull** (rsync from a source) and **push** (wait for files in a working directory) — and reports outcomes to Nagios via NSCA and pushes metrics to InfluxDB or VictoriaMetrics. The whole implementation lives in `backup-tool.py` (~1700 LOC, OOP, Python stdlib + 3 deps).

## Repository Layout

- `backup-tool.py` — entire implementation (entry point + all classes)
- `backup-tool.yaml` — sample config. **Out of sync with the current code** (see Known Gaps)
- `scripts/pack_and_encrypt.sh` — `tar | pigz | gpg2` wrapper used by the `encrypted-package` format
- `requirements.txt` — `requests`, `PyYAML`, `influxdb`
- `README.md` — user-facing docs
- `run-state.yaml`, `cleanup-state.yaml`, `validation-state.yaml`, `push-metrics-state.yaml` — generated under `common.path.state`

## Code Architecture (`backup-tool.py`)

Enums (canonical lists of valid values, lines 26–91):
- `Action` — `run`, `cleanup`, `validate`, `push-metrics`, `conf-check`
- `BackupType` — `pull`, `push`
- `Format` — `raw`, `package`, `compressed-package`, `encrypted-package`
- `MetricServerProvider` — `influx`, `victoria-metrics`
- `Nagios` — `OK=0`, `WARNING=1`, `CRITICAL=2`, `UNKNOWN=3`
- `RequiredCommonParams` (`:43-64`) — **authoritative config schema**

Exception hierarchy (`:109-129`), each carries a Nagios code:
- `TargetError` → CRITICAL · `TargetWarning` → WARNING · `TargetSkipException` → OK · `TargetCleanupError`

Domain classes:
- `Backup` (`:394`) — represents one backup directory/archive (name `backup-YYYY-MM-DD_HH-MM`)
- `Validator` (`:553`) — centralized config/param validation
- `Target` (`:620`) base → `PullTarget` (`:997`, rsync) and `PushTarget` (`:1104`, work-dir watcher)
- `MetricServer` (`:131`) — Influx + VictoriaMetrics push
- `NagiosServer` (`:369`) — NSCA report
- `State` (`:1179`) base → `RunState`, `CleanupState`, `ValidateState`, `PushMetricsState` (all YAML-backed)

Main loop at `:1510` loads YAML, validates `common`, dispatches per action, catches `TargetException` per target so one failure doesn't stop the rest.

## Entry Point & Actions

`./backup-tool.py <action> [opts]`

| Action | Purpose | Required flags |
|---|---|---|
| `run` | Create backups | `-t/--targets` |
| `cleanup` | Rotate (size/count) | `-t/--targets` |
| `validate` | Detect undersized backups | `-t/--targets` |
| `push-metrics` | Push state to metric server | — |
| `conf-check` | Validate config only | — |

Global: `-c/--conf` (default `/etc/backup-tool/backup-tool.yaml`), `-v` repeat (1=INFO, 2=DEBUG), `--no-report`.
Per-action: `--force` (cleanup, deletes even the last backup), `--skip-frequency` / `-m/--mode {full,inc}` / `--stats-file` (run). `-t all` expands to every defined target.

## Configuration Schema (current code)

Required, validated by `RequiredCommonParams` (`:43-64`):

```yaml
common:
  nagios: { host, port, host_service, run_service, cleanup_service, validation_service, push_metrics_service }
  log_file: <path>
  path: { backup, work, script, state }   # all four directories
  metric_server: { provider, host, port, ... }  # optional, provider ∈ {influx, victoria-metrics}

default:   # inherited by every target unless overridden
  format, owner, permissions, max_size | max_num, encryption_key, password_file, timeout, pre_hooks, exclude

targets:
  <name>:
    type: pull|push
    # pull:  sources (list), exclude, timeout, password_file, rsync_port (873)
    # push:  frequency (e.g. 1h/1d/2w/3m), work_dir derived from common.path.work
    # both:  dest (default: target name), format, owner, permissions, max_size | max_num, pre_hooks
```

`max_size` and `max_num` are mutually exclusive (`:635-643`); at least one is mandatory per target.

## Key Behaviors

- Backup naming: `backup-YYYY-MM-DD_HH-MM`, plus a `latest` symlink updated on each successful run (`:887-891`)
- Cleanup keeps 120% headroom (`cleanup_ratio = 1.2`, `:632`) and refuses to delete the last backup unless `--force`
- Validation flags a backup invalid if its size is < 60% of the average (`min_valid_size_diff_ratio = 0.6`, `:633`)
- Pull uses `rsync -rlptoW --timeout 30 --no-specials --no-devices` (+ `--contimeout/--password-file/--port` when remote, `:1074`)
- Push waits for files in `common.path.work/<target>/` and moves them to `dest/backup-...` only if `frequency` has elapsed (`:1146`)
- Formats: `raw` (dir), `package` (tar), `compressed-package` (tar+pigz), `encrypted-package` (tar+pigz+gpg2 via `scripts/pack_and_encrypt.sh`)
- `pre_hooks` run before backup creation (e.g. stopping a DB)

## Conventions

- Every log line carries `[<target-name>]` via the `record_factory` in `get_logger` (`:1476`). Never log without that context.
- All shell-outs go through `run_cmd()` (`:1493`) — don't call `subprocess` directly.
- Param validation goes through `Validator` static methods (`validate_required_param`, `validate_type`, `validate_port`, `validate_file_exist`, `validate_match`, `validate_allowed_values`, ...).
- Raise the right exception class — its `.code` becomes the per-target Nagios status; misuse skews monitoring.
- State files (under `common.path.state`) are the single source of truth between actions: `push-metrics` reads what `run`/`cleanup`/`validate` wrote.

## External Dependencies

- System binaries: `rsync`, `tar`, `pigz`, `gpg2`, `find`, `du`, `/usr/sbin/send_nsca`, `/bin/echo`
- Python: `requests`, `PyYAML`, `influxdb` (`requirements.txt`)

## Known Gaps / TODO

- **Config schema drift**: `backup-tool.yaml` (and the pre-rewrite `README.md`) used legacy keys (`dirs.*`, `influx.*`, `files.*`) that fail `RequiredCommonParams.validate`. Treat the current `backup-tool.py:43-64` as the source of truth.
- `wake_on_lan` block exists in `backup-tool.yaml` (target `desktop`) but is **not** read anywhere in the code.
- `-m/--mode inc` is declared in `parse_args` but not implemented (`:1430` help text says so).
- VictoriaMetrics log push has a `TODO` (`:354`).
- `run_cmd` has a `TODO` for elapsed-time stats (`:1494`).
- No unit tests, no CI/CD, no `pyproject.toml`/`setup.py` — the script is invoked directly.
- Sparse docstrings and incomplete type hints.

## Common Tasks for AI

- **New backup format** → add to `Format` enum (`:70`) and a branch in `Target.create_backup()` (~`:840`).
- **New metric provider** → add to `MetricServerProvider` (`:83`) and a handler in `MetricServer` (`:131`).
- **New action** → add to `Action` enum (`:76`), add a `State` subclass if it needs persistence, and wire dispatch in the main block (`:1542-1664`).
- **New required common param** → extend `RequiredCommonParams` (`:43`).
- **Touching the CLI** → keep `parse_args` (`:1386`) the single source of truth; document changes in `README.md`.
