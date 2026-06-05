# backup-tool

Automated backup orchestration for multiple targets, with Nagios reporting and InfluxDB / VictoriaMetrics integration. A single Python 3 CLI that pulls data over rsync or accepts pushed files into a working directory, rotates and validates backups, and ships the results to your monitoring stack.

## Features

- Two backup modes: **pull** (rsync from remote/local sources) and **push** (wait for files in a working directory, on a schedule)
- Four storage formats: `raw`, `package` (tar), `compressed-package` (tar + pigz), `encrypted-package` (tar + pigz + gpg2)
- Retention by total size (`max_size`) or backup count (`max_num`), with a safety margin and last-backup protection
- `latest` symlink kept up to date on every successful run
- Validation pass that flags backups whose size deviates from the running average
- Per-target `pre_hooks` (e.g. dump a database, stop a service)
- Reporting to Nagios via NSCA and metric push to InfluxDB or VictoriaMetrics
- YAML configuration with inheritable defaults and per-target overrides

## Requirements

- Python **3.7+**
- System binaries on the backup host:
  - `rsync` (pull mode), `tar`, `pigz` (compressed/encrypted format), `gpg2` (encrypted format)
  - `find`, `du`
  - `/usr/sbin/send_nsca` and `/bin/echo` (for Nagios reporting)
- Python dependencies (see `requirements.txt`):
  - `requests`, `PyYAML`, `influxdb`

## Installation

```bash
git clone <repo-url> /opt/backup-tool
cd /opt/backup-tool
pip install -r requirements.txt
chmod +x backup-tool.py

# Default config location
sudo install -d /etc/backup-tool
sudo cp backup-tool.yaml /etc/backup-tool/backup-tool.yaml
# Edit /etc/backup-tool/backup-tool.yaml to match your environment
```

## Quick Start

```bash
# 1. Validate the configuration
./backup-tool.py conf-check -c /etc/backup-tool/backup-tool.yaml

# 2. Run a single target in verbose mode
./backup-tool.py run -c /etc/backup-tool/backup-tool.yaml -t my-target -vv

# 3. Once happy, run all targets
./backup-tool.py run -c /etc/backup-tool/backup-tool.yaml -t all
```

## Configuration

The configuration is a single YAML file with three top-level sections: `common`, `default`, and `targets`.

### `common`

| Key | Required | Description |
|---|---|---|
| `nagios.host` | yes | NSCA server hostname |
| `nagios.port` | yes | NSCA server port (typically `5667`) |
| `nagios.host_service` | yes | Nagios host name |
| `nagios.run_service` | yes | Nagios service for the `run` action |
| `nagios.cleanup_service` | yes | Nagios service for the `cleanup` action |
| `nagios.validation_service` | yes | Nagios service for the `validate` action |
| `nagios.push_metrics_service` | yes | Nagios service for the `push-metrics` action |
| `log_file` | yes | Absolute path to the log file |
| `path.backup` | yes | Root directory where backups are stored |
| `path.work` | yes | Working directory for push targets (per-target subdir is auto-created) |
| `path.script` | yes | Directory containing helper scripts (e.g. `pack_and_encrypt.sh`) |
| `path.state` | yes | Directory for state files (`run-state.yaml` etc.) |
| `metric_server.provider` | no | `influx` or `victoria-metrics` |
| `metric_server.host` | if provider | Metric server host |
| `metric_server.port` | if provider | Metric server port |
| `metric_server.user` | influx | InfluxDB user |
| `metric_server.password_file` | no | File with the metric server password |
| `metric_server.database` | influx | InfluxDB database |
| `metric_server.ssl` | no | Use HTTPS (InfluxDB) |
| `metric_server.verify_ssl` | no | Verify TLS certificate |

### `default`

Any option listed under `default` is inherited by every target unless the target overrides it.

| Key | Description |
|---|---|
| `format` | `raw` / `package` / `compressed-package` / `encrypted-package` |
| `owner` | User that will own the resulting backup |
| `permissions` | Octal permission mask (e.g. `600`) |
| `max_size` | Quota by size — `<digit><B\|KB\|MB\|GB\|TB>` (e.g. `100GB`). Mutually exclusive with `max_num` |
| `max_num` | Quota by count (integer). Mutually exclusive with `max_size` |
| `encryption_key` | GPG recipient key ID, used by `encrypted-package` |
| `password_file` | File holding the rsync password for pull targets |
| `timeout` | rsync connection timeout in seconds |
| `pre_hooks` | List of shell commands to run before the backup is created |
| `exclude` | List of rsync `--exclude` patterns (pull targets) |

### `targets`

Common to both target types: `type` (`pull` / `push`), `dest` (relative path under `common.path.backup`, defaults to the target name), plus any of the `default` keys above.

| Pull-only key | Description |
|---|---|
| `sources` | List of rsync sources (local paths or `rsync://user@host/path`) |
| `rsync_port` | Custom rsync port (default `873`) |
| `timeout` | Override `default.timeout` |
| `password_file` | Override `default.password_file` |
| `exclude` | Override `default.exclude` (full replacement, not append) |

| Push-only key | Description |
|---|---|
| `frequency` | Minimum interval between backups, `<digit><h\|d\|w\|m>` (e.g. `15h`, `1d`, `2w`, `3m`). The tool watches `common.path.work/<target>/` and only consumes files once the interval has elapsed |

### Complete example

```yaml
common:
  nagios:
    host: nagios.example.com
    port: 5667
    host_service: Backup server
    run_service: Backup status
    cleanup_service: Backup cleanup status
    validation_service: Backup validation status
    push_metrics_service: Backup metrics status
  log_file: /var/log/backup-tool.log
  path:
    backup: /var/backups/backups
    work: /var/backups/work-dir
    script: /etc/backup-tool/scripts
    state: /var/lib/backup-tool
  metric_server:
    provider: influx
    host: influx.example.com
    port: 8086
    user: backup_user
    database: backup
    password_file: /etc/backup-tool/secrets/.influxpass
    verify_ssl: false

default:
  format: package
  owner: root
  permissions: 600
  password_file: /etc/backup-tool/secrets/.rsyncpass
  encryption_key: SOME_GPG_KEY_ID
  max_size: 100GB
  timeout: 5
  exclude:
    - /proc
    - /sys
    - /dev
    - /run
    - /tmp
    - /var/cache/apt
    - /var/lib/docker/overlay2
    - .cache
    - "*.sock"

targets:
  mgmt:
    type: pull
    sources:
      - /etc
      - /root
      - /var/backups
      - /home

  remote-server:
    type: pull
    sources:
      - rsync://backup_user@remote.example.com/etc
      - rsync://backup_user@remote.example.com/home
    exclude:
      - Downloads
    max_size: 50GB
    timeout: 120

  database-dumps:
    type: push
    dest: psql/main
    frequency: 1d
    max_num: 14
```

## Actions

```bash
./backup-tool.py <action> [options]
```

| Action | Purpose |
|---|---|
| `run` | Create new backups for the given targets |
| `cleanup` | Rotate backups according to `max_size` / `max_num` |
| `validate` | Check backup sizes against the per-target average |
| `push-metrics` | Push the latest state to the metric server |
| `conf-check` | Validate the YAML configuration and exit |

Common options:

| Option | Applies to | Description |
|---|---|---|
| `-c`, `--conf <path>` | all | Path to config file. Default: `/etc/backup-tool/backup-tool.yaml` |
| `-v`, `-vv`, `-vvv` | all | Verbosity (`-v` = INFO, `-vv` = DEBUG, `-vvv` = DEBUG + tracebacks) |
| `--no-report` | all | Skip the NSCA report at the end of the run |
| `-t`, `--targets <name...>` | `run`, `cleanup`, `validate` | Target list or `all` |
| `-x`, `--exclude <name...>` | `run`, `cleanup`, `validate` | Targets to exclude from `--targets` (e.g. `-t all -x desktop`) |
| `--force` | `cleanup` | Allow deleting the last remaining backup |
| `--skip-frequency` | `run` | Ignore the `frequency` gate on push targets |
| `-m`, `--mode {full,inc}` | `run` | Reserved (only `full` is implemented today) |
| `--stats-file <path>` | `run` | Write rsync stats and progress to this file |

Examples:

```bash
./backup-tool.py run -c /etc/backup-tool/backup-tool.yaml -t mgmt remote-server
./backup-tool.py run -c /etc/backup-tool/backup-tool.yaml -t all -x desktop
./backup-tool.py cleanup -c /etc/backup-tool/backup-tool.yaml -t all --force
./backup-tool.py validate -c /etc/backup-tool/backup-tool.yaml -t all
./backup-tool.py push-metrics -c /etc/backup-tool/backup-tool.yaml
./backup-tool.py conf-check -c /etc/backup-tool/backup-tool.yaml
```

## Cron Setup

```cron
# /etc/cron.d/backup-tool
0 2 * * *  root  /opt/backup-tool/backup-tool.py run -c /etc/backup-tool/backup-tool.yaml -t all
0 3 * * *  root  /opt/backup-tool/backup-tool.py cleanup -c /etc/backup-tool/backup-tool.yaml -t all
0 4 * * 0  root  /opt/backup-tool/backup-tool.py validate -c /etc/backup-tool/backup-tool.yaml -t all
0 * * * *  root  /opt/backup-tool/backup-tool.py push-metrics -c /etc/backup-tool/backup-tool.yaml
```

## Monitoring Integration

### Nagios (NSCA)

After each action the tool computes the worst per-target status and sends a passive check result to NSCA:

| Action | Nagios service used |
|---|---|
| `run` | `common.nagios.run_service` |
| `cleanup` | `common.nagios.cleanup_service` |
| `validate` | `common.nagios.validation_service` |
| `push-metrics` | `common.nagios.push_metrics_service` |

Status codes mirror Nagios conventions: `OK=0`, `WARNING=1`, `CRITICAL=2`, `UNKNOWN=3`. Use `--no-report` to suppress the report (useful for ad-hoc runs).

### Metrics (InfluxDB / VictoriaMetrics)

`push-metrics` reads the latest `run-state.yaml`, `cleanup-state.yaml`, and `validation-state.yaml` files from `common.path.state` and sends them to the configured `metric_server` under the `backup_tool` measurement. Typical fields include backup size, copy/pack duration, throughput, last-success timestamp, recovered bytes on cleanup, average size on validation, and per-target Nagios status.

## Backup Formats

| Format | What it produces |
|---|---|
| `raw` | The directory as-is (no archiving) |
| `package` | `tar` archive |
| `compressed-package` | `tar` piped through `pigz` (parallel gzip) |
| `encrypted-package` | `tar | pigz | gpg2 --encrypt -r <encryption_key>` via `scripts/pack_and_encrypt.sh` |

For `encrypted-package` you must provide `encryption_key` (a GPG recipient key already in your keyring) at either the `default` or target level.

## Troubleshooting

- **Logs** — `common.log_file` (set verbosity with `-v`/`-vv`/`-vvv`). Every line is tagged with the target name in `[brackets]`.
- **State files** — inspect `<common.path.state>/{run,cleanup,validation,push-metrics}-state.yaml` for the last per-target result.
- **`Section 'common' is not defined` / missing required params** — the YAML schema changed; ensure your config uses `common.path.*`, `common.log_file`, and all seven `nagios.*` keys (see Configuration above).
- **`Target not defined in config file`** — the `-t` name does not match any key under `targets:`.
- **`Target must have defined at least one parameter which declares limitations`** — set `max_size` or `max_num` (target or default level).
- **rsync timeout / authentication errors** — verify `password_file` permissions (`600`), `rsync_port`, and reachability to the source.
- **NSCA failures** — confirm `/usr/sbin/send_nsca` is installed and reachable; you can pass `--no-report` to bypass it for a single run.

## Known Limitations

- The sample `backup-tool.yaml` shipped in this repository uses **legacy configuration keys** (`dirs.*`, `influx.*`, `files.*`) and will not pass `conf-check` against the current code. Use the schema documented above; the legacy sample will be migrated in a follow-up change.
- `--mode inc` is accepted on the command line but **incremental backups are not implemented** — only `full` works today.
- A `wake_on_lan` block accepted in some configurations is currently **not honoured** by the code.
- VictoriaMetrics metric push is supported; log streaming to VictoriaMetrics is **not implemented yet**.
- No unit tests, no CI/CD pipeline, and no installable package (`pyproject.toml` / `setup.py`).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
