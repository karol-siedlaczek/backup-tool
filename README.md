# Little doc

### Common config params

| Parameter | Description |
|:----------|:------------|
| `nagios.host` |  |
| `nagios.port` |  |
| `nagios.host_service` |  |
| `nagios.run_service` |  |
| `nagios.cleanup_service` |  |
| `influx.host` |  |
| `influx.port` |  |
| `influx.user` |  |
| `influx.database` |  |
| `influx.password_file` |  |
| `influx.verify_ssl` |  |
| `files.log` |  |
| `files.hosts` |  |
| `files.run_state` |  |
| `files.cleanup_state` |  |
| `dirs.backups` |  |
| `dirs.works` | Working directory when backup tool will expect push backups, so if `work_dir` is `/var/backups` backup for e.g. `target-03` should be uploaded to `/var/backup/target-03/` |
| `dirs.scripts` |  |

### Target config params
| Parameter | Purpose | Description |
|:----------|:--------|:------------|
| `format` | Default / Target | Available options: `raw`, `package`, `compressed_package`, `encrypted_package` |
| `owner` | Default / Target | User who will own the backup |
| `max_num` | Default / Target | Define quota for backups in number |
| `permissions` | Default / Target | Permissions which will be set on backup |
| `max_size` | Default / Target | Define quota for backups in size in format `<digit><B\|KB\|MB\|GB\|TB>`, e.g. 20GB, 100MB, 1TB |
| `encryption_key` | Default / Target | Encryption key which will be use to encrypt backup if format `encrypted_packaged` has been chosen |
| `type` | Target | Available options: `pull` and `push` |
| `dest` | Target | Destination where backups will be stored under `common.dirs.backups` directory, if not defined default will be target name |
| `pre_hooks` | Target | Custom commands which will run before backup create |
| `rsync_port` | Pull target | Rsync port, default is `873` |
| `password_file` | Pull target | Password file which should contains rsync password |
| `timeout` | Pull target | Timeout in seconds to establish rsync connection |
| `exclude` | Pull target | Paths to exclude in rsync |
| `sources` | Pull target | Rsync sources |
| `frequency` | Push target | Frequency in hours when the backup tool except backups to be uploaded from external source. Hours needs to defined in format `<digit><d>\|<w>\|<m>`, e.g. 3d (3 days), 2w (2 weeks), 120m (120 minutes) |

## Example
```yaml
common:
  nagios:
    host: nagios.example.com
    port: 5667
    host_service: Backup server
    run_service: Backup status
    cleanup_service: Backup cleanup status

  influx:
    host: influx.example.com
    port: 8086
    user: backup_user
    database: backup
    password_file: /etc/backup-tool/secrets/.influxpass
    verify_ssl: false

  files:
    log: /var/log/backup-tool.log
    hosts: /etc/hosts
    run_state: /etc/backup-tool/run-state.yaml
    cleanup_state: /etc/backup-tool/cleanup-state.yaml

  dirs:
    backups: /var/backups/backups
    work: /var/backups/work-dir
    scripts: /etc/backup-tool/scripts

default:
  format: package 
  owner: root
  password_file: /etc/backup-tool/secrets/.rsyncpass
  encryption_key: SOME_KEY
  permissions: 600
  max_size: 100GB
  timeout: 5
  exclude:
    - /proc
    - /sys
    - /dev
    - /run
    - /tmp
    - /var/run
    - /var/cache/apt
    - /var/lib/lxcfs
    - /var/lib/docker/overlay2
    - .cache
    - "*.sock"

# All parameters under "default" markup will be appended to below target options (if it is not overwritten)
targets:
  target-01:
    dest: target01/noice_backup
    type: pull
    sources:
      - /etc
      - /root
      - /var
      - /mnt
      - /home
      - /usr
    max_size: 200GB
  
  target-02: # Will be stored in <common.dirs.backups>/<target_name>
    type: pull
    sources:
      - /etc
    exclude:
      - /etc/rsyncd.secrets # Will overwrite default exclude
    max_size: 1GB

  target-03:
    type: push
    dest: target-03/backups
    max_size: 25GB
    frequency: 15h
```
