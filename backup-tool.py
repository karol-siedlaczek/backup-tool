#!/usr/bin/env python3

import re
import os
import sys
import pwd
import grp
import yaml
import math
import argparse
from glob import glob
from influxdb import InfluxDBClient
from inspect import isclass
from datetime import datetime, timedelta
from wakeonlan import send_magic_packet
import subprocess
import logging

DEFAULTS = {
    'LOG_LEVEL': 1,
    'CONFIG_FILE': '/etc/backup-tool/backup-tool.yaml',
    'REQUIRED_COMMON_PARAMS': ['nsca_host', 'nsca_port', 'nagios_host', 'nagios_backup_service', 'nagios_cleanup_service', 'base_dest', 'log_file', 'hosts_file', 'backup_state_file', 'cleanup_state_file', 'work_dir'],
    'FORMATS': {
        'PACKAGE': 'package',
        'ENCRYPTED_PACKAGE': 'encrypted_package',
        'RAW': 'raw'
    },
    'BACKUP_TYPES': {
        'PUSH': 'push',
        'PULL': 'pull'
    }
}

NAGIOS = {
    'OK': 0,
    'WARNING': 1,
    'CRITICAL': 2,
    'UNKNOWN': 3
}

class TargetException(Exception):
    __slots__ = ['code']
    
    def __init__(self, code) -> None:
        self.code = code


class TargetError(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(NAGIOS['CRITICAL'])
        log.error(msg)


class TargetWarning(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(NAGIOS['WARNING'])
        log.warning(msg)


class TargetSkipException(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(NAGIOS['OK'])
        log.info(msg)


class TargetCleanupError(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(NAGIOS['CRITICAL'])
        log.error(msg)
    

class Cmd():
    __slots__ = ['output', 'code', 'failed']
    
    def __init__(self, output, code) -> None:
        self.output = output
        self.code = code
        self.failed = code > 0
    
    @classmethod
    def run(cls, cmd):
        process = subprocess.run(cmd, stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
        return_code = process.returncode
        output = process.stderr if process.stderr else process.stdout
        return cls(output.decode('utf-8').replace('\n', ' '), return_code)


class Influx():  # TODO - Setup pushing stats to influx
    __slots__ = ['client']
    
    def __init__(self, host, port, user, password_file, database) -> None:
        if not os.path.isfile(password_file):
            raise FileNotFoundError(f"File with password to connect {host}:{port} influx server does not exist or not valid file")
        elif os.stat(password_file).st_size == 0:
            raise OSError(f"File with password to connect {host}:{port} influx server is empty, provide single line with password")
        with open(password_file, 'r') as f:
            password = f.read().strip()
        self.client = InfluxDBClient(host, port, user, password, database)
        self.client.ping()
            

class Nsca():
    __slots__ = ['bin', 'nagios_hosts', 'nagios_host', 'nagios_service', 'host', 'port']
    
    def __init__(self, nagios_host, nagios_service, host, port) -> None:
        self.bin = '/usr/sbin/send_nsca'
        self.nagios_host = nagios_host
        self.nagios_service = nagios_service
        self.host = host
        self.port = port
    
    def send_report_to_nagios(self, code, msg) -> None:
        cmd = f"echo -e '{self.nagios_host}\t{self.nagios_service}\t{code}\t{msg}' | {self.bin} -H {self.host} -p {self.port}"
        result = Cmd.run(cmd)
        if result.failed:
            raise ConnectionError(f"Sending nsca packet to {self.host}:{self.port} failed: {result.output}")
        
    @staticmethod
    def get_status_by_code(code) -> str:
        for nagios_status, nagios_code in NAGIOS.items():
            if code == nagios_code: return nagios_status
        return 'UNKNOWN'
  
           
class State():
    __slots__ = ['state_file', 'state']
    
    def __init__(self, state_file) -> None:
        self.state_file = state_file
        try:
            with open(self.state_file, 'r') as f: 
                self.state = yaml.safe_load(f)
        except FileNotFoundError:
            self.state = self.__init_state_file()
        finally:
            if not isinstance(self.state, dict):
                self.state = self.__init_state_file()
    
    def __init_state_file(self) -> dict:
        open(self.state_file, 'w').close()
        os.chmod(self.state_file, 0o640)
        return {}
        
    def set_target_status(self, target_name, new_state, msg) -> None:
        with open(self.state_file, 'w') as f:
            yaml.safe_dump(new_state, f)
        
        self.state = new_state
        curr_status = self.state[str(target_name)]['status']
        print(f'[{target_name}] {curr_status}: {msg}')
        
        if curr_status == 'CRITICAL':
            log.error(msg)
        elif curr_status == 'WARNING':
            log.warning(msg)
        else:
            log.info(msg)
        
    def remove_undefined_targets(self, defined_targets) -> None:
        targets_in_state_file = list(self.state.keys())
        
        for state_target in targets_in_state_file:
            if state_target not in defined_targets:
                del self.state[state_target]
        with open(self.state_file, 'w') as f:
            yaml.safe_dump(self.state, f)
        
    def get_most_failure_status(self) -> str:
        most_failure_status = 'OK'
        
        for target_state in self.state.values():
            status = target_state.get('status')
            if int(NAGIOS[status]) > int(NAGIOS[most_failure_status]):
                most_failure_status = status
        return most_failure_status
    
    def get_summary(self) -> str:
        summary = ''
        
        for target, target_state in self.state.items():
            summary += f"{target_state.get('status')}: [{target}] {target_state.get('msg')}</br>"
        return summary


class BackupState(State):
    def __init__(self, state_file) -> None:
        super().__init__(state_file)
    
    def set_target_status(self, target_name, msg, code, files_num=None, transfer_speed=None) -> None:
        new_state = self.state
        new_state[str(target_name)] = {
            'code': code,
            'status': Nsca.get_status_by_code(code),
            'files_num': files_num,
            'transfer_speed': transfer_speed,
            'msg': str(msg)
        }
        super().set_target_status(target_name, new_state, msg)
    

class CleanupState(State):
    def __init__(self, state_file) -> None:
        super().__init__(state_file)
    
    def set_target_status(self, target_name, msg, code, recovered_space=None, removed_backups=None, total_size=None, max_size=None, max_num=None) -> None:
        new_state = self.state
        new_state[str(target_name)] = {
            'code': code,
            'status': Nsca.get_status_by_code(code),
            'recovered_space': recovered_space,
            'removed_backups': removed_backups,
            'total_size': total_size,
            'max_size': max_size,
            'max_num': max_num,
            'msg': str(msg)
        }
        super().set_target_status(target_name, new_state, msg)


class Backup():
    __slots__ = ['path', 'directory', 'package', 'date', 'size', 'incremental_file', 'manifest_file']
    DATE_FORMAT = '%Y-%m-%d_%H-%M'
    
    def __init__(self, path) -> None:
        self.path = path
        directory, package = os.path.split(self.path)
        self.directory = directory
        self.package = package
        
        if self.__is_valid_backup():
            date_regex = r'([\d]{4}-[\d]{2}-[\d]{2}_[\d]{2}-[\d]{2})'
            self.date = datetime.strptime(re.search(date_regex, package).group(1), self.DATE_FORMAT)
            self.size = Backup.get_dir_size(self.path) if os.path.isdir(self.path) else os.stat(self.path).st_size
            self.incremental_file = os.path.join(self.directory, 'incremental.snapshot')
            self.manifest_file = None
        else:
            raise NameError(f"File '{path}' has not valid filename for backup")
       
    @property
    def display_date(self) -> str:
        return self.date.strftime(Backup.DATE_FORMAT)
    
    @property
    def display_size(self) -> str:
        return get_display_size(self.size)
    
    def __is_valid_backup(self) -> bool:  # Matches only filenames created by backup tool
        regex = r'^backup-[\d]{4}-[\d]{2}-[\d]{2}_[\d]{2}-[\d]{2}|\.tar\.gz|\.gpg$'
        return bool(re.match(regex, self.package))

    def remove(self) -> None:
        try:
            log.info(f"Deleting backup '{self}' in progress...")
            files_to_delete = [self.path]
            manifest_file = self.__get_manifest_file()
            if manifest_file:
                files_to_delete.append(manifest_file)
            for file_to_delete in files_to_delete:
                remove_file_or_dir(file_to_delete)
            log.info(f"Backup '{self}' deleted [{self.display_size}]")
        except PermissionError as error:
            raise TargetError(f"Cannot delete backup '{self}', reason: {error}")
    
    def __get_manifest_file(self) -> str:
        if self.manifest_file:
            return self.manifest_file
        else:
            try:
                return glob(f'{self.directory}/manifests/manifest-{self.display_date}*')[0]
            except IndexError:
                return None
    
    def create_manifest_file(self, format, encryption_key=None) -> None:
        manifest_file = os.path.join(self.directory, 'manifests', f'manifest-{self.display_date}.txt')
        os.makedirs(os.path.join(self.directory, 'manifests'), exist_ok=True)
        result = Cmd.run(f'find "{self.path}" -printf "%AF %AT\t%s\t%p\n" > "{manifest_file}"')
        encrypting_failed = False
        packed_manifest_file = None

        if result.failed:
            raise TargetError(f"Getting content to manifest file from '{self.path}' failed: [{result.code}] {result.output}")
        
        if format == DEFAULTS['FORMATS']['ENCRYPTED_PACKAGE']:
            packed_manifest_file = manifest_file.replace('.txt', '.tar.gz.gpg')
            if encryption_key:
                result = Cmd.run(f'tar czO "{manifest_file}" | gpg2 -er "{encryption_key}" --always-trust > "{packed_manifest_file}" && rm -rf "{manifest_file}"')
            else:
                log.warning(f"Backup '{self.path}' is encrypted, but no encryption key is provided to encrypt manifest file {manifest_file}, manifest file will be only created as package")
                encrypting_failed = True
        if format == DEFAULTS['FORMATS']['PACKAGE'] or encrypting_failed:
            # c - create, g - list for incremental, p - preserve permissions, 
            # z - compress to gzip, f - file to backup, i - ignore zero-blocks, O - extract fields to stdio
            packed_manifest_file = manifest_file.replace('.txt', '.tar.gz')
            result = Cmd.run(f'tar czf "{packed_manifest_file}" "{manifest_file}" && rm -rf "{manifest_file}"')    
        
        if result and result.failed:
            raise TargetError(f"Creating manifest file to '{manifest_file}' failed: [{result.code}] {result.output}")
        self.manifest_file = packed_manifest_file if packed_manifest_file else manifest_file
        log.info(f"Manifest file created in '{self.manifest_file}'")

    def set_permissions(self, permissions) -> None:
        os.chmod(self.path, eval(f"0o{permissions}"))
    
    def set_owner(self, owner) -> None:
        uid = pwd.getpwnam(owner).pw_uid
        gid = grp.getgrnam(owner).gr_gid
        os.chown(self.path, uid, gid)
    
    @staticmethod
    def get_today_package_name() -> str:
        return f'backup-{datetime.now().strftime(Backup.DATE_FORMAT)}'
    
    @staticmethod
    def get_dir_size(path='.') -> int:
        total = 0
        with os.scandir(path) as it:
            for entry in it:
                if entry.is_file():
                    total += entry.stat().st_size
                elif entry.is_dir():
                    total += Backup.get_dir_size(entry.path)
        return total
        
    def __str__(self) -> str:
        return self.path
    

class TargetValidator():
    @staticmethod
    def validate_required_param(param, value) -> None:
        if not value:
            raise TargetError(f"Parameter '{param}' is required")
        
    @staticmethod
    def validate_match(param, regex, value, custom_msg=None):
        match = re.fullmatch(regex, str(value))
        if not match:
            raise TargetError(f"""Parameter '{param}' with '{value}' value {str(custom_msg) if custom_msg else f"does not match to '{regex}' pattern"}""")
        return match
    
    @staticmethod
    def validate_min_value(param, min_value, value) -> None:
        if value < min_value:
            raise TargetError(f"Parameter '{param}' with '{value}' value is too small, minimal value is {min_value}")

    @staticmethod
    def validate_type(param, class_type, value, custom_msg=None) -> None:
        if not isclass(class_type):
            raise AttributeError(f"Type '{class_type}' is not class")
        elif not isinstance(value, class_type):
            raise TargetError(f"Parameter '{param}' with '{value}' value {str(custom_msg) if custom_msg else f'is not valid {class_type} type'}")
        
    @staticmethod
    def validate_absolute_dir_path(param, dir_path):
        regex = r'^((/[a-zA-Z0-9-_]+)+|/)$'
        match = re.fullmatch(regex, dir_path)
        if not match:
            raise TargetError(f"Parameter '{param}' with '{dir_path}' path is not valid absolute path to directory")
        return match
    
    @staticmethod 
    def validate_file_exist(param, file_path) -> None:
        if not os.path.exists(file_path):
            raise TargetError(f"Parameter '{param}' with '{file_path}' path points to file which does not exist")
    
    @staticmethod
    def validate_allowed_values(param, value, allowed_values) -> None:
        if value not in allowed_values:
            raise TargetError(f"Parameter '{param}' has invalid '{value}' value, possible choices: {allowed_values}")

    
class Target():    
    def __init__(self, name, base_dest, conf, default_conf) -> None:
        self.name = name
        self.backup = None
        self.type = conf.get('type')
        self.dest = os.path.join(base_dest, conf.get('dest')) if conf.get('dest') else os.path.join(base_dest, self.name)
        self.max_size = None
        self.max_num = None
        max_size = conf.get('max_size') or default_conf.get('max_size')
        max_num = conf.get('max_num') or default_conf.get('max_num')
        self.files_num = None
        self.transfer_speed = None

        if max_size and max_num:
            log.debug(f"Parameter 'max_size' and 'max_num' are mutually exclusive, max_num ({max_num}) will be overwritten by max_size ({max_size})")
            self.max_size = max_size
        elif not max_size and not max_num:
            raise TargetException("Target must have defined any parameter to declare limitations, by size choose parameter 'max_size' with value <digit><B|KB|MB|GB|TB>, by count select 'max_num' with value <digit>")
        elif max_size:
            self.max_size = max_size
        else:
            self.max_num = max_num
            
        self.format = conf.get('format') or default_conf.get('format')
        self.owner = conf.get('owner') or default_conf.get('owner')
        self.permissions = conf.get('permissions') or default_conf.get('permissions')
        self.encryption_key = conf.get('encryption_key') or default_conf.get('encryption_key')
    
    @property
    def type(self) -> str:
        return self._type
    
    @property
    def dest(self) -> str:
        return self._dest
    
    @property
    def max_size(self) -> int:
        return self._max_size
    
    @property
    def display_max_size(self) -> str:
        return get_display_size(self.max_size)
    
    @property
    def max_num(self) -> int:
        return self._max_num
    
    @property
    def format(self) -> str:
        return self._format
    
    @property
    def owner(self) -> str:
        return self._owner
    
    @property
    def permissions(self) -> int:
        return self._permissions
    
    @property
    def encryption_key(self) -> str:
        return self._encryption_key
    
    @type.setter
    def type(self, value) -> str:
        TargetValidator.validate_required_param('type', value)
        TargetValidator.validate_allowed_values('type', value, DEFAULTS['BACKUP_TYPES'].values())
        self._type = value
        
    @dest.setter
    def dest(self, value) -> str:
        TargetValidator.validate_required_param('dest', value)
        TargetValidator.validate_absolute_dir_path('dest', value)
        self._dest = value
    
    @max_size.setter
    def max_size(self, value) -> int:
        if value:
            match = TargetValidator.validate_match('max_size', r'^([1-9]{1}[\d]*)\s?(B|KB|MB|GB|TB)$', value)
            size, unit = match.groups()
            
            if unit == 'B':
                self._max_size = int(size)
            elif unit == 'KB':
                self._max_size = int(size) * 1024
            elif unit == 'MB':
                self._max_size = int(size) * 1024 * 1024
            elif unit == 'GB':
                self._max_size = int(size) * 1024 * 1024 * 1024
            elif unit == 'TB':
                self._max_size = int(size) * 1024 * 1024 * 1024 * 1024
        else:
            self._max_size = None
    
    @max_num.setter
    def max_num(self, value) -> int:
        if value:
            TargetValidator.validate_type('max_num', int, value)
            TargetValidator.validate_min_value('max_num', 2, value)
            self._max_num = value
        else:
            self._max_num = None
    
    @format.setter
    def format(self, value) -> str:
        TargetValidator.validate_required_param('format', value)
        TargetValidator.validate_allowed_values('format', value, DEFAULTS['FORMATS'].values())
        self._format = value
    
    @owner.setter
    def owner(self, value) -> str:
        TargetValidator.validate_required_param('owner', value)
        TargetValidator.validate_type('owner', str, value)
        self._owner = value
    
    @permissions.setter
    def permissions(self, value) -> str:
        TargetValidator.validate_required_param('permissions', value)
        TargetValidator.validate_match('permissions', r'^[0-7]{3}$', value)
        self._permissions = value
    
    @encryption_key.setter
    def encryption_key(self, value) -> str:
        if self.format == DEFAULTS['FORMATS']['ENCRYPTED_PACKAGE']:
            TargetValidator.validate_required_param('encryption_key', value)
            TargetValidator.validate_type('encryption_key', str, value)
            self._encryption_key = value
        else:
            self._encryption_key = None
    
    def get_conf(self) -> dict[str, str]:  # TODO add comment to dump when variable is taken from default params
        return vars(self)

    def get_backups_size(self) -> int:
        if os.path.exists(self.dest):
            result = Cmd.run(f"du -sb '{self.dest}' | awk '{{print $1}}'")
            if result.failed:
                raise TargetError(f"Counting total size of backups failed: [{result.code}] {result.output}")
            else:
                return int(result.output)
        else:
            return 0
    
    def get_backups_num(self) -> int:
        total_num = 0
        try:
            for backup_package in os.listdir(self.dest):
                try:
                    Backup(os.path.join(self.dest, backup_package))
                    total_num += 1
                except NameError:
                    continue
            return int(total_num)
        except FileNotFoundError:
            return 0
    
    def get_oldest_backup(self) -> Backup | None:
        oldest_backup = None
        try:
            for backup_package in os.listdir(self.dest):
                try:
                    backup = Backup(os.path.join(self.dest, backup_package))
                    if not oldest_backup or backup.date < oldest_backup.date:
                        oldest_backup = backup
                except NameError:
                    continue
            return oldest_backup
        except FileNotFoundError:
            return None
    
    def get_latest_backup(self) -> Backup | None:
        latest_backup = None
        try:
            for backup_package in os.listdir(self.dest):
                try:
                    backup = Backup(os.path.join(self.dest, backup_package))
                    if not latest_backup or backup.date > latest_backup.date:
                        latest_backup = backup
                except NameError:
                    continue
            return latest_backup
        except FileNotFoundError:
            return None
        
    def create_backup(self, path) -> Backup:
        backup = Backup(path)
        cmd = None
        
        try:
            backup.create_manifest_file(self.format, self.encryption_key)
        except TargetError as error:
            backup.remove()
            raise TargetError(error)
        
        if self.format == DEFAULTS['FORMATS']['PACKAGE']:
            new_path = f"{path}.tar.gz"
            log.info(f"Packing backup to '{new_path}'...")
            cmd = f'tar -g "{backup.incremental_file}" -piz -cf "{new_path}" "{path}" && rm -rf "{path}"'
            success_msg = f"Backup successfully packed to '{new_path}' path"
        elif self.format == DEFAULTS['FORMATS']['ENCRYPTED_PACKAGE']:
            new_path = f"{path}.tar.gz.gpg"
            log.info(f"Packing and encrypting backup to '{new_path}'...")
            cmd = f'tar -g "{backup.incremental_file}" -piz -cO "{path}" | gpg2 -er "{self.encryption_key}" --always-trust > "{new_path}" && rm -rf "{path}"'
            success_msg = f"Backup successfully packed and encrypted to '{new_path}' path" 
        if cmd:
            log.debug(f"Packing backup with cmd: {cmd}")
            result = Cmd.run(cmd)

            if result.failed:
                backup.remove()
                raise TargetError(f"Packing backup failed: [{result.code}] {result.output}")
            else:
                log.info(success_msg)
                backup = Backup(new_path)
        else:
            log.debug(f"Backup '{path}' preserved in raw format")
            backup = Backup(path)
        
        try:
            backup.set_permissions(self.permissions)
            backup.set_owner(self.owner)
        except PermissionError as e:
            backup.remove()
            raise TargetError(f'Setting backup privileges failed: {e}')
        log.info(f"Backup finished successfully")
        self.backup = backup
        return backup
                
    def __str__(self) -> str:
        return self.name
        
    
class PullTarget(Target):    
    def __init__(self, name, base_dest, conf, default_conf) -> None:
        super().__init__(name, base_dest, conf, default_conf)
        self.sources = conf.get('sources') or default_conf.get('sources')
        self.timeout = conf.get('timeout') or default_conf.get('timeout')
        self.password_file = conf.get('password_file') or default_conf.get('password_file')
        self.exclude = conf.get('exclude') or default_conf.get('exclude')
        self.wake_on_lan = bool(conf.get('wake_on_lan'))
        self.files_num = 0
        self.transfer_speed = 0  # bytes per sec
        
        if self.wake_on_lan:
            self._mac_address = conf.get('wake_on_lan').get('mac_address')
    
    @property
    def sources(self) -> list:
        return self._sources
    
    @property
    def timeout(self) -> int:
        return self._timeout
    
    @property
    def password_file(self) -> str:
        return self._password_file
    
    @property
    def exclude(self) -> list:
        return self._exclude
    
    @property
    def mac_address(self) -> str:
        return self._mac_address
    
    @sources.setter
    def sources(self, value) -> None:
        TargetValidator.validate_required_param('sources', value)
        TargetValidator.validate_type('sources', list, value)
        self._sources = value
    
    @timeout.setter
    def timeout(self, value) -> None:
        TargetValidator.validate_required_param('timeout', value)
        TargetValidator.validate_type('timeout', int, value)
        self._timeout = value
    
    @password_file.setter
    def password_file(self, value) -> None:
        TargetValidator.validate_required_param('password_file', value)
        TargetValidator.validate_file_exist('password_file', value)
        self._password_file = value
    
    @exclude.setter
    def exclude(self, value) -> None:
        if value:
            TargetValidator.validate_type('exclude', list, value)
            self._exclude = value
        else:
            self._exclude = None
    
    @mac_address.setter
    def mac_address(self, value) -> None:
        TargetException.validate_required_param('mac_address', value)  # Only required when wake_on_lan is True
        TargetException.validate_match('mac_address', r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', value, 'is not valid MAC address')
        self._mac_address = value
        
    def create_backup(self) -> Backup:
        new_backup_path = os.path.join(self.dest, Backup.get_today_package_name())
        
        base_cmd = f'rsync -a --progress --info=stats2 --contimeout={self.timeout} --password-file="{self.password_file}"'
        if self.exclude:
            exclude_args = ' '.join(f'--exclude "{exclude_arg}"' for exclude_arg in self.exclude)
            base_cmd = f'{base_cmd} {exclude_args}'
        source_args = ' '.join(source for source in self.sources)
        cmd = f'{base_cmd} {source_args} {new_backup_path} > {os.path.join(new_backup_path, "rsync.log")}' 
        os.makedirs(new_backup_path, exist_ok=True)
        log.info(f"Pulling target files to '{new_backup_path}' path...")
        log.debug(f"Used rsync cmd: {cmd}")
        result = Cmd.run(cmd)

        if result.code == 24:
            log.warning(f"Some files vanished in source during syncing: [{result.code}] {result.output}")
        elif result.failed:
            remove_file_or_dir(new_backup_path)
            raise TargetError(f"Pulling target files failed: [{result.code}] rsync: {result.output}")
        print(result.output)
        try:
            rsync_log_output = Cmd.run(f"tail -n 30 {new_backup_path}/rsync.log").output
            print(rsync_log_output)
            self.files_num = int(re.findall(r'[nN]umber\sof\sfiles:\s([0-9,]*)', rsync_log_output)[0])
            self.transfer_speed = float(re.findall(r'bytes[\s]*?([0-9,.]*)\s?bytes/sec', rsync_log_output)[0].replace(',', ''))
        except Exception as e:
            log.error(f'Failed to get metrics from rsync output: {e}')
        print(self.files_num)
        print(self.transfer_speed)
        log.info(f"Backup pulled and saved in '{new_backup_path}' path")
        return super().create_backup(new_backup_path)
    
    def send_wol_packet(self) -> None:
        send_magic_packet(self.mac_address)
        log.debug(f'WOL packet sent to {self.mac_address}')
        

class PushTarget(Target):    
    def __init__(self, name, base_dest, work_dir, conf, default_conf) -> None:
        super().__init__(name, base_dest, conf, default_conf)
        self.work_dir = os.path.join(work_dir, self.name)
        self.frequency = conf.get('frequency') or default_conf.get('frequency')
    
    @property
    def work_dir(self) -> str:
        return self._work_dir
    
    @property
    def frequency(self) -> int:  # Hours
        return self._frequency
    
    @work_dir.setter
    def work_dir(self, value) -> None:
        TargetValidator.validate_required_param('work_dir', value)
        TargetValidator.validate_absolute_dir_path('work_dir', value)
        self._work_dir = value
        
    @frequency.setter
    def frequency(self, value) -> None:  # Param examples: 16h = 16hours, 1d = 1 day, 3w = 3 weeks, 2m = 2 months
        TargetValidator.validate_required_param('frequency', value)
        match = TargetValidator.validate_match('frequency', r'^([\d]{1,4})\s?([h|d|m|w]{1})$', value)
        number, date_attr = match.groups()
        
        if date_attr == 'h':
            self._frequency = int(number)
        elif date_attr == 'd':
            self._frequency = int(number) * 24
        elif date_attr == 'w':
            self._frequency = int(number) * 7 * 24
        elif date_attr == 'm':
            self._frequency = int(number) * 30 * 24
    
    def create_backup(self) -> Backup:
        latest_backup = self.get_latest_backup()
        
        if latest_backup:
            last_backup_hours_ago = (datetime.now() - latest_backup.date) // timedelta(hours=1)
        os.makedirs(self.work_dir, exist_ok=True)
        files_in_workdir = os.listdir(self.work_dir)
        
        if not latest_backup or last_backup_hours_ago >= self.frequency:  # There is no backup or correct number of days passed since last backup
            if files_in_workdir:
                new_backup_path = os.path.join(self.dest, Backup.get_today_package_name())
                os.makedirs(new_backup_path, exist_ok=True)
                
                log.info(f"Moving files from '{self.work_dir}' working directory to '{new_backup_path}' path...")
                result = Cmd.run(f'mv {self.work_dir}/* {new_backup_path}')
                
                if result.failed:
                    remove_file_or_dir(new_backup_path)
                    raise TargetError(f"Moving files from '{self.work_dir}' working directory to '{new_backup_path}' failed: [{result.code}] {result.output}")
                else:
                    log.info(f"Files moved from '{self.work_dir}' working directory to '{new_backup_path}' path")
                    return super().create_backup(new_backup_path)
            else:
                raise TargetError(f"Not found any file to process in '{self.work_dir}' work directory")
        elif files_in_workdir:
            raise TargetWarning(f"Backup should not be created but found some files in '{self.work_dir}' working directory")
        else:
            raise TargetSkipException(f"Found latest backup from '{latest_backup.display_date}' created {format_hours_to_ago(last_backup_hours_ago)} ago, frequency is {format_hours_to_ago(self.frequency)}, backup creation skipped")


def remove_file_or_dir(path) -> None:
    result = Cmd.run(f"rm -rf '{path}'")
    if result.failed:
        raise TargetError(f"Removing '{path}' failed: [{result.code}] {result.output}")

def parse_args():
    parser = argparse.ArgumentParser(description='Backup script', add_help=False)
    parser.add_argument('action', choices=['cleanup', 'run', 'push-stats'])
    action = parser.parse_known_args()[0].action
    parser.add_argument('-v', '--verbose', 
                        action='count', 
                        default=DEFAULTS['LOG_LEVEL'],
                        help=f'Default verbose level is {DEFAULTS["LOG_LEVEL"]}')
    if action != 'push-stats':
        parser.add_argument('-t', '--targets',
                            required=True,
                            nargs='+',
                            help=f'Target list defined in {DEFAULTS["CONFIG_FILE"]} configuration file under "targets" markup')
        parser.add_argument('-m', '--mode',
                            default='full',
                            choices=['full', 'inc'],
                            help=f'Not implemented yet, currently all backups are full')
        parser.add_argument('--noReport',
                            default=False,
                            action='store_true',
                            help=f'Disable sending state of this iteration to NSCA server defined in {DEFAULTS["CONFIG_FILE"]}')
    if action == 'cleanup':
        parser.add_argument('--force',
                            default=False,
                            action='store_true',
                            help=f'Clean backups to 0 backups, even if limits are to small, no matter what')
    parser.add_argument('-h', '--help', action='help')
    return parser.parse_args()

def get_display_size(size) -> str:
    if size == 0:
        return '0B'
    size_names = ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
    i = int(math.floor(math.log(size, 1024)))
    p = math.pow(1024, i)
    display_size = round(size / p, 2)
    return f'{display_size} {size_names[i]}'

def format_hours_to_ago(hours_amount) -> str:
    days = hours_amount // 24
    hours = hours_amount % 24
    
    if days == 0:
        return f"{hours} hours" if hours != 1 else f"{hours} hour"
    elif days == 1:
        if hours == 0:
            return "1 day"
        else:
            return f"1 day and {hours} hours" if hours != 1 else "1 day and 1 hour"
    else:
        if hours == 0:
            return f"{days} days"
        else:
            return f"{days} days and {hours} hours" if hours != 1 else f"{days} days and 1 hour"

def validate_conf_commons(commons) -> None:
    try:
        if not commons:
            raise EnvironmentError("key 'common' is not defined")
        for param in DEFAULTS['REQUIRED_COMMON_PARAMS']:
            if not commons.get(param):
                raise EnvironmentError(f"parameter '{param}' is missing in 'common' key")
    except EnvironmentError as error:
        print(f"File '{DEFAULTS['CONFIG_FILE']}' is not valid config: {error}")
        sys.exit(NAGIOS['UNKNOWN'])

def get_logger(log_file, verbose_level) -> None:
    def record_factory(*args, **kwargs) -> logging.LogRecord:
        record = old_factory(*args, **kwargs)
        record.target = target
        return record
    
    logging.basicConfig(
        filename = log_file, 
        format = '%(asctime)s %(name)s %(levelname)s [%(target)s] %(message)s', 
        datefmt = '%Y-%m-%d %H:%M:%S', 
        level = 30 - (10 * verbose_level) if verbose_level > 0 else 0
    )

    old_factory = logging.getLogRecordFactory()
    logging.setLogRecordFactory(record_factory)
    return logging.getLogger('backup-tool')

if __name__ == "__main__":
    args = parse_args()
    
    with open(DEFAULTS['CONFIG_FILE'], "r") as f:
        conf = yaml.safe_load(f)
        
    common_conf = conf.get('common')
    validate_conf_commons(common_conf)
    log = get_logger(common_conf.get('log_file'), args.verbose)
    target = '-'
    
    if args.action == 'cleanup':
        state = CleanupState(common_conf.get('cleanup_state_file'))
        nagios_service = common_conf.get('nagios_cleanup_service')
    else:
        state = BackupState(common_conf.get('backup_state_file'))
        nagios_service = common_conf.get('nagios_backup_service')
    
    nsca = Nsca(common_conf.get('nagios_host'), nagios_service, common_conf.get('nsca_host'), common_conf.get('nsca_port'))
    
    if args.action == 'push-stats':
        influx_host = common_conf.get('influx_host')
        influx_port = common_conf.get('influx_port')    
        print(f'[{args.action.upper()}] Start pushing stats to {influx_host}:{influx_port}')
        log.info(f'[{args.action.upper()}] Start pushing stats to {influx_host}:{influx_port}')
        try:
            influxdb = Influx(influx_host, influx_port, common_conf.get('influx_user'), common_conf.get('influx_password_file'), common_conf.get('influx_database'))
        except (OSError, FileNotFoundError, ConnectionError) as e:
            print(f"ERROR: Connection to influx server failed: {e}")
            log.error(f"ERROR: Connection to influx server failed: {e}")
            sys.exit(1)
        sys.exit(0)
        
    for target in args.targets:
        try:
            target_conf = conf['targets'].get(target)
            if not target_conf: 
                raise TargetError(f"Target not defined in '{DEFAULTS['CONFIG_FILE']}' conf file")
            
            if target_conf.get('type') == DEFAULTS['BACKUP_TYPES']['PUSH']:
                target = PushTarget(target, common_conf.get('base_dest'), common_conf.get('work_dir'), target_conf, conf.get('default'))
            else:
                target = PullTarget(target, common_conf.get('base_dest'), target_conf, conf.get('default'))
            
            log.info(f'[{args.action.upper()}] Start processing target')

            if args.action == 'run':
                if type(target) == PullTarget and target.wake_on_lan: 
                    target.send_wol_packet()
                target.create_backup()
                state.set_target_status(target, f'({target.backup.display_size}) {target.backup.path}', NAGIOS['OK'], target.files_num, target.transfer_speed)
            elif args.action == 'cleanup':
                total_recovered_space = 0
                total_removed_backups = 0
                total_num = target.get_backups_num()
                total_size = target.get_backups_size()
                
                if total_num == 0: 
                    state.set_target_status(target, 'No found any backup', NAGIOS['WARNING'], total_recovered_space, total_removed_backups, target.max_size)
                elif target.max_size:
                    if total_size >= target.max_size:
                        latest_backup = target.get_latest_backup()
                        oldest_backup = target.get_oldest_backup()
                        
                        log.info(f"Start cleanup, current total size over limit ({get_display_size(total_size)} / {target.display_max_size})")

                        while target.max_size - total_size <= latest_backup.size * 1.5:  # Directory needs to have at least 150% of latest backup size
                            if target.get_backups_num() == 1 and not args.force:
                                raise TargetCleanupError(f"Cleanup aborted, only 1 backup left but current max_size limit ({target.display_max_size}) is not enough for next backup (~{latest_backup.display_size}), consider increasing the limit or use -f/--force are to process cleanup")
                            oldest_backup.remove()
                            total_removed_backups += 1
                            total_recovered_space += oldest_backup.size
                            oldest_backup = target.get_oldest_backup()
                            total_size = target.get_backups_size()
                        msg = f'Cleanup finished, removed {total_removed_backups} backup/s, recovered {get_display_size(total_recovered_space)} ({get_display_size(target.get_backups_size())} / {target.display_max_size})'
                        state.set_target_status(target, msg, NAGIOS['OK'], total_recovered_space, total_removed_backups, total_size, target.max_size, target.max_num)
                    else:
                        msg = f'No cleanup needed ({get_display_size(total_size)} / {get_display_size(target.max_size)})'
                        state.set_target_status(target, msg, NAGIOS['OK'], total_recovered_space, total_removed_backups, total_size, target.max_size, target.max_num)
                elif target.max_num:
                    if total_num >= target.max_num:                      
                        log.info(f"Start cleanup, max number of backups exceeded ({total_num} / {target.max_num})")
                        
                        while total_num >= target.max_num:
                            if total_num == 1 and not args.force:
                                raise TargetCleanupError(f"Cleanup aborted, only 1 backup left and current max_num limit allows only for {target.max_num} backup, directory cannot be empty, consider increasing the limit or use -f/--force are to process cleanup")
                            oldest_backup = target.get_oldest_backup()
                            oldest_backup.remove()
                            total_removed_backups += 1
                            total_recovered_space += oldest_backup.size
                            total_num = target.get_backups_num()
                        msg = f'Cleanup finished, removed {total_removed_backups} backup/s, recovered {get_display_size(total_recovered_space)} ({total_num} / {target.max_num})'
                        state.set_target_status(target, msg, NAGIOS['OK'], total_recovered_space, total_removed_backups, total_size, target.max_size, target.max_num)
                    else:
                        msg = f'No cleanup needed ({total_num} / {target.max_num})'
                        state.set_target_status(target, msg, NAGIOS['OK'], total_recovered_space, total_removed_backups, total_size, target.max_size, target.max_num)
        except TargetException as e:
            state.set_target_status(target, str(e), e.code)
        
    state.remove_undefined_targets(list(conf["targets"]))

    #if not args.noReport:
    #    nsca.send_report_to_nagios(NAGIOS[state.get_most_failure_status()], state.get_summary())
