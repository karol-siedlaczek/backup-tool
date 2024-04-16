#!/usr/bin/env python3

import re
import os
import sys
import pwd
import grp
import yaml
import math
import argparse
from enum import Enum, auto
from glob import glob
from influxdb import InfluxDBClient
from inspect import isclass
from datetime import datetime, timedelta
from wakeonlan import send_magic_packet
import subprocess
import logging

CONFIG_FILE = '/etc/backup-tool/backup-tool.yaml'
# TODO
# c - create, g - list for incremental, p - preserve permissions, 
# z - compress to gzip, f - file to backup, i - ignore zero-blocks, O - extract fields to stdio

class Defaults(Enum):
    @staticmethod
    def list(enum_class=None) -> list:
        class_name = enum_class or Defaults
        return [ name.lower() for name, member in class_name.__members__.items() ]
    
    def __str__(self) -> str:
        return self.name.lower() if isinstance(self.name, str) else self.name
    
    @classmethod
    def _missing_(cls, value):
        value = value.lower()
        for member in cls:
            if member.value == value:
                return member
        return None
    
class RequiredCommonParams(Defaults):
    NAGIOS = ['host', 'port', 'host_service', 'run_service', 'cleanup_service']
    INFLUX = ['host', 'port', 'user', 'database', 'password_file']
    FILES = ['log', 'hosts', 'run_state', 'cleanup_state']
    DIRS = ['backups', 'work', 'scripts']
    
    @staticmethod
    def validate(commons) -> None:
        try:
            if not commons:
                raise EnvironmentError("section 'common' is not defined")
            for parent_param in list(RequiredCommonParams):
                parent_attr = commons.get(str(parent_param))
                if not parent_attr:
                    raise EnvironmentError(f"parameter 'common.{parent_param}' is not defined")
                for child_param in parent_param.value:
                    child_attr = parent_attr.get(str(child_param))
                    if not child_attr:
                        raise EnvironmentError(f"parameter 'common.{parent_param}.{child_param}' is not defined")
        except EnvironmentError as e:
            print(f"File '{CONFIG_FILE}' is not valid config: {e}")
            sys.exit(Nagios.UNKNOWN)

class BackupType(Defaults):
    PUSH = 'push'
    PULL = 'pull'

class Format(Defaults):
    PACKAGE = 'package'
    ENCRYPTED_PACKAGE = 'encrypted-package'
    RAW = 'raw'
    
class Action(Defaults):
    CLEANUP = 'cleanup'
    RUN = 'run'
    PUSH_STATS = 'push-stats'

class Nagios(str, Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3
    
    def __str__(self) -> str:
        return self
    
    @staticmethod
    def get_status_by_code(code):
        for nagios_item in Nagios:
            if int(nagios_item.value) == int(code): return nagios_item.name
        return Nagios.UNKNOWN.name


class TargetException(Exception):
    __slots__ = ['code']
    
    def __init__(self, code) -> None:
        self.code = code

class TargetError(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(Nagios.CRITICAL)
        log.error(msg)

class TargetWarning(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(Nagios.WARNING)
        log.warning(msg)

class TargetSkipException(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(Nagios.OK)
        log.info(msg)

class TargetCleanupError(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(Nagios.CRITICAL)
        log.error(msg)

class InfluxServer():  # TODO - Setup pushing stats to influx
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
    
class NagiosServer():
    __slots__ = ['bin', 'host', 'port', 'host_service', 'service']
    
    def __init__(self, host, port, host_service, service) -> None:
        self.bin = '/usr/sbin/send_nsca'
        self.host = host
        self.port = port
        self.host_service = host_service
        self.service = service
    
    def send_report_to_nagios(self, code, msg) -> None:
        msg = f'{self.host_service}\t{self.service}\t{code}\t{msg}'
        echo_process = subprocess.Popen(f'echo -e {msg}'.split(' '), stdout=subprocess.PIPE)
        nsca_process = subprocess.Popen(['send_nsca', '-H', str(self.host), '-p', str(self.port)], stdin=echo_process.stdout, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        stdout, stderr = nsca_process.communicate()
        if stderr:
            raise ConnectionError(f"Sending nsca packet to {self.host}:{self.port} failed: {stderr}")
        else:
            log.debug(f"Nsca packet '{msg}' sent to {self.host}:{self.port}, output: {stdout}") 
    
    def __str__(self) -> str:
        return self.name
           
           
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
        
        if curr_status == Nagios.CRITICAL.name:
            log.error(msg)
        elif curr_status == Nagios.WARNING.name:
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
            if int(getattr(Nagios, status)) > int(getattr(Nagios, most_failure_status)):
                most_failure_status = status
        return most_failure_status
    
    def get_summary(self) -> str:
        summary = ''
        
        for target, target_state in self.state.items():
            summary += f"{target_state.get('status')}: [{target}] {target_state.get('msg')} ({target_state.get('timestamp')})</br>"
        return summary[:-5]

class RunState(State):
    def __init__(self, state_file) -> None:
        super().__init__(state_file)
    
    def set_target_status(self, target_name, msg, code, elapsed_time_copy=None, elapsed_time_pack=None, transfer_speed_copy=None, transfer_speed_pack=None) -> None:
        new_state = self.state
        new_state[str(target_name)] = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'code': int(code),
            'status': Nagios.get_status_by_code(code),
            'times': {
                'copy': {
                    'duration': elapsed_time_copy,
                    'transfer_speed': transfer_speed_copy
                },
                'pack': {
                    'duration': elapsed_time_pack,
                    'transfer_speed': transfer_speed_pack
                }
            },
            'msg': f'{msg[:100]}... ({len(msg) - 100} log lines truncated)' if len(msg) > 100 else msg
        }
        super().set_target_status(target_name, new_state, msg)

class CleanupState(State):
    def __init__(self, state_file) -> None:
        super().__init__(state_file)
    
    def set_target_status(self, target_name, msg, code, recovered_space=None, removed_backups=None, total_size=None, max_size=None, max_num=None) -> None:
        new_state = self.state
        new_state[str(target_name)] = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'code': int(code),
            'status': Nagios.get_status_by_code(code),
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
    
    def __is_valid_backup(self) -> bool:  # Matches only filenames created by backup tool
        regex = r'^backup-[\d]{4}-[\d]{2}-[\d]{2}_[\d]{2}-[\d]{2}|\.tar\.gz|\.gpg$'
        return bool(re.match(regex, self.package))

    def remove(self) -> None:
        try:
            log.debug(f"Deleting '{self}' in progress...")
            files_to_delete = [self.path]
            manifest_file = self.__get_manifest_file()
            if manifest_file:
                files_to_delete.append(manifest_file)
            for file_to_delete in files_to_delete:
                remove_file_or_dir(file_to_delete)
            log.debug(f"Path '{self}' deleted [{get_display_size(self.size)}]")
        except PermissionError as error:
            raise TargetError(f"Cannot delete '{self}', reason: {error}")
    
    def __get_manifest_file(self) -> str:
        if self.manifest_file:
            return self.manifest_file
        else:
            try:
                return glob(f'{self.directory}/manifests/manifest-{self.display_date}*')[0]
            except IndexError:
                return None
    
    def create_manifest_file(self, format, scripts_dir, encryption_key=None) -> None:
        manifest_file = f'manifest-{self.display_date}.txt'
        manifests_dir = os.path.join(self.directory, 'manifests')
        os.makedirs(manifests_dir, exist_ok=True)
        old_cwd = os.getcwd()
        os.chdir(manifests_dir)
        
        try:
            with open(manifest_file, 'w') as f:
                f.writelines(run_cmd(f'/usr/bin/find {self.path} -printf %AF-%AT\t%s\t%p\n'))
        except subprocess.CalledProcessError as e:
            raise TargetError(f"Getting content to manifest file from '{self.path}' failed: {e}: {e.stderr}")

        if format == Format.PACKAGE.value or format == Format.ENCRYPTED_PACKAGE.value:
            self.manifest_file = manifest_file.replace('.txt', '.tar.gz')
            
            if encryption_key:
                try:
                    self.manifest_file = run_cmd(f"{scripts_dir}/pack_and_encrypt.sh {manifest_file} {encryption_key} {self.manifest_file}")
                except subprocess.CalledProcessError as e:
                    raise TargetError(f"Packing and encrypting manifest to {self.manifest_file} failed: {e}: {e.stderr}")
            else:
                try:
                    run_cmd(f"tar czf {self.manifest_file} {manifest_file}")
                except subprocess.CalledProcessError as e:
                    raise TargetError(f"Packing manifest to {self.manifest_file} failed: {e}: {e.stderr}")
            remove_file_or_dir(manifest_file)
        else:
            self.manifest_file = manifest_file
        os.chdir(old_cwd)
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
    def validate_file_path(param=None, file_path=None, custom_msg=None):
        regex = r'^([/[a-z+*|[a-zA-Z0-9]+\.[a-zA-Z0-9]+)$'
        match = re.fullmatch(regex, file_path)
        if not match:
            raise TargetError(custom_msg or f"Parameter '{param}' with '{file_path}' path is not valid path to file")
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
    def __init__(self, name, base_dest, conf, default_conf, scripts_dir) -> None:
        self.name = name
        self.backup = None
        self.type = conf.get('type')
        self.dest = os.path.join(base_dest, conf.get('dest')) if conf.get('dest') else os.path.join(base_dest, self.name)
        self.scripts_dir = scripts_dir
        self.max_size = None
        self.max_num = None
        max_size = conf.get('max_size') or default_conf.get('max_size')
        max_num = conf.get('max_num') or default_conf.get('max_num')
        self.elapsed_time_copy = None
        self.elapsed_time_pack = None
        self.transfer_speed_copy = None
        self.transfer_speed_pack = None

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
        TargetValidator.validate_allowed_values('type', value, Defaults.list(BackupType))
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
        TargetValidator.validate_allowed_values('format', value, Defaults.list(Format))
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
        if self.format == Format.ENCRYPTED_PACKAGE.value:
            TargetValidator.validate_required_param('encryption_key', value)
            TargetValidator.validate_type('encryption_key', str, value)
            self._encryption_key = value
        else:
            self._encryption_key = None

    def get_backups_size(self) -> int:
        if os.path.exists(self.dest):
            try:
                output = run_cmd(f"du -sb {self.dest}").split('\t')[0]
            except subprocess.CalledProcessError as e:
                raise TargetError(f"Counting total size of backups failed: {e}: {e.stderr}")
            else:
                return int(output)
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
        backup.set_permissions(self.permissions)
         
        try:
            backup.create_manifest_file(self.format, self.scripts_dir, self.encryption_key)
        except TargetError as error:
            backup.remove()
            raise TargetError(error)
        
        if self.elapsed_time_copy:  # bytes per sec
            self.transfer_speed_copy = backup.size / self.elapsed_time_copy

        if self.format == Format.PACKAGE.value or self.format == Format.ENCRYPTED_PACKAGE.value:
            pack_start_time = datetime.now()
            old_cwd = os.getcwd()
            os.chdir(backup.directory)
            new_package = f"{backup.package}.tar.gz"
            
            if self.encryption_key:
                log.info(f"Packing and encrypting backup to '{new_package}.gpg'...")
                try:
                    new_package = run_cmd(f"{self.scripts_dir}/pack_and_encrypt.sh {backup.package} {self.encryption_key} {new_package}")
                except subprocess.CalledProcessError as e:
                    backup.remove()
                    raise TargetError(f"Packing and encrypting backup failed: {e}: {e.stderr}")
                log.info(f"Backup successfully packed and encrypted to '{new_package}' path")
            else:
                log.info(f"Packing backup to '{new_package}'...")
                try:
                    run_cmd(f'tar -piz -cf {new_package} {backup.package}')
                except subprocess.CalledProcessError as e:
                    backup.remove()
                    raise TargetError(f"Packing backup failed: {e}: {e.stderr}")
                log.info(f"Backup successfully packed to '{new_package}' path")

            self.elapsed_time_pack = round(((datetime.now() - pack_start_time).microseconds / 1000000 ), 2)
            backup.remove()
            backup = Backup(os.path.join(backup.directory, new_package))
            os.chdir(old_cwd)
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
        
        if self.elapsed_time_pack:  # bytes per sec
            self.transfer_speed_pack = self.backup.size / self.elapsed_time_pack
        return backup
    
    def __str__(self) -> str:
        return self.name
        
class PullTarget(Target):    
    def __init__(self, name, conf, default_conf, base_dest, scripts_dir, stats_file) -> None:
        super().__init__(name, base_dest, conf, default_conf, scripts_dir)
        self.sources = conf.get('sources') or default_conf.get('sources')
        self.timeout = conf.get('timeout') or default_conf.get('timeout')
        self.password_file = conf.get('password_file') or default_conf.get('password_file')
        self.exclude = conf.get('exclude') or default_conf.get('exclude')
        self.wake_on_lan = bool(conf.get('wake_on_lan'))
        self.stats_file = stats_file    
        self.remote = bool(re.match(r'^rsync:\/\/[a-zA-Z_\-\.0-9]*@', self.sources[0]))
        
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
    
    @property
    def stats_file(self) -> str:
        return self._stats_file
    
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
    
    @stats_file.setter
    def stats_file(self, value) -> None:
        if value:
            TargetValidator.validate_file_path(file_path=value, custom_msg=f"Path to stats file '{value}' defined with --statsFile is not valid file path")
            self._stats_file = value
        else:
            self._stats_file = None
        
    def create_backup(self) -> Backup:
        new_backup_path = os.path.join(self.dest, Backup.get_today_package_name())
        base_cmd = f'rsync -aW{f" --contimeout {self.timeout} --password-file {self.password_file}" if self.remote else ""}'
        
        if self.stats_file:
            base_cmd += " --stats --info=name1,progress2"
        if self.exclude:
            exclude_args = ' '.join(f'--exclude "{exclude_arg}"' for exclude_arg in self.exclude)
            base_cmd = f'{base_cmd} {exclude_args}'
        
        source_args = ' '.join(source for source in self.sources)
        cmd = f'{base_cmd} {source_args} {new_backup_path}' 
        os.makedirs(new_backup_path, exist_ok=True)
        log.info(f"Pulling target files to '{new_backup_path}' path...")
        log.debug(f"Used rsync cmd: {cmd}")
        
        try:
            copy_start_time = datetime.now()
            result = run_cmd(cmd)  # TODO - add reaction to 24 code (some file vanished) log.warning(f"Some files vanished in source during syncing: [{result.code}] {result.output}")
            self.elapsed_time_copy = round(((datetime.now() - copy_start_time).microseconds / 1000000), 2)
        except subprocess.CalledProcessError as e:
            remove_file_or_dir(new_backup_path)
            raise TargetError(f"Pulling target files failed: {e}: {e.stderr}")
        
        if self.stats_file:
            with open(self.stats_file, 'w') as f:
                f.writelines(result)
        
        log.info(f"Backup pulled and saved in '{new_backup_path}' path")
        return super().create_backup(new_backup_path)
    
    def send_wol_packet(self) -> None:
        send_magic_packet(self.mac_address)
        log.debug(f'WOL packet sent to {self.mac_address}')
        
class PushTarget(Target):    
    def __init__(self, name, conf, default_conf, base_dest, scripts_dir, work_dir) -> None:
        super().__init__(name, base_dest, conf, default_conf, scripts_dir)
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
                try:
                    run_cmd(f'mv {self.work_dir}/* {new_backup_path}')
                except subprocess.CalledProcessError as e:
                    remove_file_or_dir(new_backup_path)
                    raise TargetError(f"Moving files from '{self.work_dir}' working directory to '{new_backup_path}' failed: {e}: {e.stderr}")

                log.info(f"Files moved from '{self.work_dir}' working directory to '{new_backup_path}' path")
                return super().create_backup(new_backup_path)
            else:
                raise TargetError(f"Not found any file to process in '{self.work_dir}' work directory")
        elif files_in_workdir:
            raise TargetWarning(f"Backup should not be created but found some files in '{self.work_dir}' working directory")
        else:
            raise TargetSkipException(f"Found latest backup from '{latest_backup.display_date}' created {format_hours_to_ago(last_backup_hours_ago)} ago, frequency is {format_hours_to_ago(self.frequency)}, backup creation skipped")


def remove_file_or_dir(path) -> None:
    try:
        run_cmd(f"rm -rf {path}")
    except subprocess.CalledProcessError as e:
        raise TargetError(f"Removing '{path}' failed: {e}: {e.stderr}")

def parse_args():
    parser = argparse.ArgumentParser(description='Backup script', add_help=False)
    parser.add_argument('action', choices=Defaults.list(Action))
    action = parser.parse_known_args()[0].action
    parser.add_argument('-v', '--verbose', 
                        action='count', 
                        default=1,
                        help=f'Default verbose level is 1 (INFO)')
    if action != 'push-stats':
        parser.add_argument('-t', '--targets',
                            required=True,
                            nargs='+',
                            help=f'Target list defined in {CONFIG_FILE} configuration file under "targets" markup')
        parser.add_argument('-m', '--mode',
                            default='full',
                            choices=['full', 'inc'],
                            help=f'Not implemented yet, currently all backups are full')
        parser.add_argument('--noReport',
                            default=False,
                            action='store_true',
                            help=f'Disable sending state of this iteration to NSCA server defined in {CONFIG_FILE}')
    if action == 'cleanup':
        parser.add_argument('--force',
                            default=False,
                            action='store_true',
                            help=f'Clean backups to 0 backups, even if limits are to small, no matter what')
    elif action == 'run':
        parser.add_argument('--statsFile',
                            type=str,
                            help=f'Redirect rsync logs to file pointed by this argument')
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

def run_cmd(cmd, check=True) -> str:
    process = subprocess.run(cmd.split(' '), stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False, check=check, text=True)
    return process.stdout or process.stderr

if __name__ == "__main__":
    args = parse_args()
    
    with open(CONFIG_FILE, "r") as f:
        conf = yaml.safe_load(f)
    common_conf = conf.get('common')
    RequiredCommonParams.validate(common_conf)
    log = get_logger(common_conf['files']['log'], args.verbose)
    catch_exception_class = TargetException if args.verbose > 1 else Exception
    target = '-'

    if args.action == 'cleanup':
        state = CleanupState(common_conf['files']['cleanup_state'])
        nagios_service = common_conf['nagios']['cleanup_service']
    else:
        state = RunState(common_conf['files']['run_state'])
        nagios_service = common_conf['nagios']['run_service']
    
    nagios = NagiosServer(common_conf['nagios']['host'], common_conf['nagios']['port'], common_conf['nagios']['host_service'], nagios_service)

    if args.action == Action.PUSH_STATS.value:  # TODO
        influx_host = common_conf['influx']['host']
        influx_port = common_conf['influx']['port']   
        print(f'[{args.action.upper()}] Start pushing stats to {influx_host}:{influx_port}')
        log.info(f'[{args.action.upper()}] Start pushing stats to {influx_host}:{influx_port}')
        try:
            influxdb = InfluxServer(influx_host, influx_port, common_conf['influx']['user'], common_conf['influx']['password_file'], common_conf['influx']['database'])
        except (OSError, FileNotFoundError, ConnectionError) as e:
            print(f"ERROR: Connection to influx server failed: {e}")
            log.error(f"ERROR: Connection to influx server failed: {e}")
            sys.exit(Nagios.WARNING)
        sys.exit(Nagios.OK)
    
    if 'all' in args.targets:
        args.targets = list(conf.get('targets'))
    
    for target in args.targets:
        try:
            target_conf = conf['targets'].get(target)
            if not target_conf: 
                raise TargetError(f"Target not defined in '{CONFIG_FILE}' conf file")
            
            if target_conf.get('type') == BackupType.PUSH.value:
                target = PushTarget(target, target_conf, conf.get('default'), common_conf['dirs']['backups'], common_conf['dirs']['scripts'], common_conf['dirs']['work'])
            elif target_conf.get('type') == BackupType.PULL.value:
                target = PullTarget(target, target_conf, conf.get('default'), common_conf['dirs']['backups'], common_conf['dirs']['scripts'], args.statsFile if hasattr(args, 'statsFile') else None)
            else:
                raise TargetException(f"Type '{target_conf.get('type')}' is not defined")
            
            log.info(f'[{args.action.upper()}] Start processing target')

            if args.action == Action.RUN.value:
                if type(target) == PullTarget and target.wake_on_lan: 
                    target.send_wol_packet()
                target.create_backup()
                state.set_target_status(target, f'({get_display_size(target.backup.size)}) {target.backup.path}', Nagios.OK, target.elapsed_time_copy, target.elapsed_time_pack, target.transfer_speed_copy, target.transfer_speed_pack)
            elif args.action == Action.CLEANUP.value:
                total_recovered_space = 0
                total_removed_backups = 0
                total_num = target.get_backups_num()
                total_size = target.get_backups_size()
                
                if total_num == 0: 
                    state.set_target_status(target, 'No found any backup', Nagios.WARNING, 0, 0, target.max_size)
                elif target.max_size:
                    if total_size >= target.max_size:
                        latest_backup = target.get_latest_backup()
                        oldest_backup = target.get_oldest_backup()
                        
                        log.info(f"Start cleanup, current total size over limit ({get_display_size(total_size)} / {target.display_max_size})")

                        while target.max_size - total_size <= latest_backup.size * 1.5:  # Directory needs to have at least 150% free space of latest backup size
                            if target.get_backups_num() == 1 and not args.force:
                                raise TargetCleanupError(f"Cleanup aborted, only 1 backup left but current max_size limit ({target.display_max_size}) is not enough for next backup*1.5 (~{get_display_size(latest_backup.size*1.5)}), consider increasing the limit or use -f/--force are to process cleanup")
                            log.info(f"Backup '{oldest_backup}' removing...")
                            oldest_backup.remove()
                            log.info(f"Backup '{oldest_backup}' removed")
                            total_removed_backups += 1
                            total_recovered_space += oldest_backup.size
                            oldest_backup = target.get_oldest_backup()
                            total_size = target.get_backups_size()
                        msg = f'Cleanup finished, removed {total_removed_backups} backup/s, recovered {get_display_size(total_recovered_space)} ({get_display_size(target.get_backups_size())} / {target.display_max_size})'
                        state.set_target_status(target, msg, Nagios.OK, total_recovered_space, total_removed_backups, total_size, target.max_size, target.max_num)
                    else:
                        msg = f'No cleanup needed ({get_display_size(total_size)} / {get_display_size(target.max_size)})'
                        state.set_target_status(target, msg, Nagios.OK, total_recovered_space, total_removed_backups, total_size, target.max_size, target.max_num)
                elif target.max_num:
                    if total_num >= target.max_num:                      
                        log.info(f"Start cleanup, max number of backups exceeded ({total_num} / {target.max_num})")
                        
                        while total_num >= target.max_num:
                            if total_num == 1 and not args.force:
                                raise TargetCleanupError(f"Cleanup aborted, only 1 backup left and current max_num limit allows only for {target.max_num} backup, directory cannot be empty, consider increasing the limit or use -f/--force are to process cleanup")
                            oldest_backup = target.get_oldest_backup()
                            log.info(f"Backup '{oldest_backup}' removing...")
                            oldest_backup.remove()
                            log.info(f"Backup '{oldest_backup}' removed")
                            total_removed_backups += 1
                            total_recovered_space += oldest_backup.size
                            total_num = target.get_backups_num()
                        msg = f'Cleanup finished, removed {total_removed_backups} backup/s, recovered {get_display_size(total_recovered_space)} ({total_num} / {target.max_num})'
                        state.set_target_status(target, msg, Nagios.OK, total_recovered_space, total_removed_backups, total_size, target.max_size, target.max_num)
                    else:
                        msg = f'No cleanup needed ({total_num} / {target.max_num})'
                        state.set_target_status(target, msg, Nagios.OK, 0, 0, total_size, target.max_size, target.max_num)
            else:
                raise TargetException(f"Action '{args.action}' is not defined")
        except catch_exception_class as e:
            code = e.code if hasattr(e, 'code') else Nagios.CRITICAL
            state.set_target_status(target, str(e), code)
        
    state.remove_undefined_targets(list(conf["targets"]))

    if not args.noReport:
        nagios.send_report_to_nagios(getattr(Nagios, str(state.get_most_failure_status())), state.get_summary())
