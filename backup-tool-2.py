#!/usr/bin/env python3

import re
import os
import sys
import yaml
import json
import math
import shutil
import argparse
from inspect import isclass
from glob import glob
from datetime import datetime
from wakeonlan import send_magic_packet
import subprocess
import logging as log

# TODO - Set permissions on created backup
#
# TODO - Edit function to remove backups over max 
#        Now it is deleting only one backup when number is greater, 
#        it should constantly deleting backup until number is not greater than max
#
# TODO - Info for further ansible
# apt install gnupg2 tar rsync
# pip3 install wakeonlan
# c - create, g - list for incremental, p - preserve permissions, 
# z - compress to gzip, f - file to backup, i - ignore zero-blocks, O - extract fields to stdio

DEFAULTS = {
    'LOG_LEVEL': 1,
    'CONFIG_FILE': 'backup-tool.yaml',
    'REQUIRED_COMMON_PARAMS': ['nsca_host', 'nsca_port', 'nagios_host', 'nagios_service', 'base_dest', 'log_file', 'hosts_file', 'state_file', 'work_dir'],
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

class Cmd():
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

class Nsca():
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
        
    def set_target_status(self, target_name, msg, code) -> None:
        old_state = self.state.get(target_name)['status'] if self.state.get(target_name) else 'EMPTY'
        self.state[str(target_name)] = {
            'code': code,
            'status': Nsca.get_status_by_code(code),
            'msg': str(msg)
        }
        with open(self.state_file, 'w') as f:
            yaml.safe_dump(self.state, f)
        log.info(f"State change from {old_state} state to {self.state[str(target_name)]['status']} state")
        
    def remove_undefined_targets(self, defined_targets) -> None:
        targets_in_state_file = list(self.state.keys())
        
        for state_target in targets_in_state_file:
            if state_target not in defined_targets:
                del self.state[state_target]
        with open(self.state_file, 'w') as f:
            yaml.safe_dump(self.state, f)
        
    def get_status(self) -> str:
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

class Backup():
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
    
    def __is_valid_backup(self) -> bool:  # Matches only filenames created by backup tool
        regex = r'^backup-[\d]{4}-[\d]{2}-[\d]{2}_[\d]{2}-[\d]{2}|\.tar\.gz|\.gpg$'
        return bool(re.match(regex, self.package))
       
    @property
    def display_date(self) -> str:
        return self.date.strftime(Backup.DATE_FORMAT)
    
    @property
    def display_size(self) -> str:
        if self.size == 0:
            return '0B'
        size_names = ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
        i = int(math.floor(math.log(self.size, 1024)))
        p = math.pow(1024, i)
        display_size = round(self.size / p, 2)
        return f'{display_size} {size_names[i]}'

    def remove(self) -> None:
        try:
            log.info(f"Deleting backup '{self}' in progress...")
            files_to_delete = [self.path]
            manifest_file = self.__get_manifest_file()
            if manifest_file:
                files_to_delete.append(manifest_file)
            for file_to_delete in files_to_delete:
                try:
                    shutil.rmtree(file_to_delete)
                except NotADirectoryError:
                    os.remove(file_to_delete)
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
            packed_manifest_file = manifest_file.replace('.txt', '.tar.gz')
            result = Cmd.run(f'tar czf "{packed_manifest_file}" "{manifest_file}" && rm -rf "{manifest_file}"')    
        
        if result and result.failed:
            raise TargetError(f"Creating manifest file to '{manifest_file}' failed: [{result.code}] {result.output}")
        self.manifest_file = packed_manifest_file if packed_manifest_file else manifest_file
        log.info(f"Manifest file created in '{self.manifest_file}'")

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
        match = re.fullmatch(regex, value)
        if not match:
            raise TargetError(f"""Parameter '{param}' with '{value}' value {str(custom_msg) if custom_msg else f"does not match to '{regex}' pattern"}""")
        return match

    @staticmethod
    def validate_type(param, class_type, value, custom_msg=None) -> None:
        if not isclass(class_type):
            raise AttributeError(f"Type '{class_type}' is not class")
        elif not isinstance(class_type, value):
            raise TargetError(f"Parameter '{param}' with '{value}' value {str(custom_msg) if custom_msg else f'is not valid {class_type} type'}")
        
    @staticmethod
    def validate_dir_path(param, dir_path):
        regex = r'^((/[a-zA-Z0-9-_]+)+|/)$'
        match = re.fullmatch(regex, dir_path)
        if not match:
            raise TargetError(f"Parameter '{param}' with '{dir_path}' path is not valid path to directory")
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
        self.dest = os.path.join(base_dest, conf.get('dest')) or os.path.join(base_dest, self.name)
        max_size = conf.get('max_size') or default_conf.get('max_size')
        max_num = conf.get('max_num') or default_conf.get('max_num')
        
        if max_size and max_num:
            log.warning("Parameter 'max_size' and 'max_num' are mutually exclusive, max_num will be overwritten by max_size")
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
        if self.format == DEFAULTS['FORMATS']['ENCRYPTED_PACKAGE']:
            self.encryption_key = conf.get('encryption_key') or default_conf.get('encryption_key')
    
    @property
    def type(self) -> str:
        return self._type
    
    @property
    def dest(self) -> str:
        return self._dest
    
    @property
    def max_size(self) -> int:
        return self.max_size
    
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
    def permissions(self) -> str:
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
        TargetValidator.validate_dir_path('dest', value)
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
    def max_number(self, value) -> int:
        return self._max_num
    
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
        TargetValidator.validate_match('permissions', r'^[0-7]{3,4}$', value)
        self._permissions = value
    
    @encryption_key.setter
    def encryption_key(self, value) -> str:
        TargetValidator.validate_required_param('encryption_key', value)
        TargetValidator.validate_type('encryption_key', str, value)
        self._encryption_key = value
    
    def get_conf(self) -> dict[str, str]:  # TODO add comment to dump when variable is taken from default params
        return vars(self)

    def get_backup_count(self) -> int:
        count = 0
        try:
            for backup_package in os.listdir(self.dest):
                try:
                    Backup(os.path.join(self.dest, backup_package))
                    count += 1
                except NameError:
                    continue
            return int(count)
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
        else:
            log.debug(f"Backup '{path}' preserved in raw format")
            return Backup(path)
        
        log.debug(f"Packing backup with cmd: {cmd}")
        result = Cmd.run(cmd)

        if result.failed:
            backup.remove()
            raise TargetError(f"Packing backup failed: [{result.code}] {result.output}")
        else:
            log.info(success_msg)
            return Backup(new_path)
                
    def __str__(self) -> str:
        return self.name
        
    
class PullTarget(Target):
    def __init__(self, name, base_dest, conf, default_conf) -> None:
        super().__init__(name, base_dest, conf, default_conf)
        self.sources = conf.get('sources') or default_conf.get('sources')
        self.timeout = conf.get('sources') or default_conf.get('sources')
        self.password_file = conf.get('password_file') or default_conf.get('password_file')
        self.exclude = conf.get('exclude') or default_conf.get('exclude')
        self.wake_on_lan = bool(conf.get('wake_on_lan'))
        
        if self.wake_on_lan:
            self.mac_address = conf.get('wake_on_lan').get('mac_address')
    
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
        
        base_cmd = 'rsync -alt'
        if self.exclude:
            exclude_args = ' '.join(f'--exclude "{exclude_arg}"' for exclude_arg in self.exclude)
            base_cmd = f'{base_cmd} {exclude_args}'
        source_args = ' '.join(directory for directory in self.sources)
        cmd = f'{base_cmd} --contimeout={self.timeout} --password-file="{self.password_file}" {source_args} {new_backup_path}'

        os.makedirs(new_backup_path, exist_ok=True)
        log.debug(f"Pulling backup using rsync with command: {cmd}")
        result = Cmd.run(cmd)

        if result.code == 24:
            log.warning(f"Some files vanished in source during syncing: [{result.code}] {result.output}")
        elif result.failed:
            shutil.rmtree(new_backup_path)
            raise TargetError(f"Syncing files from source using rsync failed: [{result.code}] {result.output}")
        log.info(f"Backup saved in '{new_backup_path}'")
        
        self.backup = super().create_backup(new_backup_path)
        log.info(f"Backup finished successfully, size: {self.backup.display_size}")
    
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
    def frequency(self) -> int:
        return self._frequency
    
    @work_dir.setter
    def work_dir(self, value) -> None:
        TargetValidator.validate_required_param('work_dir', value)
        TargetValidator.validate_dir_path('work_dir', value)
        self._work_dir = value
        
    @frequency.setter
    def frequency(self, value) -> None:  # * Param examples: 1d = 1 day, 3w = 3 weeks, 2m = 2 months
        TargetValidator.validate_required_param('frequency', value)
        match = TargetValidator.validate_match('frequency', r'^([\d]{1,4})\s?([d|m|w]{1})$', value)
        number, date_attr = match.groups()
        if date_attr == 'd':
            self._frequency = int(number)
        elif date_attr == 'w':
            self._frequency = int(number) * 7
        elif date_attr == 'm':
            self._frequency = int(number) * 30
      
    def create_backup(self) -> Backup:
        latest_backup = self.get_latest_backup()
        
        try:
            days_ago = (datetime.now() - latest_backup.date).days
        except AttributeError:  # * There is no backup yet for this target
            pass
        finally:
            os.makedirs(self.work_dir, exist_ok=True)
            files_in_workdir = os.listdir(self.work_dir)
            
            if not latest_backup or days_ago >= self.frequency:  # * There is no backup or correct number of days passed since last backup
                if files_in_workdir:
                    new_backup_path = os.path.join(self.dest, Backup.get_today_package_name())
                    os.makedirs(new_backup_path, exist_ok=True)
                    
                    log.info(f"Moving files from '{self.work_dir}' working directory to '{new_backup_path}' path...")
                    result = Cmd.run(f'mv {self.work_dir}/* {new_backup_path}')
                    
                    if result.failed:
                        shutil.rmtree(new_backup_path)
                        raise TargetError(f"Moving files from '{self.work_dir}' working directory to '{new_backup_path}' failed: [{result.code}] {result.output}")
                    else:
                        log.info(f"Files moved from '{self.work_dir}' working directory to '{new_backup_path}' path")
                        self.backup = super().create_backup(new_backup_path)
                        log.info(f"Backup finished successfully, size: {self.backup.display_size}")
                else:
                    raise TargetError(f"Not found any file to process in '{self.work_dir}' work directory")
            elif files_in_workdir:
                raise TargetWarning(f"Backup should not be created but found some files in '{self.work_dir}' working directory")
            else:
                raise TargetSkipException(f"Found latest backup from '{latest_backup.display_date}' created {days_ago} days ago, frequency is {self.frequency} days, backup creation skipped")


def parse_args():
    parser = argparse.ArgumentParser(description='Backup script')
    parser.add_argument('action', choices=['cleanup', 'run'])
    parser.add_argument('-v', '--verbose', 
                        action='count', 
                        default=DEFAULTS['LOG_LEVEL'],
                        help=f'Default verbose level is {DEFAULTS["LOG_LEVEL"]}')
    parser.add_argument('-t', '--targets',
                        required=True,
                        nargs='+',
                        help=f'Target list defined in {DEFAULTS["CONFIG_FILE"]} configuration file under "targets" markup')
    parser.add_argument('-m', '--mode',
                        default='full',
                        choices=['full', 'inc'],
                        help=f'Some help text')
    parser.add_argument('-r', '--report',
                        default=True,
                        action='store_true',
                        help=f'Enable to send reports about error iterations to nsca server defined in {DEFAULTS["CONFIG_FILE"]}')
    
    return parser.parse_args()

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


def set_log_config(log_file, verbose_level) -> None:
    def record_factory(*args, **kwargs) -> log.LogRecord:
        record = old_factory(*args, **kwargs)
        record.target = target
        return record
    
    log.basicConfig(
        filename = log_file, 
        format = '%(asctime)s %(name)s %(levelname)s [%(target)s] %(message)s', 
        datefmt = '%Y-%m-%d %H:%M:%S', 
        level = 30 - (10 * verbose_level) if verbose_level > 0 else 0
    )

    old_factory = log.getLogRecordFactory()
    log.setLogRecordFactory(record_factory)

if __name__ == "__main__":
    args = parse_args()
    
    with open(DEFAULTS['CONFIG_FILE'], "r") as f:
        conf = yaml.safe_load(f)
        
    common_conf = conf.get('common')
    validate_conf_commons(common_conf)
    set_log_config(common_conf.get('log_file'), args.verbose)
    nsca = Nsca(common_conf.get('nagios_host'), common_conf.get('nagios_service'), common_conf.get('nsca_host'), common_conf.get('nsca_port'))
    state = State(common_conf.get('state_file'))
    influx_output = ''
    
    for target in args.targets:
        try:
            target_conf = conf['targets'].get(target)
            if not target_conf: 
                raise TargetError(f'Target not defined in "{DEFAULTS["CONFIG_FILE"]}"')
            
            if target_conf.get('type') == DEFAULTS['BACKUP_TYPES']['PUSH']:
                target = PushTarget(target, common_conf.get('base_dest'), common_conf.get('work_dir'), target_conf, conf.get('default'))
            else:
                target = PullTarget(target, common_conf.get('base_dest'), target_conf, conf.get('default'))
             
            log.info('Start processing target')

            if args.action == 'cleanup':  # TODO - add max_size and max_number of backup to measure
                if target.get_backup_count() >= target.max:
                    oldest_backup = target.get_oldest_backup()
                    log.info(f"Max ({target.max}) number of backups exceeded, oldest backup '{oldest_backup}' will be deleted")
                    oldest_backup.remove()
            else:
                if type(target) == PullTarget and target.wake_on_lan: 
                    target.send_wol_packet()
                target.create_backup()
                msg = f'[{target}] {target.backup.path} ({target.backup.display_size})'
                code = NAGIOS['OK']
        except TargetException as e:
            msg = str(e)
            code = e.code
        finally:
            print(f'{Nsca.get_status_by_code(code)}: {msg}')
            state.set_target_status(target, msg, code)

    state.remove_undefined_targets(list(conf["targets"]))
    #if args.report:
    #    nsca.send_report_to_nagios(NAGIOS[state.get_status()], state.get_summary())
    # TODO - influx client
