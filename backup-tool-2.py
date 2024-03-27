#!/usr/bin/env python3

import re
import os
import sys
import yaml
import json
import math
import shutil
import socket
import argparse
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
# z - compress to gzip, f - file to backup, i - ignore zero-blocks, O - extract fiels to stdio

DEFAULTS = {
    'LOG_LEVEL': 1,
    'CONFIG_FILE': 'backup-tool.yaml',
    'REQUIRED_COMMON_PARAMS': ['nsca_host', 'nsca_port', 'nagios_host', 'nagios_service', 'base_dest', 'log_file', 'hosts_file', 'state_file', 'work_dir'],
    'FORMATS': {
        'PACKAGE': 'package',
        'ENCRYPTED_PACKAGE': 'encrypted_package',
        'RAW': 'raw'
    }
}

NAGIOS = {
    'OK': 0,
    'WARNING': 1,
    'CRITICAL': 2,
    'UNKNOWN': 3
}

class TargetException(Exception):
    pass


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
        output, exit_code = run_cmd(cmd)
        if exit_code > 0:
            raise ConnectionError(f"Sending nsca packet to {self.host}:{self.port} failed: {output}")
        
    @staticmethod
    def get_status_by_code(code) -> str:
        for nagios_status, nagios_code in NAGIOS.items():
            if code == nagios_code: return nagios_status
        return 'UNKNOWN'


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
            self.manifest_file = None
        else:
            raise NameError(f"File '{path}' has not valid filename for backup")
    
    def __is_valid_backup(self) -> bool:  # Matches only filenames created by backup tool
        regex = r'^backup-[\d]{4}-[\d]{2}-[\d]{2}_[\d]{2}-[\d]{2}|\.tar\.gz|\.gpg$'
        return bool(re.match(regex, self.package))
    
    @property
    def size(self) -> int:
        return os.stat(self.path).st_size
       
    @property
    def display_size(self) -> str:
        if self.size == 0:
            return '0B'
        size_names = ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
        i = int(math.floor(math.log(self.size, 1024)))
        p = math.pow(1024, i)
        display_size = round(self.size / p, 2)
        return f'{display_size} {size_names[i]}'
    
    def set_package(self, new_package) -> None:
        self.path = os.path.join(self.directory, new_package)
        self.package = new_package
    
    def remove(self) -> None:
        try:
            log.info(f"Deleting backup '{self}' in progress...")
            
            for file_to_delete in [self.path, self.__get_manifest_file()]:
                try:
                    shutil.rmtree(file_to_delete)
                except NotADirectoryError:
                    os.remove(file_to_delete)

            log.info(f"Backup '{self}' deleted [{self.display_size}]")
        except PermissionError as error:
            raise TargetException(f"Cannot delete backup '{self}', reason: {error}")
    
    def __get_manifest_file(self) -> str:  # TODO - FIX, it could raise IndexError when manifest file does not exit
        return self.manifest_file if self.manifest_file else glob(f'{self.directory}/manifests/manifest-{self.date.strftime(Backup.DATE_FORMAT)}*')[0]
    
    def create_manifest_file(self, format, encryption_key=None) -> None:
        manifest_file = os.path.join(self.directory, 'manifests', f'manifest-{self.date.strftime(Backup.DATE_FORMAT)}.txt')
        os.makedirs(os.path.join(self.directory, 'manifests'), exist_ok=True)
        result = Cmd.run(f'find "{self.path}" -printf "%AF %AT\t%s\t%p\n" > "{manifest_file}"')
        encrypting_failed = False
        packed_manifest_file = None
        if result.failed:
            raise TargetException(f"Getting content to manifest file from {self.path} failed: [{result.code}] {result.output}")
        
        if format == DEFAULTS['FORMATS']['ENCRYPTED_PACKAGE']:
            packed_manifest_file = manifest_file.replace('.txt', '.tar.gz.gpg')
            if encryption_key:
                result = Cmd.run(f'tar czO "{manifest_file}" | gpg2 -er "{encryption_key}" --always-trust > "{packed_manifest_file}" && rm -rf "{manifest_file}"')
            else:
                log.warning(f"Backup {self.path} is encrypted, but no encryption key is provided to encrypt manifest file {manifest_file}, manifest file will be only created as package")
                encrypting_failed = True
        if format == DEFAULTS['FORMATS']['PACKAGE'] or encrypting_failed:
            packed_manifest_file = manifest_file.replace('.txt', '.tar.gz')
            result = Cmd.run(f'tar czf "{packed_manifest_file}" "{manifest_file}" && rm -rf "{manifest_file}"')    
        
        if result and result.failed:
            raise TargetException(f"Creating manifest file to {manifest_file} failed: [{result.code}] {result.output}")
        self.manifest_file = packed_manifest_file if packed_manifest_file else manifest_file

    @staticmethod
    def get_today_backup_name() -> str:
        return f'backup-{datetime.now().strftime(Backup.DATE_FORMAT)}'
        
    def __str__(self) -> str:
        return self.path
            

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
        log.info(f"State change {old_state} > {self.state[str(target_name)]['status']}: {msg}")
        
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


class Target():
    def __init__(self, name, base_dest, conf, default_conf) -> None:
        self.name = name
        self.backup = None
        self.encryption_key = None
        self.dest = os.path.join(base_dest, conf['dest']) if conf.get('dest') else os.path.join(base_dest, self.name)
        required_conf_params = ['format', 'owner', 'password_file', 'permissions', 'max', 'type']
        self.set_required_params(conf, default_conf, required_conf_params)
        
        if self.format not in DEFAULTS['FORMATS'].values():
            raise TargetException(f"Target has unknown backup format, possible choices: {DEFAULTS['FORMATS'].values()}")
        elif self.format == DEFAULTS['FORMATS']['ENCRYPTED_PACKAGE']:
            if conf.get('encryption_key'):
                self.encryption_key = conf['encryption_key']
            elif default_conf.get('encryption_key'):
                self.encryption_key = default_conf['encryption_key']
            else:
                raise TargetException("To encrypt backup package parameter 'encryption_key' need to be defined")
                
    def set_required_params(self, conf, default_conf, params):
        for param in params:
            value = conf.get(param)
            if value:
                setattr(self, param, value)
            else:
                default_value = default_conf.get(param)
                if default_value:
                    setattr(self, param, default_value)
                else:
                    raise TargetException(f"Required parameter '{param}' is not defined")
    
    def dump_conf(self) -> None:
        attrs = vars(self)
        print(f'{self}:\n{json.dumps(attrs, indent=2)}\n')
        
    @property
    def backup_count(self) -> int:
        try:
            count = 0
            
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
        try:
            oldest_backup = None
            
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
        
    def create_backup(self) -> Backup:
        try:
            self.backup.create_manifest_file(self.format, self.encryption_key)
        except TargetException as error:
            self.backup.remove()
            raise TargetException(error)
        
        if self.format == DEFAULTS['FORMATS']['PACKAGE']:
            package = f"{self.backup.path}.tar.gz"
            self.backup.set_package(package)
            log.info(f"Packing backup to {self.backup.path}...")
            cmd = f'tar -pigz -cf "{package}" "{self.backup.path}" && rm -rf "{self.backup.path}"'
            success_msg = f"Backup successfully packed to {self.backup.path}"
        elif self.format == DEFAULTS['FORMATS']['ENCRYPTED_PACKAGE']:
            package = f"{self.backup.path}.tar.gz.gpg"
            self.backup.set_package(package)
            log.info(f"Packing and encrypting backup to {self.backup.path}...")
            cmd = f'tar -pigz -cO "{self.backup.path}" | gpg2 -er "{self.encryption_key}" --always-trust > "{package}" && rm -rf "{self.backup.path}"'
            success_msg = f"Backup successfully packed and encrypted to {self.backup.path}"
        else:
            log.debug(f"Backup {self.backup.path} preserved in raw format")
            return self.backup
        
        result = Cmd.run(cmd)
        
        if result.failed:
            self.backup.remove()
            raise TargetException(f"Packing backup failed: [{result.code}] {result.output}")
        else:
            log.info(success_msg)
            self.backup = Backup(package)
            return self.backup        
                
    def __str__(self) -> str:
        return self.name
        
    
class PullTarget(Target):
    def __init__(self, name, base_dest, conf, default_conf) -> None:
        super().__init__(name, base_dest, conf, default_conf)
        self.set_required_params(conf, default_conf, ['sources', 'timeout', 'password_file'])
        self.wake_on_lan = bool(conf.get('wake_on_lan'))
        
        if self.wake_on_lan:
            self.mac_address = conf.get('wake_on_lan').get('mac_address')
        self.exclude = conf['exclude'] if conf.get('exclude') else default_conf.get('exclude')
    
    def send_wol_packet(self) -> None:
        send_magic_packet(self.mac_address)
        log.debug(f'WOL packet sent to {self.mac_address}')
        
    def validate_connection(self) -> None:
        sample_src = self.sources[0]
        
        if sample_src.startswith('rsync://'):  # Check if source match to remote location pattern
            try:
                host = re.match(r'rsync:\/\/.*@([a-zA-Z_\-0-9]*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/', sample_src).group(1)
            except AttributeError:
                raise TargetException(f"Cannot indicate host address or host name from '{sample_src}' source, cannot check if host is listening on tcp:873")
            s = socket.socket()
            s.settimeout(self.timeout)
            
            error = None
            try:
                s.connect((host, 873))  # Default rsync tcp port
            except socket.error as e:
                error = e
            finally:
                s.close()
                if error:
                    raise TargetException(f"Failed connection to '{host}' in {self.timeout} seconds: {error}")
        else:
            log.debug(f'Target source does not match to remote location pattern')
            
    def create_backup(self) -> Backup:
        backup = Backup(os.path.join(self.dest, Backup.get_today_backup_name()))
        os.makedirs(backup.path, exist_ok=True)
        
        base_cmd = 'rsync -alt'
        if self.exclude:
            exclude_args = ' '.join(f'--exclude "{exclude_arg}"' for exclude_arg in self.exclude)
            base_cmd = f'{base_cmd} {exclude_args}'
        source_args = ' '.join(directory for directory in self.sources)
        cmd = f'{base_cmd} --contimeout=5 --password-file="{self.password_file}" {source_args} {backup.path}'
        self.backup = backup
        log.debug(f"Pulling backup using rsync with command: {cmd}")
        result = Cmd.run(cmd)
        
        if result.code == 24:
            log.warning(f"Some files vanished in source during syncing: [{result.code}] {result.output}")
        elif result.failed:
            self.backup.remove()
            raise TargetException(f"Syncing files from source using rsync failed: [{result.code}] {result.output}")

        super().create_backup()
        

class PushTarget(Target):
    def __init__(self, name, base_dest, conf, default_conf) -> None:
        super().__init__(name, base_dest, conf, default_conf)
        self.set_required_params(conf, default_conf, ['check_date'])

def parse_args():
    parser = argparse.ArgumentParser(description='Backup script')
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
        print(f"File '{DEFAULTS['CONFIG_FILE']}' is not valid config for backup-tool: {error}")
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
    
    for target in args.targets:
        try:
            target_conf = conf['targets'].get(target)
            
            if target_conf:
                if target_conf.get('type') == 'push':
                    target = PushTarget(target, common_conf.get('base_dest'), target_conf, conf.get('default'))
                else:
                    target = PullTarget(target, common_conf.get('base_dest'), target_conf, conf.get('default'))
            else:
                raise TargetException(f'Target not defined in "{DEFAULTS["CONFIG_FILE"]}"')
            log.info('Start processing target')
            
            if type(target) == PullTarget:
                #target.validate_connection()
                if target.wake_on_lan:
                    target.send_wol_packet()
                    
            if target.backup_count >= target.max:
                oldest_backup = target.get_oldest_backup()
                log.info(f"Max ({target.max}) number of backups exceeded, oldest backup '{oldest_backup}' will be deleted")
                oldest_backup.remove()
            
            new_backup = target.create_backup()
            
            print(target)
            print(target.backup_count)
            #target.dump_conf()
        
            state.set_target_status(target.name, f'[{target}] {target.backup.path} ({target.backup.display_size})', NAGIOS['OK'])
            print(f'OK: [{target}] {target.backup.path} ({target.backup.display_size})')
        except TargetException as error:
            log.error(error)
            print(f'[{target}] {os.path.basename(__file__)}: {error}')
            state.set_target_status(target, error, NAGIOS['CRITICAL'])

    state.remove_undefined_targets(list(conf["targets"]))
    #nsca.send_report_to_nagios(NAGIOS[state.get_status()], state.get_summary())
