#!/usr/bin/env python3

# Karol Siedlaczek 2023-2025

import re
import os
import sys
import pwd
import grp
import yaml
import math
import argparse
from typing import Tuple
from requests import packages, post
from requests.exceptions import HTTPError
from enum import Enum
from glob import glob
from influxdb import InfluxDBClient
from inspect import isclass
from datetime import datetime, timedelta
from yaml.scanner import ScannerError
import subprocess
import logging

class Defaults(Enum):
    @staticmethod
    def list(enum_class=None) -> list:
        class_name = enum_class or Defaults
        return [member.value for member in class_name]
        #class_name = enum_class or Defaults
        #return [ name.lower() for name, member in class_name.__members__.items() ]
    
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
    NAGIOS = ['host', 'port', 'host_service', 'run_service', 'cleanup_service', 'validation_service', 'push_metrics_service']
    LOG_FILE = []
    DIR = ['backup', 'work', 'script', 'state']
    
    @staticmethod
    def validate(common_conf) -> None:
        missing_required_params = []
        
        if not common_conf:
            raise EnvironmentError("Section 'common' is not defined")
        for parent_param in list(RequiredCommonParams):
            parent_attr = common_conf.get(str(parent_param))
            if not parent_attr:
                missing_required_params.append(f' - common.{parent_param}')
            for child_param in parent_param.value:
                child_attr = parent_attr.get(str(child_param))
                if not child_attr:
                    missing_required_params.append(f' - common.{parent_param}.{child_param}')
        if len(missing_required_params) > 0:
            raise EnvironmentError('\n'.join(missing_required_params))

class BackupType(Defaults):
    PUSH = 'push'
    PULL = 'pull'

class Format(Defaults):
    PACKAGE = 'package'
    COMPRESSED_PACKAGE = 'compressed-package'
    ENCRYPTED_PACKAGE = 'encrypted-package'
    RAW = 'raw'
    
class Action(Defaults):
    CLEANUP = 'cleanup'
    RUN = 'run'
    PUSH_METRICS = 'push-metrics'
    VALIDATE = 'validate'
    CONF_CHECK = 'conf-check'
    
class MetricServerType(Defaults):
    INFLUX = 'influx'
    VICTORIA_METRICS = 'victoria-metrics'

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
    __slots__ = ['code', 'msg']
    
    def __init__(self, code, msg) -> None:
        self.code = code

class TargetError(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(Nagios.CRITICAL, msg)

class TargetWarning(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(Nagios.WARNING, msg)

class TargetSkipException(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(Nagios.OK, msg)

class TargetCleanupError(TargetException):
    def __init__(self, msg) -> None:
        super().__init__(Nagios.CRITICAL, msg)

class MetricServer():
    __slots__ = ['host', 'port', 'type', 'influx_client', 'auth', 'url', 'measurement_name', 'run_metrics_file', 'cleanup_metrics_file', "validation_metrics_file"]
    
    def __init__(self, conf: dict, metrics_base_path: str):
        packages.urllib3.disable_warnings()
        if not conf:
            raise EnvironmentError(f"Not found configuration in config file for metric server, section 'common.metric_server' need to be defined")
        
        self.measurement_name = 'backup_tool'
        self.run_metrics_file = f'{metrics_base_path}/run-state.yaml'
        self.cleanup_metrics_file = f'{metrics_base_path}/cleanup-state.yaml'
        self.validation_metrics_file = f'{metrics_base_path}/validation-state.yaml'
        
        try:
            password_file = conf.get('password_file')
            if password_file:
                Validator.validate_file_exist('common.metric_server.password_file', password_file)
                
                if os.stat(password_file).st_size == 0:
                    raise OSError(f"Password file is empty, provide single line with password, file: {password_file}")
                else:
                    with open(password_file, 'r') as f:
                        password = f.read().strip()
            else:
                password = None
            
            metric_server_type = conf.get('type')
            Validator.validate_allowed_values('common.metric_server.type', metric_server_type, Defaults.list(MetricServerType))
        
            host = conf.get('host')
            port = conf.get('port')
            user = conf.get('user')
            Validator.validate_required_param('common.metric_server.host', host)
            Validator.validate_required_param('common.metric_server.port', port)
            Validator.validate_port('common.metric_server.port', port)
            self.host = host
            self.port = port
            self.type = metric_server_type
            
            if metric_server_type == MetricServerType.INFLUX.value:
                Validator.validate_required_param('common.metric_server.user', user)
                database = conf.get('database')
                ssl = conf.get('ssl')
                verify_ssl = conf.get('verify_ssl')
                
                Validator.validate_required_param('common.metric_server.database', database)
                
                if ssl:
                    Validator.validate_type('common.metric_server.ssl', bool, ssl)
                if verify_ssl:
                    Validator.validate_type('common.metric_server.verify_ssl', bool, verify_ssl)
                
                self.influx_client = InfluxDBClient(
                    self.host, 
                    self.port, 
                    user, 
                    password, 
                    database, 
                    ssl=ssl, 
                    verify_ssl=verify_ssl
                )
                self.influx_client.ping()
            elif metric_server_type == MetricServerType.VICTORIA_METRICS.value:
                self.auth = (user, password) if password else None
                self.url = f"http://{self.host}:{self.port}/write"
        except TargetError as e:
            raise EnvironmentError(e)
        
    def push_run_metrics(self) -> None:
        log.debug(f'Pushing run metrics to {self.host}:{self.port}...')
        with open(self.run_metrics_file, "r") as f:
            stats = yaml.safe_load(f)
            
        if self.type == MetricServerType.INFLUX.value:
            self.__push_run_metrics_to_influx(stats)
        elif self.type == MetricServerType.VICTORIA_METRICS.value:
            self.__push_run_metrics_to_victoria_metrics(stats)
        log.debug(f'Run metrics pushed to {self.host}:{self.port}')
    
    def __push_run_metrics_to_influx(self, stats) -> None:            
        points = []
        for target, stat in stats.items():
            copy_stat = stat.get('processing').get('copy')
            pack_stat = stat.get('processing').get('pack')
            points.append({
                'measurement': self.measurement_name,
                'tags': self.__get_influx_tags(target, 'run', stat),
                'fields': {
                    'msg': stat.get('msg'),
                    'str_timestamp': stat.get('timestamp', {}).get('display'),
                    'timestamp_unix': stat.get('timestamp', {}).get('unix'),
                    'backup_size_bytes': stat.get('backup_size', {}).get('bytes'),
                    'copy_duration_sec': copy_stat.get('seconds'),
                    'pack_duration_sec': pack_stat.get('seconds'),
                    'copy_bytes_per_sec': copy_stat.get('bytes_per_second'),
                    'pack_bytes_per_sec': pack_stat.get('bytes_per_second')
                }
            })
        self.influx_client.write_points(points)
        
    def __push_run_metrics_to_victoria_metrics(self, stats) -> None:
        metrics = []
        for target, stat in stats.items():
            copy_stat = stat.get('processing').get('copy')
            pack_stat = stat.get('processing').get('pack')
            tags = self.__get_victoria_metrics_tags(target, 'run', stat)
            fields = []
            # TODO - VictoriaMetrics does not accept string, maybe VictoriaLogs should be used instead?
            #self.add_field(fields, 'msg', stat.get("msg"))
            self.add_field(fields, 'timestamp_unix', stat.get('timestamp', {}).get('unix'))
            self.add_field(fields, 'backup_size_bytes', stat.get('backup_size', {}).get('bytes'))
            self.add_field(fields, 'copy_duration_sec', copy_stat.get('seconds'))
            self.add_field(fields, 'pack_duration_sec', pack_stat.get('seconds'))
            self.add_field(fields, 'copy_bytes_per_sec', copy_stat.get('bytes_per_second'))
            self.add_field(fields, 'pack_bytes_per_sec', pack_stat.get('bytes_per_second'))
            metrics.append(f"{self.measurement_name},{tags} {','.join(fields)}")
        self.__write_to_victoria_metrics(metrics)
    
    def push_cleanup_metrics(self) -> None:
        log.debug(f'Pushing cleanup metrics to {self.host}:{self.port}...')
        with open(self.cleanup_metrics_file, "r") as f:
            stats = yaml.safe_load(f)
            
        if self.type == MetricServerType.INFLUX.value:
            self.__push_cleanup_metrics_to_influx(stats)
        elif self.type == MetricServerType.VICTORIA_METRICS.value:
            self.__push_cleanup_metrics_to_victoria_metrics(stats)
        log.debug(f'Cleanup metrics pushed to {self.host}:{self.port}')
    
    def __push_cleanup_metrics_to_influx(self, stats) -> None:
        points = []        
        for target, stat in stats.items():
            points.append({
                'measurement': self.measurement_name,
                'tags': self.__get_influx_tags(target, 'cleanup', stat),
                'fields': {
                    'msg': stat.get('msg'),
                    'str_timestamp': stat.get('timestamp', {}).get('display'),
                    'timestamp_unix': stat.get('timestamp', {}).get('unix'),
                    'recovered_bytes': stat.get('recovered_data', {}).get('bytes'),
                    'removed_backups': stat.get('removed_backups'),
                    'total_num': stat.get('total_num'),
                    'total_size_bytes': stat.get('total_size', {}).get('bytes'),
                    'max_num': stat.get('max_num'),
                    'max_size_bytes': stat.get('max_size', {}).get('bytes')
                }
            })
        self.influx_client.write_points(points)
        
    def __push_cleanup_metrics_to_victoria_metrics(self, stats) -> None:
        metrics = []
        for target, stat in stats.items():
            tags = self.__get_victoria_metrics_tags(target, 'cleanup', stat)
            fields = []
            # TODO - VictoriaMetrics does not accept string, maybe VictoriaLogs should be used instead?
            #self.add_field(fields, 'msg', stat.get("msg"))
            self.add_field(fields, 'timestamp_unix', stat.get('timestamp', {}).get('unix'))
            self.add_field(fields, 'recovered_bytes', stat.get('recovered_data', {}).get('bytes'))
            self.add_field(fields, 'removed_backups', stat.get('removed_backups'))
            self.add_field(fields, 'total_num', stat.get('total_num'))
            self.add_field(fields, 'total_size_bytes', stat.get('total_size', {}).get('bytes'))
            self.add_field(fields, 'max_num', stat.get('max_num'))
            self.add_field(fields, 'max_size_bytes', stat.get('max_size', {}).get('bytes', None))
            metrics.append(f"{self.measurement_name},{tags} {','.join(fields)}")
        self.__write_to_victoria_metrics(metrics)
    
    def push_validation_metrics(self) -> None:
        log.debug(f'Pushing validation metrics to {self.host}:{self.port}...')
        with open(self.validation_metrics_file, "r") as f:
            stats = yaml.safe_load(f)
            
        if self.type == MetricServerType.INFLUX.value:
            self.__push_validation_metrics_to_influx(stats)
        elif self.type == MetricServerType.VICTORIA_METRICS.value:
            self.__push_validation_metrics_to_victoria_metrics(stats)
        log.debug(f'Validation metrics pushed to {self.host}:{self.port}')
    
    def __push_validation_metrics_to_influx(self, stats) -> None:
        points = []        
        for target, stat in stats.items():
            points.append({
                'measurement': self.measurement_name,
                'tags': self.__get_influx_tags(target, 'validation', stat),
                'fields': {
                    'msg': stat.get('msg'),
                    'str_timestamp': stat.get('timestamp', {}).get('display'),
                    'timestamp_unix': stat.get('timestamp', {}).get('unix'),
                    'avg_size_bytes': stat.get('avg_size', {}).get('bytes'),
                    'invalid_backups_num': stat.get('invalid_backups_num'),
                    'recent_invalid_streak': stat.get('recent_invalid_streak')
                }
            })
        self.influx_client.write_points(points)
        
    def __push_validation_metrics_to_victoria_metrics(self, stats) -> None:
        metrics = []
        for target, stat in stats.items():
            tags = self.__get_victoria_metrics_tags(target, 'validation', stat)
            fields = []
            # TODO - VictoriaMetrics does not accept string, maybe VictoriaLogs should be used instead?
            #self.add_field(fields, 'msg', stat.get("msg"))
            self.add_field(fields, 'timestamp_unix', stat.get('timestamp', {}).get('unix'))
            self.add_field(fields, 'avg_size_bytes', stat.get('avg_size', {}).get('bytes'))
            self.add_field(fields, 'invalid_backups_num', stat.get('invalid_backups_num'))
            self.add_field(fields, 'recent_invalid_streak', stat.get('recent_invalid_streak'))
            metrics.append(f"{self.measurement_name},{tags} {','.join(fields)}")
        self.__write_to_victoria_metrics(metrics)
    
    def __get_influx_tags(self, target: str, action: str, stat: dict) -> dict:
        return {
            'target': target,
            'status': stat.get('status').get('display'),
            'code': stat.get('status').get('code'),
            'action': action,
            'type': stat.get('type'),
            'format': stat.get('format')
        }
    
    def __get_victoria_metrics_tags(self, target: str, action: str, stat: dict) -> str:
        tags = [
            f'target={target}',
            f'status={stat.get("status").get("display")}',
            f'code={stat.get("status").get("code")}',
            f'action={action}',
            f'type={stat.get("type")}',
            f'format={stat.get("format")}'
        ]
        return ','.join(tags)
    
    def add_field(self, fields: list, key: str, value) -> None:
        if value is not None:
            fields.append(f"{key}={value}i")
    
    def __write_to_victoria_metrics(self, metrics) -> None:
        body = "\n".join(metrics) + "\n"
        response = post(self.url, data=body, auth=self.auth)
        response.raise_for_status()
    
class NagiosServer():
    __slots__ = ['nsca_bin', 'echo_bin', 'host', 'port', 'host_service', 'service']
    
    def __init__(self, host, port, host_service, service) -> None:
        self.nsca_bin = '/usr/sbin/send_nsca'
        self.echo_bin = '/bin/echo'
        self.host = host
        self.port = port
        self.host_service = host_service
        self.service = service
    
    def send_report_to_nagios(self, code: int, msg: str) -> None:
        msg = f'{self.host_service}\t{self.service}\t{code}\t{msg}'
        cmd = f"{self.echo_bin} -e '{msg}' | {self.nsca_bin} -H {self.host} -p {self.port}"
        
        try:
            result = run_cmd(cmd)
            log.debug(f"Nsca packet '{msg}' sent to {self.host}:{self.port}, output: {result}") 
        except subprocess.CalledProcessError as e:
            raise ConnectionError(f"Sending nsca packet to {self.host}:{self.port} failed {e}: {e.stderr}")
    
    def __str__(self) -> str:
        return self.name


class Backup():
    #__slots__ = ['path', 'directory', 'file', 'date', 'incremental_file', 'manifest_file', '_copy_duration_sec', '_copy_bytes_per_sec', '_pack_duration_sec', '_pack_bytes_per_sec']
    DATE_FORMAT = '%Y-%m-%d_%H-%M'
    
    def __init__(self, path: str) -> None:
        self.path = path
        directory, file = os.path.split(self.path)
        self.directory = directory
        self.file = file
        self.copy_duration_sec = None
        self.copy_bytes_per_sec = None
        self.pack_duration_sec = None
        self.pack_bytes_per_sec = None
        
        if self.__is_valid_backup():
            if not os.path.exists(path):
                raise FileNotFoundError(f"Backup '{path}' does not exists")
            date_regex = r'([\d]{4}-[\d]{2}-[\d]{2}_[\d]{2}-[\d]{2})'
            self.date = datetime.strptime(re.search(date_regex, file).group(1), self.DATE_FORMAT)
            self.incremental_file = os.path.join(self.directory, 'incremental.snapshot')
            self.manifest_file = None
        else:
            raise NameError(f"File '{path}' has not valid filename for backup")
    
    @property
    def size(self) -> int:
        return get_path_size(self.path)
    
    @property
    def display_date(self) -> str:
        return self.date.strftime(Backup.DATE_FORMAT)
    
    @property
    def copy_duration_sec(self) -> int:
        return self._copy_duration_sec
    
    @property
    def pack_duration_sec(self) -> int:
        return self._pack_duration_sec
    
    @property
    def copy_bytes_per_sec(self) -> int:
        return self._copy_bytes_per_sec
    
    @property
    def pack_bytes_per_sec(self) -> int:
        return self._pack_bytes_per_sec
    
    @copy_duration_sec.setter
    def copy_duration_sec(self, value) -> None:
        if value is not None and value == 0:
            self._copy_duration_sec = 1
        else:
            self._copy_duration_sec = value
    
    @pack_duration_sec.setter
    def pack_duration_sec(self, value) -> None:
        if value is not None and value == 0:
            self._pack_duration_sec = 1
        else:
            self._pack_duration_sec = value
        
    @copy_bytes_per_sec.setter
    def copy_bytes_per_sec(self, value) -> None:
        if value is not None and value == 0:
            self._copy_bytes_per_sec = 1
        else:
            self._copy_bytes_per_sec = value
        
    @pack_bytes_per_sec.setter
    def pack_bytes_per_sec(self, value) -> None:
        if value is not None and value == 0:
            self._pack_bytes_per_sec = 1
        else:
            self._pack_bytes_per_sec = value
    
    def __is_valid_backup(self) -> bool:  # Matches only filenames created by backup tool
        regex = r'^backup-[\d]{4}-[\d]{2}-[\d]{2}_[\d]{2}-[\d]{2}|\.tar\.gz|\.gpg|\.tar$'
        return bool(re.match(regex, self.file))

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
                return glob(f'{self.directory}/manifests/backup-{self.display_date}.manifest*')[0]
            except IndexError:
                return None
    
    def create_manifest_file(self) -> None:
        self.manifest_file = f'backup-{self.display_date}.manifest'
        manifests_dir = os.path.join(self.directory, 'manifests')
        os.makedirs(manifests_dir, exist_ok=True)
        manifest_path = os.path.join(manifests_dir, self.manifest_file)
        old_cwd = os.getcwd()
        os.chdir(self.path)
        
        try:
            log.info(f"Saving manifest file in '{manifest_path}'...")
            with open(manifest_path, 'w') as f:
                f.writelines(run_cmd(f"/usr/bin/find . -printf '%AF-%AT\t%s\t%p\n'"))
        except subprocess.CalledProcessError as e:
            raise TargetError(f"Saving manifest file from '{self.file}' failed: {e}: {e.stderr}")

        # TODO - Some problems here - Fix encrypted packages
        # if format == Format.PACKAGE.value or format == Format.ENCRYPTED_PACKAGE.value or Format.COMPRESSED_PACKAGE:
        #     self.manifest_file = manifest_file.replace('.txt', '.tar')
            
        #     if encryption_key:
        #         try:
        #             self.manifest_file = run_cmd(f"{script_dir}/pack_and_encrypt.sh {manifest_file} {encryption_key} {self.manifest_file}")
        #         except subprocess.CalledProcessError as e:
        #             raise TargetError(f"Packing and encrypting manifest to {self.manifest_file} failed: {e}: {e.stderr}")
        #     else:
        #         try:
        #             run_cmd(f"tar czf {self.manifest_file} {manifest_file}")
        #         except subprocess.CalledProcessError as e:
        #             raise TargetError(f"Packing manifest to {self.manifest_file} failed: {e}: {e.stderr}")
        #     remove_file_or_dir(manifest_file)
        # else:
        #     self.manifest_file = manifest_file
        os.chdir(old_cwd)
        log.info(f"Manifest file created in '{manifest_path}'")

    def set_permissions(self, permissions: str) -> None:
        os.chmod(self.path, eval(f"0o{permissions}"))
    
    def set_owner(self, owner: str) -> None:
        uid = pwd.getpwnam(owner).pw_uid
        gid = grp.getgrnam(owner).gr_gid
        os.chown(self.path, uid, gid)
    
    @staticmethod
    def get_today_name() -> str:
        return f'backup-{datetime.now().strftime(Backup.DATE_FORMAT)}'
        
    def __str__(self) -> str:
        return self.path

class InvalidBackup():
    __slots__ = ['backup', 'reason']
    
    def __init__(self, backup: Backup, reason: str) -> None:
        self.backup = backup
        self.reason = reason

class Validator():
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
    def validate_max_value(param, max_value, value) -> None:
        if value > max_value:
            raise TargetError(f"Parameter '{param}' with '{value}' value is too big, maximum value is {max_value}")

    @staticmethod
    def validate_port(param, value) -> None:
        min_value = 1
        max_value = 65535
        try:
            Validator.validate_type(param, int, value)
            Validator.validate_min_value(param, min_value, value)
            Validator.validate_max_value(param, max_value, value)
        except TargetError as _:
            raise TargetError(f"Parameter '{param}' is not valid port number, value ({value}) is out of range ({min_value}-{max_value})")
    
    @staticmethod
    def validate_type(param, class_type, value, custom_msg=None) -> None:
        if not isclass(class_type):
            raise AttributeError(f"Type '{class_type}' is not class")
        elif not isinstance(value, class_type):
            raise TargetError(f"Parameter '{param}' with '{value}' value {str(custom_msg) if custom_msg else f'is not valid {class_type.__name__} type'}")
        
    @staticmethod
    def validate_absolute_dir_path(param, dir_path):
        regex = r'^((/[a-zA-Z0-9-_]+)+/?)$'
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
    def __init__(self, name: str, base_dest: str, conf: str, default_conf: str, script_dir: str) -> None:
        self.name = name
        self.backup = None
        self.type = conf.get('type')
        self.dest = os.path.join(base_dest, conf.get('dest')) if conf.get('dest') else os.path.join(base_dest, self.name)
        self.script_dir = script_dir
        self.max_size = None
        self.max_num = None
        self.pre_hooks = conf.get('pre_hooks') or default_conf.get('pre_hooks')
        max_size = conf.get('max_size') or default_conf.get('max_size')
        max_num = conf.get('max_num') or default_conf.get('max_num')
        self.cleanup_ratio = 1.2
        self.min_valid_size_diff_ratio = 0.6

        if max_size and max_num:
            log.warning(f"Parameter 'max_size' and 'max_num' are mutually exclusive, max_num ({max_num}) will be overwritten by max_size ({max_size})")
            self.max_size = max_size
        elif not max_size and not max_num:
            raise TargetError("Target must have defined at least one parameter which declares limitations. First option is by size - choose parameter 'max_size' with value <digit><B|KB|MB|GB|TB>, to limit by backups count select 'max_num' with value <digit>")
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
    def pre_hooks(self) -> list:
        return self._pre_hooks
    
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
    def type(self, value) -> None:
        Validator.validate_required_param('type', value)
        Validator.validate_allowed_values('type', value, Defaults.list(BackupType))
        self._type = value
        
    @dest.setter
    def dest(self, value) -> None:
        Validator.validate_required_param('dest', value)
        Validator.validate_absolute_dir_path('dest', value)
        self._dest = value
    
    @max_size.setter
    def max_size(self, value) -> None:
        if value:
            match = Validator.validate_match('max_size', r'^([1-9]{1}[\d]*)\s?(B|KB|MB|GB|TB)$', value)
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
    def max_num(self, value) -> None:
        if value:
            Validator.validate_type('max_num', int, value)
            Validator.validate_min_value('max_num', 2, value)
            self._max_num = value
        else:
            self._max_num = None
    
    @pre_hooks.setter
    def pre_hooks(self, value) -> None:
        if value:
            Validator.validate_type('pre_hooks', list, value)
            self._pre_hooks = value
        else:
            self._pre_hooks = []
    
    @format.setter
    def format(self, value) -> None:
        Validator.validate_required_param('format', value)
        Validator.validate_allowed_values('format', value, Defaults.list(Format))
        self._format = value
    
    @owner.setter
    def owner(self, value) -> None:
        Validator.validate_required_param('owner', value)
        Validator.validate_type('owner', str, value)
        self._owner = value
    
    @permissions.setter
    def permissions(self, value) -> None:
        Validator.validate_required_param('permissions', value)
        Validator.validate_match('permissions', r'^[0-7]{3}$', value)
        self._permissions = value
    
    @encryption_key.setter
    def encryption_key(self, value) -> None:
        if self.format == Format.ENCRYPTED_PACKAGE.value:
            Validator.validate_required_param('encryption_key', value)
            Validator.validate_type('encryption_key', str, value)
            self._encryption_key = value
        else:
            self._encryption_key = None
        
    def get_backups_size(self) -> int:
        return get_path_size(self.dest)
        
    def get_backups_num(self) -> int:
        total_num = 0
        try:
            for backup_file in os.listdir(self.dest):
                try:
                    Backup(os.path.join(self.dest, backup_file))
                    total_num += 1
                except NameError:
                    continue
            return int(total_num)
        except FileNotFoundError:
            return 0
    
    def get_oldest_backup(self) -> Backup | None:
        oldest_backup = None
        try:
            for backup_file in os.listdir(self.dest):
                try:
                    backup = Backup(os.path.join(self.dest, backup_file))
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
            for backup_file in os.listdir(self.dest):
                try:
                    backup = Backup(os.path.join(self.dest, backup_file))
                    if not latest_backup or backup.date > latest_backup.date:
                        latest_backup = backup
                except NameError:
                    continue
            return latest_backup
        except FileNotFoundError:
            return None
    
    def get_backups(self) -> list[Backup]:
        backups = []
        try:
            for backup_file in os.listdir(self.dest):
                try:
                    backups.append(Backup(os.path.join(self.dest, backup_file)))
                except NameError:
                    continue
            return backups
        except FileNotFoundError:
            return []
        
    def run_pre_hooks(self):
        for pre_hook in self.pre_hooks:
            log.info(f"Executing pre-hook: '{pre_hook}'...")
            try:
                run_cmd(pre_hook)
                log.info(f"Pre-hook '{pre_hook}' executed successfully")
            except subprocess.CalledProcessError as e:
                raise TargetError(f"Failed to execute pre-hook: '{pre_hook}', error: {e}")
        
    def create_backup(self, path: str, copy_duration_sec: int = None) -> Backup:            
        backup = Backup(path)
        backup.set_permissions(self.permissions)
         
        try:
            backup.create_manifest_file()
        except TargetError as error:
            backup.remove()
            raise TargetError(error)
        
        if self.format == Format.PACKAGE.value or self.format == Format.ENCRYPTED_PACKAGE.value or self.format == Format.COMPRESSED_PACKAGE.value:
            pack_start_time = datetime.now()
            old_cwd = os.getcwd()
            os.chdir(backup.directory)
            new_package = f"{backup.file}.tar"
            
            if self.encryption_key:
                log.info(f"Packing and encrypting backup to '{backup.directory}/{new_package}.gpg'...")
                try:
                    new_package = run_cmd(f"{self.script_dir}/pack_and_encrypt.sh {backup.file} {self.encryption_key} {new_package} {backup.incremental_file}")
                except subprocess.CalledProcessError as e:
                    backup.remove()
                    raise TargetError(f"Packing and encrypting backup failed: {e}: {e.stderr}")
                log.info(f"Backup successfully packed and encrypted to '{backup.directory}/{new_package}' path")
            else:
                if self.format == Format.COMPRESSED_PACKAGE.value:
                    new_package += '.gz'
                    cmd = f'tar -g {backup.incremental_file} -piz -cf {new_package} {backup.file}'
                else:
                    cmd = f'tar -g {backup.incremental_file} -pi -cf {new_package} {backup.file}'
                
                log.info(f"Packing backup to '{backup.directory}/{new_package}'...")
                try:
                    run_cmd(cmd)
                except subprocess.CalledProcessError as e:
                    backup.remove()
                    remove_file_or_dir(new_package)
                    raise TargetError(f"Packing backup failed: {e}: {e.stderr}")
                log.info(f"Backup successfully packed to '{backup.directory}/{new_package}' path")

            backup.pack_duration_sec = (datetime.now() - pack_start_time).seconds
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
        
        if backup.pack_duration_sec is not None:
            backup.pack_bytes_per_sec = round(backup.size / backup.pack_duration_sec)
        
        if copy_duration_sec is not None:
            backup.copy_duration_sec = copy_duration_sec
            backup.copy_bytes_per_sec = round(backup.size / backup.copy_duration_sec)

        return backup

    def cleanup(self) -> Tuple[str, int, int, int, int]:
        def remove_oldest_backup() -> int:
            oldest_backup = self.get_oldest_backup()
            oldest_backup_size = oldest_backup.size
            log.info(f"Removing '{oldest_backup}' oldest backup...")
            oldest_backup.remove()
            log.info(f"Oldest backup '{oldest_backup}' removed")
            return oldest_backup_size
        
        total_recovered_bytes = 0
        total_removed_backups = 0
        total_num = self.get_backups_num()
            
        if self.max_size:
            total_size = self.get_backups_size()
            
            if total_size >= self.max_size:
                latest_backup = target.get_latest_backup()
                log.info(f"Start cleanup, current total size over limit ({get_display_size(total_size)} / {self.display_max_size})")
 
                while True: # Directory needs to have at least 120% free space of latest backup size
                    if total_size + latest_backup.size * self.cleanup_ratio <= self.max_size:
                        msg = f'Cleanup finished, removed {total_removed_backups} backup/s, recovered {get_display_size(total_recovered_bytes)} ({get_display_size(total_size)} / {self.display_max_size})'
                        break
                    elif total_num == 1 and not args.force:
                        raise TargetCleanupError(
                            f"Cleanup aborted, only 1 backup left but current max_size " +
                            f"limit ({self.display_max_size}) is not enough for next backup * {self.cleanup_ratio} " +
                            f"(~{get_display_size(latest_backup.size * self.cleanup_ratio)}), consider increasing the limit or use -f/--force to process cleanup"
                        )
                    oldest_backup_size = remove_oldest_backup()
                    total_removed_backups += 1
                    total_num -= 1
                    total_recovered_bytes += oldest_backup_size
                    total_size -= oldest_backup_size
            else:
                msg = f'No cleanup needed ({get_display_size(total_size)} / {get_display_size(self.max_size)})'
        elif total_num >= self.max_num:  
            log.info(f"Start cleanup, max number of backups exceeded ({total_num} / {self.max_num})")
            
            while total_num >= self.max_num:
                if total_num == 1 and not args.force:
                    raise TargetCleanupError(
                        f"Cleanup aborted, only 1 backup left and current max_num limit allows only for {self.max_num} backup, " +
                        f"directory cannot be empty, consider increasing the limit or use -f/--force to process cleanup"
                    )
                oldest_backup_size = remove_oldest_backup()
                total_removed_backups += 1
                total_num -= 1
                total_recovered_bytes += oldest_backup_size
            msg = f'Cleanup finished, removed {total_removed_backups} backup/s, recovered {get_display_size(total_recovered_bytes)} ({total_num} / {self.max_num})'
        else:
            msg = f'No cleanup needed ({total_num} / {self.max_num})'
            
        return msg, total_recovered_bytes, total_removed_backups, total_size, total_num

    def validate(self) -> Tuple[list[InvalidBackup], int, int]:
        total_num = self.get_backups_num()
        log.info("Start validating target...")
        
        if total_num == 0:
            log.info("Validation finished, no backups found")
            return [], 0, 0
        
        invalid_backups = []
        recent_invalid_streak = 0
        found_valid_backup = False
        total_size = self.get_backups_size()
        avg_size = round(total_size / total_num) if total_num else 0
        avg_size_display = get_display_size(avg_size)
        sorted_backups = sorted(self.get_backups(), key=lambda b: b.date, reverse=True)
        
        for backup in sorted_backups:
            backup_size = backup.size
            size_diff_ratio = backup_size / avg_size
            
            if size_diff_ratio < self.min_valid_size_diff_ratio:
                reason = f"Backup size ({get_display_size(backup_size)}) is less than minimum " + \
                    f"valid ratio ({self.min_valid_size_diff_ratio}) compared to the average backup size '{avg_size_display}'"
                invalid_backups.append(InvalidBackup(backup, reason))
                if not found_valid_backup:
                   recent_invalid_streak += 1 
            else:
                found_valid_backup = True
        
        if len(invalid_backups) > 0:
            log.warning(f"Validation finished, found {len(invalid_backups)}/{total_num} backups that did not passed validation checks")
        else:
            log.info(f"Validation finished, all backups ({total_num}) are valid")
        return invalid_backups, avg_size, recent_invalid_streak
        
    def __str__(self) -> str:
        return self.name
     
        
class PullTarget(Target):    
    def __init__(self, name: str, conf: str, default_conf: str, base_dest: str, script_dir: str, stats_file: str) -> None:
        super().__init__(name, base_dest, conf, default_conf, script_dir)
        self.sources = conf.get('sources') or default_conf.get('sources')
        self.timeout = conf.get('timeout') or default_conf.get('timeout')
        self.password_file = conf.get('password_file') or default_conf.get('password_file')
        self.exclude = conf.get('exclude') or default_conf.get('exclude')
        self.stats_file = stats_file    
        self.rsync_port = conf.get('rsync_port') or 873
        self.remote = bool(re.match(r'^\'?rsync:\/\/[a-zA-Z_\-\.0-9]*@', self.sources[0]))
    
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
    def stats_file(self) -> str:
        return self._stats_file
    
    @property
    def rsync_port(self) -> str:
        return self._rsync_port
    
    @sources.setter
    def sources(self, value) -> None:
        Validator.validate_required_param('sources', value)
        Validator.validate_type('sources', list, value)
        self._sources = value
    
    @timeout.setter
    def timeout(self, value) -> None:
        Validator.validate_required_param('timeout', value)
        Validator.validate_type('timeout', int, value)
        self._timeout = value
    
    @password_file.setter
    def password_file(self, value) -> None:
        Validator.validate_required_param('password_file', value)
        Validator.validate_file_exist('password_file', value)
        self._password_file = value
    
    @rsync_port.setter
    def rsync_port(self, value) -> None:
        Validator.validate_port('rsync_port', value)
        self._rsync_port = value
    
    @exclude.setter
    def exclude(self, value) -> None:
        if value:
            Validator.validate_type('exclude', list, value)
            self._exclude = value
        else:
            self._exclude = None
    
    @stats_file.setter
    def stats_file(self, value) -> None:
        if value:
            Validator.validate_file_path(file_path=value, custom_msg=f"Path to stats file '{value}' defined with --stats-file is not valid file path")
            self._stats_file = value
        else:
            self._stats_file = None
        
    def create_backup(self) -> Backup:
        self.run_pre_hooks()
        new_backup_path = os.path.join(self.dest, Backup.get_today_name()) # -rlptgoD
        base_cmd = f'rsync -rlptoW --timeout 30 --no-specials --no-devices{f" --contimeout {self.timeout} --password-file {self.password_file} --port {self.rsync_port}" if self.remote else ""}'
        
        if self.stats_file:
            base_cmd += " --stats --info=name1,progress2"
        if self.exclude:
            exclude_args = ' '.join(f'--exclude "{exclude_arg}"' for exclude_arg in self.exclude)
            base_cmd = f'{base_cmd} {exclude_args}'
        
        cmd = f'{base_cmd} {" ".join(self.sources)} {new_backup_path}'
        os.makedirs(new_backup_path, exist_ok=True)
        log.info(f"Pulling target files to '{new_backup_path}' path...")
        log.debug(f"rsync cmd: {cmd}")
        
        try:
            copy_start_time = datetime.now()
            result = run_cmd(cmd)  # TODO - Add reaction to 24 code (some file vanished) log.warning(f"Some files vanished in source during syncing: [{result.code}] {result.output}")
            copy_duration_sec = (datetime.now() - copy_start_time).seconds
        except subprocess.CalledProcessError as e:
            remove_file_or_dir(new_backup_path)
            log.error(f"Pulling target files failed: [{e.returncode}] {e}: {e.stderr}")
            raise TargetError(f"Pulling target files failed: {e.stderr}")
        
        if self.stats_file:
            with open(self.stats_file, 'w') as f:
                f.writelines(result)
        
        log.info(f"Backup saved in '{new_backup_path}' path")
        return super().create_backup(new_backup_path, copy_duration_sec)

        
class PushTarget(Target):    
    def __init__(self, name: str, conf: str, default_conf: str, base_dest: str, script_dir: str, work_dir: str, skip_frequency: bool) -> None:
        super().__init__(name, base_dest, conf, default_conf, script_dir)
        self.work_dir = os.path.join(work_dir, self.name)
        
        if (skip_frequency or conf.get('skip_frequency') or (conf.get('frequency') == None and default_conf.get('skip_frequency'))):
            self.frequency = 0
        else:
            self.frequency = conf.get('frequency') or default_conf.get('frequency')
    
    @property
    def work_dir(self) -> str:
        return self._work_dir
    
    @property
    def frequency(self) -> int:  # Hours
        return self._frequency
    
    @work_dir.setter
    def work_dir(self, value) -> None:
        Validator.validate_required_param('work_dir', value)
        Validator.validate_absolute_dir_path('work_dir', value)
        self._work_dir = value
        
    @frequency.setter
    def frequency(self, value) -> None:  # Param examples: 16h = 16hours, 1d = 1 day, 3w = 3 weeks, 2m = 2 months
        if (isinstance(value, int) and value >= 0):
            self._frequency = 0
        else:
            Validator.validate_required_param('frequency', value)
            match = Validator.validate_match('frequency', r'^([\d]{1,4})\s?([h|d|m|w]{1})$', value)
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
        self.run_pre_hooks()
        latest_backup = self.get_latest_backup()
        
        if latest_backup:
            last_backup_hours_ago = (datetime.now() - latest_backup.date) // timedelta(hours=1)
        os.makedirs(self.work_dir, exist_ok=True)
        files_in_workdir = os.listdir(self.work_dir)
        
        if not latest_backup or last_backup_hours_ago >= self.frequency:  # There is no backup or correct number of days passed since last backup
            if files_in_workdir:
                new_backup_path = os.path.join(self.dest, Backup.get_today_name())
                os.makedirs(new_backup_path, exist_ok=True)
                
                log.info(f"Moving files from '{self.work_dir}' working directory to '{new_backup_path}' path...")
                try:
                    copy_start_time = datetime.now()
                    run_cmd(f'mv {self.work_dir}/* {new_backup_path}')
                    copy_duration_sec = (datetime.now() - copy_start_time).seconds
                except subprocess.CalledProcessError as e:
                    remove_file_or_dir(new_backup_path)
                    raise TargetError(f"Moving files from '{self.work_dir}' working directory to '{new_backup_path}' failed: {e}: {e.stderr}")

                log.info(f"Files moved from '{self.work_dir}' working directory to '{new_backup_path}' path")
                return super().create_backup(new_backup_path, copy_duration_sec)
            else:
                raise TargetError(f"Not found any file to process in '{self.work_dir}' work directory")
        elif files_in_workdir:
            raise TargetWarning(f"Backup should not be created but found some files in '{self.work_dir}' working directory")
        else:
            raise TargetSkipException(f"Found latest backup from '{latest_backup.date}' created {format_hours_to_ago(last_backup_hours_ago)} ago, frequency is {format_hours_to_ago(self.frequency)}, backup creation skipped")


class State():
    MAX_MSG = 300
    __slots__ = ['state_file', 'state']
    
    def __init__(self, state_file: str) -> None:
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
        os.chmod(self.state_file, 0o660)
        return {}
        
    def update(self, label: str, new_state: dict, status_code: int, msg: str, log_as_debug: bool = False) -> None:
        with open(self.state_file, 'w') as f:
            yaml.safe_dump(new_state, f)

        self.state = new_state
        print(f'{f"[{label}] " if label else ""}{Nagios.get_status_by_code(status_code)}: {msg}')
        
        if status_code == int(Nagios.CRITICAL):
            log.error(msg)
        elif status_code == int(Nagios.WARNING):
            log.warning(msg)
        else:
            if log_as_debug:
                log.debug(msg)
            else:
                log.info(msg)
        
    def remove_undefined_targets(self, defined_targets: list) -> None:
        targets_in_state_file = list(self.state.keys())
        
        for state_target in targets_in_state_file:
            if state_target not in defined_targets:
                del self.state[state_target]
        with open(self.state_file, 'w') as f:
            yaml.safe_dump(self.state, f)
        
    def get_most_failure_status(self) -> dict:
        most_failure_status = {
            'code': 0,
            'display': 'OK'
        }
        
        for target_state in self.state.values():
            status = target_state.get('status')
            
            if int(status['code']) > int(most_failure_status['code']):
                most_failure_status = status
        return most_failure_status
    
    def get_default_target_state_fields(self, code: int, backup_type: str, backup_format: str, msg: str) -> dict:
        now = datetime.now()
        return {
            'timestamp': {
                'unix': int(now.timestamp()),
                'display': now.strftime("%Y-%m-%d %H:%M:%S")
            },
            'status': {
                'code': int(code),
                'display': Nagios.get_status_by_code(code)  
            },
            'type': backup_type,
            'format': backup_format,
            'msg': f'{msg[:State.MAX_MSG]}... ({len(msg) - State.MAX_MSG} log lines truncated)' if len(msg) > State.MAX_MSG else msg
        }
    
    def get_summary(self) -> str:
        summary = ''
        
        for target, target_state in self.state.items():
            status = target_state.get('status', {})
            if int(status['code']) > 0:
                msg = target_state.get('msg').strip().replace("\r\n", " ").replace("\n", " ")
                timestamp = target_state.get('timestamp', {}).get('display', None)
                status_display = status.get('display', 'UNDEFINED')
                
                summary += f"{status_display}: [{target}] {msg} ({timestamp})</br>"
        
        if summary == '':
            return "OK: All backups successful" 
        else:
            return summary[:-5]

class RunState(State):
    def __init__(self, state_file) -> None:
        super().__init__(state_file)
    
    def update(self, target_name: str, code: int, backup_type: str, backup_format: str, msg: str, size: int=None, copy_duration_sec: int=None, pack_duration_sec: int=None, copy_bytes_per_sec: int=None, pack_bytes_per_sec: int=None) -> None:
        new_state = self.state
        new_state[target_name] = {
            **self.get_default_target_state_fields(code, backup_type, backup_format, msg),
            'backup_size': {
                'bytes': size,
                'display': get_display_size(size) if size else None
            },
            'processing': {
                'copy': {
                    'seconds': copy_duration_sec,
                    'bytes_per_second': copy_bytes_per_sec
                },
                'pack': {
                    'seconds': pack_duration_sec,
                    'bytes_per_second': pack_bytes_per_sec
                }
            },
        }
        super().update(target_name, new_state, code, msg)


class CleanupState(State):
    def __init__(self, state_file) -> None:
        super().__init__(state_file)
    
    def update(self, target_name: str, code: int, backup_type: str, backup_format: str, msg: str, recovered_bytes: int=None, removed_backups: int=None, total_size: int=None, total_num: int=None, max_size: int=None, max_num: int=None) -> None:
        new_state = self.state
        new_state[target_name] = {
            **self.get_default_target_state_fields(code, backup_type, backup_format, msg),
            'recovered_data': {
                'bytes': recovered_bytes,
                'display': get_display_size(recovered_bytes) if recovered_bytes else None
            },
            'removed_backups': removed_backups,
            'total_size': {
                'bytes': total_size,
                'display': get_display_size(total_size) if total_size else None
            },
            'total_num': total_num,
            'max_size': {
                'bytes': max_size,
                'display': get_display_size(max_size) if max_size else None
            },
            'max_num': max_num,
        }
        super().update(target_name, new_state, code, msg)

class ValidateState(State):
    def __init__(self, state_file: str) -> None:
        super().__init__(state_file)
        
    def update(self, target_name: str, code: int, backup_type: str, backup_format: str, msg: str = None, invalid_backups: list[InvalidBackup] = [], avg_size: int = None, recent_invalid_streak: int = None) -> None:
        new_state = self.state
        if not msg:
            if len(invalid_backups) > 0:
                msg = f"Validation failed for {len(invalid_backups)} backups"
            else:
                msg = f"Validation successful"
        
        new_state[target_name] = {
            **self.get_default_target_state_fields(code, backup_type, backup_format, msg),
            'avg_size': {
                'bytes': avg_size,
                'display': get_display_size(avg_size) if avg_size else None
            },
            'recent_invalid_streak': recent_invalid_streak,
            'invalid_backups_num': len(invalid_backups),
            'invalid_backups': [{ 'path': b.backup.path, 'reason': b.reason } for b in invalid_backups],
        }
        super().update(target_name, new_state, code, msg)

class PushMetricsState(State):
    def __init__(self, state_file: str) -> None:
        super().__init__(state_file)
    
    def update(self, metric_server_type, code: int, msg: str) -> None:
        now = datetime.now()
        new_state = self.state
        new_state[metric_server_type] = {
            'timestamp': {
                'unix': int(now.timestamp()),
                'display': now.strftime("%Y-%m-%d %H:%M:%S")
            },
            'status': {
                'code': int(code),
                'display': Nagios.get_status_by_code(code)  
            },
            'msg': f'{msg[:State.MAX_MSG]}... ({len(msg) - State.MAX_MSG} log lines truncated)' if len(msg) > State.MAX_MSG else msg
        }
        super().update(None, new_state, code, msg, True)

def remove_file_or_dir(path: str) -> None:
    try:
        run_cmd(f"rm -rf {path}")
    except subprocess.CalledProcessError as e:
        raise TargetError(f"Removing '{path}' failed: {e}: {e.stderr}")

def parse_args():
    parser = argparse.ArgumentParser(description='Backup script', add_help=False)
    parser.add_argument('action', choices=[e.value for e in Action])
    action = parser.parse_known_args()[0].action
    
    parser.add_argument('-c', '--conf',
        default='/etc/backup-tool/backup-tool.yaml',
        type = str,
        help = "Config file, default is '/etc/backup-tool/backup-tool.yaml'"
    )
    parser.add_argument('-v', '--verbose', 
        action='count', 
        default=1,
        help=f'Default verbose level is 1 (INFO)'
    )
    parser.add_argument('--no-report',
        default=False,
        action='store_true',
        help='Disable sending state of this iteration to NSCA server defined in config file'
    )
    if action in [Action.CLEANUP.value, Action.RUN.value, Action.VALIDATE.value]:
        parser.add_argument('-t', '--targets',
            required=True,
            nargs='+',
            help='Target list defined in config file under "targets" markup'
        )
            
    if action == Action.CLEANUP.value:
        parser.add_argument('--force',
            default=False,
            action='store_true',
            help=f'Normally (even if conditions allow it) cleanup iteration will not delete ' +
                    'the last backup to avoid losing all backups and current run will return warning, ' +
                    'but with this argument defined? No one will care about your last backups, if conditions allow even last backup will be deleted'
        )
    elif action == Action.RUN.value:
        parser.add_argument('--skip-frequency',
            default=False,
            action='store_true',
            help='Do not check if backup in type "push" should be skipped if "frequency" parameter does not allow'
        )
        parser.add_argument('-m', '--mode',
            default='full',
            choices=['full', 'inc'],
            help=f'Not implemented yet, currently backups can be made only in full mode'
        )
        parser.add_argument('--stats-file',
            type=str,
            help=f'Redirect rsync stats and progress to file pointed by this argument'
        )
    parser.add_argument('-h', '--help', action='help')
    return parser.parse_args()

def get_display_size(size: int) -> str:
    if size == 0:
        return '0B'
    size_names = ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
    i = int(math.floor(math.log(size, 1024)))
    p = math.pow(1024, i)
    display_size = round(size / p, 2)
    return f'{display_size} {size_names[i]}'

def get_path_size(path: str) -> int:
    if os.path.exists(path):
        try:
            path_size = run_cmd(f"du -sb {path}").split('\t')[0]
        except subprocess.CalledProcessError as e:
            raise TargetError(f"Counting total size of path failed: {e}: {e.stderr}")
        return int(path_size)
    else:
        return 0

def format_hours_to_ago(hours_amount: int) -> str:
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


def get_logger(log_file: str, verbose_level: int) -> None:
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

def run_cmd(cmd: str, check: bool=True) -> str:
    process = subprocess.run(
        cmd, 
        shell=True, 
        stdin=subprocess.DEVNULL, 
        stderr=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        check=check, 
        text=True, 
        executable="/bin/bash"
    )
    return process.stdout or process.stderr

if __name__ == "__main__":
    args = parse_args()
    
    try:
        with open(args.conf, "r") as f:
            conf = yaml.safe_load(f)
    except ScannerError as e:
        print(f"Config file '{args.conf}' is not valid YAML file, error:\n{e}")
        sys.exit(int(Nagios.CRITICAL))
    except Exception as e:
        print(f"Config file '{args.conf}' is unable to read, error:\n{e}")
        sys.exit(int(Nagios.CRITICAL))
    
    common_conf = conf.get('common')
    
    try:
        RequiredCommonParams.validate(common_conf)
    except EnvironmentError as e:
        print(f"Config file '{args.conf}' has missing required parameters:\n{e}")
        sys.exit(int(Nagios.UNKNOWN))
        
    if args.action == Action.CONF_CHECK.value:
        print(f"Config file '{args.conf}' is valid")
        sys.exit(int(Nagios.OK))
    
    log = get_logger(common_conf['log_file'], args.verbose)
    catch_exception_class = TargetException if args.verbose > 1 else Exception
    target = '-'
    
    for _, path in common_conf['dir'].items():
        os.makedirs(path, exist_ok=True)       
    
    if args.action == Action.CLEANUP.value:
        state = CleanupState(f"{common_conf['dir']['state']}/cleanup-state.yaml")
        nagios_service = common_conf['nagios']['cleanup_service']
    elif args.action == Action.VALIDATE.value:
        state = ValidateState(f"{common_conf['dir']['state']}/validation-state.yaml")
        nagios_service = common_conf['nagios']['validation_service']
    elif args.action == Action.RUN.value:
        state = RunState(f"{common_conf['dir']['state']}/run-state.yaml")
        nagios_service = common_conf['nagios']['run_service']
    elif args.action == Action.PUSH_METRICS.value:
        state = PushMetricsState(f"{common_conf['dir']['state']}/push-metrics-state.yaml")
        nagios_service = common_conf['nagios']['push_metrics_service']
    
    nagios = NagiosServer(common_conf['nagios']['host'], common_conf['nagios']['port'], common_conf['nagios']['host_service'], nagios_service)

    if args.action == Action.PUSH_METRICS.value:
        metric_server = None
        
        try:
            metric_server = MetricServer(common_conf.get('metric_server'), common_conf['dir']['state'])
        except (EnvironmentError, FileNotFoundError) as e:
            state.update(common_conf.get('metric_server', {}).get('type', 'unknown'), int(Nagios.WARNING), f"Initializing metric server failed with error: {e}")
        
        if metric_server:    
            try:
                metric_server.push_run_metrics()
                metric_server.push_cleanup_metrics()
                metric_server.push_validation_metrics()
                state.update(metric_server.type, int(Nagios.OK), f"All metrics successfully pushed to {metric_server.host}:{metric_server.port} ({metric_server.type})")
            except (HTTPError, ConnectionError) as e:
                state.update(metric_server.type, int(Nagios.WARNING), f"Pushing metrics failed with error: {e}")
            except (AttributeError, FileNotFoundError) as e:
                state.update(metric_server.type, int(Nagios.WARNING), f"Unable to read source file with metrics: {e}")
    else:     
        if 'all' in args.targets:
            args.targets = list(conf.get('targets'))
    
        for target in args.targets:
            try:                      
                target_conf = conf['targets'].get(target)
                if not target_conf: 
                    raise TargetError("Target not defined in config file")
                
                if target_conf.get('type') == BackupType.PUSH.value:
                    target = PushTarget(target, target_conf, conf.get('default'), common_conf['dir']['backup'], common_conf['dir']['script'], common_conf['dir']['work'], getattr(args, "skip_frequency", False))
                elif target_conf.get('type') == BackupType.PULL.value:
                    target = PullTarget(target, target_conf, conf.get('default'), common_conf['dir']['backup'], common_conf['dir']['script'], getattr(args, "stats_file", None))
                else:
                    raise TargetError(f"Type '{target_conf.get('type')}' is not valid option. Valid options are: {Defaults.list(BackupType)}")
                
                log.info(f'[{args.action.upper()}] Start processing target')

                if args.action == Action.RUN.value:
                    backup = target.create_backup()
                    print(backup)
                    print(backup.copy_bytes_per_sec)
                    print(backup.copy_duration_sec)
                    state.update(
                        target.name, 
                        int(Nagios.OK), 
                        target.type, 
                        target.format, 
                        f'({get_display_size(backup.size)}) {backup.file}', 
                        backup.size, 
                        backup.copy_duration_sec, 
                        backup.pack_duration_sec, 
                        backup.copy_bytes_per_sec, 
                        backup.pack_bytes_per_sec
                    )
                elif args.action == Action.CLEANUP.value:                
                    if target.get_backups_num() == 0:
                        state.update(
                            target.name, 
                            int(Nagios.WARNING), 
                            target.type, 
                            target.format, 
                            'Not found any backup', 
                            0,
                            0, 
                            0,
                            0,
                            target.max_size, 
                            target.max_num
                        )
                    else:
                        msg, recovered_bytes, removed_backups, total_size, total_num = target.cleanup()
                        state.update(
                            target.name, 
                            int(Nagios.OK), 
                            target.type,
                            target.format,
                            msg, 
                            recovered_bytes, 
                            removed_backups, 
                            total_size, 
                            total_num, 
                            target.max_size, 
                            target.max_num
                        )
                elif args.action == Action.VALIDATE.value:
                    invalid_backups, avg_size, recent_invalid_streak = target.validate()
                    if len(invalid_backups) > 0:
                        state.update(
                            target.name, 
                            int(Nagios.WARNING), 
                            target.type, 
                            target.format,
                            None,
                            invalid_backups, 
                            avg_size, 
                            recent_invalid_streak
                        )
                    else:
                        state.update(
                            target.name, 
                            int(Nagios.OK), 
                            target.type,
                            target.format,
                            None,
                            [], 
                            avg_size, 
                            recent_invalid_streak
                        )
                else:
                    raise TargetError(f"Action '{args.action}' is not valid option. Valid options are: {Defaults.list(Action)}")
            except catch_exception_class as e:
                code = e.code if hasattr(e, 'code') else Nagios.CRITICAL
                state.update(target.name, int(code), target.type, target.format, str(e))

    if not args.no_report:
        nagios.send_report_to_nagios(state.get_most_failure_status()['code'], state.get_summary())
    
    if args.action != Action.PUSH_METRICS.value:
        state.remove_undefined_targets(list(conf["targets"]))
    sys.exit(int(Nagios.OK))
