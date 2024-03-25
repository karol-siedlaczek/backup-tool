#!/usr/bin/env python3

import re
import os
import sys
import yaml
import json
import struct
import socket
import argparse
from wakeonlan import send_magic_packet
import subprocess
import logging as log

DEFAULTS = {
    'LOG_LEVEL': 1,
    'CONFIG_FILE': 'backup-tool.yaml',
    'REQUIRED_COMMON_PARAMS': ['nsca_host', 'nsca_port', 'nagios_host', 'nagios_service', 'base_dest', 'log_file', 'hosts_file', 'state_file'],
    'ALLOWED_FORMATS': ['package', 'encrypted_package', 'raw']
    # 'ACTIONS': {
    #     'RUN': 'run',  # Run active target
    #     'CLEAN_ERRORS': 'clean-errors',  # Clean error lines from log file
    #     'CHECK': 'check'  # Check if passive target arrived to dest paths in correct time 
    # }
}

NAGIOS = {
    'OK': 0,
    'WARNING': 1,
    'CRITICAL': 2,
    'UNKNOWN': 3
}

class TargetException(Exception):
    pass


class Backup():
    
    @staticmethod
    def is_valid_backup(path) -> bool:  # Matches only filenames created by backup tool
        regex = r'^backup-[\d]{4}-[\d]{2}-[\d]{2}_[\d]{2}:[\d]{2}|\.tar\.gz|\.gpg$'
        return bool(re.match(regex, path))
        

class State():
    def __init__(self, state_file) -> None:
        self.state_file = state_file
        try:
            with open(state_file, 'r') as f: 
                self.state = yaml.safe_load(f)
        except FileNotFoundError:
            self.state = self.__init_state_file(state_file)
        finally:
            if not isinstance(self.state, dict):
                self.state = self.__init_state_file(state_file)
    
    def __init_state_file(self, state_file) -> dict:
        open(state_file, 'w').close()
        os.chmod(state_file, 0o640)
        return {}
        
    def set_target_status(self, target_name, msg, code) -> None:
        old_state = self.state.get(target_name)['status'] if self.state.get(target_name) else 'EMPTY'
        self.state[target_name] = {
            'code': code,
            'status': Nsca.get_status_by_code(code),
            'msg': str(msg)
        }
        with open(self.state_file, 'w') as f:
            yaml.safe_dump(self.state, f)
        log.info(f"State change {old_state} > {self.state[target_name]['status']}: {msg}")
        
    def remove_undefined_targets(self, defined_targets) -> None:
        state_targets = list(self.state.keys())
        
        for target in state_targets:
            if target not in defined_targets:
                del self.state[target]
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
    def get_status_by_code(code):
        for nagios_status, nagios_code in NAGIOS.items():
            if code == nagios_code: return nagios_status
        return 'UNKNOWN'


class Target():
    def __init__(self, name, conf, default_conf) -> None:
        self.name = name
        self.backup_file = None
        required_conf_params = ['format', 'owner', 'password_file', 'permissions', 'max', 'type']
        self.set_required_params(conf, default_conf, required_conf_params)
                
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
            backups = os.listdir(self.dest)
            for backup_file in backups:
                if Backup.is_valid_backup(backup_file):
                    count += 1
            return int(count)
        except FileNotFoundError:
            return 0
        
    def delete_oldest_backup(self) -> None:
        log.info()
        
    def __remove_backup() -> None:
        pass
        
    
    
class PullTarget(Target):
    def __init__(self, name, base_dest, conf, default_conf) -> None:
        super().__init__(name, conf, default_conf)
        self.set_required_params(conf, default_conf, ['src', 'timeout'])
        self.dest = os.path.join(base_dest, self.name)
        self.wake_on_lan = bool(conf.get('wake_on_lan'))
        
        if self.wake_on_lan:
            self.mac_address = conf.get('wake_on_lan').get('mac_address')
        self.exclude = conf['exclude'] if conf.get('exclude') else default_conf.get('exclude')
    
    def send_wol_packet(self) -> None:
        send_magic_packet(self.mac_address)
        log.debug(f'WOL packet sent to {self.mac_address}')
        
    def validate_connection(self) -> None:
        sample_src = self.src[0]
        
        if sample_src.startswith('rsync://'):  # Check if source match to remote location pattern
            try:
                host = re.match(r'rsync:\/\/.*@([a-zA-Z_-]*)\/', sample_src).group(1)
            except AttributeError:
                raise TargetException(f"Cannot indicate host address or host name from '{self.src[0]}' source, cannot check if host is listening on tcp:873")
            s = socket.socket()
            s.settimeout(self.timeout)
            
            try:
                s.connect((host, 873))  # Default rsync tcp port
                connected = True
            except socket.error as error:
                connected = False
            finally:
                s.close()
                if not connected:
                    raise TargetException(f"Failed connection to '{host}' in {self.timeout} seconds: {error}")
        else:
            log.debug(f'Target source does not match to remote location pattern')
        
    def __str__(self):
        return self.name
        

class PushTarget(Target):
    def __init__(self, name, conf, default_conf) -> None:
        super().__init__(name, conf, default_conf)
        self.set_required_params(conf, default_conf, ['path', 'check_date'])
        
    def __str__(self):
        return self.name
    
# def get_today():
#     return (datetime.now()).strftime('%Y-%m-%d')



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


def validate_conf_commons(commons):
    try:
        if not commons:
            raise EnvironmentError("key 'common' is not defined")
        for param in DEFAULTS['REQUIRED_COMMON_PARAMS']:
            if not commons.get(param):
                raise EnvironmentError(f"parameter '{param}' is missing in 'common' key")
    except EnvironmentError as error:
        print(f"File '{DEFAULTS['CONFIG_FILE']}' is not valid config for backup-tool: {error}")
        sys.exit(NAGIOS['UNKNOWN'])


def set_log_config(log_file, verbose_level):
    def record_factory(*args, **kwargs):
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


def run_cmd(cmd):
    process = subprocess.run(cmd, stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    return_code = process.returncode
    output = process.stderr if process.stderr else process.stdout
    return output.decode('utf-8').replace('\n', ' '), return_code
    
    
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
                    target = PushTarget(target, target_conf, conf.get('default'))
                else:
                    target = PullTarget(target, common_conf.get('base_dest'), target_conf, conf.get('default'))
            else:
                raise TargetException(f'Target not defined in "{DEFAULTS["CONFIG_FILE"]}"')
            
            if type(target) == PullTarget:
                target.validate_connection()
                if target.wake_on_lan:
                    target.send_wol_packet()
            
            if target.backup_count >= target.max:
                log.info(f"Max ({target.max}) number of backups exceeded, oldest backup will be deleted")
                target.delete_oldest_backup()
            
            
            target.dump_conf()
            print(target)
        
            
            state.set_target_status(target.name, 'backup-today', NAGIOS['OK'])
        except TargetException as error:
            log.error(error)
            print(f'[{target}] {os.path.basename(__file__)}: {error}')
            state.set_target_status(target, error, NAGIOS['CRITICAL'])

    state.remove_undefined_targets(list(conf["targets"]))
    #nsca.send_report_to_nagios(NAGIOS[state.get_status()], state.get_summary())
