#!/usr/bin/env python3

import json
import os
import re
import sys
import struct
import socket
import time
import shutil
import logging
import argparse
import requests
from git import GitError
import ipaddress
import subprocess
from datetime import datetime
from dateutil.relativedelta import relativedelta

FILE_BACKUP = 'file'
DATABASE_BACKUP = 'database'
GIT_BACKUP = 'git'
LOCAL_BACKUP = 'local'
REMOTE_BACKUP = 'remote'
PSQL_BACKUP = 'psql'
MYSQL_BACKUP = 'mysql'
GITHUB_BACKUP = 'github'
TAR_FORMAT = 'tar'
PLAIN_FORMAT = 'plain'
CLEAN_ERRORS = 'clean-errors'

DEFAULTS = {
    'HOST_ADDRESS': ipaddress.IPv4Address('127.0.0.1'),
    'LOG_FILE': os.path.abspath(os.path.join('/var', 'log', f'{os.path.basename(__file__).split(".")[0]}.log')),
    'LOG_LEVEL': 1,
    'OWNER': 'root',
    'MAX': 10,  # max number of backups, if max number will be exceeded the oldest file backup be deleted
    'HOSTS_FILE': os.path.abspath(os.path.join(os.sep, 'etc', 'hosts')),
    'FORMAT_CHOICES': [PLAIN_FORMAT, TAR_FORMAT],
    'ACTION_CHOICES': {
        FILE_BACKUP: [LOCAL_BACKUP, REMOTE_BACKUP],
        DATABASE_BACKUP: [PSQL_BACKUP, MYSQL_BACKUP],
        GIT_BACKUP: [GITHUB_BACKUP],
        CLEAN_ERRORS: None
    },
    'PASSWD_FILE': {
        'RSYNC': os.path.join(os.path.expanduser("~"), '.backup-tool/.rsyncpass'),
        'PSQL': os.path.join(os.path.expanduser("~"), '.backup-tool/.pgpass'),
        'MYSQL': os.path.join(os.path.expanduser("~"), '.backup-tool/.my.cnf',),
        'GITHUB': os.path.join(os.path.expanduser("~"), '.backup-tool/.github.token',)
    },
}


class Host:
    network = 'eth0'
    ip_address_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    mac_address_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'

    def __init__(self, host_address, hosts_file=DEFAULTS['HOSTS_FILE']):
        self.ip_address = host_address
        self.hosts_file = hosts_file
        self.name = None
        self.mac_address = None
        self.broadcast = None

    @property
    def name(self):
        return self._name

    @property
    def mac_address(self):
        return self._mac_address

    @property
    def broadcast(self):
        return self._broadcast

    @name.setter
    def name(self, value):
        try:
            hosts = open(self.hosts_file, 'r')
            for host in hosts:
                try:
                    ip_address = host.split()[0]
                    hostname = host.split()[-1]
                    if ip_address == str(self.ip_address):
                        self._name = hostname
                except IndexError:
                    pass
        except FileNotFoundError as e:
            logging.warning(f'{os.path.basename(__file__)}: {e}, define this file as --hostsFile or skip if arg --tryStartHost is not used, host will be represented by IP address')
            self._name = None

    @mac_address.setter
    def mac_address(self, value):
        ip_neigh = os.popen(f'ip neigh show {self.ip_address}').read().split()
        if ip_neigh:
            for line in ip_neigh:
                if re.match(self.mac_address_pattern, line):
                    self._mac_address = line
        else:
            self._mac_address = None

    @broadcast.setter
    def broadcast(self, value):
        if self.mac_address is None:  # host not found in ip neigh, abort setting broadcast
            self._broadcast = None
        else:
            ip_addr = os.popen(f'ip -4 addr show {self.network} | grep inet').read().split()  # linux usage
            for index, line in enumerate(ip_addr):
                if re.match(self.ip_address_pattern, line) and ip_addr[index - 1] == 'brd':
                    self._broadcast = line

    def start(self):
        mac_address = self.mac_address.replace(self.mac_address[2], '')
        data = ''.join(['FFFFFFFFFFFF', mac_address * 20])  # pad the synchronization stream.
        send_data = b''
        for i in range(0, len(data), 2):  # split up the hex values and pack.
            send_data = b''.join([send_data, struct.pack('B', int(data[i: i + 2], 16))])
        wol_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # broadcast it to the LAN.
        wol_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        wol_sock.sendto(send_data, (self.broadcast, 7))
        logging.debug(f'WOL packet has been sent to "{self}" to turn on host')

    def is_up(self, timeout):
        start_timestamp = datetime.strptime(datetime.now().strftime('%H:%M:%S'), '%H:%M:%S')
        end_timestamp = start_timestamp + relativedelta(seconds=+timeout)  # setting up timeout
        waiting = True
        print(f'checking if "{self}" is up...')
        while waiting:
            response = os.popen(f'ping -c 1 {self}').read()  # for linux -c, for windows -n
            if re.search('[Dd]estination [Hh]ost [Uu]nreachable', response) or \
                    re.search('[Rr]equest [Tt]imed [Oo]ut', response) or \
                    re.search('[Rr]eceived = 0', response) or \
                    re.search('0 [Rr]eceived', response):
                time.sleep(1)
                print(f'waiting for {self}...')
                if datetime.now().strftime("%H:%M:%S") >= end_timestamp.strftime("%H:%M:%S"):
                    logging.warning(f'Request timed out, {self} did not response to ping in {int((end_timestamp - start_timestamp).total_seconds())} seconds')
                    return False
            else:
                print(f'host "{self}" is up')
                logging.info(f'host "{self}" is up')
                waiting = False
        return True

    def __str__(self):
        try:
            return self.name
        except AttributeError:
            return str(self.ip_address)


class Backup:
    dest_dir = None

    def __init__(self, backup_type, parent_dir, max_num, owner, output_format):
        self.type = backup_type
        self.parent_dir = parent_dir
        self.max = max_num
        self.owner = owner
        self.format = output_format
        self.__set_dest_dir()
        self.failed = False
        self.msg = None

    def __set_dest_dir(self):
        path = os.path.join(self.parent_dir, f'backup-{get_today()}')
        if not os.path.exists(path):
            os.makedirs(path)
        self.dest_dir = path

    def delete_oldest_backups(self):
        is_old_backup_to_delete = True
        while is_old_backup_to_delete:
            if self.__get_num() > self.max:
                oldest_backup = self.__get_oldest_backup()
                self.__remove_backup(oldest_backup)
            else:
                is_old_backup_to_delete = False

    def __get_num(self):
        try:
            count = 0
            backups = os.listdir(self.parent_dir)
            for backup in backups:
                backup_path = os.path.join(self.parent_dir, backup)
                if os.path.isdir(backup_path) and Backup.is_backup_file(backup_path):
                    count += 1
            return int(count)
        except FileNotFoundError:
            return 0  # no parent directory for backups means no backup

    def __get_oldest_backup(self):
        os.chdir(self.parent_dir)
        files = sorted(os.listdir(os.getcwd()), key=os.path.getmtime)  # files[0] is the oldest file, files[-1] is the newest
        for entry in files:
            if os.path.isdir(entry) and Backup.is_backup_file(entry):  # looking for first dir in array, so it will find the oldest dir
                logging.info(f'max ({self.max}) num of backups exceeded, oldest backup "{entry}" will be deleted')
                return entry

    def __remove_backup(self, backup_path):
        try:
            logging.debug(f'deleting backup "{backup_path}" in progress...')
            if Backup.is_backup_file(backup_path):
                shutil.rmtree(backup_path)
                logging.info(f'backup "{backup_path}" has been deleted')
            else:
                logging.warning(f'backup not deleted, name of "{backup_path}" does not fit to backup pattern filename')
        except PermissionError as e:
            logging.error(f'{os.path.basename(__file__)}: {e}, cannot delete backup "{backup_path}"')
            print(f'{os.path.basename(__file__)}: an error has occurred, check {DEFAULTS["LOG_FILE"]} for more information')

    def __set_privileges(self):
        timestamp = datetime.now().strftime('%Y%m%d%H%M.%S')
        os.system(f'touch -t {timestamp} {self.dest_dir}')
        os.system(f'chown -R {self.owner}:{self.owner} {self.dest_dir}')
        os.system(f'chmod 400 {self.dest_dir}')

    def create(self):
        if self.failed:
            logging.error(f'backup "{self}" failed with message "{self.msg}", directory for backup will be deleted')
            self.__remove_backup(self.dest_dir)
            print(f'ERROR: backup "{self}" failed with message "{self.msg}", directory for backup will be deleted')
        else:
            if self.format == TAR_FORMAT:
                logging.info(f'archiving backup "{self.dest_dir}"...')
                os.chdir(self.parent_dir)
                backup_file = os.path.basename(os.path.normpath(self.dest_dir))
                os.system(f'tar -czf {backup_file}.tar.gz {backup_file} && rm -rf {backup_file}')
                logging.info(f'backup "{self.dest_dir}" archived to package')
                self.dest_dir = f'{self.dest_dir}.tar.gz'
            self.__set_privileges()
            logging.info(f'COMPLETE: backup success "{self}"')

    @staticmethod
    def is_backup_file(backup_path):
        backup_regex = r'backup-[0-9]{4}-[0-9]{2}-[0-9]{2}(\.tar\.gz)?$'  # to avoid deleting unexpected directory when user provide wrong path
        return re.search(backup_regex, backup_path)

    def __repr__(self):
        return self.dest_dir


class FileDatabaseBackup(Backup):
    def __init__(self, backup_type, host, user, password, dest_dir, max_num, owner, output_format):
        super().__init__(backup_type, dest_dir, max_num, owner, output_format)
        self.host = host
        self.user = user
        self.password = password
        self.cmd = None

    def set_cmd(self):
        logging.debug(f'cmd: {self.cmd if self.password is None else self.cmd.replace(self.password, "****")}')

    def create(self):
        self.msg, return_code = run_command(self.cmd)
        self.failed = False if return_code == 0 else True
        super().create()


class FileBackup(FileDatabaseBackup):
    password_file = None

    def __init__(self, backup_type, host, user, password, dest_dir, max_num, owner, output_format, rsync_password_file, source_dirs, excluded_dirs):
        super().__init__(backup_type, host, user, password, dest_dir, max_num, owner, output_format)
        self.__set_password_file(rsync_password_file)
        self.source_dirs = source_dirs
        self.excluded_dirs = excluded_dirs

    def __set_password_file(self, rsync_password_file):
        if self.type == REMOTE_BACKUP:
            password_file = rsync_password_file
        else:  # LOCAL_BACKUP type
            password_file = None
        if password_file and not self.password and not os.path.isfile(password_file):
            raise OSError(f'Password file "{password_file}" does not exist, use -p/--password to input password as arg or create this file')
        self.password_file = password_file

    def set_cmd(self):  # TO DO (add exclude dirs)
        log_file = f'--info=progress2 > {os.path.join(self.dest_dir, "rsync.log")}'
        base_cmd = 'rsync --stats -altv'
        if self.excluded_dirs:
            exclude_args = ' '.join(f'--exclude "{directory}"' for directory in self.excluded_dirs)
            base_cmd = f'{base_cmd} {exclude_args}'
        if self.type == LOCAL_BACKUP:
            source_dirs = ' '.join(directory for directory in self.source_dirs)
            self.cmd = f'{base_cmd} {source_dirs} {self.dest_dir} {log_file}'
        elif self.type == REMOTE_BACKUP:
            source_dirs = ' '.join(f'rsync://{self.user}@{self.host.ip_address}{directory}' for directory in self.source_dirs)
            if not self.password:
                base_cmd = f'{base_cmd} --password-file="{self.password_file}"'
            else:
                base_cmd = f'RSYNC_PASSWORD={self.password} {base_cmd}'
            self.cmd = f'{base_cmd} {source_dirs} {self.dest_dir} {log_file}'
        super().set_cmd()

    def create(self):
        logging.info(f'START: backup "{self}" in progress, source dirs: {", ".join(f"{self.host}:{directory}" for directory in self.source_dirs)}')
        self.set_cmd()
        super().create()


class DatabaseBackup(FileDatabaseBackup):
    password_file = None

    def __init__(self, backup_type, host, user, password, password_file, dest_dir, max_num, owner, output_format, database, port):
        super().__init__(backup_type, host, user, password, dest_dir, max_num, owner, output_format)
        self.__set_password_file(password_file)
        self.database = database
        self.port = port

    def __set_password_file(self, file_with_password):
        if file_with_password and not self.password and not os.path.isfile(file_with_password):
            raise OSError(f'Password file "{file_with_password}" does not exist, use -p/--password to input password as arg or create this file, see details how to create this file in {self.type} docs')
        self.password_file = file_with_password

    def set_cmd(self):
        log_file = os.path.join(self.dest_dir, "dump.log")
        sql_file = os.path.join(self.dest_dir, f"{self.database}.sql")
        if self.type == PSQL_BACKUP:  # -F t to .tar format
            self.cmd = f'pg_dump -h {self.host.ip_address} -p {self.port} -U {self.user} -v {self.database} > {sql_file} 2> {log_file}'
            if self.password:
                self.cmd = f'PGPASSWORD={self.password} {self.cmd}'
            elif self.password_file:
                self.cmd = f'PGPASSFILE={self.password_file} {self.cmd}'
        elif self.type == MYSQL_BACKUP:
            self.cmd = f'-h {self.host.ip_address} -P {self.port} -u {self.user} -v'
            if self.password:
                self.cmd = f'mysqldump --password={self.password} {self.cmd}'
            elif self.password_file:
                self.cmd = f'mysqldump --defaults-file={self.password_file} {self.cmd}'
            self.cmd = f'{self.cmd} {self.database} > {sql_file} 2> {log_file}'
        super().set_cmd()

    def create(self):
        logging.info(f'START: backup "{self}" in progress, database: {self.host}:{self.database}')
        self.set_cmd()
        super().create()


class GitBackup(Backup):
    token = None

    def __init__(self, backup_type, dest_dir, max_num, owner, output_format, token, token_file, allowed_repos):
        super().__init__(backup_type, dest_dir, max_num, owner, output_format)
        self.__set_token(token, token_file)
        self.allow_repos = allowed_repos if allowed_repos else []

    def __set_token(self, token, token_file):
        if token:
            self.token = token
        elif token_file:
            if not os.path.isfile(token_file):
                raise OSError(f'Token file "{token_file}" does not exist, use -t/--token to input token as arg or create this file')
            with open(token_file, 'r') as f:
                self.token = f.read().strip()

    def create(self):
        try:
            repos = self.get_repos()
            logging.info(f'START: backup "{self}" in progress, GitHub repositories from "{repos[0]["owner"]["login"]}" account')
            for repo in repos:
                if repo['name'] in self.allow_repos or not self.allow_repos:
                    msg, return_code = run_command(f'git clone https://ouath2:{self.token}@github.com/{repo["full_name"]}.git {self.dest_dir}/{repo["owner"]["login"]}/{repo["name"]}')
                    if return_code != 0:
                        raise GitError(msg)
        except GitError as e:
            self.failed = True
            self.msg = e
        finally:
            super().create()

    def get_repos(self):
        response = requests.get('https://api.github.com/user/repos', headers={'Authorization': f'token {self.token}'})
        json_content = json.loads(response.content.decode('utf-8'))
        if response.ok:
            return json_content
        else:
            raise GitError(f"{response.reason} ({response.status_code}): {json_content['message']}")


def run_command(command):
    process = subprocess.run(command, stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    return_code = process.returncode
    output = process.stderr if process.stderr else process.stdout
    return output.decode('utf-8').replace('\n', ' '), return_code


def clean_errors_in_log(log_file, since):
    regex = r'^(?P<timestamp>[0-9]{4}-[0-9]{2}-[0-9]{2}\s[0-9]{2}:[0-9]{2}:[0-9]{2})\s(?P<user>\S*)\s(?P<level>\S*)\s(?P<msg>.*)$'

    new_lines = []
    with open(log_file, 'r') as f:
        for index, line in enumerate(f.readlines()):
            try:
                result = re.search(regex, line)
                if datetime.strptime(result.group('timestamp'), '%Y-%m-%d %H:%M:%S') > since and result.group('level') in ['ERROR', 'CRITICAL']:
                    line = f'{result.group("timestamp")} {result.group("user")} {result.group("level")}_HANDLED {result.group("msg")}\n'
                    print(f"{index}: line '{line.strip()}' has been marked as handled")
            except AttributeError:
                pass
            finally:
                new_lines.append(line)

    with open(log_file, 'w') as f:
        f.writelines(new_lines)


def get_today():
    return (datetime.now()).strftime('%Y-%m-%d')


def is_type_local():
    try:
        return sys.argv[2] == LOCAL_BACKUP
    except IndexError:
        return False


def is_type_daemon():
    try:
        return sys.argv[2] == REMOTE_BACKUP
    except IndexError:
        return False


def is_all_repositories():
    return '--all' in sys.argv or '-a' in sys.argv


def set_default_password_file():
    try:
        if sys.argv[2] == MYSQL_BACKUP:
            return DEFAULTS['PASSWD_FILE']['MYSQL']
        elif sys.argv[2] == PSQL_BACKUP:
            return DEFAULTS['PASSWD_FILE']['PSQL']
        elif sys.argv[1] == 'file':
            return DEFAULTS["PASSWD_FILE"]["RSYNC"]
        else:
            return f"'{DEFAULTS['PASSWD_FILE']['MYSQL']}' if '{MYSQL_BACKUP}' type or '{DEFAULTS['PASSWD_FILE']['PSQL']}' if '{PSQL_BACKUP}' type"
    except IndexError:
        return False


def valid_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError(f'Value "{value}" is not a valid date in "%Y-%m-%d" format')


def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('action', choices=DEFAULTS['ACTION_CHOICES'].keys())
    action_arg = parser.parse_known_args()[0].action
    if not action_arg == CLEAN_ERRORS:
        parser.add_argument('-d', '--destDir', required=True, type=os.path.abspath,
                            help='Destination directory where backup will be stored, backup will be created as sub '
                                 'directory of directory specified here in format <dest_dir>/backup-<curr_date> '
                                 'in file backup or <dest_dir>/<database>/<backup>-<curr_date> if database backup')
        parser.add_argument('-f', '--format', default=PLAIN_FORMAT, choices=DEFAULTS['FORMAT_CHOICES'],
                            help=f'Selects the format of the output backup, default is {PLAIN_FORMAT}')
        parser.add_argument('-o', '--owner',  default=DEFAULTS['OWNER'], help=f'User which will be owner of backup files, default is {DEFAULTS["OWNER"]}',)
        parser.add_argument('-m', '--max', type=int, default=DEFAULTS['MAX'],
                            help=f'Number of max backup directories, if there will be more than '
                                 f'specified number the oldest backup will be deleted, default is {DEFAULTS["MAX"]}')
    parser.add_argument('-v', '--verbose', action='count', default=DEFAULTS['LOG_LEVEL'],
                        help=f'Default verbose level is {DEFAULTS["LOG_LEVEL"]}')
    parser.add_argument('--logFile', '-l', default=DEFAULTS['LOG_FILE'],
                        help=f'Define log file, default is {DEFAULTS["LOG_FILE"]}')
    if action_arg == FILE_BACKUP or action_arg == DATABASE_BACKUP:
        if not is_type_local():
            parser.add_argument('-u', '--user', required=True, help='User')
            parser.add_argument('-H', '--hostAddress', type=ipaddress.IPv4Address,
                                help=f'This option allows to specify IP address to bind to', required=True)
            parser.add_argument('--hostsFile', default=DEFAULTS['HOSTS_FILE'],
                                help=f'File with hosts, default path is {DEFAULTS["HOSTS_FILE"]}')
            parser.add_argument('--tryStartHost', action='store_true', help='Sends WOL packet to host if ping is not successful')
        else:
            parser.set_defaults(hostsFile=DEFAULTS["HOSTS_FILE"], user='local', hostAddress=DEFAULTS['HOST_ADDRESS'])
        password_args = parser.add_mutually_exclusive_group()
        password_args.add_argument('-p', '--password', help='Not essential option, script by default will take password from file defined in --passwdFile')
        password_args.add_argument('--passwdFile', default=set_default_password_file(), help=f'File with password, default path is {set_default_password_file()}')
    if action_arg == FILE_BACKUP:
        parser.add_argument('type', choices=DEFAULTS['ACTION_CHOICES'][FILE_BACKUP])
        parser.add_argument('-s', '--sourceDirs', required=True, nargs='+', help='These directories which will be part of backup, all data from these directories will be recursively copied to directory from -d/--destDir')
        parser.add_argument('-e', '--exclude', nargs='+', help='Exclude files or directory matching pattern/s')
    elif action_arg == DATABASE_BACKUP:
        parser.add_argument('type', choices=DEFAULTS['ACTION_CHOICES'][DATABASE_BACKUP])
        parser.add_argument('-P', '--port', required=True, help='Database port')
        parser.add_argument('-D', '--databases', required=True, nargs='+', help='Database list')
    elif action_arg == GIT_BACKUP:
        parser.add_argument('type', choices=DEFAULTS['ACTION_CHOICES'][GIT_BACKUP])
        token_args = parser.add_mutually_exclusive_group()
        token_args.add_argument('-t', '--token', help='Token to connect with git')
        token_args.add_argument('--tokenFile', default=DEFAULTS['PASSWD_FILE']['GITHUB'], help=f'File with token, default file is {DEFAULTS["PASSWD_FILE"]["GITHUB"]}')
        parser.add_argument('-r', '--repositories', nargs='+', required=not is_all_repositories(), help='Repository list')
        parser.add_argument('-a', '--all', action='store_true', help='All repositories will be copied')
    elif action_arg == CLEAN_ERRORS:
        parser.add_argument('-s', '--since', type=valid_date, default=get_today(),
                            help="Time from which errors in log file should be cleaned")
    parser.add_argument('-h', '--help', action='help')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(filename=args.logFile, format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=30 - (10 * args.verbose) if args.verbose > 0 else 0)

    try:
        if args.action == FILE_BACKUP or args.action == DATABASE_BACKUP:
            host = Host(args.hostAddress, args.hostsFile)
            if host.ip_address is not DEFAULTS['HOST_ADDRESS'] and not host.is_up(10):
                if args.tryStartHost:
                    host.start()
                    if not host.is_up(120):
                        raise ConnectionError(f'Request timeout to {host}, host did not answer to WOL packet')
                else:
                    raise ConnectionError(f'Request timeout to {host}')
            if args.type in DEFAULTS['ACTION_CHOICES'][DATABASE_BACKUP]:
                for database in args.databases:
                    backup = DatabaseBackup(args.type, host, args.user, args.password, args.passwdFile, os.path.join(args.destDir, database), args.max, args.owner, args.format, database, args.port)
                    backup.delete_oldest_backups()
                    backup.create()
            else:
                backup = FileBackup(args.type, host, args.user, args.password, args.destDir, args.max, args.owner, args.format, args.passwdFile, args.sourceDirs, args.exclude)
                backup.delete_oldest_backups()
                backup.create()
        elif args.action == CLEAN_ERRORS:
            clean_errors_in_log(args.logFile, args.since)
        else:
            backup = GitBackup(args.type, args.destDir, args.max, args.owner, args.format, args.token, args.tokenFile, args.repositories)
            backup.delete_oldest_backups()
            backup.create()
    except (ValueError, ConnectionError, OSError, subprocess.TimeoutExpired) as e:
        logging.error(f'{os.path.basename(__file__)}: {e}')
        print(f'{os.path.basename(__file__)}: {e}')
