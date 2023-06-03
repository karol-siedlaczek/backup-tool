#!/usr/bin/env python3

import os
import re
import sys
import struct
import socket
import time
import shutil
import logging
import argparse
import git
import github
import ipaddress
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

DEFAULTS = {
    'HOST_ADDRESS': ipaddress.IPv4Address('127.0.0.1'),
    'LOG_FILE': os.path.abspath(os.path.join('/var', 'log', f'{os.path.basename(__file__).split(".")[0]}.log')),
    'OWNER': 'root',
    'MAX': 10,  # max number of backups, if max number will be exceeded the oldest file backup be deleted
    'HOSTS_FILE': os.path.abspath(os.path.join(os.sep, 'etc', 'hosts')),
    'FORMAT_CHOICES': [PLAIN_FORMAT, TAR_FORMAT],
    'BACKUP_TYPE_CHOICES': {
        FILE_BACKUP: [LOCAL_BACKUP, REMOTE_BACKUP],
        DATABASE_BACKUP: [PSQL_BACKUP, MYSQL_BACKUP],
        GIT_BACKUP: [GITHUB_BACKUP]
    },
    'PASSWD_FILE': {
        'RSYNC': os.path.join(os.path.expanduser("~"), '.rsyncpass'),
        'PSQL': os.path.join(os.path.expanduser("~"), '.pgpass'),
        'MYSQL': os.path.join(os.path.expanduser("~"), '.my.cnf',),
        'GITHUB': os.path.join(os.path.expanduser("~"), '.github-token',)
    },
}

logging.basicConfig(filename=DEFAULTS['LOG_FILE'], format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)


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
        logging.info(f'checking if "{self}" is up...')
        while waiting:
            response = os.popen(f'ping -c 1 {self}').read()  # for linux -c, for windows -n
            if re.search('[Dd]estination [Hh]ost [Uu]nreachable', response) or \
                    re.search('[Rr]equest [Tt]imed [Oo]ut', response) or \
                    re.search('[Rr]eceived = 0', response) or \
                    re.search('0 [Rr]eceived', response):
                time.sleep(1)
                print(f'waiting for {self}...')
                if datetime.now().strftime("%H:%M:%S") >= end_timestamp.strftime("%H:%M:%S"):
                    logging.error(f'Request timed out, {self} did not response to ping in {int((end_timestamp - start_timestamp).total_seconds())} seconds')
                    return False
            else:
                logging.info(f'host "{self}" is up')
                waiting = False
        return True

    def __str__(self):
        if self.name is None:
            return str(self.ip_address)
        else:
            return self.name


class Backup:
    def __init__(self, backup_type, parent_dir, max_num, owner, output_format):
        self.type = backup_type
        self.parent_dir = parent_dir
        self.max = max_num
        self.owner = owner
        self.format = output_format
        self.dest_dir = self.set_dest_dir()

    def get_num(self):
        try:
            count = 0
            backups = os.listdir(self.parent_dir)
            for backup in backups:
                if os.path.isdir(os.path.join(self.parent_dir, backup)):
                    count += 1
            return int(count)
        except FileNotFoundError:
            return 0  # no parent directory for backups means no backup

    def get_oldest_backup(self):
        os.chdir(self.parent_dir)
        files = sorted(os.listdir(os.getcwd()), key=os.path.getmtime)  # files[0] is the oldest file, files[-1] is the newest
        for entry in files:
            if os.path.isdir(entry):  # looking for first dir in array, so it will find the oldest dir
                logging.info(f'max ({self.max}) num of backups exceeded, oldest backup "{entry}" will be deleted')
                return entry

    def remove_backup(self, backup_path):
        try:
            regex_pattern = r'^backup-[0-9]{4}-[0-9]{2}-[0-9]{2}$|^backup-[0-9]{4}-[0-9]{2}-[0-9]{2}\.tar\.gz$'  # to avoid deleting unexpected directory when user provide wrong path
            logging.info(f'deleting backup "{backup_path}" in progress...')
            if re.match(regex_pattern, backup_path):
                shutil.rmtree(backup_path)
                logging.debug(f'oldest backup "{backup_path}" has been deleted')
            else:
                logging.warning(f'backup not deleted, name of "{backup_path}" does not fit to backup pattern filename')
        except PermissionError as e:
            logging.error(f'{os.path.basename(__file__)}: {e}, cannot delete backup "{backup_path}"')
            print(f'{os.path.basename(__file__)}: an error has occurred, check {DEFAULTS["LOG_FILE"]} for more information')

    def set_privileges(self):
        timestamp = datetime.now().strftime('%Y%m%d%H%M.%S')
        os.system(f'touch -t {timestamp} {self.dest_dir}')
        os.system(f'chown -R {self.owner}:{self.owner} {self.dest_dir}')
        os.system(f'chmod 440 {self.dest_dir}')

    def set_dest_dir(self):
        path = os.path.join(self.parent_dir, f'backup-{get_today()}')
        if not os.path.exists(path):
            os.makedirs(path)
        return path

    def create(self):
        if self.format == TAR_FORMAT:
            logging.info(f'archiving backup "{self.dest_dir}"...')
            os.chdir(self.parent_dir)
            backup_file = os.path.basename(os.path.normpath(self.dest_dir))
            os.system(f'tar -czf {backup_file}.tar.gz {backup_file} && rm -rf {backup_file}')
            logging.info(f'backup "{self.dest_dir}" archived to package')
            self.dest_dir = f'{self.dest_dir}.tar.gz'
        elif self.format == PLAIN_FORMAT:
            pass
        if Backup.get_dir_size(self.dest_dir) > 800:  # bytes
            logging.info(f'COMPLETE: backup success "{self}"')
        else:
            logging.error(f'ERROR: backup "{self}" failed, size is less than 500 B, deleting directory with backup...')
            backup.remove_backup(self.dest_dir)
            logging.info(f'failed backup "{self}" deleted')
            print(f'ERROR: backup "{self}" failed, size is less than 500 B, backup directory has been deleted')

    @staticmethod
    def get_dir_size(path):
        total_size = 0
        with os.scandir(path) as directory:
            for entry in directory:
                if entry.is_file():
                    total_size += entry.stat().st_size
                elif entry.is_dir():
                    total_size += Backup.get_dir_size(entry.path)
        return total_size

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
        os.system(self.cmd)
        super().create()


class FileBackup(FileDatabaseBackup):
    def __init__(self, backup_type, host, user, password, dest_dir, max_num, owner, output_format, rsync_password_file, source_dirs, excluded_dirs):
        super().__init__(backup_type, host, user, password, dest_dir, max_num, owner, output_format)
        self.password_file = rsync_password_file
        self.source_dirs = source_dirs
        self.excluded_dirs = excluded_dirs

    @property
    def password_file(self):
        return self._password_file

    @password_file.setter
    def password_file(self, rsync_password_file):
        if self.type == REMOTE_BACKUP:
            password_file = rsync_password_file
        else:  # LOCAL_BACKUP type
            password_file = None
        if password_file and not self.password and not os.path.isfile(password_file):
            raise OSError(f'Password file "{password_file}" does not exist, use -p/--password to input password as arg or create this file')
        self._password_file = password_file

    def set_cmd(self):  # TO DO (add exclude dirs)
        log_file = f'--info=progress2 > {os.path.join(self.dest_dir, "rsync.log")}'
        base_cmd = 'rsync -altv'
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
    def __init__(self, backup_type, host, user, password, password_file, dest_dir, max_num, owner, output_format, database, port):
        super().__init__(backup_type, host, user, password, dest_dir, max_num, owner, output_format)
        self.password_file = password_file
        self.database = database
        self.port = port

    @property
    def password_file(self):
        return self

    @password_file.setter
    def password_file(self, file_with_password):
        if file_with_password and not self.password and not os.path.isfile(file_with_password):
            raise OSError(f'Password file "{file_with_password}" does not exist, use -p/--password to input password as arg or create this file, see details how to create this file in {self.type} docs')
        self._password_file = file_with_password

    def set_cmd(self):
        log_file = os.path.join(self.dest_dir, "dump.log")
        sql_file = os.path.join(self.dest_dir, f"{self.database}.sql")
        if self.type == PSQL_BACKUP:  # -F t to .tar format
            self.cmd = f'pg_dump -h {self.host.ip_address} -p {self.port} -U {self.user} -v {self.database} > {sql_file} 2> {log_file}'
            if self.password:
                self.cmd = f'PGPASSWORD={self.password} {self.cmd}'
        elif self.type == MYSQL_BACKUP:
            self.cmd = f'mysqldump -h {self.host.ip_address} -P {self.port} -u {self.user} -v'
            if self.password:
                self.cmd = f'{self.cmd} --password={self.password}'
            self.cmd = f'{self.cmd} {self.database} > {sql_file} 2> {log_file}'
        super().set_cmd()

    def create(self):
        logging.info(f'START: backup "{self}" in progress, database: {self.host}:{self.database}')
        self.set_cmd()
        super().create()


class GitBackup(Backup):
    def __init__(self, backup_type, dest_dir, max_num, owner, output_format, token, token_file, repositories):
        super().__init__(backup_type, dest_dir, max_num, owner, output_format)
        git_token = self.get_token(token, token_file)
        self.git = github.Github(git_token)
        self.repositories = repositories if repositories else []

    def create(self):
        user = self.git.get_user()
        logging.info(f'START: backup "{self}" in progress, GitHub repositories from "{user.raw_data["login"]}" account, repo list: "{user.raw_data["repos_url"]}"')
        self.set_dest_dir()
        for repo in user.get_repos():
            if repo.name in self.repositories or not self.repositories:
                logging.info(f'cloning "{repo.name}" to "{self.dest_dir}/{repo.name}"...')
                git.Repo.clone_from(repo.clone_url, f'{self.dest_dir}/{repo.name}')
        super().create()

    def get_token(self, token, token_file):
        if token:
            return token
        elif token_file:
            if not os.path.isfile(token_file):
                raise OSError(f'Token file "{token_file}" does not exist, use -t/--token to input token as arg or create this file')
            with open(token_file, 'r') as f:
                return f.read().replace('\n', '')


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

def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('action', choices=DEFAULTS['BACKUP_TYPE_CHOICES'].keys())
    action_arg = parser.parse_known_args()[0].action
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
        parser.add_argument('type', choices=DEFAULTS['BACKUP_TYPE_CHOICES'][FILE_BACKUP])
        parser.add_argument('-s', '--sourceDirs', required=True, nargs='+', help='These directories which will be part of backup, all data from these directories will be recursively copied to directory from -d/--destDir')
        parser.add_argument('-e', '--exclude', nargs='+', help='Exclude files or directory matching pattern/s')
    elif action_arg == DATABASE_BACKUP:
        parser.add_argument('type', choices=DEFAULTS['BACKUP_TYPE_CHOICES'][DATABASE_BACKUP])
        parser.add_argument('-P', '--port', required=True, help='Database port')
        parser.add_argument('-D', '--databases', required=True, nargs='+', help='Database list')
    elif action_arg == GIT_BACKUP:
        parser.add_argument('type', choices=DEFAULTS['BACKUP_TYPE_CHOICES'][GIT_BACKUP])
        token_args = parser.add_mutually_exclusive_group()
        token_args.add_argument('-t', '--token', help='Token to connect with git')
        token_args.add_argument('--tokenFile', default=DEFAULTS['PASSWD_FILE']['GITHUB'], help=f'File with token, default file is {DEFAULTS["PASSWD_FILE"]["GITHUB"]}')
        parser.add_argument('-r', '--repositories', nargs='+', required=not is_all_repositories(), help='Repository list')
        parser.add_argument('-a', '--all', action='store_true', help='All repositories will be copied')

    parser.add_argument('-h', '--help', action='help')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
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
            if args.type in DEFAULTS['BACKUP_TYPE_CHOICES'][DATABASE_BACKUP]:
                for database in args.databases:
                    backup = DatabaseBackup(args.type, host, args.user, args.password, args.passwdFile, os.path.join(args.destDir, database), args.max, args.owner, args.format, database, args.port)
                    if backup.get_num() > backup.max:
                        oldest_backup = backup.get_oldest_backup()
                        backup.remove_backup(oldest_backup)
                    backup.create()
            else:  # if DEFAULTS['FILE_BACKUP_CHOICES'].contains(args.type)
                backup = FileBackup(args.type, host, args.user, args.password, args.destDir, args.max, args.owner, args.format, args.passwdFile, args.sourceDirs, args.exclude)
                if backup.get_num() > backup.max:
                    oldest_backup = backup.get_oldest_backup()
                    backup.remove_backup(oldest_backup)
                backup.create()
        else:  # git backup backup_type, dest_dir, max_num, owner, output_format, token, token_file, repositories
            backup = GitBackup(args.type, args.destDir, args.max, args.owner, args.format, args.token, args.tokenFile, args.repositories)
            if backup.get_num() > backup.max:
                oldest_backup = backup.get_oldest_backup()
                backup.remove_backup(oldest_backup)
            backup.create()
    except (ValueError, ConnectionError, OSError) as e:
        logging.error(f'{os.path.basename(__file__)}: {e}')
        print(f'{os.path.basename(__file__)}: {e}')
