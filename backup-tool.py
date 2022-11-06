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
from getpass import getpass
import ipaddress
from datetime import datetime
from dateutil.relativedelta import relativedelta

DAEMON_BACKUP = 'daemon'
SSH_BACKUP = 'ssh'
LOCAL_BACKUP = 'local'
PSQL_BACKUP = 'psql'
MYSQL_BACKUP = 'mysql'
TAR_FORMAT = 'tar'
PLAIN_FORMAT = 'plain'

DEFAULTS = {
    'HOST_ADDRESS': ipaddress.IPv4Address('127.0.0.1'),
    'LOG_FILE': os.path.abspath(os.path.join(os.sep, 'var', 'log', f'{os.path.basename(__file__).split(".")[0]}.log')),
    'OWNER': 'root',
    'MAX': 10,  # max number of backups, if max number will be exceeded the oldest file backup be deleted
    'HOSTS_FILE': os.path.abspath(os.path.join(os.sep, 'etc', 'hosts')),
    'FORMAT_CHOICES': [PLAIN_FORMAT, TAR_FORMAT],
    'FILE_BACKUP_CHOICES': [DAEMON_BACKUP, SSH_BACKUP, LOCAL_BACKUP],
    'DATABASE_BACKUP_CHOICES': [PSQL_BACKUP, MYSQL_BACKUP],
    'PASSWD_FILE': {
        'DAEMON': os.path.join(os.path.expanduser("~"), '.rsyncpass'),
        'SSH': os.path.join(os.path.expanduser("~"), '.ssh', '.password'),
        'PSQL': os.path.join(os.path.expanduser("~"), '.pgpass'),
        'MYSQL': os.path.join(os.path.expanduser("~"), '.my.cnf',)
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
    def __init__(self, backup_type, host, user, password, no_password, parent_dir, max_num, owner, output_format):
        self.type = backup_type
        self.password = password
        self.host = host
        self.user = user
        self.no_password = no_password
        self.parent_dir = parent_dir
        self.max = max_num
        self.owner = owner
        self.format = output_format
        self.cmd = None
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

    def remove_oldest(self):
        os.chdir(self.parent_dir)
        files = sorted(os.listdir(os.getcwd()), key=os.path.getmtime)  # files[0] is the oldest file, files[-1] is the newest
        oldest_backup = None
        for file in files:
            if os.path.isdir(file):  # looking for first dir in array, so it will find the oldest dir
                oldest_backup = file
                break
        try:
            regex_pattern = r'^backup-[0-9]{4}-[0-9]{2}-[0-9]{2}$|^backup-[0-9]{4}-[0-9]{2}-[0-9]{2}\.tar\.gz$'  # to avoid deleting unexpected directory when user provide wrong path
            logging.info(f'max ({self.max}) num of backups exceeded, deleting oldest backup "{oldest_backup}" in progress...')
            if re.match(regex_pattern, oldest_backup):
                shutil.rmtree(oldest_backup)
                logging.debug(f'oldest backup "{oldest_backup}" has been deleted')
            else:
                logging.warning(f'backup not deleted, name of "{oldest_backup}" does not fit to backup pattern filename')
        except PermissionError as e:
            logging.error(f'{os.path.basename(__file__)}: {e}, cannot delete oldest backup "{oldest_backup}"')
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

    def set_cmd(self):
        logging.debug(f'cmd: {self.cmd if self.password is None else self.cmd.replace(self.password, "****")}')

    def create(self):
        os.system(self.cmd)
        if self.format == TAR_FORMAT:
            logging.info(f'archiving backup "{self.dest_dir}"...')
            os.chdir(self.parent_dir)
            backup_file = os.path.basename(os.path.normpath(self.dest_dir))
            os.system(f'tar -czf {backup_file}.tar.gz {backup_file} && rm -rf {backup_file}')
            logging.info(f'backup "{self.dest_dir}" archived to package')
            self.dest_dir = f'{self.dest_dir}.tar.gz'
        elif self.format == PLAIN_FORMAT:
            pass
        self.set_privileges()
        logging.info(f'COMPLETE: backup "{self}"')

    def __repr__(self):
        return self.dest_dir


class FileBackup(Backup):
    def __init__(self, backup_type, host_address, user, password, no_password, dest_dir, max_num, owner, output_format, daemon_password_file, ssh_password_file, source_dirs, excluded_dirs):
        super().__init__(backup_type, host_address, user, password, no_password, dest_dir, max_num, owner, output_format)
        self.password_file = (daemon_password_file, ssh_password_file)
        self.source_dirs = source_dirs
        self.excluded_dirs = excluded_dirs

    @property
    def password_file(self):
        return self._password_file

    @password_file.setter
    def password_file(self, password_files):
        if self.type == DAEMON_BACKUP:
            password_file = password_files[0]
        elif self.type == SSH_BACKUP:
            password_file = password_files[1]
        else:  # LOCAL_BACKUP type
            password_file = None
        if password_file and self.no_password and not os.path.isfile(password_file):
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
        elif self.type == SSH_BACKUP:  # -l to copy links, -v verbosity in log, -t timestamps in log, -a archive mode is equivalent to  -rlptgoD, so recurse mode is on etc.
            source_dirs = ' '.join(f'{self.host.ip_address}:{directory}' for directory in self.source_dirs)
            if self.no_password:
                password_arg = f'-f {self.password_file}'
            else:
                password_arg = f'-p {self.password}'
            self.cmd = f'{base_cmd} --rsh="sshpass -P assphrase {password_arg} ssh -l {self.user}" {source_dirs} {self.dest_dir} {log_file}'
        elif self.type == DAEMON_BACKUP:
            source_dirs = ' '.join(f'rsync://{self.user}@{self.host.ip_address}{directory}' for directory in self.source_dirs)
            if self.no_password:
                base_cmd = f'{base_cmd} --password-file="{self.password_file}"'
            else:
                base_cmd = f'RSYNC_PASSWORD={self.password} {base_cmd}'
            self.cmd = f'{base_cmd} {source_dirs} {self.dest_dir} {log_file}'
        super().set_cmd()

    def create(self):
        logging.info(f'START: backup "{self}" in progress, source dirs: {", ".join(f"{self.host}:{directory}" for directory in self.source_dirs)}')
        self.set_cmd()
        super().create()


class DatabaseBackup(Backup):
    def __init__(self, backup_type, host_address, user, password, no_password, dest_dir, max_num, owner, output_format, database, port):
        super().__init__(backup_type, host_address, user, password, no_password, dest_dir, max_num, owner, output_format)
        self.password_file = (DEFAULTS['PASSWD_FILE']['PSQL'], DEFAULTS['PASSWD_FILE']['MYSQL'])
        self.database = database
        self.port = port

    @property
    def password_file(self):
        return self

    @password_file.setter
    def password_file(self, password_files):
        password_file = None
        if self.type == PSQL_BACKUP:
            password_file = password_files[0]
        elif self.type == MYSQL_BACKUP:
            password_file = password_files[1]
        if password_file and self.no_password and not os.path.isfile(password_file):
            raise OSError(f'Password file "{password_file}" does not exist, use -p/--password to input password as arg or create this file, see details how to create this file in {self.type} docs')
        self._password_file = password_file

    def set_cmd(self):
        log_file = os.path.join(self.dest_dir, "dump.log")
        sql_file = os.path.join(self.dest_dir, f"{self.database}.sql")
        if self.type == PSQL_BACKUP:  # -F t to .tar format
            self.cmd = f'pg_dump -h {self.host.ip_address} -p {self.port} -U {self.user} -v {self.database} > {sql_file} 2> {log_file}'
            if not self.no_password:
                self.cmd = f'PGPASSWORD={self.password} {self.cmd}'
        elif self.type == MYSQL_BACKUP:
            self.cmd = f'mysqldump -h {self.host.ip_address} -P {self.port} -u {self.user} -v'
            if not self.no_password:
                self.cmd = f'{self.cmd} --password={self.password}'
            self.cmd = f'{self.cmd} {self.database} > {sql_file} 2> {log_file}'
        super().set_cmd()

    def create(self):
        logging.info(f'START: backup "{self}" in progress, database: {self.host}:{self.database}')
        self.set_cmd()
        super().create()


def get_today():
    return (datetime.now()).strftime('%Y-%m-%d')


def is_database_backup():
    for index, arg in enumerate(sys.argv):
        if arg in DEFAULTS['DATABASE_BACKUP_CHOICES'] and sys.argv[index - 1] == '--type':
            return True
    return False


def is_file_backup():
    for index, arg in enumerate(sys.argv):
        if arg in DEFAULTS['FILE_BACKUP_CHOICES'] and sys.argv[index - 1] == '--type':
            return True
    return False


def is_localhost():  # check if arg is defined to use in localhost
    for index, arg in enumerate(sys.argv):
        if arg == str(DEFAULTS['HOST_ADDRESS']) and (sys.argv[index - 1] == '--hostAddress' or sys.argv[index - 1] == '-H'):
            return True
    if '--hostAddress' not in sys.argv and '-H' not in sys.argv:
        return True
    return False


def parse_args():
    parser = argparse.ArgumentParser(description='Script to make backups')
    parser.add_argument('--type',
                        choices=DEFAULTS['FILE_BACKUP_CHOICES'] + DEFAULTS['DATABASE_BACKUP_CHOICES'],
                        help='Type of rsync connection to create file backups',
                        required=True)
    parser.add_argument('-D', '--databases',
                        nargs='+',
                        help='Specifies the name of the databases to dump',
                        type=str,
                        metavar='database1',
                        required=is_database_backup())
    parser.add_argument('-P', '--dbPort',
                        help='Database port, only usable when --database backup',
                        type=int,
                        metavar='port',
                        required=is_database_backup())
    parser.add_argument('-s', '--sourceDirs',
                        nargs='+',
                        metavar='path1',
                        help='All directories which will be part of backup, all data from these directories '
                             'will be recursively copied to directory from -d/--destDir',
                        required=is_file_backup())
    parser.add_argument('-d', '--destDir',
                        help='Destination directory where backup will be stored, backup will be created '
                             'as sub directory of directory specified here in format <dest_dir>/backup-<curr_date> '
                             'in file backup or <dest_dir>/<database>/<backup>-<curr_date> if database backup',
                        type=os.path.abspath,
                        metavar='directory',
                        required=True)
    parser.add_argument('-H', '--hostAddress',
                        help=f'This option allows to specify IP address to bind to, default is {DEFAULTS["HOST_ADDRESS"]}',
                        type=ipaddress.IPv4Address,
                        metavar='ip_address',
                        default=DEFAULTS['HOST_ADDRESS'])
    parser.add_argument('-u', '--user',
                        help='User name to connect as to make database dump or establish connection by rsync',
                        type=str,
                        metavar='username',
                        required=is_database_backup() or (not is_localhost() and is_file_backup()))
    parser.add_argument('-p', '--password',
                        help='This option is not essential, if --nopasswd is not defined script will be prompt for password',
                        type=str,
                        metavar='password_plain')
    parser.add_argument('-n', '--nopasswd',
                        help='Force to not use password and not prompt for password, script will try to lookup to default files with passwords (depends on --type choose)',
                        action='store_true')
    parser.add_argument('-f', '--format',
                        help=f'Selects the format of the output backup, default is {PLAIN_FORMAT}',
                        choices=DEFAULTS['FORMAT_CHOICES'],
                        default=PLAIN_FORMAT)
    parser.add_argument('-o', '--owner',
                        help=f'User which will be owner of the output backup, default is {DEFAULTS["OWNER"]}',
                        type=str,
                        metavar='username',
                        default=DEFAULTS['OWNER'])
    parser.add_argument('-e', '--exclude',
                        help='Exclude files or directory matching pattern/s',
                        type=str,
                        nargs='+',
                        metavar='pattern')
    parser.add_argument('--tryStartHost',
                        help='Choose this option if you want send WOL packet to host if ping is not successful',
                        action='store_true')
    parser.add_argument('-m', '--max',
                        help=f'Number of max backup directories, if there will be more than specified number the oldest backup will be deleted, default is {DEFAULTS["MAX"]}',
                        type=int,
                        metavar='number',
                        default=DEFAULTS['MAX'])
    parser.add_argument('--daemonPasswdFile',
                        help=f'File with password for rsync user to establish connection in rsync by daemon, default is {DEFAULTS["PASSWD_FILE"]["DAEMON"]}',
                        type=str,
                        metavar='file',
                        default=DEFAULTS['PASSWD_FILE']['DAEMON'])
    parser.add_argument('--sshPasswdFile',
                        help=f'File with password for rsync user to establish connection in rsync via ssh, default is {DEFAULTS["PASSWD_FILE"]["SSH"]}',
                        type=str,
                        metavar='file',
                        default=DEFAULTS['PASSWD_FILE']['SSH'])
    parser.add_argument('--hostsFile',
                        help=f'File with hosts, default is {DEFAULTS["HOSTS_FILE"]}',
                        type=str,
                        metavar='file',
                        default=DEFAULTS['HOSTS_FILE'])
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.password is None and not args.nopasswd and args.user:
        args.password = getpass(prompt=f'Enter password for {args.user} user: ')
    elif args.type in DEFAULTS['FILE_BACKUP_CHOICES'] and args.type != LOCAL_BACKUP and args.hostAddress is DEFAULTS['HOST_ADDRESS']:  # if backup is not local, bot host address points to localhost
        raise ValueError(f'selected value "{args.type}" in --type arg requires -h/--hostAddress different than default {DEFAULTS["HOST_ADDRESS"]}')
    try:
        host = Host(args.hostAddress, args.hostsFile)
        if host.ip_address is not DEFAULTS['HOST_ADDRESS'] and not host.is_up(10):
            if args.tryStartHost:
                host.start()
                if not host.is_up(120):
                    raise ConnectionError(f'Request timeout to {host}, host did not answer to WOL packet')
            else:
                raise ConnectionError(f'Request timeout to {host}')
        if args.type in DEFAULTS['DATABASE_BACKUP_CHOICES']:
            for database in args.databases:
                backup = DatabaseBackup(args.type, host, args.user, args.password, args.nopasswd, os.path.join(args.destDir, database), args.max, args.owner, args.format, database, args.dbPort)
                if backup.get_num() > backup.max:
                    backup.remove_oldest()
                backup.create()
        else:  # if DEFAULTS['FILE_BACKUP_CHOICES'].contains(args.type)
            backup = FileBackup(args.type, host, args.user, args.password, args.nopasswd, args.destDir, args.max, args.owner, args.format, args.daemonPasswdFile, args.sshPasswdFile, args.sourceDirs, args.exclude)
            if backup.get_num() > backup.max:
                backup.remove_oldest()
            backup.create()
    except (ValueError, ConnectionError, OSError) as e:
        logging.error(f'{os.path.basename(__file__)}: {e}')
        print(f'{os.path.basename(__file__)}: {e}')
