#!/usr/bin/env python3

import argparse
import git
import os
import logging
import github
import shutil
import re
import sys
from getpass import getpass
from datetime import datetime

DEFAULTS = {
    'LOG_FILE': os.path.abspath(os.path.join('log', f'{os.path.basename(__file__).split(".")[0]}.log')), # os.sep, 'var',
    'OWNER': 'root',
    'MAX': 10
}

logging.basicConfig(filename=DEFAULTS['LOG_FILE'], format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)


class GitBackup:
    def __init__(self, token, parent_dir, max_num, owner):
        self.github = github.Github(token)
        self.parent_dir = parent_dir
        self.max = max_num
        self.owner = owner
        self.dest_dir = None

    def create(self):
        user = self.github.get_user()
        self.set_dest_dir()
        for repo in user.get_repos():
            print(repo.name)
            git.Repo.clone_from(repo.clone_url, f'{self.parent_dir}/{repo.name}')

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


def get_today():
    return (datetime.now()).strftime('%Y-%m-%d')


def parse_args():
    parser = argparse.ArgumentParser(description='Script to backup all repos (private and public) from GitHub')
    parser.add_argument('-t', '--token',
                        type=str,
                        help='Fine-grainted access token generated in GitHub account settings')
    parser.add_argument('--tokenFile',
                        help=f'File with Fine-grainted access token to GitHub API',
                        type=str,
                        metavar='file')
    parser.add_argument('-d', '--destDir',
                        help='Destination directory where backup will be stored, backup will be created '
                             'as sub directory of directory specified here in format '
                             '<dest_dir>/backup-<curr_date>/<repository_n> ',
                        type=os.path.abspath,
                        metavar='directory',
                        required=True)
    parser.add_argument('-o', '--owner',
                        help=f'User which will be owner of the output backup, default is {DEFAULTS["OWNER"]}',
                        type=str,
                        metavar='username',
                        default=DEFAULTS['OWNER'])
    parser.add_argument('-m', '--max',
                        help=f'Number of max backup directories, if there will be more than specified number '
                             f'the oldest backup will be deleted, default is {DEFAULTS["MAX"]}',
                        type=int,
                        metavar='number',
                        default=DEFAULTS['MAX'])
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.token is None and not args.tokenFile:
        args.token = getpass(prompt=f'Enter GitHub fine-grainted token: ')
    elif not args.token and args.tokenFile:
        with open(args.tokenFile) as f:
            args.token = f.readline()
    github_backup = GitBackup(args.token, args.destDir, args.max, args.owner)
    if github_backup.get_num() > github_backup.max:
        github_backup.remove_oldest()
    #github.create()
