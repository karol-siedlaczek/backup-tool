#!/usr/bin/env python3

import os
import sys
import yaml
import argparse
import logging as log
from datetime import datetime

DEFAULTS = {    
    'LOG_LEVEL': 1,
    'CONFIG_FILE': 'backup-tool.yaml',
    # 'ACTIONS': {
    #     'RUN': 'run',  # Run active target
    #     'CLEAN_ERRORS': 'clean-errors',  # Clean error lines from log file
    #     'CHECK': 'check'  # Check if passive target arrived to dest paths in correct time 
    # }
}


log.basicConfig(filename=conf['default']['log_file'], format='%(asctime)s %(name)s %(levelname)s [%(target)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=30 - (10 * args.verbose) if args.verbose > 0 else 0)

old_factory = log.getLogRecordFactory()

def record_factory(*args, **kwargs):
    record = old_factory(*args, **kwargs)
    record.target = target
    return record

log.setLogRecordFactory(record_factory)


class BackupException(Exception):
    pass

def valid_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError(f'Value "{value}" is not a valid date in "%Y-%m-%d" format')

def get_today():
    return (datetime.now()).strftime('%Y-%m-%d')

def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('action', choices=['run', 'clean-log'])
    action = parser.parse_known_args()[0].action
            
    if action == 'clean-log':
        parser.add_argument('-s', '--since', 
                            type=valid_date, 
                            default=get_today(),
                            help="Time from which errors in log file should be cleaned")
    else:
        parser.add_argument('-v', '--verbose', 
                            action='count', 
                            default=DEFAULTS['LOG_LEVEL'],
                            help=f'Default verbose level is {DEFAULTS["LOG_LEVEL"]}')
        parser.add_argument('-t', '--targets',
                            required=True,
                            nargs='+',
                            help=f'Target defined in {DEFAULTS["CONFIG_FILE"]} configuration file')
   
        parser.add_argument('-m', '--mode',
                            default='full',
                            choices=['full', 'inc'],
                            help=f'Some help text')
    parser.add_argument('-h', '--help', action='help')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args() 
    
    if args.action == 'clean-log':
        sys.exit(1)
    
    try: 
        with open(DEFAULTS['CONFIG_FILE'], "r") as stream:
            conf = yaml.load(stream, Loader=yaml.SafeLoader)

        
        targets = []
        try:
            for target in args.targets:
                targets.append(conf['targets'][target])
        except KeyError as e:
            raise BackupException(f'Not found "{target}" target in "{DEFAULTS["CONFIG_FILE"]}", choose from: {list(conf["targets"])}')
        
        for target in targets:
            log.info(f'Processing "{target}" target')
        
    except BackupException as e:
        log.error(f'{os.path.basename(__file__)}: {e}')
        print(f'{os.path.basename(__file__)}: {e}')
        sys.exit(1)
