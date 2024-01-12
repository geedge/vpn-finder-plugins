#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/3/18 15:36
# @author    : yinjinagyi
# @File    : LoggingTool.py
# @Function:


import yaml
import logging.config
import sys
sys.path.append('..')
from tool.Functions import get_project_path




class Logger:
    LOGGER_NAME = 'runLogger'

    def getLogger(self, loggerName=LOGGER_NAME):
        logging.config.dictConfig(load_config())
        logger = logging.getLogger(loggerName)
        return logger


def load_config():
    project_path = get_project_path()
    path = project_path + '/logging.yaml'
    with open(path, 'r') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
    config['handlers']['console_file']['filename'] = config['handlers']['console_file']['filename']
    return config
