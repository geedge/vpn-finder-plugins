#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/8 12:36
# @author    : yinjinagyi
# @File    : Config.py
# @Function: read config23.10.yaml file and manage all configurations

import yaml
import os
import sys
sys.path.append('..')

from tool.LoggingTool import Logger
from tool.Functions import get_project_path

logger = Logger().getLogger()


class Config:
    def __init__(self):
        # read version information from version.txt, and choose yaml file according to version
        with open(get_project_path() + '/version.txt', 'r') as f:
            version = f.read().strip()
        # 如果文件不存在则报错，日志写入日志文件
        if not os.path.exists(get_project_path() + '/config{}.yaml'.format(version)):
            logger.error('config{}.yaml file does not exist'.format(version))
            sys.exit()

        self.config = self.read_yaml(get_project_path() + '/config{}.yaml'.format(version))


    # read yaml file
    def read_yaml(self, yaml_file):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                config = yaml.load(f.read(), Loader=yaml.FullLoader)
                return config
        except Exception as e:
            print(e)
            sys.exit()

