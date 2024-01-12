#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/8 12:36
# @author    : yinjinagyi
# @File    : Config.py
# @Function: read config.yaml file and manage all configurations

import yaml
import os
import sys
sys.path.append('..')
from tool.Functions import get_project_path


class Config:
    def __init__(self):
        # read config.yaml file
        self.config = self.read_yaml(get_project_path() + '/config.yaml')


    # read yaml file
    def read_yaml(self, yaml_file):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                config = yaml.load(f.read(), Loader=yaml.FullLoader)
                return config
        except Exception as e:
            print(e)
            sys.exit()




if __name__ == '__main__':
    config = Config().config
    print(config)
    print(config['time_zone'])
    print(config['sql']['cyberghost']['sql_tsg'])
