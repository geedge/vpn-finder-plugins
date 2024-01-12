#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/6/12 16:09
# @author    : yinjinagyi
# @File    : KnowledgeBaseTool.py
# @Function:

import json
import sys
import time
from warnings import simplefilter
import requests
from tool import Functions, LoggingTool

logger = LoggingTool.Logger().getLogger()
simplefilter(action='ignore', category=FutureWarning)


class KnowledgeApi:
    def __init__(self, config):
        self.config = config
        self.api_address = config['knowledgebase']['host']
        self.api_username = config['knowledgebase']['kb_username']
        self.api_pin = config['knowledgebase']['api_pin']
        self.api_path = config['knowledgebase']['api_path']
        self.retry_max = config['knowledgebase']['api_retry_times']
        self.request_timeout = config['knowledgebase']['api_timeout']
        # self.api_token = self.get_api_token()
        self.api_token = config['knowledgebase']['api_token']

    def get_api_token(self):
        url = "http://" + self.api_address + "/sys/login"
        data = {
            "username": self.api_username,
            "pin": self.api_pin
        }
        try:
            resp = requests.post(url, data=json.dumps(data),
                                 headers={'Content-Type': 'application/json'}, timeout=self.request_timeout)
            return json.loads(resp.text).get('data').get('token')
        except Exception as e:
            logger.error(e)
            sys.exit()

    def get_library_id(self, library_name):
        global resp
        url = "http://" + self.api_address + "/v1/knowledgeBase/list?name=" + library_name
        header = {
            "Cn-Authorization": self.api_token
        }
        try:
            resp = requests.get(url, headers=header, timeout=self.request_timeout)
            return json.loads(resp.text).get('data').get('list')[0].get('knowledgeId')
        except Exception as e:
            logger.error(resp.text)
            logger.error(e)
            sys.exit()


    def file_import(self, file_path, knowledge_id, action, description=''):
        url = 'http://' + self.api_address + self.api_path
        file = open(file_path, "rb")
        file_object = {"file": file}

        param = {
            "knowledgeId": knowledge_id,
            "action": action,
            "description": description
        }

        header = {
            "Cn-Authorization": self.api_token
        }

        is_succeed = 0
        response_code = -1
        for i in range(self.retry_max):
            try:
                resp = requests.post(url, files=file_object, params=param,
                                     headers=header, timeout=self.request_timeout)
                resp = json.loads(resp.text)
                logger.info(resp)
                response_code = resp.get('code')
                if response_code == 200:
                    is_succeed = 1
                    break
            except requests.RequestException as e:
                time.sleep(5)
                logger.error(e)
                continue

        if not is_succeed:
            logger.error('Import Failed!')
            sys.exit()
        else:
            logger.info('Import succeed. Response code {}.'.format(response_code))

        file.close()
