#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/24 15:18
# @author    : yinjinagyi
# @File    : windscribevpn_serverip.py
# @Function:
import re

import sys
sys.path.append('..')
from statsmodels.datasets import check_internet

from tool.MariadbTool import MariadbUtil
from vpn_detector import VpnDetector


class WindscribevpnServerip(VpnDetector):
    """

    This class is used to detect windscribevpn server ip
    """
    def __init__(self):
        super().__init__('', '')
        self.plugin_config = self.load_config()['windscribevpn_serverip']
        self.plugin_id = self.plugin_config['plugin_id']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['object_type']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.confidence = self.plugin_config['confidence']
        self.output_file_name = self.plugin_name + '_' + str(self.start_time).replace(' ', '_').replace(':', '')[:13] + '.csv'

        self.kb_sql = self.plugin_config['kb_sql']
        self.kb_dbname = self.config['knowledgebase']['db_name']
        self.kb_table_name = self.config['knowledgebase']['domain_library_name']

        self.mariadb = MariadbUtil(self.config['mariadb']['host'], self.config['mariadb']['port'],
                                   self.config['mariadb']['user'], str(self.config['mariadb']['pswd']),
                                   self.config['mariadb']['db_name'])
        self.mariadb_dbname = self.config['mariadb']['db_name']
        self.mariadb_ip_tb_name = self.config['mariadb']['ip_table_name']
        self.mariadb_domain_tb_name = self.config['mariadb']['domain_table_name']


    def find_more_servernames(self, server_name_list):
        """
        Find more server name from observed windscribe server name list
        :return: server name list
        """
        prefix_list = []
        expanded_server_names = []

        pattern = re.compile(r'\D+(\d+)\.\w+\.\w+')
        for server_name in server_name_list:
            domain = server_name.strip()
            match = pattern.match(domain)
            if match:
                numeric_part = match.group(1)
                domain_pattern = re.sub(numeric_part, '{index}', domain)
                prefix_list.append(domain_pattern)
            else:
                continue

        prefix_list = set(prefix_list)

        for domain_prefix in prefix_list:
            domain_list = [re.sub(r'{index}', str(index).zfill(3), domain_prefix) for index in range(1000)]
            expanded_server_names.extend(domain_list)
        return expanded_server_names


    def find_server(self):
        """
        Get windscribevpn server ip by resolving windscribevpn server name
        :return: windscribevpn server ip list
        """
        self.kb_sql = self.kb_sql.replace("{$mariadb_dbname}", self.mariadb_dbname).replace("{$mariadb_domain_tablename}", self.mariadb_domain_tb_name)

        servername_list = []
        resolved_ip_list = []
        try:
            query_result = self.mariadb.query_sql(self.kb_sql)
        finally:
            self.mariadb.close()

        if query_result:
            servername_list = [i[0] for i in query_result]

        # 判断是否能够访问外网，如果能够访问外网，则从外网获取windscribe_servername_list的域名解析地址
        if check_internet():
            servername_list = self.find_more_servernames(servername_list)
            if len(servername_list) > 0:
                resolved_ip_list = self.resolve_dns_for_domain_list(servername_list)
            else:
                self.logger.info('No windscribe server name found from knowledge base')
        else:
            self.logger.info('No internet access, skip to resolve windscribe server name')

        return resolved_ip_list



def extract_pattern(domain):
    pattern = re.compile(r'\D+(\d+)\.\w+\.\w+')

    match = pattern.match(domain)
    if match:
        numeric_part = match.group(1)
        domain_pattern = re.sub(numeric_part, '{index}', domain)
        return domain_pattern
    else:
        return
