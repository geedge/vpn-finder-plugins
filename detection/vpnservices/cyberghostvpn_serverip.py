#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/16 20:01
# @author    : yinjinagyi
# @File    : cyberghostvpn_serverip.py.py
# @Function:
import re

from vpn_detector import VpnDetector
from tool.Functions import check_internet
from tool.MariadbTool import MariadbUtil


class CyberghostvpnServerip(VpnDetector):
    """
    This class is used to detect cyberghostvpn server ip
    """

    def __init__(self):
        super().__init__('', '')
        self.plugin_config = self.load_config()['cyberghostvpn_serverip']
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
        Find more server name from observed cyberghost server name list
        :return: server name list
        """
        pattern_list = []
        expanded_server_names = []


        for server_name in server_name_list:
            pattern = re.compile(r'\.(.*?)\-rack')
            pattern_list.append(pattern.findall(server_name)[0])
        pattern_list = set(pattern_list)

        for pattern_str in pattern_list:
            domain_list = [f"blade{str(index1)}.{pattern_str}-rack4{str(index2).zfill(2)}.nodes.gen4.ninja" for index1 in range(1, 100) for index2 in range(1, 100)]
            expanded_server_names.extend(domain_list)

        return expanded_server_names


    def find_server(self):
        """
        Get cyberghostvpn server ip by resolving cyberghostvpn server name
        :return: cyberghostvpn server ip list
        """
        self.kb_sql = self.kb_sql.replace("{$mariadb_dbname}", self.mariadb_dbname).replace(
            "{$mariadb_domain_tablename}", self.mariadb_domain_tb_name)

        servername_list = []
        resolved_ip_list = []
        try:
            query_result = self.mariadb.query_sql(self.kb_sql)
        finally:
            self.mariadb.close()

        if query_result:
            servername_list = [i[0] for i in query_result]

        # 判断是否能够访问外网，如果能够访问外网，则从外网获取cyberghost_servername_list的域名解析地址
        if check_internet():
            servername_list = self.find_more_servernames(servername_list)
            if len(servername_list) > 0:
                resolved_ip_list = self.resolve_dns_for_domain_list(servername_list)
            else:
                self.logger.info('No cyberghost server name found from knowledge database.')
        else:
            self.logger.info('Failed to resolve cyberghost vpn servername. Cannot access internet.')

        return resolved_ip_list






