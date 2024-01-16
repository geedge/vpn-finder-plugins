#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/12 10:00
# @author    : yinjinagyi
# @File    : ipvanishvpn_serverip.py
# @Function:

import socket
from vpn_detector import VpnDetector
from tool.Functions import check_internet
from tool.MariadbTool import MariadbUtil


class IpvanishvpnServerip(VpnDetector):
    """
    This class is used to detect ipvanishvpn server ip
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['ipvanishvpn_serverip']
        self.plugin_id = self.plugin_config['plugin_id']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['object_type']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.confidence = self.plugin_config['confidence']
        self.output_file_name = self.plugin_name + '_' + str(self.start_time).replace(' ', '_').replace(':', '')[:13] + '.csv'
        self.start_time = start_time
        self.end_time = end_time

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
        Find more server name from observed ipvanish server name list
        :return: server name list
        """
        prefix_list = []
        expanded_server_names = []

        for server_name in server_name_list:
            domain = server_name.strip()
            domain_prefix = domain[:5]
            prefix_list.append(domain_prefix)

        prefix_list = set(prefix_list)

        for domain_prefix in prefix_list:
            domain_list = [f"{domain_prefix}{str(index).zfill(2)}.vpn.ipvanish.com" for index in range(100)]
            expanded_server_names.extend(domain_list)

        return expanded_server_names


    def find_server(self):
        """
        Get ipvanishvpn server ip from clickhouse database
        :return: ipvanishvpn server ip list
        """
        self.kb_sql = self.kb_sql.replace("{$mariadb_dbname}", self.mariadb_dbname).replace("{$mariadb_domain_tablename}", self.mariadb_domain_tb_name)

        ipvanish_servername_list = []
        resolved_ip_list = []
        try:
            query_result = self.mariadb.query_sql(self.kb_sql)
        finally:
            self.mariadb.close()

        if query_result:
            ipvanish_servername_list = [i[0] for i in query_result]

        # 判断是否能够访问外网，如果能够访问外网，则从外网获取ipvanish_servername_list的域名解析地址
        if check_internet():
            ipvanish_servername_list = self.find_more_servernames(ipvanish_servername_list)
            if len(ipvanish_servername_list) > 0:
                resolved_ip_list = self.resolve_dns_for_domain_list(ipvanish_servername_list)
            else:
                self.logger.info('No ipvanish server name found from knowledge database.')
        else:
            self.logger.info('Failed to resolve ipvanish vpn servername. Cannot access internet.')

        return resolved_ip_list



