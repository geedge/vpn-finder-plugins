#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/17 15:25
# @author    : yinjinagyi
# @File    : ivacyvpn_serverip.py
# @Function:

import sys

from Functions import check_internet
from MariadbTool import MariadbUtil

sys.path.append('..')
from vpn_detector import VpnDetector

class IvacyvpnServerip(VpnDetector):
    """

    This class is used to detect ivacyvpn server ip
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['ivacyvpn_serverip']
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




    def find_server(self):
        """
        Find ivacyvpn server ip by resolving ivacyvpn server name
        :return: server ip list
        """
        self.kb_sql = self.kb_sql.replace("{$mariadb_dbname}", self.mariadb_dbname).replace("{$mariadb_domain_tablename}", self.mariadb_domain_tb_name)

        server_name_list = []
        server_ip_list = []

        try:
            query_result = self.mariadb.query_sql(self.kb_sql)
        finally:
            self.mariadb.close()

        if query_result:
            for row in query_result:
                server_name_list.append(row[0])

        # add dc-xxx.pointtoserver.com to server_name_list
        server_name_list.extend([f"dc-{str(index)}.pointtoserver.com" for index in range(1000)])
        server_name_list = list(set(server_name_list))

        if check_internet():
            server_ip_list = self.resolve_dns_for_domain_list(server_name_list)
            if server_ip_list:
                server_ip_list = list(set(server_ip_list))
            else:
                self.logger.info("No ivacyvpn server name found from knowledge database.")
        else:
            self.logger.info("No internet connection, skip dns resolve.")
        return server_ip_list





