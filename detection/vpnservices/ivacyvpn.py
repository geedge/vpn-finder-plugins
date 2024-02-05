#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/31 14:30
# @author    : yinjinagyi
# @File    : ivacyvpn.py.py
# @Function:
import datetime

import pandas as pd

from tool.Functions import check_internet
from tool.MariadbTool import MariadbUtil
from vpn_detector import VpnDetector, ServerGroup


class Ivacyvpn(VpnDetector):
    """

    This class is used to detect ivacyvpn server ip and server name
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['ivacyvpn']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.plugin_name = self.plugin_config['plugin_name']
        self.plugin_id = self.plugin_config['plugin_id']
        self.confidence = self.plugin_config['confidence']
        self.start_time = start_time
        self.end_time = end_time

    def find_server(self):
        """
        Get ivacyvpn server ip and server name from clickhouse database
        :return: ivacyvpn server ip list and server name list
        """
        result_group = []

        # start finding ivacyvpn server name
        ivacyvpn_detector = IvacyvpnServername(self.start_time, self.end_time)
        result_group.extend(ivacyvpn_detector.find_server())

        # start finding ivacyvpn server ip
        ivacyvpn_detector = IvacyvpnServerip()
        result_group.extend(ivacyvpn_detector.find_server())

        return result_group



class IvacyvpnServerip(VpnDetector):
    """

    This class is used to detect ivacyvpn server ip
    """

    def __init__(self):
        super().__init__('', '')
        self.plugin_config = self.load_config()['ivacyvpn']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['ip']['object_type']
        # 开始时间为当前的整点时间
        self.start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:00:00")
        self.output_file_name = self.plugin_name + '-' + self.object_type + '_' + str(self.start_time).replace(' ', '_').replace(':', '')[:13] + '.csv'

        self.kb_sql = self.plugin_config['ip']['kb_sql']
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

        if self.config['common']['active_scan']['switch']=='on' and check_internet():
            server_ip_list = self.resolve_dns_for_domain_list(server_name_list)
            if server_ip_list:
                server_ip_list = list(set(server_ip_list))
                self.logger.info(
                    '[{}] - Get {} server ip by resolving server name successfully.'.format(self.plugin_name,
                                                                                            len(server_ip_list)))
            else:
                self.logger.info("[{}] - No ivacyvpn server name found from knowledge database.".format(self.plugin_name))
        else:
            self.logger.info("[{}] - No internet connection, skip dns resolve.".format(self.plugin_name))

        return [ServerGroup(self.object_type, server_ip_list, self.output_file_name)]


class IvacyvpnServername(VpnDetector):
    """

    This class is used to detect ivacyvpn server name
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['ivacyvpn']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['domain']['object_type']
        self.output_file_name = self.plugin_name + '-' + self.object_type + '_' + str(self.start_time).replace(' ', '_').replace(':', '')[:13] + '.csv'
        self.start_time = start_time
        self.end_time = end_time

        self.sql = self.plugin_config['domain']['sql']

    def find_server(self):
        """
        Get ivacyvpn server name from clickhouse database
        :return: ivacyvpn server name list
        """
        self.logger.info('[{}] - Start to query ivacyvpn server name from session record'.format(self.plugin_name))

        # construct query sql
        TIME_FILTER_PATTERN = self.config['common']['time_filter_pattern'].replace('recv_time_columnname',
                                                                                   self.config['common'][
                                                                                       'recv_time_columnname'])
        time_filter = TIME_FILTER_PATTERN.replace("{$start_time}", str(self.start_time)).replace("{$end_time}", str(
            self.end_time)).replace("{$time_zone}", self.time_zone)
        self.sql = self.sql.replace("{$db_name}", self.dbname).replace("{$table_name}", self.table_name)
        self.sql = self.sql.replace("{$time_filter}", time_filter)
        self.logger.info("[{}] - Sql for {}: {}".format(self.plugin_name, self.plugin_config['plugin_name'], self.sql))

        # query data from clickhouse database
        try:
            ivacyvpn_servername_df = pd.DataFrame(self.client.execute(self.sql))
        finally:
            self.client.disconnect()

        if ivacyvpn_servername_df.empty:
            self.logger.info('[{}] - No ivacyvpn server name found from session records'.format(self.plugin_name))
            return []
        ivacyvpn_servername_list = ivacyvpn_servername_df[0].drop_duplicates().tolist()
        self.logger.info('[{}] - Query ivacyvpn server name from session records successfully. {} items found'
                         .format(self.plugin_name, len(ivacyvpn_servername_list)))

        return [ServerGroup(self.object_type, ivacyvpn_servername_list, self.output_file_name)]
