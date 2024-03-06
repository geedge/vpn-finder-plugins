#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/30 18:20
# @author    : yinjinagyi
# @File    : ipvanishvpn.py
# @Function:

import sys
sys.path.append('..')
import datetime
import pandas as pd
from tool.Functions import check_internet
from tool.MariadbTool import MariadbUtil

from vpn_detector import VpnDetector, ServerGroup


class Ipvanishvpn(VpnDetector):
    """

    This class is used to detect ipvanishvpn server ip and server name
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['ipvanishvpn']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.plugin_name = self.plugin_config['plugin_name']
        self.plugin_id = self.plugin_config['plugin_id']
        self.confidence = self.plugin_config['confidence']
        self.start_time = start_time
        self.end_time = end_time


    def find_server(self):
        """
        Get ipvanishvpn server ip and server name from clickhouse database
        :return: ipvanishvpn server ip list and server name list
        """
        result_group = []

        # start finding ipvanishvpn server name
        ipvanishvpn_server_name_detector = IpvanishvpnServername(self.start_time, self.end_time)
        server_name_object = ipvanishvpn_server_name_detector.find_server()
        result_group.extend(server_name_object)

        # start finding ipvanishvpn server ip
        ipvanishvpn_server_ip_detector = IpvanishvpnServerip()
        # server_name_list 初始化本周期已查询到的
        ipvanishvpn_server_ip_detector.server_name_list = server_name_object[0].server_list if len(
            server_name_object) > 0 else []
        result_group.extend(ipvanishvpn_server_ip_detector.find_server())

        return result_group


class IpvanishvpnServerip(VpnDetector):
    """
    This class is used to detect ipvanishvpn server ip
    """

    def __init__(self):
        super().__init__('', '')
        self.plugin_config = self.load_config()['ipvanishvpn']
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

        self.server_name_list = []


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
        Get ipvanishvpn server ip by resolving ipvanishvpn server name
        :return: ipvanishvpn server ip list
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

        self.server_name_list.extend(servername_list)

        # 判断是否能够访问外网，如果能够访问外网，则从外网获取ipvanish_servername_list的域名解析地址
        if self.config['common']['active_scan']['switch'] and check_internet():
            servername_list = self.find_more_servernames(servername_list)
            if len(servername_list) > 0:
                resolved_ip_list = self.resolve_dns_for_domain_list(self.server_name_list,
                                                                  max_workers=self.config['common']['active_scan'][
                                                                      'max_workers'],
                                                                  max_calls_per_second=
                                                                  self.config['common']['active_scan'][
                                                                      'max_calls_per_sec'])
                self.logger.info(
                    '[{}] - Get {} server ip by resolving server name successfully.'.format(
                        self.plugin_name, len(resolved_ip_list)))
            else:
                self.logger.info('[{}] - No ipvanish server name found from knowledge database.'.format(self.plugin_name))
        else:
            self.logger.info('[{}] - No internet connection, skip dns resolve.'.format(self.plugin_name))

        return [ServerGroup(self.object_type, resolved_ip_list, self.output_file_name)]


class IpvanishvpnServername(VpnDetector):
    """

    This class is used to detect ipvanish server name
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['ipvanishvpn']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['domain']['object_type']
        self.output_file_name = self.plugin_name + '-' + self.object_type + '_' + str(self.start_time).replace(' ', '_').replace(':', '')[:13] + '.csv'
        self.start_time = start_time
        self.end_time = end_time

        self.sql = self.plugin_config['domain']['sql']

    def find_server(self):
        """
        Get ipvanishvpn server name from clickhouse database
        :return: ipvanishvpn server name list
        """
        self.logger.info('[{}] - Start to query ipvanishvpn server name from session record'.format(self.plugin_name))

        # construct query sql
        TIME_FILTER_PATTERN = self.config['common']['time_filter_pattern'].replace('recv_time_columnname', self.config['common']['recv_time_columnname'])
        time_filter = TIME_FILTER_PATTERN.replace("{$start_time}", str(self.start_time)).replace("{$end_time}", str(
            self.end_time)).replace("{$time_zone}", self.time_zone)
        self.sql = self.sql.replace("{$db_name}", self.dbname).replace("{$table_name}", self.table_name)
        self.sql = self.sql.replace("{$time_filter}", time_filter)
        self.logger.info("[{}] - Sql for {}: {}".format(self.plugin_name, self.plugin_config['plugin_name'], self.sql))

        # query data from clickhouse database
        try:
            ipvanishvpn_servername_df = pd.DataFrame(self.client.execute(self.sql))
        finally:
            self.client.disconnect()

        if ipvanishvpn_servername_df.empty:
            self.logger.info('[{}] - No ipvanishvpn server name found from session records'.format(self.plugin_name))
            return []
        ipvanishvpn_servername_list = ipvanishvpn_servername_df[0].drop_duplicates().tolist()
        self.logger.info('[{}] - Query ipvanishvpn server name from session records successfully. {} items found'
                         .format(self.plugin_name, len(ipvanishvpn_servername_list)))

        return [ServerGroup(self.object_type, ipvanishvpn_servername_list, self.output_file_name)]
