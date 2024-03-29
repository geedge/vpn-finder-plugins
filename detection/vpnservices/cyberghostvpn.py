#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/31 15:03
# @author    : yinjinagyi
# @File    : cyberghostvpn.py
# @Function:
import datetime
import re

import pandas as pd

from tool.Functions import check_internet
from tool.MariadbTool import MariadbUtil
from vpn_detector import VpnDetector, ServerGroup


class Cyberghostvpn(VpnDetector):
    """

    This class is used to detect cyberghostvpn server ip and server name
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['cyberghostvpn']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.plugin_name = self.plugin_config['plugin_name']
        self.plugin_id = self.plugin_config['plugin_id']
        self.confidence = self.plugin_config['confidence']
        self.start_time = start_time
        self.end_time = end_time


    def find_server(self):
        """
        Get cyberghostvpn server ip and server name from clickhouse database
        :return: cyberghostvpn server ip list and server name list
        """
        result_group = []

        # start finding cyberghostvpn server name
        cyberghostvpn_server_name_detector = CyberghostvpnServername(self.start_time, self.end_time)
        server_name_object = cyberghostvpn_server_name_detector.find_server()
        result_group.extend(server_name_object)

        # start finding cyberghostvpn server ip
        cyberghostvpn_server_ip_detector = CyberghostvpnServerip(self.start_time, self.end_time)
        cyberghostvpn_server_ip_detector.server_name_list = server_name_object[0].server_list if len(server_name_object) > 0 else []
        result_group.extend(cyberghostvpn_server_ip_detector.find_server())

        return result_group



class CyberghostvpnServerip(VpnDetector):
    """
    This class is used to detect cyberghostvpn server ip
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['cyberghostvpn']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['ip']['object_type']
        # 开始时间为当前的整点时间
        self.start_time = start_time
        self.end_time = end_time
        self.output_file_name = self.plugin_name + '-' + self.object_type + '_' + str(self.start_time).replace(' ',
                                                                                                               '_').replace(
            ':', '')[:13] + '.csv'

        self.kb_sql = self.plugin_config['ip']['kb_sql']
        self.kb_dbname = self.config['knowledgebase']['db_name']
        self.kb_table_name = self.config['knowledgebase']['domain_library_name']

        self.mariadb = MariadbUtil(self.config['mariadb']['host'], self.config['mariadb']['port'],
                                   self.config['mariadb']['user'], str(self.config['mariadb']['pswd']),
                                   self.config['mariadb']['db_name'])
        self.mariadb_dbname = self.config['mariadb']['db_name']
        self.mariadb_ip_tb_name = self.config['mariadb']['ip_table_name']
        self.mariadb_domain_tb_name = self.config['mariadb']['domain_table_name']

        self.sql = self.plugin_config['ip']['sql']

        self.server_name_list = []


    def find_more_servernames(self, server_name_list):
        """
        Find more server name from observed cyberghost server name list
        :return: server name list
        """
        pattern_list = []
        expanded_server_names = []


        for server_name in server_name_list:
            # pattern = re.compile(r'\.(.*?)\-rack')
            pattern = re.compile(r'\.(.*?)\.nodes')
            findall = pattern.findall(server_name)
            if len(findall) > 0:
                pattern_list.append(findall[0])
        pattern_list = set(pattern_list)

        for pattern_str in pattern_list:
            domain_list = [f"blade{str(index1)}.{pattern_str}.nodes.gen4.ninja" for index1 in range(1, 100)]
            expanded_server_names.extend(domain_list)

        return expanded_server_names


    def find_server_name_patterns(self, server_name_list):
        pattern_list = []

        for server_name in server_name_list:
            # pattern = re.compile(r'\.(.*?)\-rack')
            pattern = re.compile(r'\.(.*?)\.nodes')
            findall = pattern.findall(server_name)
            if len(findall) > 0:
                pattern_list.append(findall[0])
        pattern_list = set(pattern_list)

        return pattern_list



    def find_server(self):
        """
        Get cyberghostvpn server ip by resolving cyberghostvpn server name
        :return: cyberghostvpn server ip list
        """
        self.kb_sql = self.kb_sql.replace("{$mariadb_dbname}", self.mariadb_dbname).replace(
            "{$mariadb_domain_tablename}", self.mariadb_domain_tb_name)

        # 根据server name获取ip
        self.logger.info('[{}] - Get servername from knowledge base.'.format(self.plugin_name))
        servername_list = []
        resolved_ip_list = []
        try:
            query_result = self.mariadb.query_sql(self.kb_sql)
        finally:
            self.mariadb.close()

        if query_result:
            servername_list = [i[0] for i in query_result]
        self.server_name_list.extend(servername_list)

        # 判断是否能够访问外网，如果能够访问外网，则从外网获取cyberghost_servername_list的域名解析地址
        if self.config['common']['active_scan']['switch'] and check_internet():
            # servername_list = self.find_more_servernames(servername_list)
            # if len(servername_list) > 0:
            #     resolved_ip_list = self.resolve_dns_for_domain_list(servername_list)
            #     self.logger.info('[{}] - Get {} server ip by resolving server name successfully.'.format(self.plugin_name, len(resolved_ip_list)))
            # else:
            #     self.logger.info(
            #         '[{}] - No cyberghost server name found from knowledge database.'.format(self.plugin_name))

            server_rackname_list = self.find_server_name_patterns(self.server_name_list)
            if len(server_rackname_list) > 0:
                resolved_ip_list = []
                for rack_name in server_rackname_list:
                    index = 1
                    resolve_result = self.get_resolved_addr(f"blade{str(index)}.{rack_name}.nodes.gen4.ninja")
                    while resolve_result[1] is not None:
                        self.logger.info('{}  {}'.format(resolve_result[0], resolve_result[1]))
                        resolved_ip_list.extend(resolve_result[1])
                        index += 1
                        resolve_result = self.get_resolved_addr(f"blade{str(index)}.{rack_name}.nodes.gen4.ninja")
                self.logger.info('[{}] - Get {} server ip by resolving server name successfully.'.format(self.plugin_name, len(resolved_ip_list)))
        else:
            self.logger.info('[{}] - No internet connection, skip dns resolve.'.format(self.plugin_name))


        # 根据udp探测行为获取IP
        if self.plugin_config['ip']['monitor_on']:

            self.logger.info('[{}] - Start to query server ip from session records according to udp payload feature.'.format(self.plugin_name))

            TIME_FILTER_PATTERN = self.config['common']['time_filter_pattern'].replace('recv_time_columnname',
                                                                                       self.config['common'][
                                                                                           'recv_time_columnname'])
            time_filter = TIME_FILTER_PATTERN.replace("{$start_time}", str(self.start_time)).replace("{$end_time}", str(
                self.end_time)).replace("{$time_zone}", self.time_zone)
            self.sql = self.sql.replace("{$db_name}", self.dbname).replace("{$table_name}", self.table_name)
            self.sql = self.sql.replace("{$time_filter}", time_filter)
            self.sql = self.sql.replace("{$udp_monitor_app_name}", self.plugin_config['ip']['udp_monitor_app_name'])

            self.logger.info("[{}] - Sql for {}: {}".format(self.plugin_name, self.plugin_name, self.sql))

            # query data from clickhouse database
            try:
                cyberghostvpn_serverip_df = pd.DataFrame(self.client.execute(self.sql))
            finally:
                self.client.disconnect()

            if cyberghostvpn_serverip_df.empty:
                self.logger.info('[{}] - No server ip found from session records'.format(self.plugin_name))
            else:
                cyberghostvpn_serverip_list = cyberghostvpn_serverip_df[0].drop_duplicates().tolist()
                self.logger.info('[{}] - Query server ip from clickhouse database successfully. {} items found'
                                 .format(self.plugin_name, len(cyberghostvpn_serverip_list)))
                resolved_ip_list.extend(cyberghostvpn_serverip_list)


        result_ip_list = list(set(resolved_ip_list))

        return [ServerGroup(self.object_type, result_ip_list, self.output_file_name)]



class CyberghostvpnServername(VpnDetector):
    """

    This class is used to detect cyberghostvpn server name
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['cyberghostvpn']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['domain']['object_type']
        self.output_file_name = self.plugin_name + '-' + self.object_type + '_' + str(self.start_time).replace(' ', '_').replace(':', '')[:13] + '.csv'
        self.start_time = start_time
        self.end_time = end_time

        self.sql = self.plugin_config['domain']['sql']

    def find_server(self):
        """
        Get cyberghostvpn server name from clickhouse database
        :return: cyberghostvpn server name list
        """
        self.logger.info('[{}] - Start to query cyberghostvpn server name from session record'.format(self.plugin_name))

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
            cyberghostvpn_servername_df = pd.DataFrame(self.client.execute(self.sql))
        finally:
            self.client.disconnect()

        if cyberghostvpn_servername_df.empty:
            self.logger.info('[{}] - No cyberghostvpn server name found from session records'.format(self.plugin_name))
            return []
        cyberghostvpn_servername_list = cyberghostvpn_servername_df[0].drop_duplicates().tolist()
        self.logger.info('[{}] - Query cyberghostvpn server name from session records successfully. {} items found'
                         .format(self.plugin_name, len(cyberghostvpn_servername_list)))

        return [ServerGroup(self.object_type, cyberghostvpn_servername_list, self.output_file_name)]
