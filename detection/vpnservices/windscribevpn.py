# !/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/31 15:23
# @author    : yinjinagyi
# @File    : windscribevpn.py
# @Function:
import datetime
import re

import pandas as pd
from statsmodels.datasets import check_internet

from tool.MariadbTool import MariadbUtil
from vpn_detector import VpnDetector, ServerGroup


class Windscribevpn(VpnDetector):
    """

    This class is used to detect windscribevpn server ip and server name
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['windscribevpn']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.plugin_name = self.plugin_config['plugin_name']
        self.plugin_id = self.plugin_config['plugin_id']
        self.confidence = self.plugin_config['confidence']
        self.start_time = start_time
        self.end_time = end_time

    def find_server(self):
        """
        Get windscribevpn server ip and server name from clickhouse database
        :return: windscribevpn server ip list and server name list
        """
        result_group = []


        # start finding windscribevpn server name
        windscribevpn_server_name_detector = WindscribevpnServername(self.start_time, self.end_time)
        server_name_object = windscribevpn_server_name_detector.find_server()
        result_group.extend(server_name_object)

        # start finding active windscribevpn server ip by resolving servername
        windscribevpn_server_ip_detector = WindscribevpnActiveServerip()
        # server_name_list 初始化本周期已查询到的
        windscribevpn_server_ip_detector.server_name_list = server_name_object[0].server_list if len(
            server_name_object) > 0 else []
        result_group.extend(windscribevpn_server_ip_detector.find_server())

        # starting finding windscribevpn server ip from session records
        windscribevpn_server_ip_detector = WindscribevpnServerip(self.start_time, self.end_time)
        server_ip_object = windscribevpn_server_ip_detector.find_server()
        if len(server_ip_object[0].server_list)>0 > 0:
            result_group[1].merge(server_ip_object[0])

        return result_group


class WindscribevpnActiveServerip(VpnDetector):
    """

    This class is used to detect windscribevpn server ip
    """

    def __init__(self):
        super().__init__('', '')
        self.plugin_config = self.load_config()['windscribevpn']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['ip']['object_type']
        # 开始时间为当前的整点时间
        self.start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:00:00")
        self.output_file_name = self.plugin_name + '-' + self.object_type + '_' + str(self.start_time).replace(' ',
                                                                                                               '_').replace(
            ':', '')[:13] + '.csv'

        self.kb_sql = self.plugin_config['ip']['kb_sql']
        self.sql = self.plugin_config['ip']['sql']
        self.kb_dbname = self.config['knowledgebase']['db_name']

        self.mariadb = MariadbUtil(self.config['mariadb']['host'], self.config['mariadb']['port'],
                                   self.config['mariadb']['user'], str(self.config['mariadb']['pswd']),
                                   self.config['mariadb']['db_name'])
        self.mariadb_dbname = self.config['mariadb']['db_name']
        self.mariadb_tb_name = self.config['mariadb']['table_name']

        self.server_name_list = []

    def find_more_servernames(self, server_name_list):
        """
        Find more server name from observed windscribevpn server name list
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
        self.kb_sql = self.kb_sql.replace("{$mariadb_dbname}", self.mariadb_dbname).replace(
            "{$mariadb_tablename}", self.mariadb_tb_name)

        servername_list = []
        resolved_ip_list = []
        try:
            query_result = self.mariadb.query_sql(self.kb_sql)
        finally:
            self.mariadb.close()

        if query_result:
            servername_list = [i[0] for i in query_result]

        self.server_name_list.extend(servername_list)

        # 判断是否能够访问外网，如果能够访问外网，则从外网获取windscribevpn_servername_list的域名解析地址
        if self.config['common']['active_scan']['switch'] and check_internet():
            servername_list = self.find_more_servernames(self.server_name_list)
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
                self.logger.info(
                    '[{}] - No windscribevpn server name found from knowledge database.'.format(self.plugin_name))
        else:
            self.logger.info('[{}] - No internet connection, skip dns resolve.'.format(self.plugin_name))

        return [ServerGroup(self.object_type, resolved_ip_list, self.output_file_name)]


class WindscribevpnServername(VpnDetector):
    """

    This class is used to detect windscribevpn server name
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['windscribevpn']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['domain']['object_type']
        self.output_file_name = self.plugin_name + '-' + self.object_type + '_' + str(self.start_time).replace(' ',
                                                                                                               '_').replace(
            ':', '')[:13] + '.csv'
        self.start_time = start_time
        self.end_time = end_time

        self.sql = self.plugin_config['domain']['sql']
        self.domains = ["'" + i.strip() + "'" for i in self.plugin_config['domain']['domains'].split(',')]

    def find_server(self):
        """
        Get windscribevpn server name from session records
        :return: windscribevpn server name list
        """
        self.logger.info('[{}] - Start to query windscribevpn server name from session record'.format(self.plugin_name))

        # construct query sql
        TIME_FILTER_PATTERN = self.config['common']['time_filter_pattern'].replace('recv_time_columnname',
                                                                                   self.config['common'][
                                                                                       'recv_time_columnname'])
        time_filter = TIME_FILTER_PATTERN.replace("{$start_time}", str(self.start_time)).replace("{$end_time}", str(
            self.end_time)).replace("{$time_zone}", self.time_zone)
        self.sql = self.sql.replace("{$db_name}", self.dbname).replace("{$table_name}", self.table_name)
        self.sql = self.sql.replace("{$time_filter}", time_filter)
        self.sql = self.sql.replace("{$domain_list}", ','.join(self.domains))
        self.logger.info("[{}] - Sql for {}: {}".format(self.plugin_name, self.plugin_config['plugin_name'], self.sql))

        # query data from clickhouse database
        try:
            windscribevpn_servername_df = pd.DataFrame(self.client.execute(self.sql))
        finally:
            self.client.disconnect()

        if windscribevpn_servername_df.empty:
            self.logger.info('[{}] - No windscribevpn server name found from session records'.format(self.plugin_name))
            return []
        windscribevpn_servername_list = windscribevpn_servername_df[0].drop_duplicates().tolist()
        self.logger.info('[{}] - Query windscribevpn server name from session records successfully. {} items found'
                         .format(self.plugin_name, len(windscribevpn_servername_list)))

        return [ServerGroup(self.object_type, windscribevpn_servername_list, self.output_file_name)]


class WindscribevpnServerip(VpnDetector):
    """

    This class is used to detect windscribevpn server ip
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['windscribevpn']
        self.plugin_id = self.plugin_config['plugin_id']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['ip']['object_type']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.confidence = self.plugin_config['confidence']
        self.output_file_name = self.plugin_name + '-' + self.object_type + '_' + str(self.start_time).replace(' ',
                                                                                                               '_').replace(
            ':', '')[:13] + '.csv'
        self.start_time = start_time
        self.end_time = end_time

        self.sql = self.plugin_config['ip']['sql']

    def find_server(self):
        """
        Get windscribevpn server ip from clickhouse database
        :return: windscribevpn server ip list
        """

        # 根据证书信息获取
        server_ip_list = []
        TIME_FILTER_PATTERN = self.config['common']['time_filter_pattern'].replace('recv_time_columnname',
                                                                                   self.config['common'][
                                                                                       'recv_time_columnname'])
        time_filter = TIME_FILTER_PATTERN.replace("{$start_time}", str(self.start_time)).replace("{$end_time}", str(
            self.end_time)).replace("{$time_zone}", self.time_zone)
        self.sql = self.sql.replace("{$db_name}", self.dbname).replace("{$table_name}", self.table_name)
        self.sql = self.sql.replace("{$time_filter}", time_filter)
        self.logger.info("[{}] - Sql for {}: {}".format(self.plugin_name, self.plugin_name, self.sql))

        try:
            windscribevpn_cert_serverip_df = pd.DataFrame(self.client.execute(self.sql))
        finally:
            self.client.disconnect()

        if not windscribevpn_cert_serverip_df.empty:
            server_ip_list = windscribevpn_cert_serverip_df[0].drop_duplicates().tolist()
            self.logger.info(
                '[{}] - Get {} server ip from certificate successfully.'.format(self.plugin_name,
                                                                                len(server_ip_list)))
        else:
            self.logger.info('[{}] - No windscribevpn server ip found from certificate.'.format(self.plugin_name))

        return [ServerGroup(self.object_type, server_ip_list, self.output_file_name)]


def extract_pattern(domain):
    pattern = re.compile(r'\D+(\d+)\.\w+\.\w+')

    match = pattern.match(domain)
    if match:
        numeric_part = match.group(1)
        domain_pattern = re.sub(numeric_part, '{index}', domain)
        return domain_pattern
    else:
        return