#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/23 10:39
# @author    : yinjinagyi
# @File    : vpnunlimited_serverip.py
# @Function:

from vpn_detector import VpnDetector
import pandas as pd

class VpnunlimitedServerip(VpnDetector):
    """

    This class is used to detect vpnunlimited server ip
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['vpnunlimited_serverip']
        self.plugin_id = self.plugin_config['plugin_id']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['object_type']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.confidence = self.plugin_config['confidence']
        self.output_file_name = self.plugin_name + '_' + str(self.start_time).replace(' ', '_').replace(':', '')[:13] + '.csv'
        self.start_time = start_time
        self.end_time = end_time

        self.sql = self.plugin_config['sql']
        self.domains = ["'" + i.strip() + "'" for i in self.plugin_config['domains'].split(',')]

    def find_server(self):
        """
        Get vpnunlimited server ip from session records
        :return: vpnunlimited server ip list
        """
        self.logger.info('Start to query vpnunlimited server ip from session records')

        # construct query sql
        TIME_FILTER_PATTERN = self.config['common']['time_filter_pattern'].replace('recv_time_columnname', self.config['common']['recv_time_columnname'])
        time_filter = TIME_FILTER_PATTERN.replace("{$start_time}", str(self.start_time)).replace("{$end_time}", str(
            self.end_time)).replace("{$time_zone}", self.time_zone)
        self.sql = self.sql.replace("{$db_name}", self.dbname).replace("{$table_name}", self.table_name)
        self.sql = self.sql.replace("{$time_filter}", time_filter)
        self.sql = self.sql.replace("{$domain_list}", ','.join(self.domains))

        self.logger.info("Sql for {}: {}".format(self.plugin_name, self.sql))

        # query data from clickhouse database
        try:
            vpnunlimited_serverip_df = pd.DataFrame(self.client.execute(self.sql))
        finally:
            self.client.disconnect()

        if vpnunlimited_serverip_df.empty:
            self.logger.info('No vpnunlimited server ip found from session records')
            return []
        vpnunlimited_serverip_list = vpnunlimited_serverip_df[0].drop_duplicates().tolist()
        self.logger.info('Query vpnunlimited server ip from session records successfully. {} items found'
                         .format(len(vpnunlimited_serverip_list)))

        return vpnunlimited_serverip_list