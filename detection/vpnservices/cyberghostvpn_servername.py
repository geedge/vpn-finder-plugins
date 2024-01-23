#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/16 19:51
# @author    : yinjinagyi
# @File    : cyberghostvpn_servername.py.py
# @Function:

import sys
sys.path.append('..')
from vpn_detector import VpnDetector
import pandas as pd


class CyberghostvpnServername(VpnDetector):
    """

    This class is used to detect cyberghostvpn server name
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['cyberghostvpn_servername']
        self.plugin_id = self.plugin_config['plugin_id']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['object_type']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.confidence = self.plugin_config['confidence']
        self.output_file_name = self.plugin_name + '_' + str(self.start_time).replace(' ', '_').replace(':', '')[:13] + '.csv'
        self.start_time = start_time
        self.end_time = end_time

        self.sql = self.plugin_config['sql']

    def find_server(self):
        """
        Get cyberghostvpn server name from clickhouse database
        :return: cyberghostvpn server name list
        """
        self.logger.info('Start to query cyberghostvpn server name from session record')

        # construct query sql
        TIME_FILTER_PATTERN = self.config['common']['time_filter_pattern'].replace('recv_time_columnname', self.config['common']['recv_time_columnname'])
        time_filter = TIME_FILTER_PATTERN.replace("{$start_time}", str(self.start_time)).replace("{$end_time}", str(
            self.end_time)).replace("{$time_zone}", self.time_zone)
        self.sql = self.sql.replace("{$db_name}", self.dbname).replace("{$table_name}", self.table_name)
        self.sql = self.sql.replace("{$time_filter}", time_filter)
        self.logger.info("Sql for {}: {}".format(self.plugin_name, self.sql))

        # query data from clickhouse database
        try:
            cyberghostvpn_servername_df = pd.DataFrame(self.client.execute(self.sql))
        finally:
            self.client.disconnect()

        if cyberghostvpn_servername_df.empty:
            self.logger.info('No cyberghostvpn server name found from session records')
            return []
        cyberghostvpn_servername_list = cyberghostvpn_servername_df[0].drop_duplicates().tolist()
        self.logger.info('Query cyberghostvpn server name from session records successfully. {} items found'
                         .format(len(cyberghostvpn_servername_list)))
        return cyberghostvpn_servername_list
