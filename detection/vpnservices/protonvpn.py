#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/29 18:49
# @author    : yinjinagyi
# @File    : protonvpn.py
# @Function:
import pandas as pd

from vpn_detector import VpnDetector, ServerGroup


class Protonvpn(VpnDetector):
    """
    This class is used to detect protonvpn server ip
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['protonvpn']
        self.plugin_id = self.plugin_config['plugin_id']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['object_type']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.confidence = self.plugin_config['confidence']
        self.output_file_name = self.plugin_name + '-' + self.object_type + '_' + str(self.start_time).replace(' ', '_').replace(':', '')[:13] + '.csv'
        self.start_time = start_time
        self.end_time = end_time

        self.sql = self.plugin_config['sql']

    def find_server(self):
        """
        Get protonvpn server ip from clickhouse database
        :return: protonvpn server ip list
        """
        self.logger.info('[{}] - Start to query protonvpn server ip from session record'.format(self.plugin_name))

        # construct query sql
        TIME_FILTER_PATTERN = self.config['common']['time_filter_pattern'].replace('recv_time_columnname',
                                                                                   self.config['common'][
                                                                                       'recv_time_columnname'])
        time_filter = TIME_FILTER_PATTERN.replace("{$start_time}", str(self.start_time)).replace("{$end_time}", str(
            self.end_time)).replace("{$time_zone}", self.time_zone)
        self.sql = self.sql.replace("{$db_name}", self.dbname).replace("{$table_name}", self.table_name)
        self.sql = self.sql.replace("{$time_filter}", time_filter)

        self.logger.info("[{}] - Sql for {}: {}".format(self.plugin_name, self.plugin_name, self.sql))

        # query data from clickhouse database
        try:
            protonvpn_serverip_df = pd.DataFrame(self.client.execute(self.sql))
        finally:
            self.client.disconnect()

        if protonvpn_serverip_df.empty:
            self.logger.info('[{}] - No protonvpn server ip found from session record'.format(self.plugin_name))
            return []
        protonvpn_serverip_list = protonvpn_serverip_df[0].drop_duplicates().tolist()
        self.logger.info('[{}] - Query protonvpn server ip from session records successfully. {} items found'
                         .format(self.plugin_name, len(protonvpn_serverip_list)))

        return [ServerGroup(object_type='ip', server_list=protonvpn_serverip_list, output_file_name=self.output_file_name)]
