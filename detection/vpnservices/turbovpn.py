#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/17 18:09
# @author    : yinjinagyi
# @File    : turbovpn.py
# @Function:

import pandas as pd
from vpn_detector import VpnDetector, ServerGroup


class Turbovpn(VpnDetector):
    """
    This class is used to detect turbovpn server ip
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['turbovpn']
        self.plugin_id = self.plugin_config['plugin_id']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['object_type']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.confidence = self.plugin_config['confidence']
        self.output_file_name = self.plugin_name + '-' + self.object_type + '_' + str(self.start_time).replace(' ','_').replace(':', '')[:13] + '.csv'

        self.start_time = start_time
        self.end_time = end_time

        self.sql = self.plugin_config['sql']

    def find_server(self):
        """
        Get turbovpn server ip from clickhouse database
        :return: turbovpn server ip list
        """
        self.logger.info('Start to query turbovpn server ip from session record')

        # construct query sql
        TIME_FILTER_PATTERN = self.config['common']['time_filter_pattern'].replace('recv_time_columnname', self.config['common']['recv_time_columnname'])
        time_filter = TIME_FILTER_PATTERN.replace("{$start_time}", str(self.start_time)).replace("{$end_time}", str(
            self.end_time)).replace("{$time_zone}", self.time_zone)
        self.sql = self.sql.replace("{$db_name}", self.dbname).replace("{$table_name}", self.table_name)
        self.sql = self.sql.replace("{$time_filter}", time_filter)

        self.sql = self.sql.replace("{$security_table_name}", self.plugin_config['security_table_name'])\
            .replace("{$security_policy_id}", str(self.plugin_config['security_policy_id']))

        self.logger.info("[{}] - Sql for {}: {}".format(self.plugin_name, self.plugin_name, self.sql))

        # query data from clickhouse database
        try:
            turbovpn_serverip_df = pd.DataFrame(self.client.execute(self.sql))
        finally:
            self.client.disconnect()

        if turbovpn_serverip_df.empty:
            self.logger.error('[{}] - No turbovpn server ip found from security event. Policy id: {}.'.format(self.plugin_name, self.plugin_config['security_policy_id']))
            return []
        turbovpn_serverip_list = turbovpn_serverip_df[0].drop_duplicates().tolist()
        self.logger.info('[{}] - Query turbovpn server ip from clickhouse database successfully. {} items found'
                         .format(self.plugin_name, len(turbovpn_serverip_list)))

        return [
            ServerGroup(object_type='ip', server_list=turbovpn_serverip_list, output_file_name=self.output_file_name)]

