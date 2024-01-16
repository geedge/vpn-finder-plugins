#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/11 15:45
# @author    : yinjinagyi
# @File    : hotspotvpn_serverip.py
# @Function:

from vpn_detector import VpnDetector
import pandas as pd


class HotspotvpnServerip(VpnDetector):
    """

    This class is used to detect hotspotvpn server ip
    """

    def __init__(self, start_time, end_time):
        super().__init__(start_time, end_time)
        self.plugin_config = self.load_config()['hotspotvpn_serverip']
        self.plugin_id = self.plugin_config['plugin_id']
        self.plugin_name = self.plugin_config['plugin_name']
        self.object_type = self.plugin_config['object_type']
        self.vpn_service_name = self.plugin_config['vpn_service_name']
        self.confidence = self.plugin_config['confidence']
        self.output_file_name = self.plugin_name + '_' + str(self.start_time).replace(' ', '_').replace(':', '')[:13] + '.csv'
        self.start_time = start_time
        self.end_time = end_time

        self.sql = self.plugin_config['sql']
        self.masquerede_domains = ["'"+i.strip()+"'" for i in self.plugin_config['domains'].split(',')]

    def find_server(self):
        """
        Get hotspotvpn server ip from clickhouse database
        :return: hotspotvpn server ip list
        """
        self.logger.info('Start to query hotspotvpn server ip from clickhouse database')

        # construct query sql
        TIME_FILTER_PATTERN = self.config['common']['time_filter_pattern'].replace('recv_time_columnname', self.config['common']['recv_time_columnname'])
        time_filter = TIME_FILTER_PATTERN.replace("{$start_time}", str(self.start_time)).replace("{$end_time}", str(
            self.end_time)).replace("{$time_zone}", self.time_zone)
        self.sql = self.sql.replace("{$db_name}", self.dbname).replace("{$table_name}", self.table_name)
        self.sql = self.sql.replace("{$time_filter}", time_filter)
        self.sql = self.sql.replace("{$domain_list}", ','.join(self.masquerede_domains))

        # self.logger.info("Sql for {}: {}".format(self.plugin_name, self.sql))

        # query data from clickhouse database
        try:
            hotspotvpn_serverip_df = pd.DataFrame(self.client.execute(self.sql))
        finally:
            self.client.disconnect()

        if hotspotvpn_serverip_df.empty:
            self.logger.info('No hotspotvpn server ip found from clickhouse database')
            return []
        hotspotvpn_serverip_list = hotspotvpn_serverip_df[0].drop_duplicates().tolist()
        self.logger.info('Query hotspotvpn server ip from clickhouse database successfully. {} items found'
                         .format(len(hotspotvpn_serverip_list)))

        return hotspotvpn_serverip_list
