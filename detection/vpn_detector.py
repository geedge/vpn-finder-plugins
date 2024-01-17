#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/8 13:51
# @author    : yinjinagyi
# @File    : vpn_detector.py
# @Function: This class is the parent class of various vpn classes in file vpnservices
import argparse
import datetime
import socket

import sys
import os
sys.path.append('..')

import pandas as pd
from tool.LoggingTool import Logger
from clickhouse_driver import Client
from tool.Config import Config
from tool.KnowledgeBaseTool import KnowledgeApi
import concurrent.futures


class VpnDetector:
    """
    This class is the parent class of various vpn classes in file vpnservices
    Functions: Load config, query data from clickhouse database, sava results, write data to mariadb database
    """
    def __init__(self, start_time, end_time):
        self.config = self.load_config()
        self.output_file_path = self.config['common']['output_path']
        self.logger = Logger().getLogger()
        self.kb = KnowledgeApi(self.config)
        self.start_time = start_time
        self.end_time = end_time
        self.time_zone = self.config['common']['time_zone']
        self.dbname = self.config['clickhouse']['db_name']
        self.table_name = self.config['clickhouse']['table_name']

        self.client = Client(user=self.config['clickhouse']['username'], password=self.config['clickhouse']['password'],
                             host=self.config['clickhouse']['host'],
                             port=self.config['clickhouse']['port'], database=self.dbname)

    def load_config(self):
        """
        Load config
        :return: config
        """
        config = Config().config
        return config

    def save_to_knowledgebase(self, object_list, object_type, vpn_service_name, plugin_id, plugin_name, output_filename, confidence='suspected'):
        """
        Write data to local file and knowledge base
        :param object_type:  ip or domain
        :param object_list: list of ip or domain
        :param vpn_service_name: nordvpn, cyberghostvpn, etc.
        :param plugin_id: plugin id
        :param plugin_name: plugin name
        :param output_filename: filename
        :param confidence: 3 kinds of confidence level, confirmed, suspect, tentative
        :return:
        """
        if object_type == 'ip':
            library_name = self.config['knowledgebase']['ip_library_name']
        else:
            library_name = self.config['knowledgebase']['domain_library_name']
        knowledge_id = self.kb.get_library_id(library_name)

        # convert result data into required format https://docs.geedge.net/pages/viewpage.action?pageId=104760257
        result_df = pd.DataFrame()
        if object_type == 'ip':
            result_df['ip1'] = object_list
            result_df['ip2'] = object_list
            result_df.insert(0, 'addr_format', 'Single')
        if object_type == 'domain':
            result_df['domain'] = object_list

        result_df['plugin_id'] = plugin_id
        result_df['plugin_name'] = plugin_name
        result_df['vpn_service_name'] = vpn_service_name
        result_df['method'] = 'passive_ml'
        result_df['confidence'] = confidence
        result_df['is_valid'] = 1

        # result save
        if len(result_df) > 0:
            self.logger.info('Start to update data to knowledgebase')
            result_path = os.path.join('data', plugin_name)
            if not os.path.exists(result_path):
                os.makedirs(result_path)
            result_file = os.path.join(result_path, output_filename)
            result_df.to_csv(result_file, index=False)
            self.logger.info('Write {} {} {} to local file {} successfully.'.format(len(result_df), vpn_service_name, object_type, result_file))

            # update to knowledgebase
            knowledge_api = KnowledgeApi(self.config)
            self.logger.info('[Updating knowledgebase]- {} num:{}'.format(object_type, len(object_list)))
            description_str = "Update {} record(s).".format(len(object_list))
            knowledge_api.file_import(result_file, knowledge_id, 'update', description_str)



    def get_resolved_addr(self, server_name):
        """
        Get ipvanish server ip list from server name list
        :param server_name: server name list
        :return: ip addr list
        """
        resolved_addr = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                resolved_addr = socket.gethostbyname_ex(server_name)[2]
        except Exception as e:
            # self.logger.error("Resolve failed. {}: {} ".format(server_name, e))
            pass

        return server_name, resolved_addr



    def resolve_dns_for_domain_list(self, domain_list, max_workers=100):
        """
        Resolve domain list to ip list
        :param domain_list:
        :param max_workers:
        :return:
        """
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.get_resolved_addr, domain) for domain in domain_list]
            for future in concurrent.futures.as_completed(futures):
                try:
                    server_name, resolved_addr = future.result()
                    if resolved_addr is not None:
                        results.extend(resolved_addr)
                except Exception as e:
                    self.logger.error(e)

        return results


# 入口函数定义
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='VPN detection')
    parser.add_argument('-p', '--plugin', type=str, help='plugin name')
    parser.add_argument('-m', '--mode', type=str, default='recent', help='recent or fixed')
    parser.add_argument('-r', '--recent_interval', type=str, default='1h', help='recent time')
    parser.add_argument('-s', '--start', type=str, default='', help='start time')
    parser.add_argument('-e', '--end', type=str, default='', help='end time')

    args = parser.parse_args()
    plugin_name = args.plugin
    mode = args.mode
    start_time = args.start
    end_time = args.end

    # parameter verification
    if mode == 'recent':
        if start_time != '' or end_time != '':
            print('Please input correct time format')
            exit()
        recent_interval = args.recent_interval
        if recent_interval[-1] == 'h':
            recent_interval = int(recent_interval[:-1])
        elif recent_interval[-1] == 'd':
            recent_interval = int(recent_interval[:-1]) * 24
        else:
            print('Please input correct recent interval')
            exit()
        # 根据当前时间向前取整小时
        end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:00:00")
        start_time = (datetime.datetime.now() - datetime.timedelta(hours=recent_interval)).strftime("%Y-%m-%d %H:00:00")
    elif mode == 'fixed':
        if start_time == '' or end_time == '':
            print('Please input correct time format')
            exit()

    else:
        print('Please input correct time mode')
        exit()


    detector = None
    if plugin_name == 'hotspotvpn_serverip':
        from vpnservices.hotspotvpn_serverip import HotspotvpnServerip
        detector = HotspotvpnServerip(start_time, end_time)
    elif plugin_name == 'ipvanishvpn_servername':
        from vpnservices.ipvanishvpn_servername import IpvanishvpnServername
        detector = IpvanishvpnServername(start_time, end_time)
    elif plugin_name == 'ipvanishvpn_serverip':
        from vpnservices.ipvanishvpn_serverip import IpvanishvpnServerip
        detector = IpvanishvpnServerip(start_time, end_time)
    elif plugin_name == 'cyberghostvpn_servername':
        from vpnservices.cyberghostvpn_servername import CyberghostvpnServername
        detector = CyberghostvpnServername(start_time, end_time)
    elif plugin_name == 'cyberghostvpn_serverip':
        from vpnservices.cyberghostvpn_serverip import CyberghostvpnServerip
        detector = CyberghostvpnServerip(start_time, end_time)
    elif plugin_name == 'geckovpn_serverip':
        from vpnservices.geckovpn_serverip import GeckovpnServerip
        detector = GeckovpnServerip(start_time, end_time)
    elif plugin_name == 'ivacyvpn_servername':
        from vpnservices.ivacyvpn_servername import IvacyvpnServername
        detector = IvacyvpnServername(start_time, end_time)
    elif plugin_name == 'ivacyvpn_serverip':
        from vpnservices.ivacyvpn_serverip import IvacyvpnServerip
        detector = IvacyvpnServerip(start_time, end_time)
    elif plugin_name == 'turbovpn_serverip':
        from vpnservices.turbovpn_serverip import TurbovpnServerip
        detector = TurbovpnServerip(start_time, end_time)

    else:
        print('Please input correct plugin name')
        exit()

    result_list = detector.find_server()
    if len(result_list) > 0:
        detector.save_to_knowledgebase(result_list, detector.object_type,
                                   detector.vpn_service_name, detector.plugin_id,
                                   detector.plugin_name, detector.output_file_name, detector.confidence)
        # Output logs to record the amount of data written, plugin id, plugin name and other information
        detector.logger.info(
            'Write {} {} to knowledgebase successfully. {} items found'.format(detector.vpn_service_name,
                                                                               detector.object_type,
                                                                               len(result_list)))





