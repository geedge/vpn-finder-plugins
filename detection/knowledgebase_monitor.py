#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/31 19:41
# @author    : yinjinagyi
# @File    : knowledgebase_monitor.py
# @Function:
import argparse
import datetime
import numpy as np

from tool.Config import Config
from tool.KnowledgeBaseTool import KnowledgeApi, logger


class KnowledgeBaseMonitor:

    def __init__(self):
        self.monitor_config = Config().config['monitor']
        self.knowledgebase_config = Config().config['knowledgebase']
        # 打印self.knowledgebase_config
        logger.info(self.knowledgebase_config)
        self.knowledgebase_tool = KnowledgeApi(self.knowledgebase_config)

    def get_vpn_count(self, plugin_name=None, start_t=None, end_t=None, node_type='ip', mode='active', timezone_gap_hour=0):
        """
        :param plugin_name: filter by vpn_service
        :param node_type: 'ip' or 'domain'
        :param mode: 'active' or 'new'
        :param start_t: time range, format as '2024-01-20 15:00:00'
        :param end_t: time range, format as '2024-01-20 16:00:00'
        :param timezone_gap_hour: timezone bias compared with utc, local_timezone - utc+0
        """
        q = ""

        library_id = self.knowledgebase_tool.get_library_id(self.knowledgebase_config['library_name'])
        if node_type == 'ip':
            q += "type = 'IP'"
        elif node_type == 'domain':
            q += "type = 'Domain'"
        else:
            raise ValueError(
                "Wrong parameter \"node_type\" provided for KnowledgeBaseMonitor.get_vpn_ip_count: {}".format(
                    node_type))

        # query active node or new node
        if mode == 'active':
            time_column = 'updated_time'
        elif mode == 'new':
            time_column = 'created_time'
        else:
            raise ValueError(
                "Wrong parameter \"\mode\" provided for KnowledgeBaseMonitor. get_vpn_ip_count: {}".format(mode))

        # query specific vpn service
        if plugin_name and plugin_name != 'all':
            q += " and source_name = '{}'".format(plugin_name)

        # query specific time range
        if start_t:
            start_t = (datetime.datetime.strptime(start_t, "%Y-%m-%d %H:%M:%S") - datetime.timedelta(
                hours=timezone_gap_hour)).strftime("%Y-%m-%d %H:%M:%S")
            q += " and {} >= '{}'".format(time_column, start_t)
        if end_t:
            end_t = (datetime.datetime.strptime(end_t, "%Y-%m-%d %H:%M:%S") - datetime.timedelta(
                hours=timezone_gap_hour)).strftime("%Y-%m-%d %H:%M:%S")
            q += " and {} < '{}'".format(time_column, end_t)

        q = q.lstrip(' and')
        # print(vpn_service, q)
        count_num = self.knowledgebase_tool.get_knowledgebase_count(knowledge_id=library_id, q=q)
        return count_num


    def calculate_vpn_monitor_fixtime_mode(self, start_time, end_time, vpn_service=None):
        time_zone_gap = self.monitor_config['timezone_hour_gap']
        kb_metric = dict()

        if vpn_service is None: vpn_service='all'

        # cycle active
        kb_metric['active_ip_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='ip', mode='active', timezone_gap_hour=time_zone_gap,
                                                                                           start_t=start_time, end_t=end_time, plugin_name=vpn_service)
        kb_metric['new_ip_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='ip', mode='new', timezone_gap_hour=time_zone_gap,
                                                                                        start_t=start_time, end_t=end_time, plugin_name=vpn_service)
        kb_metric['active_domain_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='domain', mode='active', timezone_gap_hour=time_zone_gap,
                                                                                               start_t=start_time, end_t=end_time, plugin_name=vpn_service)
        kb_metric['new_domain_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='domain', mode='new', timezone_gap_hour=time_zone_gap,
                                                                                            start_t=start_time, end_t=end_time, plugin_name=vpn_service)


        for key in monitor_result_dict.keys():
            print(key, monitor_result_dict[key])

        return kb_metric




    def calculate_vpn_monitor_recent_mode(self, vpn_service=None, recent_interval_h=1):
        """
        params is used to calculate the metric of active and new item

        """
        time_zone_gap = self.monitor_config['timezone_hour_gap']
        current_end_time = datetime.datetime.now().replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
        current_start_time = (datetime.datetime.now().replace(minute=0, second=0, microsecond=0)
                              - datetime.timedelta(hours=recent_interval_h)).strftime("%Y-%m-%d %H:%M:%S")

        kb_metric = dict()

        if vpn_service is None: vpn_service = 'all'

        # all
        kb_metric['ip_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='ip', timezone_gap_hour=time_zone_gap, plugin_name=vpn_service)
        kb_metric['domain_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='domain', timezone_gap_hour=time_zone_gap, plugin_name=vpn_service)

        # all active in like 7 days
        t = (datetime.datetime.now().replace(minute=0, second=0, microsecond=0)
             - datetime.timedelta(days=self.monitor_config['outdated_days'])).strftime("%Y-%m-%d %H:%M:%S")
        kb_metric['active_ip_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='ip', mode='active', timezone_gap_hour=time_zone_gap, start_t=t, plugin_name=vpn_service)
        kb_metric['active_domain_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='domain', mode='active', timezone_gap_hour=time_zone_gap, start_t=t, plugin_name=vpn_service)


        # cycle active
        kb_metric['cycle_active_ip_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='ip', mode='active', timezone_gap_hour=time_zone_gap,
                                                                                                 start_t=current_start_time, end_t=current_end_time, plugin_name=vpn_service)
        kb_metric['cycle_new_ip_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='ip', mode='new', timezone_gap_hour=time_zone_gap,
                                                                                              start_t=current_start_time, end_t=current_end_time, plugin_name=vpn_service)
        kb_metric['cycle_active_domain_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='domain', mode='active', timezone_gap_hour=time_zone_gap,
                                                                                                     start_t=current_start_time, end_t=current_end_time, plugin_name=vpn_service)
        kb_metric['cycle_new_domain_count{{type="{}"}}'.format(vpn_service)] = self.get_vpn_count(node_type='domain', mode='new', timezone_gap_hour=time_zone_gap,
                                                                                                  start_t=current_start_time, end_t=current_end_time, plugin_name=vpn_service)


        # churn ratio = (# new in current cycle)/(# all active)
        kb_metric['cycle_ip_churn_ratio{{type="{}"}}'.format(vpn_service)] = np.round(kb_metric['cycle_new_ip_count{{type="{}"}}'.format(vpn_service)]/kb_metric['active_ip_count{{type="{}"}}'.format(vpn_service)], 4) \
            if kb_metric['active_ip_count{{type="{}"}}'.format(vpn_service)] > 0 else 0
        kb_metric['cycle_domain_churn_ratio{{type="{}"}}'.format(vpn_service)] = np.round(kb_metric['cycle_new_domain_count{{type="{}"}}'.format(vpn_service)] / kb_metric['active_domain_count{{type="{}"}}'.format(vpn_service)], 4) \
            if kb_metric['active_domain_count{{type="{}"}}'.format(vpn_service)] > 0 else 0
        return kb_metric




if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='VPN monitor')
    parser.add_argument('-m', '--mode', type=str, default='recent', help='recent or fixed')
    parser.add_argument('-r', '--recent_interval', type=str, default='1h', help='recent time')
    parser.add_argument('-s', '--start', type=str, default='', help='start time')
    parser.add_argument('-e', '--end', type=str, default='', help='end time')

    args = parser.parse_args()
    mode = args.mode
    start_time = args.start
    end_time = args.end


    monitor = KnowledgeBaseMonitor()
    monitor_result_dict = {}
    config_dict = Config().config

    # online mode
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

        monitor_result_dict.update(monitor.calculate_vpn_monitor_recent_mode(vpn_service=None, recent_interval_h=recent_interval))
        vpn_service_name_list = []
        for plugin_name in config_dict:
            if 'vpn' in plugin_name and 'vpn_service_name' in config_dict[plugin_name]:
                vpn_service_name = config_dict[plugin_name]['vpn_service_name']
                monitor_result_dict.update(monitor.calculate_vpn_monitor_recent_mode(vpn_service=vpn_service_name, recent_interval_h=recent_interval))

        # save to prom file
        monitor_file = monitor.monitor_config['monitor_file_path']
        with open(monitor_file, "w") as file:
            file.write("")
        for item in monitor_result_dict.items():
            with open(monitor_file, "a") as file:
                file.write(item[0] + ' ' + str(item[1]) + '\n')
                logger.info("[Monitor] {}~{} - {} {}".format(start_time, end_time, item[0], str(item[1])))


    # offline onetime mode
    elif mode == 'fixed':
        if start_time == '' or end_time == '':
            print('Please input correct time format')
            exit()

        monitor_result_dict.update(monitor.calculate_vpn_monitor_fixtime_mode(vpn_service=None, start_time=start_time, end_time=end_time))
        vpn_service_name_list = []
        for plugin_name in config_dict:
            if 'vpn' in plugin_name and 'vpn_service_name' in config_dict[plugin_name]:
                vpn_service_name = config_dict[plugin_name]['vpn_service_name']
                monitor_result_dict.update(monitor.calculate_vpn_monitor_fixtime_mode(vpn_service=vpn_service_name, start_time=start_time, end_time=end_time))

    else:
        print('Please input correct time mode')
        exit()

    for key in monitor_result_dict.keys():
        print(key, monitor_result_dict[key])
