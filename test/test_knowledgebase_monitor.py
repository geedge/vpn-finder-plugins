#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/2/4 15:08
# @author    : yinjinagyi
# @File    : test_knowledgebase_monitor.py.py
# @Function:

import unittest

from Config import Config
from knowledgebase_monitor import KnowledgeBaseMonitor

class TestKnowledgeMonitor(unittest.TestCase):
    def setUp(self):
        config = Config().config
        self.knowledge_monitor = KnowledgeBaseMonitor()

    def test_get_knowledgebase(self):
        self.assertEqual(self.knowledge_monitor.get_vpn_count(
            plugin_name='protonvpn', start_t='2024-01-30 00:00:00',
            end_t='2024-01-31 00:00:00', timezone_gap_hour=0, node_type='ip', mode='new'),
            53655)

        self.assertEqual(self.knowledge_monitor.get_vpn_count(
            plugin_name='protonvpn', start_t='2024-01-30 00:00:00',
            end_t='2024-01-31 00:00:00', timezone_gap_hour=0, node_type='ip', mode='active'),
            53675)

        self.assertEqual(self.knowledge_monitor.get_vpn_count(
            plugin_name='ivacyvpn', start_t='2024-01-15 00:00:00',
            end_t='2024-01-31 00:00:00', timezone_gap_hour=0, node_type='domain', mode='new'),
            162)


        # time gap test
        self.assertEqual(self.knowledge_monitor.get_vpn_count(start_t='2024-01-31 00:00:00',
            end_t='2024-01-31 08:00:00', timezone_gap_hour=0, node_type='domain', mode='active'),
            1041)

        self.assertEqual(self.knowledge_monitor.get_vpn_count(start_t='2024-01-30 21:00:00',
                                                              end_t='2024-01-31 05:00:00', timezone_gap_hour=3,
                                                              node_type='domain', mode='active'), 1041)

        self.assertEqual(self.knowledge_monitor.get_vpn_count(start_t='2024-01-31 03:00:00',
                                                              end_t='2024-01-31 11:00:00', timezone_gap_hour=-3,
                                                              node_type='domain', mode='active'), 1041)


        # all domains
        self.assertEqual(self.knowledge_monitor.get_vpn_count(node_type='domain'), 71622)

        # all active domains after '2024-01-18 00:00:00'
        self.assertEqual(self.knowledge_monitor.get_vpn_count(node_type='domain', mode='active', start_t='2024-01-18 00:00:00'), 48396)


    def test_get_vpn_count(self):
        # self.assertEqual(self.knowledge_monitor.get_vpn_count(source_name='protonvpn', start_t='2024-01-30 00:00:00',
        #     end_t='2024-01-31 00:00:00', timezone_gap_hour=0, node_type='ip', mode='new'), 0)

        self.assertEqual(self.knowledge_monitor.get_vpn_count(plugin_name='windscribevpn', start_t='2024-01-15 00:00:00',
                                                              end_t='2024-05-31 00:00:00', timezone_gap_hour=0, node_type='domain', mode='active'), 1031)

        # # time gap test
        # self.assertEqual(self.knowledge_monitor.get_vpn_count(start_t='2024-01-31 00:00:00',
        #     end_t='2024-01-31 08:00:00', timezone_gap_hour=0, node_type='domain', mode='active'), 1041)
        #
        # self.assertEqual(self.knowledge_monitor.get_vpn_count(start_t='2024-01-30 21:00:00',
        #     end_t='2024-01-31 05:00:00', timezone_gap_hour=3, node_type='domain', mode='active'), 1041)
        #
        # self.assertEqual(self.knowledge_monitor.get_vpn_count(start_t='2024-01-31 03:00:00',
        #     end_t='2024-01-31 11:00:00', timezone_gap_hour=-3, node_type='domain', mode='active'), 1041)
        #
        # # all domains
        # self.assertEqual(self.knowledge_monitor.get_vpn_count(node_type='domain'), 71622)
        #
        # # all active domains after '2024-01-18 00:00:00'
        # self.assertEqual(self.knowledge_monitor.get_vpn_count(node_type='domain', mode='active', start_t='2024-01-18 00:00:00'), 48396)
