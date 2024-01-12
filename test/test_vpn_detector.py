#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/11 11:20
# @author    : yinjinagyi
# @File    : test_vpn_detector.py
# @Function:

import unittest
from detection.vpn_detector import VpnDetector

class TestVpnDetector(unittest.TestCase):
    def setUp(self):
        self.vpn_detector = VpnDetector(start_time='2023-12-01 00:00:00', end_time='2024-01-11 00:00:00')

    def test_load_config(self):
        config = self.vpn_detector.load_config()
        self.assertEqual(config['mariadb']['timezone_hour_gap'], 8)

    def test_save_to_knowledgebase(self):
        self.vpn_detector.save_to_knowledgebase(object_type='ip', object_list=['102.129.145.99', '102.129.152.191', '102.129.152.198', '102.129.152.203', '102.129.152.211', '102.129.152.217', '102.129.152.240', '102.129.153.236', '102.129.153.240', '102.129.153.247', '102.129.153.249'],
                                                vpn_service_name='cyberghostvpn', plugin_id=29,
                                                plugin_name='cyberghostvpn', output_filename='cyberghostvpn_ip.csv', confidence='suspect')

        self.vpn_detector.save_to_knowledgebase(object_type='domain', object_list=['dc-615.pointtoserver.com', 'dc-207.pointtoserver.com', 'dc-660.pointtoserver.com', 'dc-108.pointtoserver.com', 'dc-664.pointtoserver.com', 'dc-599.pointtoserver.com', 'dc-291.pointtoserver.com', 'dc-673.pointtoserver.com', 'dc-235.pointtoserver.com', 'dc-346.pointtoserver.com', 'dc-625.pointtoserver.com', 'dc-555.pointtoserver.com', 'dc-186.pointtoserver.com'],
                                                vpn_service_name='ivacyvpn', plugin_id=19, plugin_name='ivacyvpn_ip', output_filename='ivacyvpn_domain.csv', confidence='suspect')

    def test_main(self):
        self.vpn_detector.main()


