#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/16 20:12
# @author    : yinjinagyi
# @File    : test_cyberghostvpn_serverip.py.py
# @Function:

import unittest
from detection.vpnservices.cyberghostvpn_serverip import CyberghostvpnServerip

class TestCyberghostvpnServerip(unittest.TestCase):

    def setUp(self):
        self.cyberghostvpn_detector = CyberghostvpnServerip(start_time='2024-01-17 10:00:00', end_time='2024-01-18 00:00:00')

    def test_get_cyberghostvpn_serverip(self):
        self.result = self.cyberghostvpn_detector.find_server()

    def test_save_to_knowledgebase(self):
        self.cyberghostvpn_detector.save_to_knowledgebase(object_type='ip',
                                                       object_list=self.cyberghostvpn_detector.find_server(),
                                                       vpn_service_name=self.cyberghostvpn_detector.vpn_service_name,
                                                       plugin_id=self.cyberghostvpn_detector.plugin_id,
                                                       plugin_name=self.cyberghostvpn_detector.plugin_name,
                                                       output_filename=self.cyberghostvpn_detector.output_file_name,
                                                       confidence=self.cyberghostvpn_detector.confidence)