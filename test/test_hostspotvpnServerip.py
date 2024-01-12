#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/11 19:02
# @author    : yinjinagyi
# @File    : test_hostspotvpnServerip.py
# @Function:


import unittest
from detection.vpnservices.hotspotvpn_serverip import HotspotvpnServerip

class TestHotspotvpnServerip(unittest.TestCase):

    def setUp(self):
        self.hotspotvpn_detector = HotspotvpnServerip(start_time='2023-12-01 00:00:00', end_time='2024-01-11 00:00:00')

    def test_get_hotspotvpn_serverip(self):
        self.result = self.hotspotvpn_detector.find_server()
        print(self.result)

    def test_save_to_knowledgebase(self):
        self.hotspotvpn_detector.save_to_knowledgebase(object_type='ip',
                                                       object_list=self.hotspotvpn_detector.find_server(),
                                                       vpn_service_name=self.hotspotvpn_detector.vpn_service_name,
                                                       plugin_id=self.hotspotvpn_detector.plugin_id,
                                                       plugin_name=self.hotspotvpn_detector.plugin_name,
                                                       output_filename=self.hotspotvpn_detector.output_file_name,
                                                       confidence=self.hotspotvpn_detector.confidence)