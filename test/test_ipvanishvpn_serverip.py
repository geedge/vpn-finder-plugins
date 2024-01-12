#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/12 15:19
# @author    : yinjinagyi
# @File    : test_ipvanishvpn_serverip.py
# @Function:

import unittest
from detection.vpnservices.ipvanishvpn_serverip import IpvanishvpnServerip

class TestIpvanishvpnServerip(unittest.TestCase):

        def setUp(self):
            self.ipvanishvpn_detector = IpvanishvpnServerip(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

        def test_get_ipvanishvpn_serverip(self):
            self.result = self.ipvanishvpn_detector.find_server()

        def test_save_to_knowledgebase(self):
            self.ipvanishvpn_detector.save_to_knowledgebase(object_type='ip',
                                                        object_list=self.ipvanishvpn_detector.find_server(),
                                                        vpn_service_name=self.ipvanishvpn_detector.vpn_service_name,
                                                        plugin_id=self.ipvanishvpn_detector.plugin_id,
                                                        plugin_name=self.ipvanishvpn_detector.plugin_name,
                                                        output_filename=self.ipvanishvpn_detector.output_file_name,
                                                        confidence=self.ipvanishvpn_detector.confidence)

