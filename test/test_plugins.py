#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/11 19:02
# @author    : yinjinagyi
# @File    : test_plugins.py
# @Function:


import unittest

from cyberghostvpn import CyberghostvpnServerip, CyberghostvpnServername, Cyberghostvpn
from detection.vpnservices.hotspotvpn import Hotspotvpn
from geckovpn import Geckovpn
from ipvanishvpn import Ipvanishvpn, IpvanishvpnServerip, IpvanishvpnServername

from ivacyvpn import IvacyvpnServerip, IvacyvpnServername, Ivacyvpn

from detection.vpnservices.turbovpn import Turbovpn
from protonvpn import Protonvpn
from vpnunlimited import Vpnunlimited
from windscribevpn import WindscribevpnServername, Windscribevpn


class TestHotspotvpnServerip(unittest.TestCase):

    def setUp(self):
        self.hotspotvpn_detector = Hotspotvpn(start_time='2023-10-17 10:00:00', end_time='2023-10-17 20:00:00')


    def test_get_hotspotvpn_serverip(self):
        self.result = self.hotspotvpn_detector.find_server()
        for result in self.result:
            print(result.object_type)
            print(result.server_list)


class TestIpvanishvpnServername(unittest.TestCase):

    def setUp(self):
        self.ipvanishvpn_detector = IpvanishvpnServername(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

    def test_get_ipvanishvpn_servername(self):
        self.result = self.ipvanishvpn_detector.find_server()
        for result in self.result:
            print(result.object_type)
            print(result.server_list)

    def test_save_to_knowledgebase(self):
        self.ipvanishvpn_detector.save_to_knowledgebase(object_type='domain',
                                                       object_list=self.ipvanishvpn_detector.find_server(),
                                                       vpn_service_name=self.ipvanishvpn_detector.vpn_service_name,
                                                       plugin_id=self.ipvanishvpn_detector.plugin_id,
                                                       plugin_name=self.ipvanishvpn_detector.plugin_name,
                                                       output_filename=self.ipvanishvpn_detector.output_file_name,
                                                       confidence=self.ipvanishvpn_detector.confidence)


class TestIpvanishvpnServerip(unittest.TestCase):

    def setUp(self):
        self.ipvanishvpn_detector = IpvanishvpnServerip()

    def test_get_ipvanishvpn_serverip(self):
        self.result = self.ipvanishvpn_detector.find_server()
        for result in self.result:
            print(result.object_type)
            print(result.server_list)


class TestIpvanishvpn(unittest.TestCase):

    def setUp(self):
        self.ipvanishvpn_detector = Ipvanishvpn(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

    def test_get_ipvanishvpn_serverip(self):
        self.result = self.ipvanishvpn_detector.find_server()
        for result in self.result:
            print(result.object_type)
            print(result.server_list)



class TestIvacyvpnServername(unittest.TestCase):

        def setUp(self):
            self.ivacyvpn_detector = IvacyvpnServername(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

        def test_get_ivacyvpn_servername(self):
            self.result = self.ivacyvpn_detector.find_server()
            for result in self.result:
                print(result.object_type)
                print(result.server_list)



class TestIvacyvpnServerip(unittest.TestCase):

    def setUp(self):
        self.ivacyvpn_detector = IvacyvpnServerip()

    def test_get_ivacyvpn_servername(self):
        self.result = self.ivacyvpn_detector.find_server()
        for result in self.result:
            print(result.object_type)
            print(result.server_list)


class TestIvacyvpn(unittest.TestCase):

    def setUp(self):
        self.ivacyvpn_detector = Ivacyvpn(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

    def test_get_ivacyvpn_servername(self):
        self.result = self.ivacyvpn_detector.find_server()
        for result in self.result:
            print(result.object_type)
            print(result.server_list)



class TestProtonvpn(unittest.TestCase):

    def setUp(self):
        self.protonvpn_detector = Protonvpn(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

    def test_get_protonvpn_serverip(self):
        self.result = self.protonvpn_detector.find_server()
        for result in self.result:
            print(result.object_type)
            print(result.server_list)


class TestCyberghostvpn(unittest.TestCase):

    def setUp(self):
        self.cyberghostvpn_detector = Cyberghostvpn(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

    def test_get_cyberghostvpn_serverip(self):
        self.result = self.cyberghostvpn_detector.find_server()
        for result in self.result:
            print(result.object_type)
            print(result.server_list)


class TestWindscribevpn(unittest.TestCase):

        def setUp(self):
            self.windscribevpn_detector = Windscribevpn(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

        def test_get_windscribevpn_serverip(self):
            self.result = self.windscribevpn_detector.find_server()
            for result in self.result:
                print(result.object_type)
                print(result.server_list)


class TestTurbovpn(unittest.TestCase):

    def setUp(self):
        self.turbovpn_detector = Turbovpn(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

    def test_get_turbovpn_serverip(self):
        self.result = self.turbovpn_detector.find_server()
        for result in self.result:
            print(result.object_type)
            print(result.server_list)


class TestGeckovpn(unittest.TestCase):

        def setUp(self):
            self.geckovpn_detector = Geckovpn(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

        def test_get_geckovpn_serverip(self):
            self.result = self.geckovpn_detector.find_server()
            for result in self.result:
                print(result.object_type)
                print(result.server_list)


class TestVpnunlimited(unittest.TestCase):

        def setUp(self):
            self.vpnunlimited_detector = Vpnunlimited(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

        def test_get_vpnunlimited_serverip(self):
            self.result = self.vpnunlimited_detector.find_server()
            for result in self.result:
                print(result.object_type)
                print(result.server_list)