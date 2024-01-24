#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/1/11 19:02
# @author    : yinjinagyi
# @File    : test_plugins.py
# @Function:


import unittest

from cyberghostvpn_serverip import CyberghostvpnServerip
from cyberghostvpn_servername import CyberghostvpnServername
from detection.vpnservices.hotspotvpn_serverip import HotspotvpnServerip
from geckovpn_serverip import GeckovpnServerip
from ipvanishvpn_serverip import IpvanishvpnServerip
from ipvanishvpn_servername import IpvanishvpnServername
from ivacyvpn_serverip import IvacyvpnServerip
from ivacyvpn_servername import IvacyvpnServername

from detection.vpnservices.turbovpn_serverip import TurbovpnServerip
from vpnunlimited_serverip import VpnunlimitedServerip
from windscribevpn_servername import WindscribevpnServername
from windscribevpn_serverip import WindscribevpnServerip


class TestHotspotvpnServerip(unittest.TestCase):

    def setUp(self):
        self.hotspotvpn_detector = HotspotvpnServerip(start_time='2024-01-17 00:00:00', end_time='2024-01-18 00:00:00')

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


class TestGeckovpnServerip(unittest.TestCase):

    def setUp(self):
        self.geckovpn_detector = GeckovpnServerip(start_time='2023-10-17 00:00:00', end_time='2023-10-18 00:00:00')

    def test_get_geckovpn_serverip(self):
        self.result = self.geckovpn_detector.find_server()
        print(self.result)

    def test_save_to_knowledgebase(self):
        self.geckovpn_detector.save_to_knowledgebase(object_type='ip',
                                                      object_list=self.geckovpn_detector.find_server(),
                                                      vpn_service_name=self.geckovpn_detector.vpn_service_name,
                                                      plugin_id=self.geckovpn_detector.plugin_id,
                                                      plugin_name=self.geckovpn_detector.plugin_name,
                                                      output_filename=self.geckovpn_detector.output_file_name,
                                                      confidence=self.geckovpn_detector.confidence)



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


class TestCyberghostvpnServername(unittest.TestCase):

    def setUp(self):
        self.cyberghostvpn_detector = CyberghostvpnServername(start_time='2024-01-17 10:00:00', end_time='2024-01-18 00:00:00')

    def test_get_cyberghostvpn_servername(self):
        self.result = self.cyberghostvpn_detector.find_server()

    def test_save_to_knowledgebase(self):
        self.cyberghostvpn_detector.save_to_knowledgebase(object_type='domain',
                                                       object_list=self.cyberghostvpn_detector.find_server(),
                                                       vpn_service_name=self.cyberghostvpn_detector.vpn_service_name,
                                                       plugin_id=self.cyberghostvpn_detector.plugin_id,
                                                       plugin_name=self.cyberghostvpn_detector.plugin_name,
                                                       output_filename=self.cyberghostvpn_detector.output_file_name,
                                                       confidence=self.cyberghostvpn_detector.confidence)

class TestIpvanishvpnServerip(unittest.TestCase):

    def setUp(self):
        self.ipvanishvpn_detector = IpvanishvpnServerip(start_time='2023-10-17 00:00:00',
                                                        end_time='2023-10-18 00:00:00')

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


class TestIpvanishvpnServername(unittest.TestCase):

    def setUp(self):
        self.ipvanishvpn_detector = IpvanishvpnServername(start_time='2024-01-17 00:00:00', end_time='2024-01-18 00:00:00')

    def test_get_ipvanishvpn_servername(self):
        self.result = self.ipvanishvpn_detector.find_server()

    def test_save_to_knowledgebase(self):
        self.ipvanishvpn_detector.save_to_knowledgebase(object_type='domain',
                                                       object_list=self.ipvanishvpn_detector.find_server(),
                                                       vpn_service_name=self.ipvanishvpn_detector.vpn_service_name,
                                                       plugin_id=self.ipvanishvpn_detector.plugin_id,
                                                       plugin_name=self.ipvanishvpn_detector.plugin_name,
                                                       output_filename=self.ipvanishvpn_detector.output_file_name,
                                                       confidence=self.ipvanishvpn_detector.confidence)




class TestIvacyvpnServername(unittest.TestCase):

    def setUp(self):
        self.ivacyvpn_detector = IvacyvpnServername(start_time='2023-10-17 00:00:00',
                                                  end_time='2023-10-18 00:00:00')

    def test_get_ivacyvpn_servername(self):
        self.result = self.ivacyvpn_detector.find_server()

    def test_save_to_knowledgebase(self):
        self.ivacyvpn_detector.save_to_knowledgebase(object_type='domain',
                                                      object_list=self.ivacyvpn_detector.find_server(),
                                                      vpn_service_name=self.ivacyvpn_detector.vpn_service_name,
                                                      plugin_id=self.ivacyvpn_detector.plugin_id,
                                                      plugin_name=self.ivacyvpn_detector.plugin_name,
                                                      output_filename=self.ivacyvpn_detector.output_file_name,
                                                      confidence=self.ivacyvpn_detector.confidence)


class TestIvacyvpnServerip(unittest.TestCase):

    def setUp(self):
        self.ivacyvpn_detector = IvacyvpnServerip(start_time='2023-10-16 00:00:00',
                                                  end_time='2023-10-19 00:00:00')

    def test_get_ivacyvpn_serverip(self):
        self.result = self.ivacyvpn_detector.find_server()

    def test_save_to_knowledgebase(self):
        self.ivacyvpn_detector.save_to_knowledgebase(object_type='ip',
                                                      object_list=self.ivacyvpn_detector.find_server(),
                                                      vpn_service_name=self.ivacyvpn_detector.vpn_service_name,
                                                      plugin_id=self.ivacyvpn_detector.plugin_id,
                                                      plugin_name=self.ivacyvpn_detector.plugin_name,
                                                      output_filename=self.ivacyvpn_detector.output_file_name,
                                                      confidence=self.ivacyvpn_detector.confidence)

class TestTurbovpnServerip(unittest.TestCase):

    def setUp(self):
        self.turbovpn_detector = TurbovpnServerip(start_time='2024-01-16 00:00:00',
                                                  end_time='2024-01-19 00:00:00')

    def test_get_turbovpn_serverip(self):
        self.result = self.turbovpn_detector.find_server()

    def test_save_to_knowledgebase(self):
        self.turbovpn_detector.save_to_knowledgebase(object_type='ip',
                                                      object_list=self.turbovpn_detector.find_server(),
                                                      vpn_service_name=self.turbovpn_detector.vpn_service_name,
                                                      plugin_id=self.turbovpn_detector.plugin_id,
                                                      plugin_name=self.turbovpn_detector.plugin_name,
                                                      output_filename=self.turbovpn_detector.output_file_name,
                                                      confidence=self.turbovpn_detector.confidence)


class TestVpnunlimitedServerip(unittest.TestCase):

    def setUp(self):
        self.vpnunlimited_detector = VpnunlimitedServerip(start_time='2023-10-16 00:00:00',
                                                  end_time='2023-10-19 00:00:00')

    def test_get_vpnunlimited_serverip(self):
        self.result = self.vpnunlimited_detector.find_server()
        print(self.result)

    def test_save_to_knowledgebase(self):
        self.vpnunlimited_detector.save_to_knowledgebase(object_type='ip',
                                                      object_list=self.vpnunlimited_detector.find_server(),
                                                      vpn_service_name=self.vpnunlimited_detector.vpn_service_name,
                                                      plugin_id=self.vpnunlimited_detector.plugin_id,
                                                      plugin_name=self.vpnunlimited_detector.plugin_name,
                                                      output_filename=self.vpnunlimited_detector.output_file_name,
                                                      confidence=self.vpnunlimited_detector.confidence)

class TestWindscribevpnServername(unittest.TestCase):

    def setUp(self):
        self.windscribevpn_detector = WindscribevpnServername(start_time='2024-01-16 00:00:00',
                                                  end_time='2024-01-19 00:00:00')

    def test_get_windscribevpn_servername(self):
        self.result = self.windscribevpn_detector.find_server()
        print(self.result)

    def test_save_to_knowledgebase(self):
        self.windscribevpn_detector.save_to_knowledgebase(object_type='domain',
                                                      object_list=self.windscribevpn_detector.find_server(),
                                                      vpn_service_name=self.windscribevpn_detector.vpn_service_name,
                                                      plugin_id=self.windscribevpn_detector.plugin_id,
                                                      plugin_name=self.windscribevpn_detector.plugin_name,
                                                      output_filename=self.windscribevpn_detector.output_file_name,
                                                      confidence=self.windscribevpn_detector.confidence)



class TestWindscribevpnServerip(unittest.TestCase):

        def setUp(self):
            self.windscribevpn_detector = WindscribevpnServerip()

        def test_get_windscribevpn_serverip(self):
            self.result = self.windscribevpn_detector.find_server()
            print(self.result)

        def test_save_to_knowledgebase(self):
            self.windscribevpn_detector.save_to_knowledgebase(object_type='ip',
                                                        object_list=self.windscribevpn_detector.find_server(),
                                                        vpn_service_name=self.windscribevpn_detector.vpn_service_name,
                                                        plugin_id=self.windscribevpn_detector.plugin_id,
                                                        plugin_name=self.windscribevpn_detector.plugin_name,
                                                        output_filename=self.windscribevpn_detector.output_file_name,
                                                        confidence=self.windscribevpn_detector.confidence)


if __name__ == '__main__':
    # # 运行指定测试用例
    suite = unittest.TestSuite()
    suite.addTest(TestHotspotvpnServerip('test_get_hotspotvpn_serverip'))
    suite.addTest(TestGeckovpnServerip('test_get_geckovpn_serverip'))
    suite.addTest(TestCyberghostvpnServerip('test_get_cyberghostvpn_serverip'))
    suite.addTest(TestCyberghostvpnServername('test_get_cyberghostvpn_servername'))
    suite.addTest(TestIpvanishvpnServerip('test_get_ipvanishvpn_serverip'))
    suite.addTest(TestIpvanishvpnServername('test_get_ipvanishvpn_servername'))
    suite.addTest(TestIvacyvpnServername('test_get_ivacyvpn_servername'))
    suite.addTest(TestIvacyvpnServerip('test_get_ivacyvpn_serverip'))
    suite.addTest(TestTurbovpnServerip('test_get_turbovpn_serverip'))
    runner = unittest.TextTestRunner()
    runner.run(suite)



