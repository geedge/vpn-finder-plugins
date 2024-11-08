#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/2/1 10:23
# @author    : yinjinagyi
# @File    : test_knowledgebase_tool.py
# @Function:
import unittest

from Config import Config
from KnowledgeBaseTool import KnowledgeApi


class TestKnowledgeApi(unittest.TestCase):

    def setUp(self):
        config = Config().config
        self.knowledgebase_tool = KnowledgeApi(config['knowledgebase'])

    def test_get_knowledgebase(self):
        print(self.knowledgebase_tool.get_knowledgebase_count(knowledge_id=16, q="c_time >= '2023-10-26 08:12:47' AND addr_format = 'Single'"))

    def test_file_import(self):
        self.knowledgebase_tool.file_import('/Users/joy/work/iie/project/cyber_narrator/CN/3-新功能研发/vpn-detection/3.项目代码/CN-Code/vpn-finder-plugins/tmp_ip.csv',
                                            action='update')