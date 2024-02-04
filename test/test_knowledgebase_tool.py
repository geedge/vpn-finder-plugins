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
        self.knowledgebase_tool = KnowledgeApi(config)

    def test_get_knowledgebase(self):
        print(self.knowledgebase_tool.get_knowledgebase_count(knowledge_id=6, q="c_time >= '2023-10-26 08:12:47' AND addr_format = 'Single'"))
