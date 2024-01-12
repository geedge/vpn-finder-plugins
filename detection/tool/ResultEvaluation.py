#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/3/27 19:34
# @author    : yinjinagyi
# @File    : ResultEvaluation.py
# @Function:

import os
import pandas as pd

from codev.tool import toolFunction


class LabelScraper:

    def __init__(self, start_time, end_time):
        self.detected_df = self.read_result()


    def read_result(self):
        output_ip_list = []
        files = toolFunction.filter_files_by_created_time('data/result', '2023-01-01', '2023-03-30')
        for file in files:
            output_ip_list.extend(list(pd.read_csv(file, names=['ip', 'pred_y', 'score', 'time'])['ip']))

        result_df = pd.DataFrame(output_ip_list, columns=['ip', 'pred_y', 'score', 'time'])

        return result_df
