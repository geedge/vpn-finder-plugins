'''
Description: 对文件进行初始化
Author: chenxu
Date: 2022-09-20 10:53:28
LastEditTime: 2022-11-02 15:01:07
LastEditors:
'''
import Functions
import os

def dataFilerClear():
    # Clear detection1 data
    # print(os.path.join(os.getcwd()))
    Functions.clear_dir('logs/', git_keep=True)
    Functions.clear_dir('data/', git_keep=True)

dataFilerClear()
