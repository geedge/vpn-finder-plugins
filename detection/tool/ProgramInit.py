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
    Functions.clear('PsiphonServerIP.txt')
    Functions.clear_dir('logs/', git_keep=True)
    # toolFunction.clear_dir('data/feature', git_keep=True)
    # toolFunction.clear_dir('data/result', git_keep=True)
    # toolFunction.clear_dir('data/model/pic')


dataFilerClear()
