#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/3/18 20:02
# @author    : yinjinagyi
# @File    : controller.py.py
# @Function:
import datetime
import sys

import pytz
from codev.detection.ModelTraning import ModelTraining
from codev.tool import toolFunction, LoggingTool
from codev.detection.ModelDetection import ModelDetection
from codev.detection.Monitor import Monitor

logger = LoggingTool.Logger().getLogger()

if __name__ == '__main__':

    # 全局参数获取
    data = toolFunction.readYaml('config.yaml')
    config = dict()
    for item in data['config']:
        config.update(item)

    timeZone = str(config['timeZone'])

    # 获取程序启动时间
    startTime = datetime.datetime.now(tz=pytz.timezone(timeZone)).strftime("%Y-%m-%d %H:%M:%S")

    # 获得当前的日期-小时向下取整
    tailTime = datetime.datetime.now(tz=pytz.timezone(timeZone)).strftime("%Y-%m-%d %H")

    # 获得待测窗口时间
    headTime = (datetime.datetime.now(tz=pytz.timezone(timeZone)) - datetime.timedelta(
        hours=config['hours_N'])).strftime("%Y-%m-%d %H")

    # 获得时间窗口
    headTime = datetime.datetime.strptime(str(headTime) + ':00:00', '%Y-%m-%d %H:%M:%S')
    tailTime = datetime.datetime.strptime(str(tailTime) + ':00:00', '%Y-%m-%d %H:%M:%S')
    config['headTime'] = headTime
    config['tailTime'] = tailTime


    # 设置测试时间
    if config['ifTest'] == 1:
        tailTime = datetime.datetime.strptime(str(config['testEnvironmentTailTime']), '%Y-%m-%d %H:%M:%S').strftime(
            "%Y-%m-%d %H")
        headTime = config['headTime'] = datetime.datetime.strptime(tailTime, '%Y-%m-%d %H') - datetime.timedelta(
            hours=config['hours_N'])
        tailTime = datetime.datetime.strptime(str(tailTime) + ':00:00', "%Y-%m-%d %H:%M:%S")
        config['tailTime'] = tailTime

    logger.info("DataQuerying from {} to {} ".format(headTime, tailTime))

    # 配置为非模型训练模式但无model文件时报错退出
    if config['initModelTrain'] == 0:
        if not toolFunction.fileExists(config['ModelPath']):
            logger.error('Model file "{}" is not found, check if configuration is correct!'.format(config['ModelPath']))
            sys.exit()
    # 配置为模型训练模式时进行模型训练
    if config['initModelTrain'] == 1:
        logger.info("Start model generation...")
        config['headTime'] = config['training_start_time']
        config['tailTime'] = config['training_end_time']
        ModelTraining(config).training()
        logger.info("Model-training completed!")
        sys.exit()

    # 监控
    if config['monitor_switch'] == 'on':
        with open(config['monitor_file_path'], "w") as file:
            # 写入一个空字符串作为文件内容
            file.write("")
        kb_monitor_metrics = Monitor(config).calculate_kb_metric()
        for item in kb_monitor_metrics.items():
            with open(config['monitor_file_path'], "a") as file:
                file.write('vpn_thwarting_psiphon3_serverip_' + item[0] + ' ' + str(item[1]) + '\n')
                logger.info("[Monitor] - vpn_thwarting_psiphon3_serverip_{} {}".format(item[0], str(item[1])))
        ck_monitor_metrics = Monitor(config).calculate_ck_metric()
        for item in ck_monitor_metrics.items():
            with open(config['monitor_file_path'], "a") as file:
                file.write('vpn_thwarting_psiphon3_server_app_' + item[0] + ' ' + str(item[1]) + '\n')
                logger.info("[Monitor] - vpn_thwarting_psiphon3_server_app_{} {}".format(item[0], str(item[1])))

    # 配置为非训练模式且已有model文件时进行样本评估
    connectTest = toolFunction.connectTest(config)
    detection = ModelDetection(config)
    flag = connectTest.dataTest()
    if flag == 0:
        logger.error("No data in time range above! ")
    if flag == 1:
        logger.info("Start detection processing ...")
        detection.detection()

    if config['if_update_kb']:
        detection.upload_to_kb()
        logger.info("Complete update knowledgeBase!")

    # 获取程序结束时间
    endTime = datetime.datetime.now(tz=pytz.timezone(timeZone)).strftime("%Y-%m-%d %H:%M:%S")
