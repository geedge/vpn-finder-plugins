#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/7/7 10:38
# @author    : yinjinagyi
# @File    : MariadbTool.py
# @Function:

import pymysql


class MariadbUtil:

    def __init__(self, host, port, user, password, database):
        self.db = pymysql.connect(host=host,
                                  port=port,
                                  user=user,
                                  password=password,
                                  database=database)
        self.cursor = self.db.cursor()

    def query_sql(self, sql):
        """查询多条数据"""
        list_result = ()
        try:
            self.cursor.execute(sql)
            list_result = self.cursor.fetchall()
        except Exception as e:
            print(e)
        return list_result

    def insert(self, sql):
        """新增数据"""
        return self.__edit(sql)

    def update(self, sql):
        """更新数据"""
        return self.__edit(sql)

    def delete(self, sql):
        """删除数据"""
        return self.__edit(sql)

    def __edit(self, sql):
        count = 0
        try:
            count = self.cursor.execute(sql)
            self.db.commit()
        except Exception as e:
            print(e)
        return count

    def close(self):
        self.cursor.close()

