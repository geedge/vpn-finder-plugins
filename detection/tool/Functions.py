'''
Description:
Author: chenxu
Date: 2022-03-31 15:15:09
LastEditTime: 2022-09-29 10:59:11
LastEditors: yinjiangyi
'''
import datetime
import os
import re
import shutil

import pytz
import yaml
import struct
import socket
import ipaddress
import numpy as np
import pandas as pd

from clickhouse_driver import Client



'''
Description: 判断文件是否存在
Param : 文件路径
Return: 
'''


def fileExists(readfilePath):
    if os.path.exists(readfilePath):
        return True
    else:
        return False


'''
Description: 读文件
Param : 
Return: 
param {*} readfilePath
'''


def readTxt(readfilePath):
    with open(readfilePath) as file:
        lines = file.readlines()
        listStr = list()
        for line in lines:
            listStr.append("".join(line.split()))

    return listStr


'''
Description: 写文件
Param : 
Return: 
param {*} writeFilePath
param {*} content
'''


def write(writeFilePath, content):
    with open(writeFilePath, 'a') as file:
        for item in content:
            file.write("".join(item))
        file.write('\n')
    try:
        pass
    except BaseException as e:
        pass


'''
Description: 文件内容清空
Param : 
Return: 
param {*} writeFilePath
'''


def clear(writeFilePath):
    file = open(writeFilePath, 'w')
    file.closed


def clear_dir(dir_path, git_keep=False):
    shutil.rmtree(dir_path)
    os.mkdir(dir_path)
    if git_keep:
        open(dir_path + "/.gitkeep", 'a').close()


'''
    Description: 判断域名是否合法
    Param : 域名
    Return: 合法True,不合法False
'''


def is_valid_domain(domain):
    pattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
    )
    return True if pattern.match(domain) else False


'''
    Description: 判断域名中的非域名个数
    Param : 域名
    Return: 非域名个数比例
'''


def isNotDomain(hostList):
    isNotdomainNum = 0
    for item in hostList:
        item = item.split(':')[0]
        if is_valid_domain(item) == False:
            isNotdomainNum = isNotdomainNum + 1
    if len(hostList) > 0:
        return isNotdomainNum / len(hostList)

    return 0


'''
    Description: 判断域名中的www&>17&word>=3域名个数 
    Param : 域名
    Return: 非域名个数比例
'''


def wwwDomain(hostList):
    pattern = re.compile(r'(www)\.([a-zA-Z]{5,25})\.(com)')
    cnt = 0
    for item in hostList:
        if is_valid_domain(item) and pattern.match(item) and len(item) >= 17:
            cnt = cnt + 1
    if len(hostList) > 0:
        return cnt / len(hostList)

    return 0


def readYaml(path):
    file = open(path, encoding="utf-8")
    data = yaml.safe_load(file)
    file.close()
    return data


"""
    将列表拆分为指定长度的多个列表
    :param lists: 初始列表
    :param cut_len: 每个列表的长度
    :return: 一个二维数组 [[x,x],[x,x]]
    """


def cut_list(lists, cut_len):
    res_data = []
    if len(lists) > cut_len:
        for i in range(int(len(lists) / cut_len)):
            cut_a = lists[cut_len * i:cut_len * (i + 1)]
            res_data.append(cut_a)

        last_data = lists[int(len(lists) / cut_len) * cut_len:]
        if last_data:
            res_data.append(last_data)
    else:
        res_data.append(lists)

    return res_data


'''
Description: 数据库查询
Param : ip
Return: ip地理位置
'''


def queryIpDatabase(reader, ip, type):
    # reader = awdb.open_database(path)
    (record, prefix_len) = reader.get_with_prefix_len(ip)
    if type == 'isp':
        return bytes.decode(record.get('owner'))
    if type == 'country':
        return bytes.decode(record.get('areacode'))


'''
Description: 厂商匹配查询
Param : isp name
Return: 匹配结果
'''


def ipReputation(providerStr):
    providerList = ['IONOS SE', 'M247 Ltd', 'AltusHost B.V.', 'Packet Exchange Limited', 'Orion Network Limited',
                    'DigitalOcean, LLC', 'Greenhost BV', 'UK-2 Limited', 'RouteLabel V.O.F.', 'InMotion Hosting, Inc.',
                    'ONLINE S.A.S.', 'Linode, LLC', 'Hosting Services, Inc.', 'Performive LLC']
    for item in providerList:
        if item in providerStr or providerStr in item:
            return 1
    return 0


'''
Description: 国家匹配
Param : country
Return: 匹配结果
'''


def ipCountry(Country):
    if Country == 'ET':
        return 1
    return 0


'''
Description: 查询sip是否属于目标ISP
Param : 
Return: 属于返回True,否则返回False
param {str} ip_address
'''


def queryipBlock(data, ip):
    intIp = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ip)))[0])
    for index, row in data.iterrows():
        if intIp > row['maxip'] or intIp < row['minip']:
            continue
        if intIp > row['minip'] and intIp < row['maxip']:
            return True
    return False


# '''
# Description: 根据spur结果收集ISP名称
# Param :
# Return:
# '''
# def collectIspName():
#     reader = awdb.open_database('developerKits/IP_city_single_WGS84.awdb')
#     spurLabel = pd.read_csv("externalTest/data/spur.csv",names=['ip','label'])
#     spurVPNip = list()
#     for index,row in spurLabel.iterrows():
#         if row['label']!='0':
#             spurVPNip.append(queryIpDatabase(reader,row['ip'],'isp'))
#     print(Counter(spurVPNip))


'''
Description: 文件去重
Param : 
Return: 
'''


def duplicateRemoval(readDir, writeDir):
    lines_seen = set()
    outfile = open(writeDir, "w")
    f = open(readDir, "r")
    for line in f:
        if line not in lines_seen:
            outfile.write(line)
            lines_seen.add(line)
    outfile.close()


'''
Description: 判断是否是内网地址
Param : 
Return: 
param {*} ip
'''


def is_lan(ip):
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except Exception as e:
        return False


def getAsnList(file_path):
    '''
    get asn list from file
    :return:
    '''
    asn_list = []
    with open(file_path) as file:
        lines = file.readlines()
        for line in lines:
            list_list = line.split(',')
            if len(list_list) >= 1:
                asn_list.extend([str(i.strip()) for i in list_list[1:]])
            else:
                pass
    return asn_list


def getFeatureList(file_path):
    features = []
    with open(file_path) as file:
        lines = file.readlines()
        for line in lines:
            features.append(line.strip())
    return features


def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def find_invalid_ip(ip_list):
    error_ip_list = []
    for ip in ip_list:
        if not is_valid_ip(ip):
            error_ip_list.append(ip)
    return error_ip_list


def filter_files_by_time_range(path, start_day, end_day, suffix='.csv'):
    # 定义一个空列表，用于保存符合条件的文件路径
    result = []

    start_day_time = datetime.datetime.strptime(start_day, '%Y-%m-%d').date()
    end_day_time = datetime.datetime.strptime(end_day, '%Y-%m-%d').date()

    # 遍历目录下所有文件，并按照创建时间进行过滤
    for root, dirs, files in os.walk(path):
        for file in files:
            # 判断文件类型是否为csv文件
            if len(suffix) > 0 and file.endswith(suffix):
                filepath = os.path.join(root, file)
                # 获取文件创建时间
                # created_time = os.path.getctime(filepath)
                created_time = os.path.getatime(filepath)
                # 将创建时间转换为日期格式
                created_date = datetime.datetime.fromtimestamp(created_time).date()
                if created_date >= start_day_time and created_date < end_day_time:
                    result.append(filepath)
        for d in dirs:
            # 对于每个子目录，递归调用该函数，并将结果列表合并
            result.extend(filter_files_by_time_range(os.path.join(root, d), start_day, end_day))

    return list(set(result))


def filter_files_by_created_time(path, days, suffix='.csv'):
    # 定义一个空列表，用于保存符合条件的文件路径
    end_day = datetime.date.today() + datetime.timedelta(days=1)
    start_day = datetime.date.today() - datetime.timedelta(days=days)

    return filter_files_by_time_range(path, start_day.strftime('%Y-%m-%d'), end_day.strftime('%Y-%m-%d'))


def delete_dir_by_create_time(path, days):
    ds = list(os.walk(path))
    delta = datetime.timedelta(days=days)
    now = datetime.datetime.now()

    for d in ds:
        os.chdir(d[0])
        if d[2]:
            for x in d[2]:
                ctime = datetime.datetime.fromtimestamp(os.path.getmtime(x))
                if ctime < (now - delta):
                    os.remove(x)
    os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))


class connectTest():
    def __init__(self, config):
        self.headTime = config['headTime']
        self.tailTime = config['tailTime']
        self.tableName = config['tableName']
        self.timeZone = config['timeZone']
        self.client = Client(user=config['username'], password=config['password'], host=config['host'],
                             port=config['port'], database=config['database'])
        self.dbname = config['database']

    def dataTest(self):
        """
        :return: 0:no data 2:wrong configuration
        """
        # 测试数据库有无数据
        try:
            # testSQL = "select * from " + self.tableName + " where (toDateTime(common_recv_time) >= '" + str(
            #     self.headTime) + "') and (toDateTime(common_recv_time) <='" + str(self.tailTime) + "') Limit 1"

            testSQL = "select * from " + self.tableName + " where common_recv_time >= toDateTime('" \
                      + str(self.headTime) + "', '" + self.timeZone + "') and common_recv_time < toDateTime('" \
                      + str(self.tailTime) + "', '" + self.timeZone + "') limit 1 "

            queryResult = self.client.execute(testSQL)

            if len(queryResult) < 1:
                # logger.error(datetime.datetime.now(tz=pytz.timezone(self.timeZone)).strftime(
                #                        "%Y-%m-%d %H:%M:%S") + '-' + str(self.headTime) + '~' + str(
                #                        self.tailTime) + ' dataTest: ' + str('No data in this time window'))
                return 0
            return 1
        except:
            return 2
            # logger.error(datetime.datetime.now(tz=pytz.timezone(self.timeZone)).strftime(
            #                        "%Y-%m-%d %H:%M:%S") + '-' + 'time: ' + str(self.headTime) + '~' + str(
            #                        self.tailTime) + ' dataTest: ' + str(
            #                        'please check database configuration in config.yaml'))


def get_project_path():
    path = os.path.join(os.getcwd())
    return path.rsplit('vpn-thwarting', 1)[0] + 'vpn-thwarting'


def cal_psi(actual, predict, bins=10):
    """
    Discription: 计算PSI值，并输出实际和预期占比分布曲线
    :param actual: Array或series，代表真实数据，如训练集模型得分
    :param predict: Array或series，代表预期数据，如测试集模型得分
    :param bins: 分段数
    :return:
        psi: float，PSI值
        psi_df:DataFrame
    """
    actual_min = actual.min()  # 实际中的最小概率
    actual_max = actual.max()  # 实际中的最大概率
    binlen = (actual_max - actual_min) / bins
    cuts = [actual_min + i * binlen for i in range(1, bins)]  # 设定分组
    cuts.insert(0, -float("inf"))
    cuts.append(float("inf"))
    actual_cuts = np.histogram(actual, bins=cuts)  # 将actual等宽分箱
    predict_cuts = np.histogram(predict, bins=cuts)  # 将predict按actual的分组等宽分箱
    actual_df = pd.DataFrame(actual_cuts[0], columns=['actual'])
    predict_df = pd.DataFrame(predict_cuts[0], columns=['predict'])
    psi_df = pd.merge(actual_df, predict_df, right_index=True, left_index=True)
    psi_df['actual_rate'] = (psi_df['actual'] + 1) / psi_df['actual'].sum()  # 计算占比，分子加1，防止计算PSI时分子分母为0
    psi_df['predict_rate'] = (psi_df['predict'] + 1) / psi_df['predict'].sum()
    psi_df['psi'] = (psi_df['actual_rate'] - psi_df['predict_rate']) * np.log(
        psi_df['actual_rate'] / psi_df['predict_rate'])
    psi = psi_df['psi'].sum()
    return psi, psi_df


def get_file_line_count(file_path):
    """
    Discription: 获取文件行数
    :param file_path: 文件路径
    :return: 文件行数
    """
    count = 0
    for index, line in enumerate(open(file_path, 'r', encoding='utf-8')):
        count += 1
    return count


def check_internet(timeout=3, servername='www.baidu.com'):
    """
    Discription: check if the internet is connected by visit a server, timeout is 3 seconds
    :return: True or False
    """
    global s
    try:
        socket.setdefaulttimeout(timeout)
        host = socket.gethostbyname(servername)
        s = socket.create_connection((host, 80), 2)
        s.close()
        return True
    except Exception as e:
        return False


def get_project_path():
    # 返回上上级目录
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))





