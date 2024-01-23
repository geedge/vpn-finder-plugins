import argparse
import subprocess
import os
import requests
import json
import csv
import ipaddress



def get_asn_ip_ranges(asn):
    """
    Get IP ranges for a given ASN using RIPEstat API.

    Args:
    asn (str): The Autonomous System Number (ASN).

    Returns:
    list: A list of IP ranges for the given ASN.
    """
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    response = requests.get(url)
    data = response.json()

    ip_ranges = []
    if "data" in data and "prefixes" in data["data"]:
        for item in data["data"]["prefixes"]:
            ip_ranges.append(item["prefix"])
    # 创建一个空列表来存储仅 IPv4 地址
    ipv4_list = []

    for ip in ip_ranges:
        try:
            # 尝试将字符串解析为 IP 网络地址
            network = ipaddress.ip_network(ip, strict=False)
            # 检查是否为 IPv4 地址
            if type(network) is ipaddress.IPv4Network:
                ipv4_list.append(ip)
        except ValueError:
            # 如果地址无效，跳过此地址
            continue
    return ipv4_list


def run_masscan(ip_list_path, ports, rate='10000', output_path='data/tmp/masscan_output.json'):
    # 将端口列表转换为逗号分隔的字符串
    # ports = ','.join(str(port) for port in ports)

    # 设置 Masscan 命令
    masscan_cmd = [
        'masscan',
        '-p', ports,
        '--rate', rate,
        '-iL', ip_list_path,  # 使用文件路径
        '--wait', '5',
        '-oJ', output_path  # 输出为 JSON 格式
    ]

    # 执行 Masscan 扫描
    print(f"Running masscan with command: {' '.join(masscan_cmd)}")
    subprocess.run(masscan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(output_path, 'r') as file:
        data = json.load(file)
    port_ip_dict={}

    # 遍历 JSON 数据中的每个条目
    for entry in data:
        ip = entry['ip']
        for port_info in entry['ports']:
            port = port_info['port']
        # 将 IP 地址添加到对应端口的列表中
            if port in port_ip_dict:
                port_ip_dict[port].append(ip)
            else:
                port_ip_dict[port] = [ip]

    # 打印每个端口及其对应的 IP 地址
    for port, ips in port_ip_dict.items():
        print(f"Port {port}: {ips}")
    # 读取 Masscan 输出文件并解析 JSON
    #temp_output_path.unlink()
    # try:
    #     subprocess.run(['rm', output_path], check=True)
    #     print(f"The file {output_path} has been deleted.")
    # except subprocess.CalledProcessError:
    #     print(f"Failed to delete the file {output_path}.")
    #subprocess.run(f'rm {temp_output_path}')
    return port_ip_dict



def run_zgrab2(port_ip_dict, outfile, tmp_path='/tmp/'):
    # 将端口列表转换为逗号分隔的字符串
    # ports = ','.join(str(port) for port in ports)

    # 设置 Zgrab 命令
    for port, ips in port_ip_dict.items():
        with open(tmp_path+f'ips_with_{port}.txt', 'w') as file:
            for ip in ips:
                file.write(ip + '\n')
        strport=str(port)
        zgrab2_cmd = [
            'zgrab2',
            'tls',
            '-p', strport,
            '-f', tmp_path+f'ips_with_{port}.txt',
            '-o', tmp_path+f'zgrab_ips_with_{port}.json',  # 使用文件路径
        ]
        # 执行 zgrab2
        print(f"Running zgrab2 with command: {' '.join(zgrab2_cmd)}")
        result=subprocess.run(zgrab2_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # 打印输出和错误信息
        if result.stdout:
            print("ZGrab2 Output:")
            print(result.stdout.decode())
        if result.stderr:
            print("ZGrab2 Error:")
            print(result.stderr.decode())
        json2csv(port_ip_dict,tmp_path+f'zgrab_ips_with_{port}.json','./'+ outfile)
        subprocess.run(['rm',tmp_path+f'zgrab_ips_with_{port}.json'])
        subprocess.run(['rm',tmp_path+f'ips_with_{port}.txt'])



def json2csv(port_ip_dict,input_json_file,output_csv_file):
    def extract_json_objects(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            obj_str = ''  # 用于存储当前读取的 JSON 对象字符串
            depth = 0     # 用于跟踪括号深度
            for char in file.read():
                if char == '{':
                    depth += 1
                if depth > 0:
                    obj_str += char
                if char == '}':
                    depth -= 1
                    if depth == 0:
                        # 当达到闭合的大括号时，尝试解析 JSON 对象
                        try:
                            yield json.loads(obj_str)
                            obj_str = ''  # 重置字符串以用于下一个对象
                        except json.JSONDecodeError as e:
                            print(f"Error decoding JSON object: {e}")
                            # 如果出现解码错误，跳过当前对象
                            obj_str = ''

    for port, ips in port_ip_dict.items():
        # 准备 CSV 文件
        with open(output_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['ip','port',
                'cert_sha1', 'cert_serial_num', 'cert_san', 'cert_cn',
                'cert_issuer', 'cert_issuer_country', 'cert_issuer_organization',
                'cert_subject', 'cert_subject_country', 'cert_subject_organization',
                'cert_start_time', 'cert_expire_time'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for item in extract_json_objects(input_json_file):
                # 处理 json_obj

                tls_data = item.get('data', {}).get('tls', {})
                if tls_data.get('status') == 'success':
                    result = tls_data.get('result', {})
                    cert_info = result.get('handshake_log', {}).get('server_certificates', {}).get('certificate', {}).get('parsed', {})

                    # 提取所需字段
                    cert_row = {
                        'ip': item.get('ip'),
                        'port': port,
                        'cert_sha1': cert_info.get('fingerprint_sha1'),
                        'cert_serial_num': cert_info.get('serial_number'),
                        'cert_san': ','.join(cert_info.get('extensions', {}).get('subject_alt_name', {}).get('dns_names', [])),
                        'cert_cn': ','.join(cert_info.get('subject', {}).get('common_name', [])),
                        'cert_issuer': ','.join(cert_info.get('issuer', {}).get('common_name', [])),
                        'cert_issuer_country': ','.join(cert_info.get('issuer', {}).get('country', [])),
                        'cert_issuer_organization': ','.join(cert_info.get('issuer', {}).get('organization', [])),
                        'cert_subject': cert_info.get('subject_dn'),
                        'cert_subject_country': ','.join(cert_info.get('subject', {}).get('country', [])),
                        'cert_subject_organization': ','.join(cert_info.get('subject', {}).get('organization', [])),
                        'cert_start_time': cert_info.get('validity', {}).get('start'),
                        'cert_expire_time': cert_info.get('validity', {}).get('end')
                    }

                    # 写入 CSV
                    writer.writerow(cert_row)
        print(f"{output_csv_file} has been created.")


def search_ip_by_ports(ports: object, outfile: object, ip_file: object = None, asns: object = None, rate: object = 10000, port_logic='or') -> object:
    """
    Get IP with specific opening ports for a given ASN or a given file
    """
    # if ip_file is not None, get iplist from ip_file; if asns is not None, get iplist from asns; else, return error
    tmp_path = 'data/tmp/iplist.txt'
    ip_ranges = []
    if ip_file is not None:
        if not os.path.isfile(ip_file):
            print(f"IP list file not found: {ip_file}")
            exit(1)
        # 读取文件中的 IP 地址
        with open(ip_file, 'r', encoding='utf-8') as file:
            ip_ranges = file.read().splitlines()
        print("Complete getting ip ranges from file!")

    elif asns is not None:
        for asn in asns:
            ip_ranges.extend(get_asn_ip_ranges(asn))
        # 检查文件是否存在以及是否以换行符结尾
        print("Complete getting ip ranges from asn!")

    else:
        print("Please provide an IP list file or an AS number. Using parameter ip_file or asns")
        exit(1)

    # ip_ranges 保存
    with open(tmp_path, 'w', encoding='utf-8') as file:
        for ip_range in ip_ranges:
            file.write(ip_range + '\n')

    if rate:
        port_ip_dict=run_masscan(tmp_path, ports, str(rate))
    else:
        port_ip_dict=run_masscan(tmp_path, ports)

    # get values in port_ip_dict and get intersection
    selected_ip_list = []
    for port, ips in port_ip_dict.items():
        if len(selected_ip_list) == 0:
            selected_ip_list = ips
            continue
        else:
            if port_logic == 'and':
                selected_ip_list = set(selected_ip_list).intersection(ips)
            elif port_logic == 'or':
                selected_ip_list = set(selected_ip_list).union(ips)
    selected_ip_list = list(selected_ip_list)

    if outfile is not None:
        # 创建文件并保存
        with open(outfile, 'w', encoding='utf-8') as file:
            for ip in selected_ip_list:
                file.write(ip + '\n')

    return selected_ip_list





if __name__ == '__main__':
    ip_filtered_by_ports = search_ip_by_ports(ports='554, 22, 53', port_logic='or', asns=['14061'], outfile='data/tmp/filtered_ip.csv', rate='5000')