#!/usr/bin/env python3

import re
import subprocess
import time

#安全日志
logFile = '/var/log/secure'
#黑名单
hostDeny = '/etc/hosts.deny'
#封杀阈值
passwod_wrong_num = 3

#获取已经加入黑名单的ip,转换为字典
def getDenies():
    deniedDict = {}
    list = open(hostDeny).readlines()
    for ip in list:
        group = re.search(r'(\d+\.\d+\.\d+\.\d+)',ip)
        if group:
            deniedDict[group[1]] = '1'
    return deniedDict

# 监控方法
def moitorLog(logFile):
    #统计密码错误的次数
    tempIp = {}
    #已经拉黑的ip
    denieDict = getDenies()
    #读取安全日志
    popen = subprocess.Popen('tail -f' + logFile,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
    #开始监控
    while True:
        time.sleep(0.1)
        line = popen.stdout.readline().strip()
        if line:
            #出现"Failed 说明:这个用户存在，但是密码错误出现Invalid i说明:这个用户都不存在
            group = re.search(r'Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)', str(line))
            #理论上  不存在用户直接封
            if group and not denieDict.get(group[1]):
                subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(group[1], hostDeny))
                denieDict[group[1]] = '1'
                time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                print('{} --- add ip :{} to hosts.deny for invalid user'.format(time_str,group[1]))
                continue

            #用户名合法（有这个用户）密码错误
            group = re.search(r'Failed password for \w+ from (\d+\.\d+\.\d+\.\d+)', str(line))
            if group:
                ip = group[1]
                #统计ip 错误次数
                if not tempIp.get(ip):
                    tempIp[ip] = 1
                else:
                    tempIp[ip] = tempIp[ip] + 1
                #如果错误次数大于阈值的时候，直接封禁
                if tempIp[ip] > passwod_wrong_num and not denieDict.get(ip):
                    del tempIp[ip]
                    subprocess.getoutput('echo \'sshd:{}\' >> {}'.format(ip, hostDeny))
                    denieDict[ip] = '1'
                    time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    print('{} --- add ip:{} to hosts.deny for invalid password'.format(time_str, ip))
                    
if __name__ == '__main__':
    moitorLog(logFile)










