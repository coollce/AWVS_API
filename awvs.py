import requests,json,time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def create_target():
    '''
    在AWVS创建要扫描的目标，并且配置扫描速度为低速等基础条件,获取target_id
    :return:
    '''
    url='https://'+api_ip+'/api/v1/targets'
    data = {
        'address': scan_addrress,
        'description': 'fulltest',
        'criticality': 10,
    }
    resp_create=requests.post(url=url,data=json.dumps(data),headers=headers,verify=False).json()
    taget_id=resp_create['target_id']
    print('target_id={}'.format(taget_id))
    url2='https://'+api_ip+'/api/v1/targets/'+taget_id+'/configuration'
    data2={
        "scan_speed":"fast"
    }
    requests.patch(url=url2,data=json.dumps(data2),headers=headers,verify=False)
    start_scan(taget_id)


def start_scan(target_id):
    '''
    开启扫描任务，获取scan_id
    'profile_id': "11111111-1111-1111-1111-111111111112" 扫描模式为完全扫描
    :param target_id:
    :return:
    '''
    url='https://'+api_ip+'/api/v1/scans'
    data={
        'target_id': target_id,
        'profile_id': "11111111-1111-1111-1111-111111111112",
        "report_template_id": "11111111-1111-1111-1111-111111111111",
        'schedule': {"disable":False,"start_date":None,"time_sensitive":False}
    }
    resp_start=requests.post(url=url,data=json.dumps(data),headers=headers,verify=False)
    scan_id=resp_start.headers['Location'].split('/')[4]
    print('scan_id={}'.format(scan_id))
    status_scan(scan_id)

def status_scan(scan_id):
    '''
    查看任务状态，获取scan_session_id值
    :param scan_id:
    :return:
    '''
    url='https://'+api_ip+'/api/v1/scans/'+scan_id
    resp_status=requests.get(url=url,headers=headers,verify=False).json()
    status=resp_status["current_session"]["status"]
    scan_sessionid=resp_status["current_session"]["scan_session_id"]
    print('扫描状态：{}'.format(status))
    print('scan_sessionid={}'.format(scan_sessionid))
    if status =='completed':
        result_scan(scan_id,scan_sessionid)
    else:
        print('请等待15分钟--------')
        time.sleep(15*60)
        status_scan(scan_id)


def result_scan(scan_id,scan_sessionid):
    '''
    扫描完毕后查看当前扫描任务的扫描结果，获取vuln_id值
    :param scan_id:
    :param scan_sessionid:
    :return:
    '''
    url='https://'+api_ip+'/api/v1/scans/'+scan_id+'/results/'+scan_sessionid+'/vulnerabilities'
    resp_result=requests.get(url=url,headers=headers,verify=False).json()
    vulnerabilities=resp_result['vulnerabilities']
    for vuln in vulnerabilities:
        vuln_result(scan_id,scan_sessionid,vuln['vuln_id'])
    # vuln_result(scan_id,scan_sessionid,'2476136388693591114')

    # print(type(vulnerabilities),len(vulnerabilities))
    # for i in vuln_id_list:
    #     print(i)

def vuln_result(scan_id,scan_sessionid,vuln_id):
    '''
    通过vuln_id值获取漏洞的详细信息，提取每个漏洞信息中需要的字段存储到vul_list 列表中
    :param scan_id:
    :param scan_sessionid:
    :param vuln_id:
    :return:
    '''
    url='https://'+api_ip+'/api/v1/scans/'+scan_id+'/results/'+scan_sessionid+'/vulnerabilities/'+vuln_id
    resp_vuln=requests.get(url=url,headers=headers,verify=False).json()
    #测试时候随便选择几个字段，使用时候修改成需要的字段存储
    vuln_dict={"vt_name":resp_vuln['vt_name'],"status":resp_vuln['status']}

    vuln_list.append(vuln_dict)

    # print(resp_vuln['vt_name'],'\n',resp_vuln['request'])
    # pass


if __name__ == '__main__':
    #要被扫描的地址
    scan_addrress='http://testphp.vulnweb.com/'

    #AWVS服务器ip地址和端口号
    api_ip='10.51.30.63:13443'

    # api调用时候使用的header，其中主要为apikey，通过页面生成
    headers = {
        'X-Auth': '180c66b42b01646c59e92dcc1f024d7ae49fac9cbddd14be5bed243011bc1b3df',
        'Content-type': 'application/json'
    }
    vuln_list = []
    # print(start_scan('32bd6e20-034d-4067-9500-c2b1591508f5'))
    create_target()
    # status_scan('02d96910-c984-440b-9ee7-4f581d782087')
    print(vuln_list)
