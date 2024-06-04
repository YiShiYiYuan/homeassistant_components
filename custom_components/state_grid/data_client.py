"""
以下是类函数的一部分，请针对给出部分进行
1. 去掉不必要的变量赋值或中间变量，如 `n = "daily"`，代码中直接使用 `"daily"`，去掉冗余的中间变量 `n`
2. 变量命名可阅读性的修改，，
3. 不修改逻辑，不补全代码。代码：
"""

import datetime
import json
import time
import urllib.parse

import aiohttp

from .utils.crypt import d, decrypt_cbc, e, encrypt_cbc, hash_data
from .utils.logger import LOGGER
from .utils.store import async_save_to_store

appKey = "3def6c365d284881bf1a9b2b502ee68c"
appSecret = "ab7357dae64944a197ace37398897f64"
configuration = {
    "uscInfo": {
        "member": "0902",
        "devciceIp": "",
        "devciceId": "",
        "tenant": "state_grid",
    },
    "source": "SGAPP",
    "target": "32101",
    "channelCode": "0902",
    "channelNo": "0902",
    "toPublish": "01",
    "siteId": "2012000000033700",
    "srvCode": "",
    "serialNo": "",
    "funcCode": "",
    "serviceCode": {
        "order": "0101154",
        "uploadPic": "0101296",
        "pauseSCode": "0101250",
        "pauseTCode": "0101251",
        "listconsumers": "0101093",
        "messageList": "0101343",
        "submit": "0101003",
        "sbcMsg": "0101210",
        "powercut": "0104514",
        "BkAuth01": "f15",
        "BkAuth02": "f18",
        "BkAuth03": "f02",
        "BkAuth04": "f17",
        "BkAuth05": "f05",
        "BkAuth06": "f16",
        "BkAuth07": "f01",
        "BkAuth08": "f03",
    },
    "electricityArchives": {"servicecode": "0104505", "source": "0902"},
    "subscriptionList": {
        "srvCode": "APP_SGPMS_05_030",
        "serialNo": "22",
        "channelCode": "0902",
        "funcCode": "22",
        "target": "-1",
    },
    "userInformation": {"serviceCode": "01008183", "source": "SGAPP"},
    "userInform": {"serviceCode": "0101183", "source": "SGAPP"},
    "elesum": {
        "channelCode": "0902",
        "funcCode": "WEBALIPAY_01",
        "promotCode": "1",
        "promotType": "1",
        "serviceCode": "0101143",
        "source": "app",
    },
    "account": {"channelCode": "0902", "funcCode": "WEBA1007200"},
    "doorNumberManeger": {
        "source": "0902",
        "target": "-1",
        "channelCode": "09",
        "channelNo": "09",
        "serviceCode": "01010049",
        "funcCode": "WEBA40050000",
        "uscInfo": {
            "member": "0902",
            "devciceIp": "",
            "devciceId": "",
            "tenant": "state_grid",
        },
    },
    "doorAuth": {"source": "SGAPP", "serviceCode": "f04"},
    "xinZ": {
        "serCat": "101",
        "jM_busiTypeCode": "101",
        "fJ_busiTypeCode": "102",
        "jM_custType": "03",
        "fJ_custType": "02",
        "serviceType": "01",
        "subBusiTypeCode": "",
        "funcCode": "WEBA10070700",
        "order": "0101154",
        "source": "SGAPP",
        "querytypeCode": "1",
    },
    "onedo": {
        "serviceCode": "0101046",
        "source": "SGAPP",
        "funcCode": "WEBA10070700",
        "queryType": "03",
    },
    "xinHuTongDian": {
        "serCat": "110",
        "busiTypeCode": "211",
        "subBusiTypeCode": "21102",
        "funcCode": "WEBA10071200",
        "channelCode": "0902",
        "source": "09",
        "serviceCode": "0101183",
    },
    "company": {
        "serCat": "104",
        "funcCode": "WEBA10070700",
        "serviceType": "02",
        "querytypeCode": "1",
        "authFlag": "1",
        "source": "SGAPP",
        "order": "0101154",
    },
    "charge": {
        "channelCode": "09",
        "funcCode": "WEBA10071300",
        "channelNo": "0901",
        "serCat": "102",
        "jM_custType": "01",
        "jM_busiTypeCode": "102",
    },
    "other": {
        "channelCode": "09",
        "funcCode": "WEBA10079700",
        "serCat": "129",
        "busiTypeCode": "999",
        "subBusiTypeCode": "21501",
        "serviceCode": "BCP_000026",
        "srvCode": "",
        "serialNo": "",
    },
    "vatchange": {
        "submit": "0101003",
        "busiTypeCode": "320",
        "subBusiTypeCode": "",
        "serCat": "115",
        "funcCode": "WEBA10074000",
        "authFlag": "1",
    },
    "bill": {
        "clearCache": "1",
        "funcCode": "WEBALIPAY_01",
        "promotType": "1",
        "serviceCode": "BCP_000026",
    },
    "stepelect": {
        "channelCode": "0902",
        "funcCode": "WEBALIPAY_01",
        "promotType": "1",
        "clearCache": "09",
        "serviceCode": "BCP_000026",
        "source": "app",
    },
    "getday": {
        "channelCode": "0902",
        "clearCache": "11",
        "funcCode": "WEBALIPAY_01",
        "promotCode": "1",
        "promotType": "1",
        "serviceCode": "BCP_000026",
        "source": "app",
    },
    "mouthOut": {
        "channelCode": "0902",
        "clearCache": "11",
        "funcCode": "WEBALIPAY_01",
        "promotCode": "1",
        "promotType": "1",
        "serviceCode": "BCP_000026",
        "source": "app",
    },
    "meter": {
        "serCat": "114",
        "busiTypeCode": "304",
        "funcCode": "WEBA10071000",
        "subBusiTypeCode": "",
        "serviceCode": "0101046",
        "serialNo": "",
    },
    "complaint": {
        "busiTypeCode": "005",
        "srvMode": "0902",
        "anonymousFlag": "0",
        "replyMode": "01",
        "retvisitFlag": "01",
    },
    "report": {"busiTypeCode": "006"},
    "tradewinds": {"busiTypeCode": "019"},
    "somesay": {"busiTypeCode": "091"},
    "faultrepair": {
        "funcCode": "WEBA10070900",
        "serviceCode": "0101183",
        "serCat": "111",
        "busiTypeCode": "001",
        "subBusiTypeCode": "21505",
    },
    "electronicInvoice": {"serCat": "105", "busiTypeCode": "0"},
    "rename": {
        "serviceCode": "0101046",
        "funcCode": "WEBA10076100",
        "busiTypeCode": "210",
        "serCat": "109",
        "authFlag": "1",
        "gh_busiTypeCode": "211",
        "gh_subusi": "21101",
        "serialNo": "",
        "srvCode": "",
    },
    "pause": {
        "subBusiTypeCode": "",
        "serviceCode": "01010049",
        "funcCode": "WEBA10073600",
        "serCat": "107",
        "busiTypeCode": "203",
        "jr_busi": "201",
        "serialNo": "",
        "srvCode": "",
    },
    "capacityRecovery": {
        "serviceCode": "01010049",
        "source": "SGAPP",
        "srvCode": "",
        "serialNo": "",
        "funcCode": "WEBA10073700",
        "busiTypeCode_stop": "204",
        "busiTypeCode_less": "202",
        "busiTypeCode": "202",
        "subBusiTypeCode": "",
        "serCat": "108",
        "timeDay": "5",
        "authFlag": "1",
    },
    "electricityPriceChange": {
        "serviceCode": "0101183",
        "busiTypeCode": "215",
        "subBusiTypeCode": "21502",
        "serCat": "113",
        "authFlag": "1",
        "timeDay": "15",
        "funcCode": "WEBA10073900WEB",
        "srvCode": "",
        "serialNo": "",
    },
    "electricityPriceStrategyChange": {
        "serviceCode": "01008183",
        "busiTypeCode": "215",
        "subBusiTypeCode": "21506",
        "serCat": "160",
        "funcCode": "WEBV00000517WEB",
        "srvCode": "",
        "serialNo": "",
    },
    "eemandValueAdjustment": {
        "serviceCode": "0101183",
        "srvCode": "",
        "serialNo": "",
        "serCat": "112",
        "funcCode": "WEBA10073800",
        "busiTypeCode": "215",
        "subBusiTypeCode": "21504",
        "authFlag": "1",
        "timeDay": "5",
        "getMonthServiceCode": "0101046",
    },
    "businessProgress": {
        "serviceCode": "0101183",
        "srvCode": "01",
        "funcCode": "WEB01",
    },
    "increase": {
        "source": "SGAPP",
        "serialNo": "",
        "srvCode": "",
        "serviceCode_smt": "01010049",
        "serviceCode": "0101154",
        "order": "0101154",
        "funcCode": "WEBA10070800",
        "querytypeCode": "1",
        "serCat": "106",
        "busiTypeCode": "111",
        "subBusiTypeCode": "",
    },
    "fjincrea": {
        "serCat": "105",
        "busiTypeCode": "110",
        "subBusiTypeCode": "",
        "source": "SGAPP",
        "funcCode": "WEBA10070800",
        "serialNo": "",
        "srvCode": "",
        "serviceCode_smt": "01010049",
        "serviceCode": "0101154",
        "order": "0101154",
        "querytypeCode": "1",
    },
    "persIncrea": {
        "serCat": "105",
        "busiTypeCode": "109",
        "order": "0101154",
        "subBusiTypeCode": "",
        "source": "SGAPP",
        "funcCode": "WEBA10070800",
        "querytypeCode": "1",
    },
    "fgdChange": {
        "serviceCode": "0101183",
        "srvCode": "01",
        "channelCode": "09",
        "funcCode": "WEBA10070900",
        "busiTypeCode": "215",
        "subBusiTypeCode": "21505",
        "serCat": "111",
        "authFlag": "1",
    },
    "createOrder": {
        "channelCode": "0902",
        "funcCode": "WEBALIPAY_01",
        "srvCode": "BCP_000001",
        "chargeMode": "02",
        "conType": "01",
        "bizTypeId": "BT_ELEC",
    },
    "largePopulation": {
        "busiTypeCode": "383",
        "funcCode": "WEBA10076800",
        "subBusiTypeCode": "",
        "srvCode": "",
        "promotType": "",
        "promotCode": "",
        "channelCode": "0901",
        "serCat": "383",
        "serviceCode": "",
        "serialNo": "",
    },
    "biaoJiCode": {"serviceCode": "0104507", "source": "1704", "channelCode": "1704"},
    "twoGuar": {
        "busiTypeCode": "402",
        "subBusiTypeCode": "40201",
        "funcCode": "web_twoGuar",
    },
    "electTrend": {"serviceCode": "BCP_00026", "channelCode": "0902"},
    "emergency": {
        "serviceCode": "BCP_00026",
        "funcCode": "A10000000",
        "channelCode": "0902",
    },
    "infoPublic": {"serviceCode": "2545454", "source": "app"},
}
baseApi = "https://www.95598.cn/api"
get_request_key_api = "/oauth2/outer/c02/f02"
get_qr_code_api = "/osg-open-uc0001/member/c8/f24"
get_qr_code_status_api = "/osg-web0004/open/c50/f02"
get_qr_code_token_api = "/osg-uc0013/member/c4/f04"
send_code_api = "/osg-open-uc0001/member/c8/f04"
code_login_api = "/osg-uc0013/member/c4/f02"
getCertificationApi = "/osg-open-uc0001/member/c8/f11"
get_request_authorize_api = "/oauth2/oauth/authorize"
get_web_token_api = "/oauth2/outer/getWebToken"
refresh_web_token_api = "/oauth2/outer/refresh_web_token"
get_door_number_api = "/osg-open-uc0001/member/c9/f02"
get_door_balance_api = "/osg-open-bc0001/member/c05/f01"
get_door_bill_api = "/osg-open-bc0001/member/c01/f02"
get_door_ladder_api = "/osg-open-bc0001/member/c04/f03"
getJiaoFeiRecordApi = "/osg-web0004/member/c24/f01"
get_door_daily_bill_api = "/osg-web0004/member/c24/f01"
sessionIdControlApiList = [
    get_qr_code_api,
    get_qr_code_status_api,
    get_qr_code_token_api,
    send_code_api,
    code_login_api,
]
keyCodeControlApiList = [
    get_qr_code_status_api,
    get_qr_code_token_api,
    send_code_api,
    code_login_api,
    getCertificationApi,
    get_request_authorize_api,
    get_web_token_api,
    refresh_web_token_api,
    get_door_number_api,
    get_door_balance_api,
    get_door_bill_api,
    get_door_ladder_api,
    getJiaoFeiRecordApi,
    get_door_daily_bill_api,
]
authControlApiList = [
    get_door_number_api,
    get_door_balance_api,
    get_door_bill_api,
    get_door_ladder_api,
    getJiaoFeiRecordApi,
    get_door_daily_bill_api,
]
tControlApiList = [
    getCertificationApi,
    get_door_balance_api,
    get_door_bill_api,
    get_door_ladder_api,
    getJiaoFeiRecordApi,
    get_door_daily_bill_api,
]


def json_dumps(data):
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


def catchFloat(data, key):
    if key in data:
        try:
            return float(data[key])
        except:
            return 0
    else:
        return 0


class StateGridDataClient:
    hass = None
    session = None
    keyCode = None
    publicKey = None
    need_login = False
    phone = None
    codeKey = None
    serialNo = None
    qrCodeSerial = None
    userInfo = None
    accountInfo = None
    powerUserList = None
    doorAccountDict = {}
    cookie = []
    timestamp = 0
    accessToken = None
    refreshToken = None
    token = None
    expirationDate = None
    refresh_interval = 12
    is_debug = False

    def __init__(self, hass, config=None):
        self.hass = hass
        self.session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(quote_cookie=True),
            connector=aiohttp.TCPConnector(ssl=False),
        )
        if config is not None:
            try:
                self.keyCode = config["keyCode"]
                self.publicKey = config["publicKey"]
                self.accessToken = config["accessToken"]
                self.refreshToken = config["refreshToken"]
                self.token = config["token"]
                self.userInfo = config["userInfo"]
                self.powerUserList = config["powerUserList"]
                self.doorAccountDict = config["doorAccountDict"]
                self.refresh_interval = config["refresh_interval"]
                self.is_debug = config["is_debug"]
                LOGGER.warn(json.dumps(config))
            except Exception as E:
                LOGGER.error(E)

    async def save_data(self):
        data = {}
        data["keyCode"] = self.keyCode
        data["publicKey"] = self.publicKey
        data["accessToken"] = self.accessToken
        data["refreshToken"] = self.refreshToken
        data["token"] = self.token
        data["userInfo"] = self.userInfo
        data["powerUserList"] = self.powerUserList
        data["doorAccountDict"] = self.doorAccountDict
        data["refresh_interval"] = self.refresh_interval
        data["is_debug"] = self.is_debug
        # TODO:
        await async_save_to_store(self.hass, "state_grid.config", data)

    def encrypt_post_data(self, data):
        payload = {
            "_access_token": self.accessToken[len(self.accessToken) // 2 :] if self.accessToken else "",
            "state_grid": self.token[len(self.token) // 2 :] if self.token else "",
            "_data": data,
            "timestamp": self.timestamp,
        }
        return self.encrypt_wapper_data(payload)

    def encrypt_wapper_data(self, data):
        encrypt_value = encrypt_cbc(json_dumps(data), self.keyCode)
        return {
            "data": encrypt_value + hash_data(encrypt_value + str(self.timestamp)),
            "skey": d(self.keyCode, self.publicKey),
            "timestamp": str(self.timestamp),
        }

    def handle_request_result_message(self, api, result):
        ret = None
        if "data" in result and "srvrt" in result["data"] and "resultMessage" in result["data"]["srvrt"]:
            ret = result["data"]["srvrt"]["resultMessage"]
        elif "srvrt" in result and "resultMessage" in result["srvrt"]:
            ret = result["srvrt"]["resultMessage"]
        elif "message" in result:
            ret = result["message"]
        else:
            ret = json_dumps(result)
        if self.is_debug:
            LOGGER.error(api + ": " + ret)
            LOGGER.error(json_dumps(result))
        return ret

    async def fetch(self, api, data, header=None):
        self.timestamp = int(time.time() * 1000)
        if self.keyCode is None:
            self.keyCode = e(32, 16, 2)
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "application/json;charset=UTF-8",
            "Content-Type": "application/json;charset=UTF-8",
            "version": "1.0",
            "source": "0901",
            "timestamp": str(self.timestamp),
            "wsgwType": "web",
            "appKey": appKey,
        }
        if api == get_request_key_api:
            data = {"client_id": appKey, "client_secret": appSecret}
            H = encrypt_cbc(json_dumps(data), self.keyCode)
            data = {
                "data": H + hash_data(H + str(self.timestamp)),
                "skey": d(
                    self.keyCode,
                    "042BC7AD510BF9793B7744C8854C56A8C95DD1027EE619247A332EC6ED5B279F435A23D62441FE861F4B0C963347ECD5792F380B64CA084BE8BE41151F8B8D19C8",
                ),
                "client_id": appKey,
                "timestamp": str(self.timestamp),
            }
        elif api == get_qr_code_api:
            data = {
                "_access_token": "",
                "state_grid": "",
                "_data": data,
                "timestamp": self.timestamp,
            }
        elif api == get_request_authorize_api:
            data = {
                "client_id": appKey,
                "response_type": "code",
                "redirect_url": "/test",
                "timestamp": self.timestamp,
                "rsi": self.token,
            }
            data = urllib.parse.urlencode(data)
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
            headers["keyCode"] = self.keyCode
            async with self.session.post(baseApi + api, data=data, headers=headers) as J:
                self.session.cookie_jar.update_cookies(J.cookies)
                C = await J.json()
                C = decrypt_cbc(C["data"], self.token)
                C = json.loads(C)
                return C
        elif api == get_web_token_api:
            data = {
                "grant_type": "authorization_code",
                "sign": hash_data(appKey + str(self.timestamp)),
                "client_secret": appSecret,
                "state": "464606a4-184c-4beb-b442-2ab7761d0796",
                "key_code": self.keyCode,
                "client_id": appKey,
                "timestamp": self.timestamp,
                "code": data["code"],
            }
            encrypt_value = encrypt_cbc(json_dumps(data), self.keyCode)
            data = {
                "data": encrypt_value + hash_data(encrypt_value + str(self.timestamp)),
                "skey": d(self.keyCode, self.publicKey),
                "timestamp": str(self.timestamp),
            }
        elif api == refresh_web_token_api:
            data = {
                "grant_type": "refresh_token",
                "sign": hash_data(appKey + str(self.timestamp)),
                "client_secret": appSecret,
                "state": "464606a4-184c-4beb-b442-2ab7761d0796",
                "key_code": self.keyCode,
                "client_id": appKey,
                "timestamp": self.timestamp,
                "refresh_token": self.refreshToken,
            }
            encrypt_value = encrypt_cbc(json_dumps(data), self.keyCode)
            data = {
                "data": encrypt_value + hash_data(encrypt_value + str(self.timestamp)),
                "skey": d(self.keyCode, self.publicKey),
                "timestamp": str(self.timestamp),
            }
            api = get_web_token_api
        else:
            data = self.encrypt_post_data(data)
        if header is not None:
            headers.update(header)
        if api in sessionIdControlApiList:
            headers["sessionId"] = "web" + str(self.timestamp)
        if api in keyCodeControlApiList:
            headers["keyCode"] = self.keyCode
        if api in authControlApiList:
            headers["Authorization"] = "Bearer " + self.accessToken[: len(self.accessToken) // 2]
        if api in tControlApiList:
            headers["t"] = self.token[: len(self.token) // 2]
        async with self.session.post(baseApi + api, json=data, headers=headers) as resp:
            data = await resp.text()
            if data.startswith("{"):
                data = json.loads(data)
                if "encryptData" in data:
                    data = decrypt_cbc(data["encryptData"], self.keyCode)
                    data = json.loads(data)
            return data

    async def __get_request_key(self):
        self.keyCode = None
        resp = await self.fetch(get_request_key_api, {})
        data = self.handle_request_result_message("get_request_key_api", resp)
        if resp["code"] == "1":
            self.keyCode = resp["data"]["keyCode"]
            self.publicKey = resp["data"]["publicKey"]
            return {"errcode": 0}
        return {"errcode": 1, "errmsg": data}

    async def __get_qr_code(self):
        request_data = {
            "uscInfo": {
                "deviceIp": "",
                "tenant": "state_grid",
                "member": "0902",
                "deviceId": "",
            },
            "quInfo": {"optType": "01", "serialNo": e(28, 10, 1)},
        }
        response = await self.fetch(get_qr_code_api, request_data)
        result_message = self.handle_request_result_message("get_qr_code_api", response)
        if response["code"] == 1:
            if response["data"] and response["data"]["srvrt"] and response["data"]["srvrt"]["resultCode"] == "0000":
                self.qrCodeSerial = response["data"]["bizrt"]["qrCodeSerial"]
                qr_code = response["data"]["bizrt"]["qrCode"]
                return {"errcode": 0, "data": qr_code}
        return {"errcode": 1, "errmsg": result_message}

    async def __get_qr_code_status(self):
        request_data = {"bizrt": {"qrCodeSerial": self.qrCodeSerial}}
        headers = {"token": "98" + e(10, 10, 1)}
        response = await self.fetch(get_qr_code_status_api, request_data, headers)
        result_message = self.handle_request_result_message("get_qr_code_status_api", response)
        if "code" in response and response["code"] == 1:
            if "data" in response and response["data"] != "null":
                self.token = response["data"]
                return {"errcode": 0}
            else:
                return {"errcode": 1, "errmsg": "未使用网上国网 App 扫码或确认登录"}
        return {"errcode": 1, "errmsg": result_message}

    async def __get_qr_code_token(self):
        request_data = {
            "uscInfo": {"tenant": "state_grid", "member": "0902", "isEncrypt": True},
            "token": self.token,
        }
        response = await self.fetch(get_qr_code_token_api, request_data)
        result_message = self.handle_request_result_message("get_qr_code_token_api", response)
        if "srvrt" in response and "resultCode" in response["srvrt"] and response["srvrt"]["resultCode"] == "0000":
            self.userInfo = response["bizrt"]["userInfo"]
            return {"errcode": 0}
        return {"errcode": 1, "errmsg": result_message}

    async def __send_code(self, phone):
        self.phone = phone
        request_data = {
            "uscInfo": {
                "deviceIp": "",
                "tenant": "state_grid",
                "member": "0902",
                "deviceId": "",
            },
            "quInfo": {
                "sendType": "0",
                "account": phone,
                "businessType": "login",
                "accountType": "",
            },
            "Channels": "web",
        }
        response = await self.fetch(send_code_api, request_data)
        result_message = self.handle_request_result_message("send_code_api", response)
        if response["code"] == 1:
            if response["data"] and response["data"]["srvrt"] and response["data"]["srvrt"]["resultCode"] == "0000":
                self.codeKey = response["data"]["bizrt"]["codeKey"]
                return {"errcode": 0}
        return {"errcode": 1, "errmsg": result_message}

    async def __verify_code(self, code):
        request_data = {
            "uscInfo": {
                "deviceIp": "",
                "tenant": "state_grid",
                "member": "0902",
                "deviceId": "",
            },
            "quInfo": {
                "account": self.phone,
                "businessType": "login",
                "code": code,
                "optSys": "ios",
                "pushId": "00000",
                "codeKey": self.codeKey,
            },
            "Channels": "web",
        }
        response = await self.fetch(code_login_api, request_data)
        result_message = self.handle_request_result_message("code_login_api", response)
        if "srvrt" in response and "resultCode" in response["srvrt"] and response["srvrt"]["resultCode"] == "0000":
            self.token = response["bizrt"]["token"]
            self.userInfo = response["bizrt"]["userInfo"][0]
            return {"errcode": 0}
        return {"errcode": 1, "errmsg": result_message}

    async def __get_request_authorize(self):
        response = await self.fetch(get_request_authorize_api, {})
        result_message = self.handle_request_result_message("get_request_authorize_api", response)
        if "code" in response and response["code"] == "1":
            redirect_url = response["data"]["redirect_url"]
            code_index = redirect_url.rfind("code=")
            self.authorize_code = redirect_url[code_index + 5 : code_index + 5 + 32]
            return {"errcode": 0}
        return {"errcode": 1, "errmsg": result_message}

    async def __get_web_token(self):
        headers = {"code": self.authorize_code}
        response = await self.fetch(get_web_token_api, headers)
        result_message = self.handle_request_result_message("get_web_token_api", response)
        if "code" in response and response["code"] == "1":
            self.access_token = response["data"]["access_token"]
            self.refresh_token = response["data"]["refresh_token"]
            return {"errcode": 0}
        return {"errcode": 1, "errmsg": result_message}

    async def __refresh_web_token(self):
        response = await self.fetch(refresh_web_token_api, {})
        result_message = self.handle_request_result_message("refresh_web_token_api", response)
        if "code" in response and response["code"] == "1":
            self.access_token = response["data"]["access_token"]
            self.refresh_token = response["data"]["refresh_token"]
            return {"errcode": 0}
        return {"errcode": 1, "errmsg": result_message}

    async def __get_door_number(self):
        request_data = {
            "serviceCode": configuration["serviceCode"],
            "source": configuration["source"],
            "target": configuration["target"],
            "uscInfo": {
                "member": configuration["doorNumberManeger"]["uscInfo"]["member"],
                "devciceIp": configuration["doorNumberManeger"]["uscInfo"]["devciceIp"],
                "devciceId": configuration["doorNumberManeger"]["uscInfo"]["devciceId"],
                "tenant": configuration["doorNumberManeger"]["uscInfo"]["tenant"],
            },
            "quInfo": {"userId": self.userInfo["userId"]},
            "token": self.token,
        }
        response = await self.fetch(get_door_number_api, request_data)
        result_message = self.handle_request_result_message("get_door_number_api", response)
        if "code" in response and response["code"] == 1 and "data" in response and "bizrt" in response["data"]:
            self.power_user_list = response["data"]["bizrt"]["powerUserList"]
            return {"errcode": 0}
        return {"errcode": 1, "errmsg": result_message}

    async def __get_door_balance(self, door_account):
        data = {
            "data": {
                "srvCode": "",
                "serialNo": "",
                "channelCode": configuration["account"]["channelCode"],
                "funcCode": configuration["account"]["funcCode"],
                "acctId": self.userInfo["userId"],
                "userName": self.userInfo["loginAccount"],
                "promotType": "1",
                "promotCode": "1",
                "userAccountId": self.userInfo["userId"],
                "list": [
                    {
                        "consNoSrc": door_account["consNo_dst"],
                        "proCode": door_account["proNo"],
                        "sceneType": door_account["constType"],
                        "consNo": door_account["consNo"],
                        "orgNo": door_account["orgNo"],
                    }
                ],
            },
            "serviceCode": "0101143",
            "source": configuration["source"],
            "target": door_account["proNo"],
        }
        response = await self.fetch(get_door_balance_api, data)
        self.handle_request_result_message("get_door_balance_api", response)
        if "code" in response and response["code"] == 1 and "data" in response and "list" in response["data"]:
            account_balance_list = response["data"]["list"]
            if len(account_balance_list) != 0:
                door_account["accountBalance"] = account_balance_list[0]

    async def __get_door_bill(self, door_account, year):
        request_data = {
            "data": {
                "acctId": self.userInfo["userId"],
                "channelCode": configuration["channelCode"],
                "clearCache": "11",
                "consType": door_account["constType"],
                "funcCode": "ALIPAY_01",
                "orgNo": door_account["orgNo"],
                "proCode": door_account["proNo"],
                "promotCode": "1",
                "promotType": "1",
                "serialNo": "",
                "srvCode": "",
                "userName": "",
                "provinceCode": door_account["proNo"],
                "userAccountId": self.userInfo["userId"],
                "consNo": door_account["consNo"],
                "queryYear": year,
            },
            "serviceCode": "BCP_000026",
            "source": "app",
            "target": door_account["proNo"],
        }
        response = await self.fetch(get_door_bill_api, request_data)
        self.handle_request_result_message("get_door_bill_api", response)
        if "code" in response and response["code"] == 1 and "data" in response:
            if "dataInfo" in response["data"]:
                door_account["yearTotalCost"] = response["data"]["dataInfo"]
            if "mothEleList" in response["data"]:
                door_account["monthBillList"] = response["data"]["mothEleList"]
                door_account["latestBillMonth"] = response["data"]["mothEleList"][-1]["month"]

    async def __get_door_ladder(self, door_account, month):
        request_data = {
            "data": {
                "channelCode": configuration["stepelect"]["channelCode"],
                "funcCode": configuration["stepelect"]["funcCode"],
                "promotType": configuration["stepelect"]["promotType"],
                "clearCache": configuration["stepelect"]["clearCache"],
                "consNo": door_account["consNo_dst"],
                "promotCode": door_account["proNo"],
                "orgNo": door_account["orgNo"],
                "queryDate": month,
                "provinceCode": door_account["proNo"],
                "consType": door_account["constType"],
                "userAccountId": self.userInfo["userId"],
                "serialNo": "",
                "srvCode": "",
                "userName": self.userInfo["loginAccount"],
                "acctId": self.userInfo["userId"],
            },
            "serviceCode": configuration["stepelect"]["serviceCode"],
            "source": configuration["stepelect"]["source"],
            "target": door_account["proNo"],
        }
        response = await self.fetch(get_door_ladder_api, request_data)
        result_message = self.handle_request_result_message("get_door_ladder_api", response)
        if "code" in response and response["code"] == 1 and "data" in response and "list" in response["data"]:
            ladder_list = response["data"]["list"]
            if len(ladder_list) != 0:
                ladder_data = ladder_list[0]
                ladder_data["month"] = month
                door_account["ladder_flag"] = 1 if ladder_data["electricParticulars"]["levelFlag"] == "2" else 0
                self.doorAccountDict[door_account["consNo_dst"]]["ladder"] = ladder_data

    async def __get_door_daily_bill(self, door_account, year, start_date, end_date):
        request_data = {
            "params1": {
                "serviceCode": configuration["serviceCode"],
                "source": configuration["source"],
                "target": configuration["target"],
                "uscInfo": {
                    "member": configuration["uscInfo"]["member"],
                    "devciceIp": configuration["uscInfo"]["devciceIp"],
                    "devciceId": configuration["uscInfo"]["devciceId"],
                    "tenant": configuration["uscInfo"]["tenant"],
                },
                "quInfo": {"userId": self.userInfo["userId"]},
                "token": self.token,
            },
            "params3": {
                "data": {
                    "acctId": self.userInfo["userId"],
                    "consNo": door_account["consNo_dst"],
                    "consType": "01",
                    "endTime": end_date,
                    "orgNo": door_account["orgNo"],
                    "queryYear": year,
                    "proCode": door_account["proNo"],
                    "serialNo": "",
                    "srvCode": "",
                    "startTime": start_date,
                    "userName": self.userInfo["loginAccount"],
                    "funcCode": configuration["getday"]["funcCode"],
                    "channelCode": configuration["getday"]["channelCode"],
                    "clearCache": configuration["getday"]["clearCache"],
                    "promotCode": configuration["getday"]["promotCode"],
                    "promotType": configuration["getday"]["promotType"],
                },
                "serviceCode": configuration["getday"]["serviceCode"],
                "source": configuration["getday"]["source"],
                "target": door_account["proNo"],
            },
            "params4": "010103",
        }
        response = await self.fetch(get_door_daily_bill_api, request_data)
        result_message = self.handle_request_result_message("get_door_daily_bill_api", response)
        if "code" in response and response["code"] == 1 and "data" in response and "sevenEleList" in response["data"]:
            door_account["daily_bill_list"] = response["data"]["sevenEleList"]

    async def __get_door_pay_record(self, door_account):
        request_data = {
            "params1": {
                "serviceCode": configuration["serviceCode"],
                "source": configuration["source"],
                "target": configuration["target"],
                "uscInfo": {
                    "member": configuration["uscInfo"]["member"],
                    "devciceIp": configuration["uscInfo"]["devciceIp"],
                    "devciceId": configuration["uscInfo"]["devciceId"],
                    "tenant": configuration["uscInfo"]["tenant"],
                },
                "quInfo": {"userId": self.userInfo["userId"]},
                "token": self.token,
            },
            "params3": {
                "data": {
                    "acctId": self.userInfo["userId"],
                    "bgnPayDate": "2023-04-24",
                    "channelCode": configuration["channelCode"],
                    "consNo": door_account["consNo_dst"],
                    "endPayDate": "2024-04-24",
                    "funcCode": "webALIPAY_01",
                    "number": 100,
                    "orgNo": door_account["orgNo"],
                    "page": "1",
                    "proCode": door_account["proNo"],
                    "promotCode": "1",
                    "promotType": "1",
                    "serialNo": "",
                    "srvCode": "",
                    "userName": self.userInfo["loginAccount"],
                },
                "serviceCode": "0101051",
                "source": "01",
                "target": door_account["proNo"],
            },
            "params4": "010104",
        }
        await self.fetch(getJiaoFeiRecordApi, request_data)

    async def get_qr_code(self):
        response = await self.__get_request_key()
        if "errcode" in response and response["errcode"] != 0:
            return response
        return await self.__get_qr_code()

    async def check_qr_code(self):
        response = await self.__get_qr_code_status()
        if "errcode" in response and response["errcode"] != 0:
            return response
        response = await self.__get_qr_code_token()
        if "errcode" in response and response["errcode"] != 0:
            return response
        return await self.__get_token()

    async def send_phone_code(self, phone):
        response = await self.__get_request_key()
        if "errcode" in response and response["errcode"] != 0:
            return response
        return await self.__send_code(phone)

    async def verify_phone_code(self, code):
        response = await self.__verify_code(code)
        if "errcode" in response and response["errcode"] != 0:
            return response
        return await self.__get_token()

    async def __get_token(self):
        response = await self.__get_request_key()
        if "errcode" in response and response["errcode"] != 0:
            return response
        response = await self.__get_request_authorize()
        if "errcode" in response and response["errcode"] != 0:
            return response
        response = await self.__get_web_token()
        if "errcode" in response and response["errcode"] != 0:
            return response
        response = await self.__get_door_number()
        if "errcode" in response and response["errcode"] != 0:
            return response
        self.need_login = False
        await self.save_data()
        return {"errcode": 0, "data": self.powerUserList}

    async def refresh_data(self, setup=False):
        if self.need_login is True:
            LOGGER.error("国家电网需要重新登录！")
            return

        # 在早上 CST 7:25～7:50 之间尝试，同时检查上次更新时间，避免重复执行
        now = datetime.datetime.now(datetime.UTC)
        is_scheduler_morning = now.hour == 23 and 25 <= now.minute < 50 and int(time.time() * 1000) - timestamp > 3600 * 1000
        is_intervel = int(time.time() * 1000) - self.timestamp > self.refresh_interval * 3600 * 1000
        LOGGER.debug(f"now: {now}, setup: {setup}, last update: {self.timestamp/1000:.3f} debug info.")
        should_refresh = setup or is_scheduler_morning  # setup or is_scheduler_morning
        if not should_refresh:
            LOGGER.debug(f"now: {now}, last update: {self.timestamp/1000:.3f} skip refresh")
            return
        door_number_response = await self.__get_door_number()
        if "errcode" in door_number_response and door_number_response["errcode"] != 0:
            LOGGER.warning("刷新 Token")
            request_key_response = await self.__get_request_key()
            if "errcode" in request_key_response and request_key_response["errcode"] != 0:
                return
            refresh_token_response = await self.__refresh_web_token()
            if "errcode" in refresh_token_response and refresh_token_response["errcode"] == 0:
                await self.save_data()
            else:
                self.need_login = True
                LOGGER.error("刷新 Token 失败")
                return
            door_number_response = await self.__get_door_number()
            if "errcode" in door_number_response and door_number_response["errcode"] != 0:
                self.need_login = True
                LOGGER.error("重新请求失败")
                return
        now = datetime.datetime.now()
        yesterday = now - datetime.timedelta(days=1)
        yesterday_str = f"{yesterday.year}-{yesterday.month:02d}-{yesterday.day:02d}"
        forty_days_ago = yesterday - datetime.timedelta(days=40)
        forty_days_ago_str = f"{forty_days_ago.year}-{forty_days_ago.month:02d}-{forty_days_ago.day:02d}"
        for user in self.powerUserList:
            cons_no_dst = user["consNo_dst"]
            self.doorAccountDict[cons_no_dst] = user
            await self.__get_door_balance(user)
            await self.__get_door_daily_bill(user, now.year, forty_days_ago_str, yesterday_str)
            latest_daily_bill = user["daily_bill_list"][0]
            try:
                float(latest_daily_bill["dayElePq"])
            except:
                user["daily_bill_list"].pop(0)
            latest_daily_bill = user["daily_bill_list"][0]
            latest_bill_date = datetime.datetime.strptime(latest_daily_bill["day"], "%Y%m%d")
            month_total = 0
            p_total = 0
            v_total = 0
            n_total = 0
            t_total = 0
            for bill in user["daily_bill_list"]:
                bill_date = datetime.datetime.strptime(bill["day"], "%Y%m%d")
                if bill_date.month != latest_bill_date.month:
                    break
                month_total += catchFloat(bill, "dayElePq")
                p_total += catchFloat(bill, "thisPPq")
                v_total += catchFloat(bill, "thisVPq")
                n_total += catchFloat(bill, "thisNPq")
                t_total += catchFloat(bill, "thisTPq")
            prev_month = latest_bill_date - datetime.timedelta(days=latest_bill_date.day)
            prev_month_str = f"{prev_month.year}-{prev_month.month:02d}"
            if "latestBillMonth" not in user or user["latestBillMonth"] != prev_month_str:
                await self.__get_door_bill(user, prev_month.year)
                await self.__get_door_ladder(user, prev_month_str)
            latest_bill_month_date = datetime.datetime.strptime(user["latestBillMonth"], "%Y%m")
            if latest_bill_month_date.month == 12:
                year_total = 0
                for bill in user["daily_bill_list"]:
                    bill_date = datetime.datetime.strptime(bill["day"], "%Y%m%d")
                    if bill_date.month != 12:
                        break
                    year_total += catchFloat(bill, "dayElePq")
            else:
                year_total = 0
                for month_bill in user["monthBillList"]:
                    year_total += catchFloat(month_bill, "monthEleNum")
                total_months = len(user["monthBillList"])
                for bill in user["daily_bill_list"]:
                    bill_date = datetime.datetime.strptime(bill["day"], "%Y%m%d")
                    if bill_date.month <= total_months:
                        break
                    year_total += catchFloat(bill, "dayElePq")
            if year_total <= 2760:
                user["ladder_level"] = "第一阶梯"
                user["ladder_level_num"] = 1
            elif year_total <= 4800:
                user["ladder_level"] = "第二阶梯"
                user["ladder_level_num"] = 2
            else:
                user["ladder_level"] = "第三阶梯"
                user["ladder_level_num"] = 3
            if "accountBalance" in user:
                esti_amt = catchFloat(user["accountBalance"], "estiAmt")
                prepay_bal = catchFloat(user["accountBalance"], "prepayBal")
                sum_money = catchFloat(user["accountBalance"], "sumMoney")
                if prepay_bal == 0:
                    user["balance"] = sum_money
                else:
                    user["balance"] = prepay_bal - esti_amt
                history_owe = catchFloat(user["accountBalance"], "historyOwe")
                if history_owe > 0:
                    user["balance"] = -history_owe
            elif "balance" not in user:
                user["balance"] = 0
            if "yearTotalCost" in user:
                user["year_ele_num"] = catchFloat(user["yearTotalCost"], "totalEleNum")
                user["year_ele_cost"] = catchFloat(user["yearTotalCost"], "totalEleCost")
            elif "year_ele_num" not in user:
                user["year_ele_num"] = 0
                user["year_ele_cost"] = 0
            if "monthBillList" in user:
                user["last_month_ele_num"] = catchFloat(user["monthBillList"][-1], "monthEleNum")
                user["last_month_ele_cost"] = catchFloat(user["monthBillList"][-1], "monthEleCost")
            elif "last_month_ele_num" not in user:
                user["last_month_ele_num"] = 0
                user["last_month_ele_cost"] = 0
            if "daily_bill_list" in user:
                user["daily_ele_num"] = catchFloat(user["daily_bill_list"][0], "dayElePq")
                user["daily_p_ele_num"] = catchFloat(user["daily_bill_list"][0], "thisPPq")
                user["daily_v_ele_num"] = catchFloat(user["daily_bill_list"][0], "thisVPq")
                user["daily_n_ele_num"] = catchFloat(user["daily_bill_list"][0], "thisNPq")
                user["daily_t_ele_num"] = catchFloat(user["daily_bill_list"][0], "thisTPq")
            elif "daily_ele_num" not in user:
                user["daily_ele_num"] = 0
                user["daily_p_ele_num"] = 0
                user["daily_v_ele_num"] = 0
                user["daily_n_ele_num"] = 0
                user["daily_t_ele_num"] = 0
            user["month_ele_num"] = month_total
            user["month_p_ele_num"] = p_total
            user["month_v_ele_num"] = v_total
            user["month_n_ele_num"] = n_total
            user["month_t_ele_num"] = t_total
            user["daily_lasted_date"] = f"{latest_bill_date.year}-{latest_bill_date.month:02d}-{latest_bill_date.day:02d}"
            user["refresh_time"] = datetime.datetime.strftime(now, "%Y-%m-%d %H:%M:%S")
            print(user)
        await self.save_data()

    async def get_door_account_list(self):
        return list(self.doorAccountDict.values())

    def get_door_account(self):
        return self.doorAccountDict
