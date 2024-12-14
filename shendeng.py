import base64
import random
from urllib.parse import quote
import datetime
import json
import time
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os


# 生成随机MAC地址作为设备ID
def randomMac():
    macstring = "0123456789ABCDEF" * 12
    macstringlist = random.sample(macstring,12)
    return "{0[0]}{0[1]}:{0[2]}{0[3]}:{0[4]}{0[5]}:{0[6]}{0[7]}:{0[8]}{0[9]}:{0[10]}{0[11]}".format(macstringlist)



class Account:
    def __init__(self):
        self.token = ""
        self.deviceId = ""
        self.expireTime = 0
        self.vip_expire_time = 0

class WireGuardRoute:
    def __init__(self):
        # 自己电脑上的公私钥可以用wireguard的wg命令生成
        self.my_privateKey = "yC+fbNtxWG0+RxdccdF1+5NVEzk5rvfDCa0T1SMp7W0="
        self.my_publicKey = "U50FTaD71Z5kDmArmE7se+PVfV7496fd3faswVdUZ1M="

        self.peerIp = ""
        self.peerPublicKey = ""
        self.allowIps = ""




myAccount = Account()
myWireGuardRoute = WireGuardRoute()



# Generate a new X25519 key pair
my_private_key = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex('8846b6d2a7955b568023aac19b8929cff6b8a3586043c4490f882734120b5b75'))

my_public_key = my_private_key.public_key()
my_public_key = my_public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)[:32].hex()
# print("My public key:", my_public_key)

# 神灯服务器的X25519公钥是：c33dd1959d651c9d36b0ee9bcad0fac6aa65d7518531db56f4ff32c5963cf01e
shendeng_public_key = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex('c33dd1959d651c9d36b0ee9bcad0fac6aa65d7518531db56f4ff32c5963cf01e'))

# 共享密钥
shared_key = my_private_key.exchange(shendeng_public_key)
# print("Shared key:", shared_key.hex())

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(shared_key)
aes_decrypt_key = digest.finalize()
# print("AES decrypt key:", aes_decrypt_key.hex())




def aes_decrypt(orignal_data_base64):
    orignal_data = base64.b64decode(orignal_data_base64)
    iv = orignal_data[:16]
    cipherText = orignal_data[16:]


    # AES/CBC/PKCS7Padding解密
    cipher = Cipher(algorithms.AES(aes_decrypt_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(cipherText) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(plaintext) + unpadder.finalize()
    return decrypted_data.decode('utf-8')




def user_login():
    print('开始登录账号...')

    ts = int(datetime.datetime.now().timestamp())
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update("password=phone=ts=".encode('utf-8') + str(ts).encode('utf-8') + "WOYqZGTomCWAFREVnyshendeng".encode('utf-8'))
    sign = digest.finalize().hex()

    url = "https://api.zqchs.com/api/app/v3/user/login"

    payload = {
      'phone': "",
      'password': ""
    }

    headers = {
      'User-Agent': "okhttp/3.12.1",
      'Accept-Encoding': "gzip",
      'platform': "Android",
      'bundleid': "com.dfgsdswf.shengdeng",
      'versioncode': "30",
      'deviceid': myAccount.deviceId + "34:B2:0A:C4:cr4",
      'channel': "",
      'spreadnum': "",
      'push-id': "",
      'b_version': "896",
      'routetype': "",
      'appproxy': "0",
      'ua': "{\"brand\":\"XIAOMI\",\"model\":\"MI 8 SE\",\"DeviceManufacturer\":\"meizu\",\"SystemDevice\":\"16s\",\"SystemVersion\":\"9\",\"channel\":\"\",\"spreadNum\":\"\",\"APILevel\":28,\"processId\":\"03\",\"versionCode\":\"30\",\"versionName\":\"3.3.1\",\"isEmulator\":false}",
      'publickey': my_public_key,
      'ts': str(ts),
      'sign': sign
    }

    response = requests.post(url, data=payload, headers=headers)

    jsonData = json.loads(aes_decrypt(response.text))
    myAccount.token = jsonData['data']['token']
    myAccount.expireTime = jsonData['data']['expire_time']
    myAccount.vip_expire_time = jsonData['data']['vip_expire_time']


def getWireGuardRoute():
    if time.localtime() > time.localtime(myAccount.expireTime):
        print("该账号已过期，程序退出")
        exit()
    print('开始获取WireGuard节点信息...')
    ts = int(datetime.datetime.now().timestamp())
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(f"id=4is_full_route=0public_key={myWireGuardRoute.my_publicKey}ts={str(ts)}WOYqZGTomCWAFREVnyshendeng".encode('utf-8'))
    sign = digest.finalize().hex()


    url = "https://api.zqchs.com/api/app/v3/user/route_info"

    params = {
        'id': "4",
        'public_key': myWireGuardRoute.my_publicKey,
        'is_full_route': "0"
    }

    headers = {
        'User-Agent': "okhttp/3.12.1",
        'Accept-Encoding': "gzip",
        'platform': "Android",
        'bundleid': "com.dfgsdswf.shengdeng",
        'versioncode': "30",
        'deviceid': myAccount.deviceId + '34:B2:0A:C4:cr4',
        'channel': "",
        'spreadnum': "",
        'push-id': "18071adc023efd99b4f",
        'b_version': "895",
        'routetype': "",
        'appproxy': "0",
        'ua': "{\"brand\":\"meizu\",\"model\":\"16s\",\"DeviceManufacturer\":\"meizu\",\"SystemDevice\":\"16s\",\"SystemVersion\":\"9\",\"channel\":\"\",\"spreadNum\":\"\",\"APILevel\":28,\"processId\":\"5f4b99dfe320cda170817\",\"versionCode\":\"30\",\"versionName\":\"3.3.1\",\"isEmulator\":false}",
        'publickey': my_public_key,
        'authorization': myAccount.token,
        'ts': str(ts),
        'sign': sign
    }

    response = requests.get(url, params=params, headers=headers)

    # print(aes_decrypt(response.text))
    jsonData = json.loads(aes_decrypt(response.text))
    myWireGuardRoute.peerIp = jsonData['data']['ip']
    myWireGuardRoute.peerPublicKey = jsonData['data']['their_public_key']
    myWireGuardRoute.allowIps = jsonData['data']['allow_ip']

    wireguardConfig = f"wireguard://{quote(myWireGuardRoute.my_privateKey, safe='')}@{myWireGuardRoute.peerIp}/?publickey={quote(myWireGuardRoute.peerPublicKey, safe='')}&address={quote(myWireGuardRoute.allowIps + "/32", safe='')}&mtu=1280#%E7%A5%9E%E7%81%AF"
    print("\n获取成功，以下是您的WireGuard配置，请复制后直接粘贴导入到v2ray等工具：\n" + wireguardConfig)


def check_in():
    print('开始签到...')
    ts = int(datetime.datetime.now().timestamp())
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update("ts=".encode('utf-8') + str(ts).encode('utf-8') + "WOYqZGTomCWAFREVnyshendeng".encode('utf-8'))
    sign = digest.finalize().hex()

    url = "https://d3fo97rjzx0xn8.cloudfront.net/api/app/v3/user/check_in"

    headers = {
      'User-Agent': "okhttp/3.12.1",
      'Accept-Encoding': "gzip",
      'platform': "Android",
      'bundleid': "com.dfgsdswf.shengdeng",
      'versioncode': "30",
      'deviceid': myAccount.deviceId + "34:B2:0A:C4:cr4",
      'channel': "",
      'spreadnum': "",
      'push-id': "18071adc023efd99b4f",
      'b_version': "895",
      'routetype': "",
      'appproxy': "0",
      'ua': "{\"brand\":\"meizu\",\"model\":\"16s\",\"DeviceManufacturer\":\"meizu\",\"SystemDevice\":\"16s\",\"SystemVersion\":\"9\",\"channel\":\"\",\"spreadNum\":\"\",\"APILevel\":28,\"processId\":\"5f4b99dfe320cda170817\",\"versionCode\":\"30\",\"versionName\":\"3.3.1\",\"isEmulator\":false}",
      'publickey': my_public_key,
      'authorization': myAccount.token,
      'ts': str(ts),
      'sign': sign
    }

    response = requests.post(url, headers=headers)
    # print(aes_decrypt(response.text))
    jsonData = json.loads(aes_decrypt(response.text))
    if jsonData['code'] == 4075:
        print('\n该账号今天已经签到了，请勿重复签到')
        exit()
    myAccount.expireTime = jsonData['data']['expire_time']
    myAccount.vip_expire_time = jsonData['data']['vip_expire_time']
    print("签到后，该账号过期时间：", time.ctime(myAccount.expireTime))


os.system('cls')
print("\n\n------欢迎使用一键科学上网客户端 作者：Frank_MARS------\n\n1. 随机出一个新设备（2小时后过期）\n2. 使用已有的设备ID\n")
choice = input("\n请输入数字选择：")

if choice == "1":
    myAccount.deviceId = randomMac()

elif choice == "2":
    myAccount.deviceId = input("请输入欲登录的设备ID：")

else:
    print("输入错误，程序退出")
    exit()
user_login()

os.system('cls')
print("\n您本次登录的设备ID是：" + myAccount.deviceId + "\n该账号过期时间：" + time.ctime(myAccount.expireTime))
print('\n\n -------菜单------\n\n1. 签到（可增加15分钟有效期）并获取WireGuard节点信息\n2. 直接获取WireGuard节点信息\n3. 退出程序\n\n')
choice = input("你的选择是：")
if choice == "1":
    check_in()
    getWireGuardRoute()
elif choice == "2":
    getWireGuardRoute()
elif choice == "3":
    exit()
else:
    print("输入错误，程序退出")
    exit()