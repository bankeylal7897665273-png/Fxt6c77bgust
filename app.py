from flask import Flask, request, jsonify
import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from protobuf_decoder.protobuf_decoder import Parser
import codecs
import time
from datetime import datetime
import urllib3
import base64
import concurrent.futures
import threading
import os
import sys

# Disable only the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

VERIFY_API = "https://xanaf-legacy-authorised-checker.vercel.app/verify"
SECRET_KEY = "XANAF_SUPER_SECRET_KEY"
OWNER_NAME = "XANAF LEGACY"
BOT_ID = "TEAM X GST GENERATOR API"

# ---- NEW SAFE VERIFICATION SYSTEM FOR VERCEL ----
VERIFICATION_DONE = False
IS_VERIFIED = False
VERIFY_MSG = ""

@app.before_request
def verify_owner_lazy():
    global VERIFICATION_DONE, IS_VERIFIED, VERIFY_MSG
    
    # Sirf pehli baar check karega, Vercel crash nahi hoga
    if not VERIFICATION_DONE:
        try:
            r = requests.get(VERIFY_API, params={"bot_id": BOT_ID}, timeout=5).json()

            if r.get("owner") != OWNER_NAME:
                VERIFY_MSG = "Owner mismatch."
            else:
                ts = r.get("timestamp")
                sig = r.get("signature")
                msg = f"{BOT_ID}:{ts}"
                local_sig = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()

                if local_sig != sig:
                    VERIFY_MSG = "Signature invalid."
                elif abs(int(time.time()) - int(ts)) > 60:
                    VERIFY_MSG = "Token expired."
                else:
                    IS_VERIFIED = True
        except Exception as e:
            VERIFY_MSG = f"Verification API down or failed: {str(e)}"
        
        VERIFICATION_DONE = True

    if not IS_VERIFIED:
        return jsonify({"success": False, "error": "Bot stopped", "reason": VERIFY_MSG}), 403

# ---------------- KEYS ---------------- #
hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)

REGION_LANG = {"ME": "ar","IND": "hi","ID": "id","VN": "vi","TH": "th","BD": "bn","PK": "ur","TW": "zh","EU": "en","RU": "ru","NA": "en","SAC": "es","BR": "pt"}
REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com/",
    "ID": "https://clientbp.ggblueshark.com/",
    "BR": "https://client.us.freefiremobile.com/",
    "ME": "https://clientbp.common.ggbluefox.com/",
    "VN": "https://clientbp.ggblueshark.com/",
    "TH": "https://clientbp.common.ggbluefox.com/",
    "RU": "https://clientbp.ggblueshark.com/",
    "BD": "https://clientbp.ggblueshark.com/",
    "PK": "https://clientbp.ggblueshark.com/",
    "SG": "https://clientbp.ggblueshark.com/",
    "NA": "https://client.us.freefiremobile.com/",
    "SAC": "https://client.us.freefiremobile.com/",
    "EU": "https://clientbp.ggblueshark.com/",
    "TW": "https://clientbp.ggblueshark.com/"
}

def get_region(language_code: str) -> str:
    return REGION_LANG.get(language_code)

def get_region_url(region_code: str) -> str:
    return REGION_URLS.get(region_code, None)

thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        retry_strategy = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        thread_local.session.mount("http://", adapter)
        thread_local.session.mount("https://", adapter)
    return thread_local.session

# ---------------- PROTOBUF ENCODING ---------------- #
def EnC_Vr(N):
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet

# ---------------- AES ENCRYPTION ---------------- #
def E_AEs(Pc):
    Z = bytes.fromhex(Pc)
    key_bytes = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    K = AES.new(key_bytes, AES.MODE_CBC, iv)
    R = K.encrypt(pad(Z, AES.block_size))
    return bytes.fromhex(R.hex())

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key_bytes = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def generate_random_name(name_prefix):
    characters = string.ascii_letters + string.digits
    return name_prefix + ''.join(random.choice(characters) for _ in range(6)).upper()

def generate_custom_password():
    characters = string.ascii_letters + string.digits
    random_part = ''.join(random.choice(characters) for _ in range(9)).upper()
    return f"HRE-{random_part}-CODEX"

def create_single_account(args):
    name_prefix, region = args
    for attempt in range(3):
        try:
            result = create_acc(region, name_prefix)
            if result and result.get('uid') and result.get('status') == "full_login":
                return result
            time.sleep(1)
        except Exception:
            time.sleep(1)
    return None

def create_acc(region, name_prefix):
    password = generate_custom_password()
    session = get_session()
    data = f"password={password}&client_type=2&source=2&app_id=100067"
    message = data.encode('utf-8')
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()

    url = "https://100067.connect.garena.com/oauth/guest/register"
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
        "Authorization": "Signature " + signature,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive"
    }
    try:
        response = session.post(url, headers=headers, data=data, timeout=30)
        uid = response.json().get('uid')
        if not uid: return None
        return token(uid, password, region, name_prefix)
    except Exception: return None

def token(uid, password, region, name_prefix):
    session = get_session()
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Accept-Encoding": "gzip", "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
    }
    body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": key, "client_id": "100067"}
    try:
        resp_json = session.post(url, headers=headers, data=body, timeout=30).json()
        if not resp_json.get('open_id') or not resp_json.get("access_token"): return None
        result = encode_string(resp_json.get('open_id'))
        field = codecs.decode(to_unicode_escaped(result['field_14']), 'unicode_escape').encode('latin1')
        return Major_Regsiter(resp_json.get("access_token"), resp_json.get('open_id'), field, uid, password, region, name_prefix)
    except Exception: return None

def encode_string(original):
    keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    encoded = "".join(chr(ord(original[i]) ^ keystream[i % len(keystream)]) for i in range(len(original)))
    return {"open_id": original, "field_14": encoded}

def to_unicode_escaped(s):
    return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)

def Major_Regsiter(access_token, open_id, field, uid, password, region, name_prefix):
    session = get_session()
    internal_name = generate_random_name(name_prefix)
    headers = {
        "Accept-Encoding": "gzip", "Authorization": "Bearer", "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded", "Expect": "100-continue",
        "Host": "loginbp.ggblueshark.com", "ReleaseVersion": "OB53",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1"
    }
    payload = {1: internal_name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: field, 15: "en", 16: 1, 17: 1}
    try:
        body = bytes.fromhex(E_AEs(CrEaTe_ProTo(payload).hex()).hex())
        response = session.post("https://loginbp.ggblueshark.com/MajorRegister", headers=headers, data=body, verify=False, timeout=30)
        return login(uid, password, access_token, open_id, response.content.hex(), response.status_code, internal_name, region)
    except Exception: return None

def chooseregion(data_bytes, jwt_token):
    headers = {
        'User-Agent': "Dalvik/2.1.0", 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded", 'Expect': "100-continue",
        'Authorization': f"Bearer {jwt_token}", 'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1", 'ReleaseVersion': "OB53"
    }
    try: return get_session().post("https://loginbp.ggblueshark.com/ChooseRegion", data=data_bytes, headers=headers, verify=False, timeout=30).status_code
    except Exception: return None

def login(uid, password, access_token, open_id, response_hex, status_code, name, region):
    lang_b = (get_region(region) or "en").encode("ascii")
    headers = {
        "Accept-Encoding": "gzip", "Authorization": "Bearer", "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded", "Expect": "100-continue",
        "Host": "loginbp.ggblueshark.com", "ReleaseVersion": "OB53",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1"
    }
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = b'\x1a\x13' + now_str.encode() + b'"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02' + lang_b + b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
    data = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode()).replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
    Final_Payload = bytes.fromhex(encrypt_api(data.hex()))
    
    URL = "https://loginbp.common.ggbluefox.com/MajorLogin" if region.lower() == "me" else "https://loginbp.ggblueshark.com/MajorLogin"
    try:
        RESPONSE = get_session().post(URL, headers=headers, data=Final_Payload, verify=False, timeout=30)
        if RESPONSE.status_code != 200 or len(RESPONSE.text) < 10: return None
        
        if (get_region(region) or "en").lower() not in ["ar", "en"]:
            parsed_data = json.loads(get_available_room(RESPONSE.content.hex()) or "{}")
            BASE64_TOKEN = parsed_data.get('8', {}).get('data')
            if BASE64_TOKEN:
                if chooseregion(bytes.fromhex(encrypt_api(CrEaTe_ProTo({1: "RU" if region.lower() == "ru" else region}).hex())), BASE64_TOKEN) == 200:
                    return login_server(uid, password, access_token, open_id, RESPONSE.content.hex(), RESPONSE.status_code, name, region)
        
        start_idx = RESPONSE.text.find("eyJhbGci")
        if start_idx != -1:
            BASE64_TOKEN = RESPONSE.text[start_idx:-1]
            second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
            if second_dot_index != -1: BASE64_TOKEN = BASE64_TOKEN[:second_dot_index+44]
            return GET_PAYLOAD_BY_DATA(BASE64_TOKEN, access_token, 1, response_hex, status_code, name, uid, password, region)
    except Exception: return None

def login_server(uid, password, access_token, open_id, response, status_code, name, region):
    lang_b = (get_region(region) or "en").encode("ascii")
    headers = {
        "Accept-Encoding": "gzip", "Authorization": "Bearer", "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded", "Expect": "100-continue",
        "Host": "loginbp.ggblueshark.com", "ReleaseVersion": "OB53",
        "User-Agent": "Dalvik/2.1.0", "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1"
    }
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = b'\x1a\x13' + now_str.encode() + b'"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02' + lang_b + b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
    data = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode()).replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
    Final_Payload = bytes.fromhex(encrypt_api(data.hex()))
    URL = "https://loginbp.common.ggbluefox.com/MajorLogin" if region.lower() == "me" else "https://loginbp.ggblueshark.com/MajorLogin"

    try:
        RESPONSE = get_session().post(URL, headers=headers, data=Final_Payload, verify=False, timeout=30)
        if RESPONSE.status_code == 200 and len(RESPONSE.text) >= 10:
            parsed_data = json.loads(get_available_room(RESPONSE.content.hex()) or "{}")
            BASE64_TOKEN = parsed_data.get('8', {}).get('data')
            if BASE64_TOKEN:
                second_dot = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
                if second_dot != -1: BASE64_TOKEN = BASE64_TOKEN[:second_dot+44]
                return GET_PAYLOAD_BY_DATA(BASE64_TOKEN, access_token, 1, response, status_code, name, uid, password, region)
    except Exception: return None

def parse_results(parsed_results):
    return {r.field: {'wire_type': r.wire_type, 'data': parse_results(r.data.results) if r.wire_type == 'length_delimited' else r.data} for r in parsed_results}

def get_available_room(input_text):
    try: return json.dumps(parse_results(Parser().parse(input_text)))
    except Exception: return None

def GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD, region):
    url = f"{get_region_url(region) or 'https://clientbp.ggblueshark.com/'}GetLoginData"
    headers = {
        'Expect': '100-continue', 'Authorization': f'Bearer {JWT_TOKEN}', 'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1', 'ReleaseVersion': 'OB53', 'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Dalvik/2.1.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate, br',
    }
    for _ in range(3):
        try:
            response = get_session().post(url, headers=headers, data=PAYLOAD, verify=False, timeout=20)
            return json.loads(get_available_room(response.content.hex()) or "null")
        except requests.RequestException: time.sleep(2)
    return None

def GET_PAYLOAD_BY_DATA(JWT_TOKEN, NEW_ACCESS_TOKEN, date, response, status_code, name, uid, password, region):
    try:
        tp = JWT_TOKEN.split('.')[1]
        decoded = json.loads(base64.urlsafe_b64decode(tp + '=' * ((4 - len(tp) % 4) % 4)).decode('utf-8'))
        PAYLOAD = b':\x071.111.2\xaa\x01\x02ar\xb2\x01 55ed759fcf94f85813e57b2ec8492f5c\xba\x01\x014\xea\x01@6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae\x9a\x06\x014\xa2\x06\x014'
        PAYLOAD = PAYLOAD.replace(b"2023-12-24 04:21:34", datetime.now().strftime("%Y-%m-%d %H:%M:%S").encode())
        PAYLOAD = PAYLOAD.replace(b"15f5ba1de5234a2e73cc65b6f34ce4b299db1af616dd1dd8a6f31b147230e5b6", NEW_ACCESS_TOKEN.encode("UTF-8"))
        PAYLOAD = PAYLOAD.replace(b"4666ecda0003f1809655a7a8698573d0", decoded.get('external_id', '').encode("UTF-8"))
        PAYLOAD = PAYLOAD.replace(b"7428b253defc164018c604a1ebbfebdf", decoded.get('signature_md5', '').encode("UTF-8"))
        GET_LOGIN_DATA(JWT_TOKEN, bytes.fromhex(encrypt_api(PAYLOAD.hex())), region)
        return {"uid": uid, "password": password, "name": name, "region": region, "status": "full_login", "stage": "complete"}
    except Exception: return None

@app.route('/gen', methods=['GET'])
def generate_accounts():
    name = request.args.get('name', 'HUSTLER')
    try: count = max(1, min(15, int(request.args.get('count', '1'))))
    except: count = 1
    region = request.args.get('region', 'IND').upper()
    if region not in REGION_LANG: region = "IND"
    
    results, attempts = [], 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        while len(results) < count and attempts < count * 10:
            futures = [executor.submit(create_single_account, (name, region)) for _ in range(min(count - len(results), 3))]
            for future in concurrent.futures.as_completed(futures):
                attempts += 1
                result = future.result()
                if result and result.get('status') == "full_login": results.append(result)
                if len(results) >= count: break
    
    return jsonify({"success": True, "total_requested": count, "total_created": len(results), "accounts": results, "attempts_made": attempts})

@app.route('/')
def home(): return jsonify({"status": "running"})

# For Vercel - WSGI compatible
def application(environ, start_response): return app(environ, start_response)

if __name__ == '__main__': app.run(host='0.0.0.0', port=3000, debug=False)
