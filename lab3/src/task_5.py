#!/usr/bin/env python3
import requests
import base64
import protocol
import json

def add_padding(s):
    return s + "=" * ((4 - len(s)) % 4)

def ecp_public(ecp_param):
    p = base64.urlsafe_b64decode(add_padding(ecp_param["modulus"])).hex()
    a = base64.urlsafe_b64decode(add_padding(ecp_param["a"])).hex()
    b = base64.urlsafe_b64decode(add_padding(ecp_param["b"])).hex()
    g_x = base64.urlsafe_b64decode(add_padding(ecp_param["generator"]["x"])).hex()
    g_y = base64.urlsafe_b64decode(add_padding(ecp_param["generator"]["y"])).hex()
    q = base64.urlsafe_b64decode(add_padding(ecp_param["order"])).hex()
    pk_x, pk_y = protocol.DHEcpKeyGen(p, a, b, g_x, g_y, q)
    if len(pk_x) % 2 == 1:
        pk_x = "0" + pk_x
    if len(pk_y) % 2 == 1:
        pk_y = "0" + pk_y
    pk_x = base64.urlsafe_b64encode(bytes.fromhex(pk_x)).decode("utf-8").rstrip("=")
    pk_y = base64.urlsafe_b64encode(bytes.fromhex(pk_y)).decode("utf-8").rstrip("=")
    return {"x": pk_x, "y": pk_y}

def ecp_shared(ecp_challenge):
    epk_x = base64.urlsafe_b64decode(add_padding(ecp_challenge["public"]["x"])).hex()
    epk_y = base64.urlsafe_b64decode(add_padding(ecp_challenge["public"]["y"])).hex()
    shared_x, shared_y = protocol.DHEcpKeyAgr(epk_x, epk_y)
    if len(shared_x) % 2 == 1:
        shared_x = "0" + shared_x
    if len(shared_y) % 2 == 1:
        shared_y = "0" + shared_y
    shared_x = base64.urlsafe_b64encode(bytes.fromhex(shared_x)).decode("utf-8").rstrip("=")
    shared_y = base64.urlsafe_b64encode(bytes.fromhex(shared_y)).decode("utf-8").rstrip("=")
    return {"x": shared_x, "y": shared_y}

def ecp_sign(message):
    signature = protocol.SSEcpSign(message)
    s = ("" if len(signature[0]) % 2 == 0 else "0") + signature[0]
    e = ("" if len(signature[1]) % 2 == 0 else "0") + signature[1]
    s = base64.urlsafe_b64encode(bytes.fromhex(s)).decode("utf-8").rstrip("=")
    e = base64.urlsafe_b64encode(bytes.fromhex(e)).decode("utf-8").rstrip("=")
    return {"s": s, "e": e}

def ec2m_public(ec2m_param):
    global e
    e = ec2m_param["extension"]
    m = hex(int(base64.urlsafe_b64decode(add_padding(ec2m_param["modulus"]))[::-1].hex(), 16) + 2 ** e)[2:]
    a = base64.urlsafe_b64decode(add_padding(ec2m_param["a"]))[::-1].hex()
    b = base64.urlsafe_b64decode(add_padding(ec2m_param["b"]))[::-1].hex()
    g_x = base64.urlsafe_b64decode(add_padding(ec2m_param["generator"]["x"]))[::-1].hex()
    g_y = base64.urlsafe_b64decode(add_padding(ec2m_param["generator"]["y"]))[::-1].hex()
    q = base64.urlsafe_b64decode(add_padding(ec2m_param["order"])).hex()
    pk_x, pk_y = protocol.DHEc2mKeyGen(m, a, b, g_x, g_y, q)
    pk_x = "0" * ((e + 3) // 4 - len(pk_x)) + pk_x
    if len(pk_x) % 2 == 1:
        pk_x = "0" + pk_x
    pk_x = base64.urlsafe_b64encode(bytes.fromhex(pk_x)[::-1]).decode("utf-8").rstrip("=")
    pk_y = "0" * ((e + 3) // 4 - len(pk_y)) + pk_y
    if len(pk_y) % 2 == 1:
        pk_y = "0" + pk_y
    pk_y = base64.urlsafe_b64encode(bytes.fromhex(pk_y)[::-1]).decode("utf-8").rstrip("=")
    return {"x": pk_x, "y": pk_y}

def ec2m_shared(ec2m_challenge):
    global e
    epk_x = base64.urlsafe_b64decode(add_padding(ec2m_challenge["public"]["x"]))[::-1].hex()
    epk_y = base64.urlsafe_b64decode(add_padding(ec2m_challenge["public"]["y"]))[::-1].hex()
    shared_x, shared_y = protocol.DHEc2mKeyAgr(epk_x, epk_y)
    shared_x = "0" * ((e + 3) // 4 - len(shared_x)) + shared_x
    if len(shared_x) % 2 == 1:
        shared_x = "0" + shared_x
    shared_x = base64.urlsafe_b64encode(bytes.fromhex(shared_x)[::-1]).decode("utf-8").rstrip("=")
    shared_y = "0" * ((e + 3) // 4 - len(shared_y)) + shared_y
    if len(shared_y) % 2 == 1:
        shared_y = "0" + shared_y
    shared_y = base64.urlsafe_b64encode(bytes.fromhex(shared_y)[::-1]).decode("utf-8").rstrip("=")
    return {"x": shared_x, "y": shared_y}

def ec2m_sign(message):
    signature = protocol.SSEc2mSign(message)
    s = ("" if len(signature[0]) % 2 == 0 else "0") + signature[0]
    e = ("" if len(signature[1]) % 2 == 0 else "0") + signature[1]
    s = base64.urlsafe_b64encode(bytes.fromhex(s)).decode("utf-8").rstrip("=")
    e = base64.urlsafe_b64encode(bytes.fromhex(e)).decode("utf-8").rstrip("=")
    return {"s": s, "e": e}

def ecpk_public(ecpk_param):
    p = base64.urlsafe_b64decode(add_padding(ecpk_param["prime_base"])).hex()
    m = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in ecpk_param["modulus"]]
    m.append("1")
    m = ["0" if x == "" else x for x in m]
    a = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in ecpk_param["a"]]
    a = ["0" if x == "" else x for x in a]
    b = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in ecpk_param["b"]]
    b = ["0" if x == "" else x for x in b]
    g_x = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in ecpk_param["generator"]["x"]]
    g_x = ["0" if x == "" else x for x in g_x]
    g_y = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in ecpk_param["generator"]["y"]]
    g_y = ["0" if x == "" else x for x in g_y]
    q = base64.urlsafe_b64decode(add_padding(ecpk_param["order"])).hex()
    pk_x, pk_y = protocol.DHEcpkKeyGen(p, m, a, b, g_x, g_y, q)
    pk_x = [base64.urlsafe_b64encode(bytes.fromhex("" if x == "0" else (("0" if len(x) % 2 == 1 else "") + x))).decode("utf-8").rstrip("=") for x in pk_x]
    pk_y = [base64.urlsafe_b64encode(bytes.fromhex("" if x == "0" else (("0" if len(x) % 2 == 1 else "") + x))).decode("utf-8").rstrip("=") for x in pk_y]
    return {"x": pk_x, "y": pk_y}

def ecpk_shared(ecpk_challenge):
    epk_x = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in ecpk_challenge["public"]["x"]]
    epk_x = ["0" if x == "" else x for x in epk_x]
    epk_y = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in ecpk_challenge["public"]["y"]]
    epk_y = ["0" if x == "" else x for x in epk_y]
    shared_x, shared_y = protocol.DHEcpkKeyAgr(epk_x, epk_y)
    shared_x = [base64.urlsafe_b64encode(bytes.fromhex("" if x == "0" else (("0" if len(x) % 2 == 1 else "") + x))).decode("utf-8").rstrip("=") for x in shared_x]
    shared_y = [base64.urlsafe_b64encode(bytes.fromhex("" if x == "0" else (("0" if len(x) % 2 == 1 else "") + x))).decode("utf-8").rstrip("=") for x in shared_y]
    return {"x": shared_x, "y": shared_y}

def ecpk_sign(message):
    signature = protocol.SSEcpkSign(message)
    s = ("" if len(signature[0]) % 2 == 0 else "0") + signature[0]
    e = ("" if len(signature[1]) % 2 == 0 else "0") + signature[1]
    s = base64.urlsafe_b64encode(bytes.fromhex(s)).decode("utf-8").rstrip("=")
    e = base64.urlsafe_b64encode(bytes.fromhex(e)).decode("utf-8").rstrip("=")
    return {"s": s, "e": e}

def ecp_verify(ecp_sign, message: str):
    signature_s = base64.urlsafe_b64decode(add_padding(ecp_sign["s"])).hex()
    signature_e = base64.urlsafe_b64decode(add_padding(ecp_sign["e"])).hex()
    signature = (signature_s, signature_e)
    return protocol.SSEcpVerify(signature, message)

def ec2m_verify(ec2m_sign, message: str):
    signature_s = base64.urlsafe_b64decode(add_padding(ec2m_sign["s"])).hex()
    signature_e = base64.urlsafe_b64decode(add_padding(ec2m_sign["e"])).hex()
    signature = (signature_s, signature_e)
    return protocol.SSEc2mVerify(signature, message)

def ecpk_verify(ecpk_sign, message: str):
    signature_s = base64.urlsafe_b64decode(add_padding(ecpk_sign["s"])).hex()
    signature_e = base64.urlsafe_b64decode(add_padding(ecpk_sign["e"])).hex()
    signature = (signature_s, signature_e)
    return protocol.SSEcpkVerify(signature, message)

headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

student_id = 135642
params = requests.get(f"https://crypto24.random-oracle.xyz/submit/list3/{student_id}/ec/solution").json()
payload = {}
# params = {}
payload["session_id"] = params["session_id"]
# params["ecp_params"] = requests.get("https://crypto24.random-oracle.xyz/validate/list3/ecp/param").json()["params"]
public = ecp_public(params["ecp_params"])
# params["ecp_challenge"] = requests.post("https://crypto24.random-oracle.xyz/validate/list3/ecp/dh/challenge", headers=headers, json={"public": public}).json()
shared = ecp_shared(params["ecp_challenge"])
shared = json.dumps(shared, separators=(',', ':'))
signature = ecp_sign(shared)
# print(ecp_verify(signature, shared))
payload["ecp"] = {"public": public, "signature": signature}
# params["ec2m_params"] = requests.get("https://crypto24.random-oracle.xyz/validate/list3/ec2m/param").json()["params"]
public = ec2m_public(params["ec2m_params"])
# params["ec2m_challenge"] = requests.post("https://crypto24.random-oracle.xyz/validate/list3/ec2m/dh/challenge", headers=headers, json={"public": public}).json()
shared = ec2m_shared(params["ec2m_challenge"])
shared = json.dumps(shared, separators=(',', ':'))
signature = ec2m_sign(shared)
# print(ec2m_verify(signature, shared))
payload["ec2m"] = {"public": public, "signature": signature}
# params["ecpk_params"] = requests.get("https://crypto24.random-oracle.xyz/validate/list3/ecpk/param").json()["params"]
public = ecpk_public(params["ecpk_params"])
# params["ecpk_challenge"] = requests.post("https://crypto24.random-oracle.xyz/validate/list3/ecpk/dh/challenge", headers=headers, json={"public": public}).json()
shared = ecpk_shared(params["ecpk_challenge"])
shared = json.dumps(shared, separators=(',', ':'))
signature = ecpk_sign(shared)
# print(ecpk_verify(signature, shared))
payload["ecpk"] = {"public": public, "signature": signature}
result = requests.post(f"https://crypto24.random-oracle.xyz/submit/list3/{student_id}/ec/solution", headers=headers, json=payload).json()
print(result)
