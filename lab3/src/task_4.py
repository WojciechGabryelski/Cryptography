#!/usr/bin/env python3
import requests
import base64
import schnorr_signature
import json
import hashlib

def add_padding(s):
    return s + "=" * ((4 - len(s)) % 4)

def ecp_public(ecp_param):
    p = base64.urlsafe_b64decode(add_padding(ecp_param["modulus"])).hex()
    a = base64.urlsafe_b64decode(add_padding(ecp_param["a"])).hex()
    b = base64.urlsafe_b64decode(add_padding(ecp_param["b"])).hex()
    g_x = base64.urlsafe_b64decode(add_padding(ecp_param["generator"]["x"])).hex()
    g_y = base64.urlsafe_b64decode(add_padding(ecp_param["generator"]["y"])).hex()
    q = base64.urlsafe_b64decode(add_padding(ecp_param["order"])).hex()
    pk_x, pk_y = schnorr_signature.SSEcpKeyGen(p, a, b, g_x, g_y, q, 256)
    if len(pk_x) % 2 == 1:
        pk_x = "0" + pk_x
    if len(pk_y) % 2 == 1:
        pk_y = "0" + pk_y
    pk_x = base64.urlsafe_b64encode(bytes.fromhex(pk_x)).decode("utf-8")
    pk_y = base64.urlsafe_b64encode(bytes.fromhex(pk_y)).decode("utf-8")
    return {"x": pk_x, "y": pk_y}

def ecp_set_public(ecp_sign):
    pk_x = base64.urlsafe_b64decode(add_padding(ecp_sign["public"]["x"])).hex()
    pk_y = base64.urlsafe_b64decode(add_padding(ecp_sign["public"]["y"])).hex()
    schnorr_signature.SSEcpSetPublicKey(pk_x, pk_y)

def ecp_verify(ecp_sign, message: str):
    signature_s = base64.urlsafe_b64decode(add_padding(ecp_sign["signature"]["s"])).hex()
    signature_e = base64.urlsafe_b64decode(add_padding(ecp_sign["signature"]["e"])).hex()
    signature = (signature_s, signature_e)
    return schnorr_signature.SSEcpVerify(signature, message)

def ec2m_public(ec2m_param):
    e = ec2m_param["extension"]
    m = hex(int(base64.urlsafe_b64decode(add_padding(ec2m_param["modulus"]))[::-1].hex(), 16) + 2 ** e)[2:]
    a = base64.urlsafe_b64decode(add_padding(ec2m_param["a"]))[::-1].hex()
    b = base64.urlsafe_b64decode(add_padding(ec2m_param["b"]))[::-1].hex()
    g_x = base64.urlsafe_b64decode(add_padding(ec2m_param["generator"]["x"]))[::-1].hex()
    g_y = base64.urlsafe_b64decode(add_padding(ec2m_param["generator"]["y"]))[::-1].hex()
    q = base64.urlsafe_b64decode(add_padding(ec2m_param["order"])).hex()
    pk_x, pk_y = schnorr_signature.SSEc2mKeyGen(m, a, b, g_x, g_y, q, 256)
    pk_x = "0" * ((e + 3) // 4 - len(pk_x)) + pk_x
    if len(pk_x) % 2 == 1:
        pk_x = "0" + pk_x
    pk_x = base64.urlsafe_b64encode(bytes.fromhex(pk_x)[::-1]).decode("utf-8")
    pk_y = "0" * ((e + 3) // 4 - len(pk_y)) + pk_y
    if len(pk_y) % 2 == 1:
        pk_y = "0" + pk_y
    pk_y = base64.urlsafe_b64encode(bytes.fromhex(pk_y)[::-1]).decode("utf-8")
    return {"x": pk_x, "y": pk_y}

def ec2m_set_public(ec2m_sign):
    pk_x = base64.urlsafe_b64decode(add_padding(ec2m_sign["public"]["x"]))[::-1].hex()
    pk_y = base64.urlsafe_b64decode(add_padding(ec2m_sign["public"]["y"]))[::-1].hex()
    schnorr_signature.SSEc2mSetPublicKey(pk_x, pk_y)

def ec2m_verify(ec2m_sign, message: str):
    signature_s = base64.urlsafe_b64decode(add_padding(ec2m_sign["signature"]["s"])).hex()
    signature_e = base64.urlsafe_b64decode(add_padding(ec2m_sign["signature"]["e"])).hex()
    signature = (signature_s, signature_e)
    return schnorr_signature.SSEc2mVerify(signature, message)

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
    pk_x, pk_y = schnorr_signature.SSEcpkKeyGen(p, m, a, b, g_x, g_y, q, 256)
    pk_x = [base64.urlsafe_b64encode(bytes.fromhex("" if x == "0" else (("0" if len(x) % 2 == 1 else "") + x))).decode("utf-8") for x in pk_x]
    pk_y = [base64.urlsafe_b64encode(bytes.fromhex("" if x == "0" else (("0" if len(x) % 2 == 1 else "") + x))).decode("utf-8") for x in pk_y]
    return {"x": pk_x, "y": pk_y}

def ecpk_set_public(ecpk_sign):
    pk_x = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in ecpk_sign["public"]["x"]]
    pk_x = ["0" if x == "" else x for x in pk_x]
    pk_y = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in ecpk_sign["public"]["y"]]
    pk_y = ["0" if x == "" else x for x in pk_y]
    schnorr_signature.SSEcpkSetPublicKey(pk_x, pk_y)

def ecpk_verify(ecpk_sign, message: str):
    signature_s = base64.urlsafe_b64decode(add_padding(ecpk_sign["signature"]["s"])).hex()
    signature_e = base64.urlsafe_b64decode(add_padding(ecpk_sign["signature"]["e"])).hex()
    signature = (signature_s, signature_e)
    return schnorr_signature.SSEcpkVerify(signature, message)

headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

message = "Ala ma kota"
payload = {"message": message}

ecp_param = requests.get("https://crypto24.random-oracle.xyz/validate/list3/ecp/param").json()["params"]
ecp_public(ecp_param)
ecp_sign = requests.post("https://crypto24.random-oracle.xyz/validate/list3/ecp/schnorr/sign", headers=headers, json=payload).json()
ecp_set_public(ecp_sign)
print("Ecp:", ecp_verify(ecp_sign, message))

ec2m_param  = requests.get("https://crypto24.random-oracle.xyz/validate/list3/ec2m/param").json()["params"]
ec2m_public(ec2m_param)
# schnorr_signature.SSEc2mSign(message)
ec2m_sign = requests.post("https://crypto24.random-oracle.xyz/validate/list3/ec2m/schnorr/sign", headers=headers, json=payload).json()
ec2m_set_public(ec2m_sign)
print("Ec2m:", ec2m_verify(ec2m_sign, message))

ecpk_param  = requests.get("https://crypto24.random-oracle.xyz/validate/list3/ecpk/param").json()["params"]
ecpk_public(ecpk_param)
ecpk_sign = requests.post("https://crypto24.random-oracle.xyz/validate/list3/ecpk/schnorr/sign", headers=headers, json=payload).json()
ecpk_set_public(ecpk_sign)
print("Ecpk:", ecpk_verify(ecpk_sign, message))
