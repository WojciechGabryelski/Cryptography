#!/usr/bin/env python3
import requests
import base64
import diffie_hellman

def add_padding(s):
    return s + "=" * ((4 - len(s)) % 4)

def modp_public(modp_param):
    p = base64.urlsafe_b64decode(add_padding(modp_param["modulus"])).hex()
    g = base64.urlsafe_b64decode(add_padding(modp_param["generator"])).hex()
    q = base64.urlsafe_b64decode(add_padding(modp_param["order"])).hex()
    pk = diffie_hellman.DHModpKeyGen(p, g, q)
    if len(pk) % 2 == 1:
        pk = "0" + pk
    return base64.urlsafe_b64encode(bytes.fromhex(pk)).decode("utf-8")

def modp_shared(modp_challenge):
    epk = base64.urlsafe_b64decode(add_padding(modp_challenge["public"])).hex()
    shared = diffie_hellman.DHModpKeyAgr(epk)
    if len(shared) % 2 == 1:
        shared = "0" + shared
    return base64.urlsafe_b64encode(bytes.fromhex(shared)).decode("utf-8")

def f2m_public(f2m_param):
    global e
    e = f2m_param["extension"]
    m = "1" + base64.urlsafe_b64decode(add_padding(f2m_param["modulus"]))[::-1].hex()
    g = base64.urlsafe_b64decode(add_padding(f2m_param["generator"]))[::-1].hex()
    q = base64.urlsafe_b64decode(add_padding(f2m_param["order"])).hex()
    pk = diffie_hellman.DHF2mKeyGen(m, g, q)
    pk = "0" * ((e + 3) // 4 - len(pk)) + pk
    if len(pk) % 2 == 1:
        pk = "0" + pk
    return base64.urlsafe_b64encode(bytes.fromhex(pk)[::-1]).decode("utf-8")

def f2m_shared(f2m_challenge):
    global e
    epk = base64.urlsafe_b64decode(add_padding(f2m_challenge["public"]))[::-1].hex()
    shared = diffie_hellman.DHF2mKeyAgr(epk)
    shared = "0" * ((e + 3) // 4 - len(shared)) + shared
    if len(shared) % 2 == 1:
        shared = "0" + shared
    return base64.urlsafe_b64encode(bytes.fromhex(shared)[::-1]).decode("utf-8")

def fpk_public(fpk_param):
    p = base64.urlsafe_b64decode(add_padding(fpk_param["prime_base"])).hex()
    m = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in fpk_param["modulus"]]
    m.append("1")
    m = ["0" if x == "" else x for x in m]
    g = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in fpk_param["generator"]]
    g = ["0" if x == "" else x for x in g]
    q = base64.urlsafe_b64decode(add_padding(fpk_param["order"])).hex()
    pk = diffie_hellman.DHFpkKeyGen(p, m, g, q)
    return [base64.urlsafe_b64encode(bytes.fromhex("" if x == "0" else (("0" if len(x) % 2 == 1 else "") + x))).decode("utf-8") for x in pk]

def fpk_shared(fpk_challenge):
    epk = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in fpk_challenge["public"]]
    epk = ["0" if x == "" else x for x in epk]
    shared = diffie_hellman.DHFpkKeyAgr(epk)
    return [base64.urlsafe_b64encode(bytes.fromhex("" if x == "0" else (("0" if len(x) % 2 == 1 else "") + x))).decode("utf-8") for x in shared]

headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

modp_param = requests.get("https://crypto24.random-oracle.xyz/validate/list2/modp/param").json()["params"]
payload = {"public": modp_public(modp_param)}
modp_challenge = requests.post("https://crypto24.random-oracle.xyz/validate/list2/modp/challenge", headers=headers, json=payload).json()
shared = modp_shared(modp_challenge)
modp_good = shared == add_padding(modp_challenge["shared"])
print("Modp:", modp_good)

f2m_param  = requests.get("https://crypto24.random-oracle.xyz/validate/list2/f2m/param").json()["params"]
payload = {"public": f2m_public(f2m_param)}
f2m_challenge = requests.post("https://crypto24.random-oracle.xyz/validate/list2/f2m/challenge", headers=headers, json=payload).json()
shared = f2m_shared(f2m_challenge)
f2m_good = shared == add_padding(f2m_challenge["shared"])
print("F2m: ", f2m_good)

fpk_param  = requests.get("https://crypto24.random-oracle.xyz/validate/list2/fpk/param").json()["params"]
payload = {"public": fpk_public(fpk_param)}
fpk_challenge = requests.post("https://crypto24.random-oracle.xyz/validate/list2/fpk/challenge", headers=headers, json=payload).json()
shared = fpk_shared(fpk_challenge)
fpk_good = shared == [add_padding(x) for x in fpk_challenge["shared"]]
print("Fpk: ", fpk_good)

if modp_good and f2m_good and fpk_good:
    student_id = 135642
    params = requests.get(f"https://crypto24.random-oracle.xyz/submit/list2/{student_id}/solution").json()
    payload = {}
    payload["session_id"] = params["session_id"]
    public = modp_public(params["modp_params"])
    shared = modp_shared(params["modp_challenge"])
    payload["modp"] = {"public": public, "shared": shared}
    public = f2m_public(params["f2m_params"])
    shared = f2m_shared(params["f2m_challenge"])
    payload["f2m"] = {"public": public, "shared": shared}
    public = fpk_public(params["fpk_params"])
    shared = fpk_shared(params["fpk_challenge"])
    payload["fpk"] = {"public": public, "shared": shared}
    result = requests.post(f"https://crypto24.random-oracle.xyz/submit/list2/{student_id}/solution", headers=headers, json=payload).json()
    print(result)
