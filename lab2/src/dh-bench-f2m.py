#!/usr/bin/env python3
import sys
import json
import time
import base64
import diffie_hellman

def add_padding(s):
    return s + "=" * (4 - len(s) % 4)

if len(sys.argv) == 1:
    print("You must pass params file as argument")
    exit

name = sys.argv[1]
with open(name, 'r') as file:
    f2m_param = json.load(file)["params"]
e = f2m_param["extension"]
m = "1" + base64.urlsafe_b64decode(add_padding(f2m_param["modulus"]))[::-1].hex()
g = base64.urlsafe_b64decode(add_padding(f2m_param["generator"]))[::-1].hex()
q = base64.urlsafe_b64decode(add_padding(f2m_param["order"])).hex()

for line in sys.stdin:
    challenge = json.loads(line)
    start = time.time_ns()
    # start of benchmarked region
    pk = diffie_hellman.DHF2mKeyGen(m, g, q)
    # end of benchmarked region
    end = time.time_ns()
    pk = "0" * (e // 4 - len(pk))  + pk
    time_keygen = end - start
    epk = base64.urlsafe_b64decode(add_padding(challenge["public"]))[::-1].hex()
    start = time.time_ns()
    # start of benchmarked region
    shared = diffie_hellman.DHF2mKeyAgr(epk)
    # end of benchmarked region
    end = time.time_ns()
    time_finalize = end - start
    shared = "0" * (e // 4 - len(shared)) + shared
    result = {}
    result["public"] = base64.urlsafe_b64encode(bytes.fromhex(pk)[::-1]).decode("utf-8")
    result["time_keygen"] = time_keygen
    result["shared"] = base64.urlsafe_b64encode(bytes.fromhex(shared)[::-1]).decode("utf-8")
    result["time_finalize"] = time_finalize
    print(result)

# {"public": "LjtPEnPsPAAUCJ6f0NfD7V9YK9DB5tdKgK3C3cQ4raR3VALXDC4ySHdo1WVtWoPPOQ-S7hK35hejridtIIHWYOHpMn4wQosCGL1j_m_O7slb-GWsEynZbvVvWsGxAE7Xe5wu51BoIRvLKoqGkGD80nMjwqUAYaHX9cTvH4xLnbMYGp_SfLl1GZhG2frobW5hvAzxPQGiNDYKxIZ4BTl2d117cLDyb9wsE3feUobMel8fLlaN6XQ6CIoceyokaz1LY7egK3M3J-qERoJ7HYkH75kv0FaB9l60e4cfolujCZ7Rw0ENfI3QEjEMsvFpNQMJu8Snwd-wh2PNkT1EcWhmPQ"}
