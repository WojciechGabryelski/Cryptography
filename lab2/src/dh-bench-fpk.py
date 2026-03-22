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
    fpk_param = json.load(file)["params"]
p = base64.urlsafe_b64decode(add_padding(fpk_param["prime_base"])).hex()
m = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in fpk_param["modulus"]]
m.append("1")
m = ["0" if x == "" else x for x in m]
g = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in fpk_param["generator"]]
g = ["0" if x == "" else x for x in g]
q = base64.urlsafe_b64decode(add_padding(fpk_param["order"])).hex()

for line in sys.stdin:
    challenge = json.loads(line)
    start = time.time_ns()
    # start of benchmarked region
    pk = diffie_hellman.DHFpkKeyGen(p, m, g, q)
    # end of benchmarked region
    end = time.time_ns()
    time_keygen = end - start
    epk = [base64.urlsafe_b64decode(add_padding(x)).hex() for x in challenge["public"]]
    epk = ["0" if x == "" else x for x in epk]
    start = time.time_ns()
    # start of benchmarked region
    shared = diffie_hellman.DHFpkKeyAgr(epk)
    # end of benchmarked region
    end = time.time_ns()
    time_finalize = end - start
    result = {}
    result["public"] = [base64.urlsafe_b64encode(bytes.fromhex("" if x == "0" else (("0" if len(x) % 2 == 1 else "") + x))).decode("utf-8") for x in pk]
    result["time_keygen"] = time_keygen
    result["shared"] = [base64.urlsafe_b64encode(bytes.fromhex("" if x == "0" else (("0" if len(x) % 2 == 1 else "") + x))).decode("utf-8") for x in shared]
    result["time_finalize"] = time_finalize
    print(result)

# {"public": ["7_3Le-KQunFr-vg5i6_kVqcAw83yia04BfDucyM_7rA", "d_as624e2Fl4TaO28vJzX9dh0rU4nz7UYfYqdhXq8-Q", "TQCZ5yT9pG90kMJ46gUGGgC0oT5OwS3GfUBc8W4VT1s", "4KqPgyTXAkZZcNOSpc9yVyARNiyOCP5X97LZF-uvU3E", "PYdoiaapfK8e7mbXQ5vlf7noD0nCUcB6WYRsJO-AzB8", "l_p93I7QPJx26tAB8MjeZEKi1_DphnJ8HGqZTw-Zy90", "6EM3sC4B1zN_lEQu-D-ETx50uaSmfYCv9iQnwptVPVc", "JkOmS4-LUYKqcbEh9GtehbRPqdYhfJQN9fxsjHFN61c"]}
