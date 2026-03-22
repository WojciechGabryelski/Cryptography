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
    modp_param = json.load(file)["params"]
p = base64.urlsafe_b64decode(add_padding(modp_param["modulus"])).hex()
g = base64.urlsafe_b64decode(add_padding(modp_param["generator"])).hex()
q = base64.urlsafe_b64decode(add_padding(modp_param["order"])).hex()

for line in sys.stdin:
    challenge = json.loads(line)
    start = time.time_ns()
    # start of benchmarked region
    pk = diffie_hellman.DHModpKeyGen(p, g, q)
    # end of benchmarked region
    end = time.time_ns()
    time_keygen = end - start
    if len(pk) % 2 == 1:
        pk = "0" + pk
    epk = base64.urlsafe_b64decode(add_padding(challenge["public"])).hex()
    start = time.time_ns()
    # start of benchmarked region
    shared = diffie_hellman.DHModpKeyAgr(epk)
    # end of benchmarked region
    end = time.time_ns()
    time_finalize = end - start
    if len(shared) % 2 == 1:
        shared = "0" + shared
    result = {}
    result["public"] = base64.urlsafe_b64encode(bytes.fromhex(pk)).decode("utf-8")
    result["time_keygen"] = time_keygen
    result["shared"] = base64.urlsafe_b64encode(bytes.fromhex(shared)).decode("utf-8")
    result["time_finalize"] = time_finalize
    print(result)

# {"public": "NP5jo55yulqTQ9om9twpI0y7F3OkVVXWKZ2BSlXTqkLddalWF5Tto47yXn9kpnJ3wqSs9JOQPnv7fzInSWUY2U4yGxeAaDdSj8HL_nkq9Ba-2nuVF_ue0GqhbvLruNlchzD_GYgG5AYBUzgSthrH5HE1Mt9lc-mInP526MUei3MXsxPeSudk3hWdTHpjzvBHvgr-02GqtbyxooYxnaMH-ZLCJmIZsMxnsgBtl-PnCwXhcrbZkucb03H2CXfAfuU3IDCbMW5GJo4j9AYxhtngKSl2IriCHlSjN869FoFP8W5PUhQ3fs2khm_UwJ2OG8qAr66eYpD0UJwc83kykPAxkA"}
