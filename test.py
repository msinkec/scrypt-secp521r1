import json
import hashlib

from ecdsa import SigningKey, NIST521p
from ecdsa.util import sigdecode_string

from scryptlib import (
        compile_contract, build_contract_class, build_type_classes, Sig
        )


def double_sha256(m):
    return hashlib.sha256(hashlib.sha256(m).digest())


if __name__ == '__main__':
    key_priv = SigningKey.generate(curve=NIST521p)
    key_pub = key_priv.verifying_key
    point_pub = key_pub.pubkey.point

    to_add = SigningKey.generate(curve=NIST521p)
    point_to_add = to_add.verifying_key.pubkey.point
    point_sum = point_pub + point_to_add

    point_doubled = point_pub.double()

    scalar = SigningKey.generate(curve=NIST521p).privkey.secret_multiplier
    point_scaled = point_pub * scalar

    msg = 'Hello, World!'
    msg_bytes = str.encode(msg, encoding='ASCII')

    sig = key_priv.sign(msg_bytes, hashfunc=double_sha256)

    order = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409;
    r, s = sigdecode_string(sig, order)

    #############################
    ##################### sCrypt

    contract = './secp521r1.scrypt' 

    #compiler_result = compile_contract(contract, debug=False)
    #desc = compiler_result.to_desc()

    # Load desc instead:
    with open('./out/secp521r1_desc.json', 'r') as f:
        desc = json.load(f)

    type_classes = build_type_classes(desc)
    Point = type_classes['Point']
    Signature = type_classes['Signature']

    TestCheckSig = build_contract_class(desc)
    testCheckSig = TestCheckSig()

    # Point addition
    assert testCheckSig.testAdd(
                Point({ 'x': point_pub.x(), 'y': point_pub.y()}), 
                Point({ 'x': point_to_add.x(), 'y': point_to_add.y()}), 
                Point({ 'x': point_sum.x(), 'y': point_sum.y()}), 
            ).verify()

    # Point doubling
    assert testCheckSig.testDouble(
                Point({ 'x': point_pub.x(), 'y': point_pub.y()}), 
                Point({ 'x': point_doubled.x(), 'y': point_doubled.y()}), 
            ).verify()

    # Point doubling, point at inf
    assert testCheckSig.testDouble(
                Point({ 'x': 0, 'y': 0}), 
                Point({ 'x': 0, 'y': 0}), 
            ).verify()


    # Point addition, same point
    assert testCheckSig.testAdd(
                Point({ 'x': point_pub.x(), 'y': point_pub.y()}), 
                Point({ 'x': point_pub.x(), 'y': point_pub.y()}), 
                Point({ 'x': point_doubled.x(), 'y': point_doubled.y()}), 
            ).verify()

    # Point addition, point at inf
    assert testCheckSig.testAdd(
                Point({ 'x': 0, 'y': 0}), 
                Point({ 'x': point_pub.x(), 'y': point_pub.y()}), 
                Point({ 'x': point_pub.x(), 'y': point_pub.y()}), 
            ).verify()
    assert testCheckSig.testAdd(
                Point({ 'x': point_doubled.x(), 'y': point_doubled.y()}), 
                Point({ 'x': 0, 'y': 0}), 
                Point({ 'x': point_doubled.x(), 'y': point_doubled.y()}), 
            ).verify()


    # Scalar multiplication
    assert testCheckSig.testMultByScalar(
                Point({ 'x': point_pub.x(), 'y': point_pub.y()}), 
                scalar, 
                Point({ 'x': point_scaled.x(), 'y': point_scaled.y()}), 
            ).verify()

    # Signature verification
    assert testCheckSig.testVerifySig(
                msg_bytes,
                Signature({ 'r': r, 's': s}), 
                Point({ 'x': point_pub.x(), 'y': point_pub.y()}), 
            ).verify()

