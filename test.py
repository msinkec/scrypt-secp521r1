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

    compiler_result = compile_contract(contract, debug=False)
    desc = compiler_result.to_desc()

    # Load desc instead:
    #with open('./out/secp521r1_desc.json', 'r') as f:
    #    desc = json.load(f)

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

    ## Point doubling
    #dx, dy = point_doubled.to_point()

    #assert testCheckSig.testDouble(
    #            Point({ 'x': ax, 'y': ay}), 
    #            Point({ 'x': dx, 'y': dy}), 
    #        ).verify()

    ## Point doubling, point at inf
    #assert testCheckSig.testDouble(
    #            Point({ 'x': 0, 'y': 0}), 
    #            Point({ 'x': 0, 'y': 0}), 
    #        ).verify()


    ## Point addition, same point
    #assert testCheckSig.testAdd(
    #            Point({ 'x': ax, 'y': ay}), 
    #            Point({ 'x': ax, 'y': ay}), 
    #            Point({ 'x': dx, 'y': dy}), 
    #        ).verify()

    ## Point addition, point at inf
    #assert testCheckSig.testAdd(
    #            Point({ 'x': 0, 'y': 0}), 
    #            Point({ 'x': bx, 'y': by}), 
    #            Point({ 'x': bx, 'y': by}), 
    #        ).verify()
    #assert testCheckSig.testAdd(
    #            Point({ 'x': ax, 'y': ay}), 
    #            Point({ 'x': 0, 'y': 0}), 
    #            Point({ 'x': ax, 'y': ay}), 
    #        ).verify()


    ## Scalar multiplication
    #prodx, prody = point_scaled.to_point()
    #assert testCheckSig.testMultByScalar(
    #            Point({ 'x': ax, 'y': ay}), 
    #            scalar.to_int(), 
    #            Point({ 'x': prodx, 'y': prody}), 
    #        ).verify()

    ## Signature verification
    #assert testCheckSig.testVerifySig(
    #            msg_bytes,
    #            Signature({ 'r': r, 's': s}), 
    #            Point({ 'x': ax, 'y': ay}), 
    #        ).verify()

    # Point addition with many random keys
    #for i in range(500):
    #    print("Adding rand key, iter. {}".format(i))
    #    rand_key_priv = PrivateKey.from_random()
    #    rand_to_add = PrivateKey.from_random()
    #    rand_point_sum = rand_key_priv.public_key.add(rand_to_add._secret)

    #    rax, ray = rand_key_priv.public_key.to_point()
    #    rbx, rby = rand_to_add.public_key.to_point()
    #    rsumx, rsumy = rand_point_sum.to_point()

    #    assert testCheckSig.testAdd(
    #                Point({ 'x': rax, 'y': ray}), 
    #                Point({ 'x': rbx, 'y': rby}), 
    #                Point({ 'x': rsumx, 'y': rsumy}), 
    #            ).verify()

    ## Point double with many random keys
    #for i in range(500):
    #    print("Doubling rand key, iter. {}".format(i))
    #    rand_key_priv = PrivateKey.from_random()
    #    rand_point_sum = rand_key_priv.public_key.add(rand_key_priv._secret)

    #    rax, ray = rand_key_priv.public_key.to_point()
    #    rsumx, rsumy = rand_point_sum.to_point()

    #    assert testCheckSig.testDouble(
    #                Point({ 'x': rax, 'y': ray}), 
    #                Point({ 'x': rsumx, 'y': rsumy}), 
    #            ).verify()

    # Scalar point multiplication with many random keys
    #for i in range(100):
    #    print("Multiplying rand key and scalar, iter. {}".format(i))
    #    scalar = PrivateKey.from_random()

    #    pub_key = PrivateKey.from_random().public_key
    #    ax, ay = pub_key.to_point()
    #    
    #    prod = pub_key.multiply(scalar._secret)
    #    prodx, prody = prod.to_point()

    #    assert testCheckSig.testMultByScalar(
    #                Point({ 'x': ax, 'y': ay}), 
    #                scalar.to_int(), 
    #                Point({ 'x': prodx, 'y': prody}), 
    #            ).verify()
        


