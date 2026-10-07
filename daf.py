# generate_auth_tokens throws PERMISSION_DENIED every single time now, right
# after i sign the challenge. the tutorial i learned this off (from last year)
# just does kp.sign_message(challenge.encode()) and that was it, worked in the
# video. did jito change what actually needs to be signed or am i messing up
# the bytes somewhere?
import argparse
import os

import grpc
from solders.keypair import Keypair

from jito_searcher_client.generated import auth_pb2, auth_pb2_grpc


def auth(chan, kp):
    stub = auth_pb2_grpc.AuthServiceStub(chan)
    pubkey_bytes = bytes(kp.pubkey())
    chal_resp = stub.GenerateAuthChallenge(
        auth_pb2.GenerateAuthChallengeRequest(
            role=auth_pb2.SEARCHER, pubkey=pubkey_bytes
        )
    )
    chal = chal_resp.challenge
    sig = kp.sign_message(chal.encode())
    tok_resp = stub.GenerateAuthTokens(
        auth_pb2.GenerateAuthTokensRequest(
            challenge=chal,
            client_pubkey=pubkey_bytes,
            signed_challenge=bytes(sig),
        )
    )
    return tok_resp.access_token.value


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--keypair", default=os.environ.get("SEARCHER_KEYPAIR"))
    ap.add_argument("--block-engine-url", default=os.environ.get("BLOCK_ENGINE_URL"))
    args = ap.parse_args()

    with open(args.keypair) as f:
        kp = Keypair.from_json(f.read())

    chan = grpc.secure_channel(args.block_engine_url, grpc.ssl_channel_credentials())
    try:
        token = auth(chan, kp)
        print("got token:", token)
    except grpc.RpcError as e:
        print("auth blew up:", e.code(), e.details())
