from flask import Flask, jsonify, request
import os
import json
import ctypes
import base64
import time
import secrets



app = Flask(__name__)


AUTH_TOKEN = "dev-secret"
BASE_DIR = os.path.dirname(__file__)

STORE_PATH = os.path.abspath(os.path.join(BASE_DIR, "store.json"))
CRYPTO_DLL_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "crypto_c", "crypto.dll"))

AUTH_CHALLENGES = {}  
AUTH_OK = set()     
CHALLENGE_TTL = 60


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))




def ensure_store_exists():
    if not os.path.exists(STORE_PATH):
        with open(STORE_PATH, "w", encoding="utf-8") as f:
            json.dump({"users": {}, "mailbox": {}}, f, indent=2)

def load_store():
    ensure_store_exists()
    with open(STORE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_store(store):
    with open(STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)



def require_auth_json():
    data = request.get_json(silent=True) or {}
    if data.get("auth") != AUTH_TOKEN:
        return None, (jsonify({"error": "unauthorized"}), 401)
    return data, None


if not os.path.exists(CRYPTO_DLL_PATH):
    raise FileNotFoundError(f"crypto.dll not found at: {CRYPTO_DLL_PATH}")

crypto = ctypes.CDLL(CRYPTO_DLL_PATH)


crypto.crypto_test32.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
crypto.crypto_test32.restype = ctypes.c_int


crypto.sodium_init_wrapper.argtypes = []
crypto.sodium_init_wrapper.restype = ctypes.c_int


crypto.ed25519_keypair.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
crypto.ed25519_keypair.restype = ctypes.c_int


crypto.x25519_keypair.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
crypto.x25519_keypair.restype = ctypes.c_int


crypto.ed25519_sign.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
]
crypto.ed25519_sign.restype = ctypes.c_int


crypto.ed25519_verify.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_uint32,        
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
]
crypto.ed25519_verify.restype = ctypes.c_int


crypto.x3dh_derive_alice.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),  # out32
    ctypes.POINTER(ctypes.c_uint8),  # a_ik_priv
    ctypes.POINTER(ctypes.c_uint8),  # a_ek_priv
    ctypes.POINTER(ctypes.c_uint8),  # b_ik_pub
    ctypes.POINTER(ctypes.c_uint8),  # b_spk_pub
    ctypes.POINTER(ctypes.c_uint8),  # b_opk_pub
    ctypes.c_int,                    # opk_present
]
crypto.x3dh_derive_alice.restype = ctypes.c_int


crypto.x3dh_derive_bob.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),  
    ctypes.POINTER(ctypes.c_uint8),  
    ctypes.POINTER(ctypes.c_uint8),  
    ctypes.POINTER(ctypes.c_uint8),  
    ctypes.POINTER(ctypes.c_uint8),  
    ctypes.POINTER(ctypes.c_uint8),  
    ctypes.c_int,                    
]
crypto.x3dh_derive_bob.restype = ctypes.c_int


crypto.random_bytes.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
crypto.random_bytes.restype  = ctypes.c_int

crypto.pwhash_argon2id_32.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
]
crypto.pwhash_argon2id_32.restype = ctypes.c_int





init_rc = crypto.sodium_init_wrapper()
if init_rc < 0:
    raise RuntimeError("sodium_init failed (libsodium init error)")


@app.get("/ping")
def ping():
    return jsonify({"status": "ok", "msg": "server alive"})



@app.post("/crypto/test")
def crypto_test():
    data, err = require_auth_json()
    if err:
        return err

    buf = (ctypes.c_uint8 * 32)()
    rc = crypto.crypto_test32(buf)
    out = [int(x) for x in buf]
    return jsonify({"ok": True, "rc": rc, "out": out})

@app.post("/crypto/keygen_ed25519")
def keygen_ed25519():
    data, err = require_auth_json()
    if err:
        return err

    pk = (ctypes.c_uint8 * 32)()
    sk = (ctypes.c_uint8 * 64)()
    rc = crypto.ed25519_keypair(pk, sk)
    if rc != 0:
        return jsonify({"error": "ed25519_keypair failed"}), 500

    return jsonify({"ok": True, "pk": b64e(bytes(pk)), "sk": b64e(bytes(sk))})

@app.post("/crypto/keygen_x25519")
def keygen_x25519():
    data, err = require_auth_json()
    if err:
        return err

    pk = (ctypes.c_uint8 * 32)()
    sk = (ctypes.c_uint8 * 32)()
    rc = crypto.x25519_keypair(pk, sk)
    if rc != 0:
        return jsonify({"error": "x25519_keypair failed"}), 500

    return jsonify({"ok": True, "pub": b64e(bytes(pk)), "priv": b64e(bytes(sk))})

@app.post("/crypto/keygen_identity")
def keygen_identity():
    data, err = require_auth_json()
    if err:
        return err

    # IK_dh (X25519)
    ik_pub = (ctypes.c_uint8 * 32)()
    ik_priv = (ctypes.c_uint8 * 32)()
    if crypto.x25519_keypair(ik_pub, ik_priv) != 0:
        return jsonify({"error": "ik_dh keygen failed"}), 500

    # IK_sign (Ed25519)
    sign_pk = (ctypes.c_uint8 * 32)()
    sign_sk = (ctypes.c_uint8 * 64)()
    if crypto.ed25519_keypair(sign_pk, sign_sk) != 0:
        return jsonify({"error": "ik_sign keygen failed"}), 500

    return jsonify({
        "ok": True,
        "ik_dh_pub": b64e(bytes(ik_pub)),
        "ik_dh_priv": b64e(bytes(ik_priv)),
        "ik_sign_pub": b64e(bytes(sign_pk)),
        "ik_sign_priv": b64e(bytes(sign_sk)),
    })

@app.post("/crypto/sign_spk")
def sign_spk():
    data, err = require_auth_json()
    if err:
        return err

    # inputs are base64
    spk_pub = b64d(data["spk_pub"])
    ik_sign_priv = b64d(data["ik_sign_priv"])

    if len(spk_pub) != 32:
        return jsonify({"error": "spk_pub must be 32 bytes"}), 400
    if len(ik_sign_priv) != 64:
        return jsonify({"error": "ik_sign_priv must be 64 bytes"}), 400

    msg = spk_pub  # simplest correct message for this project
    msg_buf = (ctypes.c_uint8 * len(msg)).from_buffer_copy(msg)
    sk_buf  = (ctypes.c_uint8 * 64).from_buffer_copy(ik_sign_priv)
    sig_buf = (ctypes.c_uint8 * 64)()

    rc = crypto.ed25519_sign(msg_buf, len(msg), sk_buf, sig_buf)
    if rc != 0:
        return jsonify({"error": "sign failed"}), 500

    return jsonify({"ok": True, "spk_sig": b64e(bytes(sig_buf))})



@app.post("/crypto/verify_spk")
def verify_spk():
    data, err = require_auth_json()
    if err:
        return err

    spk_pub = b64d(data["spk_pub"])
    spk_sig = b64d(data["spk_sig"])
    ik_sign_pub = b64d(data["ik_sign_pub"])

    if len(spk_pub) != 32:
        return jsonify({"error": "spk_pub must be 32 bytes"}), 400
    if len(spk_sig) != 64:
        return jsonify({"error": "spk_sig must be 64 bytes"}), 400
    if len(ik_sign_pub) != 32:
        return jsonify({"error": "ik_sign_pub must be 32 bytes"}), 400

    msg = spk_pub
    msg_buf = (ctypes.c_uint8 * len(msg)).from_buffer_copy(msg)
    pk_buf  = (ctypes.c_uint8 * 32).from_buffer_copy(ik_sign_pub)
    sig_buf = (ctypes.c_uint8 * 64).from_buffer_copy(spk_sig)

    rc = crypto.ed25519_verify(msg_buf, len(msg), pk_buf, sig_buf)

    
    return jsonify({"ok": True, "valid": (rc == 0)})


@app.post("/crypto/x3dh_sender")
def x3dh_sender():
    data, err = require_auth_json()
    if err:
        return err

    a_ik_priv = b64d(data["sender_ik_priv"])
    a_ek_priv = b64d(data["sender_ek_priv"])
    b_ik_pub  = b64d(data["receiver_ik_pub"])
    b_spk_pub = b64d(data["receiver_spk_pub"])

    opk_present = 0
    b_opk_pub = b"\x00" * 32
    if data.get("receiver_opk_pub") is not None:
        b_opk_pub = b64d(data["receiver_opk_pub"])
        opk_present = 1

    out = (ctypes.c_uint8 * 32)()
    rc = crypto.x3dh_derive_alice(
        out,
        (ctypes.c_uint8 * 32).from_buffer_copy(a_ik_priv),
        (ctypes.c_uint8 * 32).from_buffer_copy(a_ek_priv),
        (ctypes.c_uint8 * 32).from_buffer_copy(b_ik_pub),
        (ctypes.c_uint8 * 32).from_buffer_copy(b_spk_pub),
        (ctypes.c_uint8 * 32).from_buffer_copy(b_opk_pub),
        opk_present
    )
    if rc != 0:
        return jsonify({"error": "x3dh_sender failed"}), 500

    return jsonify({"ok": True, "shared_key": b64e(bytes(out)), "opk_used": bool(opk_present)})

@app.post("/crypto/x3dh_receiver")
def x3dh_reciever():
    data, err = require_auth_json()
    if err:
        return err

    b_ik_priv  = b64d(data["receiver_ik_priv"])
    b_spk_priv = b64d(data["receiver_spk_priv"])
    a_ik_pub   = b64d(data["sender_ik_pub"])
    a_ek_pub   = b64d(data["sender_ek_pub"])

    opk_present = 0
    b_opk_priv = b"\x00" * 32
    if data.get("receiver_opk_priv") is not None:
        b_opk_priv = b64d(data["receiver_opk_priv"])
        opk_present = 1

    out = (ctypes.c_uint8 * 32)()
    rc = crypto.x3dh_derive_bob(
        out,
        (ctypes.c_uint8 * 32).from_buffer_copy(b_ik_priv),
        (ctypes.c_uint8 * 32).from_buffer_copy(b_spk_priv),
        (ctypes.c_uint8 * 32).from_buffer_copy(b_opk_priv),
        (ctypes.c_uint8 * 32).from_buffer_copy(a_ik_pub),
        (ctypes.c_uint8 * 32).from_buffer_copy(a_ek_pub),
        opk_present
    )
    if rc != 0:
        return jsonify({"error": "x3dh_receiver failed"}), 500

    return jsonify({"ok": True, "shared_key": b64e(bytes(out)), "opk_used": bool(opk_present)})



@app.post("/crypto/sign_msg")
def sign_msg():
    data, err = require_auth_json()
    if err:
        return err

    
    msg = b64d(data["msg_b64"])
    ik_sign_priv = b64d(data["ik_sign_priv"])

    if len(ik_sign_priv) != 64:
        return jsonify({"error": "ik_sign_priv must be 64 bytes"}), 400

    msg_buf = (ctypes.c_uint8 * len(msg)).from_buffer_copy(msg)
    sk_buf  = (ctypes.c_uint8 * 64).from_buffer_copy(ik_sign_priv)
    sig_out = (ctypes.c_uint8 * 64)()

    rc = crypto.ed25519_sign(msg_buf, len(msg), sk_buf, sig_out)
    if rc != 0:
        return jsonify({"error": "sign failed"}), 500

    sig = bytes(sig_out)
    return jsonify({"ok": True, "sig_b64": b64e(sig)})


@app.post("/crypto/verify_msg")
def verify_msg():
    data, err = require_auth_json()
    if err:
        return err

    msg = b64d(data["msg_b64"])
    sig = b64d(data["sig_b64"])
    ik_sign_pub = b64d(data["ik_sign_pub"])

    if len(ik_sign_pub) != 32:
        return jsonify({"error": "ik_sign_pub must be 32 bytes"}), 400
    if len(sig) != 64:
        return jsonify({"error": "sig must be 64 bytes"}), 400

    msg_buf = (ctypes.c_uint8 * len(msg)).from_buffer_copy(msg)
    pk_buf  = (ctypes.c_uint8 * 32).from_buffer_copy(ik_sign_pub)
    sig_buf = (ctypes.c_uint8 * 64).from_buffer_copy(sig)

    rc = crypto.ed25519_verify(msg_buf, len(msg), pk_buf, sig_buf)
    return jsonify({"ok": True, "valid": (rc == 0)})

@app.post("/crypto/random_bytes")
def crypto_random_bytes():
    data, err = require_auth_json()
    if err:
        return err

    n = int(data.get("n", 0))
    if n <= 0 or n > 4096:
        return jsonify({"error": "bad n"}), 400

    out = (ctypes.c_uint8 * n)()
    rc = crypto.random_bytes(out, n)
    if rc != 0:
        return jsonify({"error": "random failed"}), 500

    return jsonify({"ok": True, "bytes_b64": b64e(bytes(out))})


@app.post("/crypto/pwhash_derive_key")
def crypto_pwhash_derive_key():
    data, err = require_auth_json()
    if err:
        return err

    passphrase = data.get("passphrase", "")
    salt_b64 = data.get("salt_b64", None)
    if salt_b64 is None:
        return jsonify({"error": "missing salt_b64"}), 400

    salt = b64d(salt_b64)
    if len(salt) != 16:
        return jsonify({"error": "salt must be 16 bytes"}), 400

  
    pw = passphrase.encode("utf-8")

    pw_buf = (ctypes.c_uint8 * len(pw)).from_buffer_copy(pw)
    salt_buf = (ctypes.c_uint8 * 16).from_buffer_copy(salt)
    out = (ctypes.c_uint8 * 32)()

    rc = crypto.pwhash_argon2id_32(pw_buf, len(pw), salt_buf, out)
    if rc != 0:
        return jsonify({"error": "pwhash failed"}), 500

    return jsonify({"ok": True, "key_b64": b64e(bytes(out))})


@app.get("/auth/challenge/<user>")
def auth_challenge(user):
    store = load_store()
    u = store.get("users", {}).get(user)
    bundle = (u or {}).get("bundle")
    if not bundle:
        return jsonify({"error": "unknown user"}), 404

    ch = secrets.token_urlsafe(32)
    AUTH_CHALLENGES[user] = {"challenge": ch, "ts": time.time()}
    return jsonify({"challenge": ch})

@app.post("/auth/prove/<user>")
def auth_prove(user):
    data, err = require_auth_json()
    if err:
        return err
    if "sig_b64" not in data:
        return jsonify({"error": "missing sig_b64"}), 400

    store = load_store()
    u = store.get("users", {}).get(user)
    bundle = (u or {}).get("bundle")
    if not bundle:
        return jsonify({"error": "unknown user"}), 404

    rec = AUTH_CHALLENGES.get(user)
    if not rec:
        return jsonify({"error": "no active challenge"}), 400
    if time.time() - rec["ts"] > CHALLENGE_TTL:
        AUTH_CHALLENGES.pop(user, None)
        return jsonify({"error": "challenge expired"}), 400

    challenge_bytes = rec["challenge"].encode("utf-8")


    msg_buf = (ctypes.c_uint8 * len(challenge_bytes)).from_buffer_copy(challenge_bytes)
    pk_buf  = (ctypes.c_uint8 * 32).from_buffer_copy(b64d(bundle["ik_sign_pub"]))
    sig_buf = (ctypes.c_uint8 * 64).from_buffer_copy(b64d(data["sig_b64"]))

    rc = crypto.ed25519_verify(msg_buf, len(challenge_bytes), pk_buf, sig_buf)
    if rc != 0:
        return jsonify({"error": "bad signature"}), 403

    AUTH_CHALLENGES.pop(user, None)
    AUTH_OK.add(user)
    return jsonify({"ok": True})

@app.post("/crypto/hash32")
def hash32():
    data, err = require_auth_json()
    if err:
        return err

    msg = b64d(data["data_b64"])
    out = (ctypes.c_uint8 * 32)()
    crypto.hash32(msg, len(msg), out)

    return jsonify({"out_b64": b64e(bytes(out))})

@app.post("/crypto/aead_encrypt")
def aead_encrypt():
    data, err = require_auth_json()
    if err:
        return err

    key = b64d(data["key_b64"])
    nonce = b64d(data["nonce_b64"])
    pt = b64d(data["plaintext_b64"])
    ad = b64d(data.get("ad_b64", "")) if data.get("ad_b64") else b""

    ct = (ctypes.c_uint8 * (len(pt) + 16))()
    ct_len = ctypes.c_size_t()

    rc = crypto.aead_encrypt(
        key, nonce,
        pt, len(pt),
        ad, len(ad),
        ct, ctypes.byref(ct_len)
    )
    if rc != 0:
        return jsonify({"error": "encrypt failed"}), 400

    return jsonify({"ciphertext_b64": b64e(bytes(ct[:ct_len.value]))})



@app.post("/crypto/aead_decrypt")
def aead_decrypt():
    data, err = require_auth_json()
    if err:
        return err

    key = b64d(data["key_b64"])
    nonce = b64d(data["nonce_b64"])
    ct = b64d(data["ciphertext_b64"])
    ad = b64d(data.get("ad_b64", "")) if data.get("ad_b64") else b""

    pt = (ctypes.c_uint8 * len(ct))()
    pt_len = ctypes.c_size_t()

    rc = crypto.aead_decrypt(
        key, nonce,
        ct, len(ct),
        ad, len(ad),
        pt, ctypes.byref(pt_len)
    )
    if rc != 0:
        return jsonify({"error": "decrypt failed"}), 400

    return jsonify({"plaintext_b64": b64e(bytes(pt[:pt_len.value]))})





@app.post("/bundle/<user>")
def post_bundle(user):
    data, err = require_auth_json()
    if err:
        return err

    required = ["ik_dh_pub", "ik_sign_pub", "spk_id", "spk_pub", "spk_sig", "opks"]
    for k in required:
        if k not in data:
            return jsonify({"error": f"missing {k}"}), 400

    if not isinstance(data["opks"], list):
        return jsonify({"error": "opks must be a list"}), 400

    opks = []
    for item in data["opks"]:
        if "id" not in item or "pub" not in item:
            return jsonify({"error": "each opk needs id and pub"}), 400
        opks.append({"id": int(item["id"]), "pub": item["pub"], "used": False})

    store = load_store()

    # ---- Milestone 4: require proof for updates ----
    exists = user in store.get("users", {}) and "bundle" in store["users"][user]
    if exists:
        if user not in AUTH_OK:
            return jsonify({"error": "update requires auth proof"}), 403
        AUTH_OK.remove(user)  # one-time
    # ----------------------------------------------

    store["users"].setdefault(user, {})["bundle"] = {
        "ik_dh_pub": data["ik_dh_pub"],
        "ik_sign_pub": data["ik_sign_pub"],
        "spk_id": int(data["spk_id"]),
        "spk_pub": data["spk_pub"],
        "spk_sig": data["spk_sig"],
        "opks": opks
    }
    save_store(store)
    return jsonify({"ok": True})


@app.get("/bundle/<user>")
def get_bundle(user):
    store = load_store()
    bundle = store["users"].get(user, {}).get("bundle")
    if not bundle:
        return jsonify({"error": f"no bundle for {user}"}), 404

    chosen = None
    for opk in bundle["opks"]:
        if not opk.get("used", False):
            opk["used"] = True
            chosen = {"id": opk["id"], "pub": opk["pub"]}
            break

    save_store(store)

    return jsonify({
        "ik_dh_pub": bundle["ik_dh_pub"],
        "ik_sign_pub": bundle["ik_sign_pub"],
        "spk_id": bundle["spk_id"],
        "spk_pub": bundle["spk_pub"],
        "spk_sig": bundle["spk_sig"],
        "opk": chosen
    })

@app.post("/mailbox/<user>")
def post_mailbox(user):
    data, err = require_auth_json()
    if err:
        return err

    
    required_base = ["from", "to", "init", "counter", "nonce_b64", "ciphertext_b64"]
    for k in required_base:
        if k not in data:
            return jsonify({"error": f"missing {k}"}), 400

    if data["to"] != user:
        return jsonify({"error": "recipient mismatch"}), 400


    if data["init"] is True:
        required_init = ["sender_ik_dh_pub", "sender_ek_pub", "receiver_spk_id", "receiver_opk_id"]
        for k in required_init:
            if k not in data:
                return jsonify({"error": f"missing {k}"}), 400

    store = load_store()

    msg = {
        "init": bool(data["init"]),
        "from": data["from"],
        "to": data["to"],
        "counter": int(data["counter"]),
        "nonce_b64": data["nonce_b64"],
        "ciphertext_b64": data["ciphertext_b64"],
    }

    if data["init"] is True:
        msg.update({
            "sender_ik_dh_pub": data["sender_ik_dh_pub"],
            "sender_ek_pub": data["sender_ek_pub"],
            "receiver_spk_id": int(data["receiver_spk_id"]),
            "receiver_opk_id": data["receiver_opk_id"],  # may be null
        })

    store["mailbox"].setdefault(user, []).append(msg)
    save_store(store)
    return jsonify({"ok": True})



@app.get("/mailbox/<user>")
def get_mailbox(user): 
    store = load_store()
    msgs = store["mailbox"].get(user, [])
    if not msgs:
        return jsonify({"msg": None})

    msg = msgs.pop(0)
    store["mailbox"][user] = msgs
    save_store(store)
    return jsonify({"msg": msg})



if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
