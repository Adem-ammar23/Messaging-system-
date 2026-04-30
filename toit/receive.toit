import http
import net
import encoding.json
import encoding.base64
import host.file as fs

AUTH ::= "dev-secret"
BASE ::= "http://127.0.0.1:5000"

post_json_once uri payload:
  network := net.open
  client := http.Client network
  res := client.post_json --uri=uri payload
  obj := json.decode_stream res.body
  client.close
  return obj

get_json_once host path:
  network := net.open
  client := http.Client network
  res := client.get host path
  obj := json.decode_stream res.body
  client.close
  return obj

read_text path:
  data := fs.read-contents path
  return data.to-string.trim

load_json_file path:
  data := fs.read-contents path
  return json.decode data

load_sessions user:
  path := "state/$user/sessions.json"
  if not fs.is-file path:
    return {:}
  data := fs.read-contents path
  return json.decode data

save_sessions user sessions:
  path := "state/$user/sessions.json"
  fs.write-contents (json.encode sessions) --path=path

b64_of_utf8 s:
  return base64.encode s.to-byte-array

utf8_of_b64 b64:
  bytes := base64.decode b64
  return  bytes.to-string

hash32_bytes bytes:
  resp := post_json_once "$(BASE)/crypto/hash32" {
    "auth": AUTH,
    "data_b64": base64.encode bytes
  }
  return resp["out_b64"]

hash32_concat prefix_str bytes_tail:
  prefix := prefix_str.to-byte-array
  buf := prefix + bytes_tail
  return hash32_bytes buf

derive_ck_pair sk_b64 from to:
  ctx := "$(from)->$(to)"
  sk := base64.decode sk_b64
  cks_in := ("CKS|" + ctx + "|").to-byte-array + sk
  ckr_in := ("CKR|" + ctx + "|").to-byte-array + sk
  return {"ck_send": hash32_bytes cks_in, "ck_recv": hash32_bytes ckr_in}

derive_mk_and_advance_ck ck_b64:
  ck := base64.decode ck_b64
  mk_b64 := hash32_concat "MK|" ck
  next_ck_b64 := hash32_concat "CK|" ck
  return {"mk": mk_b64, "next_ck": next_ck_b64}

ad_normal from to init counter:
  return b64_of_utf8 "from=$(from)|to=$(to)|init=$(init)|counter=$(counter)"

ad_init from to counter ik_pub ek_pub spk_id opk_id:
  return b64_of_utf8 "from=$(from)|to=$(to)|init=1|counter=$(counter)|ik=$(ik_pub)|ek=$(ek_pub)|spk=$(spk_id)|opk=$(opk_id)"

// -------- Vault decrypt ----------
vault_ad_b64 user:
  return b64_of_utf8 "vault-v1|$user"

pwhash_key_b64 passphrase salt_b64:
  r := post_json_once "$(BASE)/crypto/pwhash_derive_key" {
    "auth": AUTH,
    "passphrase": passphrase,
    "salt_b64": salt_b64
  }
  return r["key_b64"]

load_vault user passphrase:
  meta := load_json_file "state/$user/secrets_meta.json"
  ct_b64 := read_text "state/$user/secrets.enc"

  key_b64 := pwhash_key_b64 passphrase meta["salt_b64"]

  dec := post_json_once "$(BASE)/crypto/aead_decrypt" {
    "auth": AUTH,
    "key_b64": key_b64,
    "nonce_b64": meta["nonce_b64"],
    "ciphertext_b64": ct_b64,
    "ad_b64": vault_ad_b64 user
  }

  if dec.contains "error":
    print "Vault decrypt failed (wrong passphrase)"
    return null

  vault_plain := base64.decode dec["plaintext_b64"].to-string
  return json.decode vault_plain
// --------------------------------

main args:
  if args.size < 2:
    print "Usage: client_receive.toit <user> <passphrase>"
    return

  user := args[0]
  passphrase := args[1]

  vault := load_vault user passphrase
  if vault == null:
    return

  sessions := load_sessions user

  while true:
    box := get_json_once "127.0.0.1:5000" "/mailbox/$user"
    msg := box["msg"]
    if msg == null:
      break

    from_user := msg["from"]
    is_init := msg["init"]
    counter := msg["counter"]
    nonce_b64 := msg["nonce_b64"]
    ct_b64 := msg["ciphertext_b64"]

    if is_init:
      if not sessions.contains from_user:
        receiver_ik_priv := vault["ik_dh_priv"]

        spk_id := msg["receiver_spk_id"]
        receiver_spk_priv := (vault["spk_priv"])["$spk_id"]

        opk_id := msg["receiver_opk_id"]
        receiver_opk_priv := null
        if opk_id != null:
          receiver_opk_priv = (vault["opk_priv"])["$opk_id"]

        payload := {
          "auth": AUTH,
          "receiver_ik_priv": receiver_ik_priv,
          "receiver_spk_priv": receiver_spk_priv,
          "sender_ik_pub": msg["sender_ik_dh_pub"],
          "sender_ek_pub": msg["sender_ek_pub"]
        }
        if receiver_opk_priv != null:
          payload["receiver_opk_priv"] = receiver_opk_priv

        derived := post_json_once "$(BASE)/crypto/x3dh_receiver" payload
        sk_b64 := derived["shared_key"]

        ck_pair := derive_ck_pair sk_b64 from_user user

        // receiver swaps chains (sender's send chain = receiver's recv chain)
        sessions[from_user] = {
          "ck_send": ck_pair["ck_recv"],
          "ck_recv": ck_pair["ck_send"],
          "send_counter": 0,
          "recv_counter": 0
        }
        save_sessions user sessions
        print "[init] Session created with $from_user"

      sess := sessions[from_user]
      expected := sess["recv_counter"]
      if counter != expected:
        print "[replay/out-of-order] from $from_user counter=$counter expected=$expected (dropped)"
        continue

      mk_step := derive_mk_and_advance_ck sess["ck_recv"]
      mk_b64 := mk_step["mk"]
      next_ck_recv_b64 := mk_step["next_ck"]

      ad_b64 := ad_init from_user user counter msg["sender_ik_dh_pub"] msg["sender_ek_pub"] msg["receiver_spk_id"] msg["receiver_opk_id"]

      dec := post_json_once "$(BASE)/crypto/aead_decrypt" {
        "auth": AUTH,
        "key_b64": mk_b64,
        "nonce_b64": nonce_b64,
        "ciphertext_b64": ct_b64,
        "ad_b64": ad_b64
      }
      if dec.contains "error":
        print "[decrypt failed] from $from_user (dropped)"
        continue

      plaintext := utf8_of_b64 dec["plaintext_b64"]
      print "[msg] from $from_user: $plaintext"

      sess["ck_recv"] = next_ck_recv_b64
      sess["recv_counter"] = expected + 1
      sessions[from_user] = sess
      save_sessions user sessions
      continue

    // normal message
    if not sessions.contains from_user:
      print "[warn] message from $from_user but no session exists (ignored)"
      continue

    sess := sessions[from_user]
    expected := sess["recv_counter"]
    if counter != expected:
      print "[replay/out-of-order] from $from_user counter=$counter expected=$expected (dropped)"
      continue

    mk_step := derive_mk_and_advance_ck sess["ck_recv"]
    mk_b64 := mk_step["mk"]
    next_ck_recv_b64 := mk_step["next_ck"]

    ad_b64 := ad_normal from_user user 0 counter

    dec := post_json_once "$(BASE)/crypto/aead_decrypt" {
      "auth": AUTH,
      "key_b64": mk_b64,
      "nonce_b64": nonce_b64,
      "ciphertext_b64": ct_b64,
      "ad_b64": ad_b64
    }
    if dec.contains "error":
      print "[decrypt failed] from $from_user (dropped)"
      continue

    plaintext := utf8_of_b64 dec["plaintext_b64"]
    print "[msg] from $from_user: $plaintext"

    sess["ck_recv"] = next_ck_recv_b64
    sess["recv_counter"] = expected + 1
    sessions[from_user] = sess
    save_sessions user sessions

  print "Inbox empty."
