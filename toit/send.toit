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

save_sessions user sessions:
  path := "state/$user/sessions.json"
  fs.write-contents (json.encode sessions) --path=path

load_sessions user:
  path := "state/$user/sessions.json"
  if not fs.is-file path:
    return {:}
  data := fs.read-contents path
  return json.decode data

b64_of_utf8 s:
  return base64.encode s.to-byte-array

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

  return {
    "ck_send": hash32_bytes cks_in,
    "ck_recv": hash32_bytes ckr_in
  }

derive_mk_and_advance_ck ck_b64:
  ck := base64.decode ck_b64
  mk_b64 := hash32_concat "MK|" ck
  next_ck_b64 := hash32_concat "CK|" ck
  return {"mk": mk_b64, "next_ck": next_ck_b64}

derive_nonce ck_b64 counter:
  ck := base64.decode ck_b64
  ctr_bytes := "$counter".to-byte-array
  h_b64 := hash32_bytes (("NONCE|").to-byte-array + ck + ("|").to-byte-array + ctr_bytes)
  h := base64.decode h_b64
  nonce24 := h[0..24]
  return base64.encode nonce24

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
  if args.size < 4:
    print "Usage: client_send.toit <from> <to> \"message\" <passphrase>"
    return

  from := args[0]
  to := args[1]
  text := args[2]
  passphrase := args[3]

  vault := load_vault from passphrase
  if vault == null:
    return

  sender_ik_priv := vault["ik_dh_priv"]
  sender_ik_pub  := read_text "state/$from/ik_dh_pub.b64"

  sessions := load_sessions from
  peer_session := sessions.get to

  // CASE: session already exists 
  if peer_session != null:
    ck_send_b64 := peer_session["ck_send"]
    send_counter := peer_session["send_counter"]

    mk_step := derive_mk_and_advance_ck ck_send_b64
    mk_b64 := mk_step["mk"]
    next_ck_send_b64 := mk_step["next_ck"]

    nonce_b64 := derive_nonce ck_send_b64 send_counter
    ad_b64 := ad_normal from to 0 send_counter
    pt_b64 := b64_of_utf8 text

    enc := post_json_once "$(BASE)/crypto/aead_encrypt" {
      "auth": AUTH,
      "key_b64": mk_b64,
      "nonce_b64": nonce_b64,
      "plaintext_b64": pt_b64,
      "ad_b64": ad_b64
    }

    peer_session["ck_send"] = next_ck_send_b64
    peer_session["send_counter"] = send_counter + 1
    sessions[to] = peer_session
    save_sessions from sessions

    msg := {
      "auth": AUTH,
      "init": false,
      "from": from,
      "to": to,
      "counter": send_counter,
      "nonce_b64": nonce_b64,
      "ciphertext_b64": enc["ciphertext_b64"]
    }
    send_message:= post_json_once "$(BASE)/mailbox/$to" msg
    print "Sent to $to (session, encrypted)"
    return

  // no session -> X3DH init
  print "No session with $to -> running X3DH"

  bundle := get_json_once "127.0.0.1:5000" "/bundle/$to"
  ek := post_json_once "$(BASE)/crypto/keygen_x25519" {"auth": AUTH}

  receiver_opk := bundle["opk"]
  receiver_opk_pub := null
  receiver_opk_id := null
  if receiver_opk != null:
    receiver_opk_pub = receiver_opk["pub"]
    receiver_opk_id = receiver_opk["id"]

  derived := post_json_once "$(BASE)/crypto/x3dh_sender" {
    "auth": AUTH,
    "sender_ik_priv": sender_ik_priv,
    "sender_ek_priv": ek["priv"],
    "receiver_ik_pub": bundle["ik_dh_pub"],
    "receiver_spk_pub": bundle["spk_pub"],
    "receiver_opk_pub": receiver_opk_pub
  }
  sk_b64 := derived["shared_key"]

  ck_pair := derive_ck_pair sk_b64 from to
  ck_send_b64 := ck_pair["ck_send"]
  ck_recv_b64 := ck_pair["ck_recv"]

  send_counter := 0
  mk_step := derive_mk_and_advance_ck ck_send_b64
  mk_b64 := mk_step["mk"]
  next_ck_send_b64 := mk_step["next_ck"]

  nonce_b64 := derive_nonce ck_send_b64 send_counter
  ad_b64 := ad_init from to send_counter sender_ik_pub ek["pub"] bundle["spk_id"] receiver_opk_id
  pt_b64 := b64_of_utf8 text

  enc := post_json_once "$(BASE)/crypto/aead_encrypt" {
    "auth": AUTH,
    "key_b64": mk_b64,
    "nonce_b64": nonce_b64,
    "plaintext_b64": pt_b64,
    "ad_b64": ad_b64
  }

  sessions[to] = {
    "ck_send": next_ck_send_b64,
    "ck_recv": ck_recv_b64,
    "send_counter": 1,
    "recv_counter": 0
  }
  save_sessions from sessions

  init_msg := {
    "auth": AUTH,
    "init": true,
    "from": from,
    "to": to,
    "sender_ik_dh_pub": sender_ik_pub,
    "sender_ek_pub": ek["pub"],
    "receiver_spk_id": bundle["spk_id"],
    "receiver_opk_id": receiver_opk_id,
    "counter": 0,
    "nonce_b64": nonce_b64,
    "ciphertext_b64": enc["ciphertext_b64"]
  }
  init_:= post_json_once "$(BASE)/mailbox/$to" init_msg
  print "Sent to $to (new session via X3DH, encrypted)"
