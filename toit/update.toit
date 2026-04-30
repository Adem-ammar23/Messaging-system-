import http
import net
import encoding.json
import encoding.base64
import host.file as fs
import host.directory as dir

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

ensure_user_dir user:
  path := "state/$user"
  if not fs.is-directory path:
    dir.mkdir path

read_text path:
  data := fs.read-contents path
  return data.to-string.trim

save_text path text:
  fs.write-contents text --path=path

load_public user:
  path := "state/$user/public.json"
  if not fs.is-file path:
    return null
  data := fs.read-contents path
  return json.decode data

load_json_file path:
  data := fs.read-contents path
  return json.decode data


b64_encode x:
  if x is string:
    return base64.encode (x as string).to-byte-array
  return base64.encode x

// --- Vault helpers ---
vault_ad_b64 user:
  return b64_encode "vault-v1|$user"

random_bytes_b64 n:
  r := post_json_once "$(BASE)/crypto/random_bytes" {
    "auth": AUTH,
    "n": n
  }
  return r["bytes_b64"]

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
  vault_obj := json.decode vault_plain
  return {"vault": vault_obj, "meta": meta}

save_vault user passphrase meta vault_obj:
  
  nonce_b64 := random_bytes_b64 24
  key_b64 := pwhash_key_b64 passphrase meta["salt_b64"]
  plain := json.encode vault_obj

  enc := post_json_once "$(BASE)/crypto/aead_encrypt" {
    "auth": AUTH,
    "key_b64": key_b64,
    "nonce_b64": nonce_b64,
    "plaintext_b64": b64_encode plain,
    "ad_b64": vault_ad_b64 user
  }

  save_text "state/$user/secrets.enc" enc["ciphertext_b64"]

  meta2 := {
    "salt_b64": meta["salt_b64"],
    "nonce_b64": nonce_b64
  }
  save_text "state/$user/secrets_meta.json" (json.encode meta2)


main args:
  if args.size < 2:
    print "Usage: client_update_bundle.toit <user> <passphrase>"
    return

  user := args[0]
  passphrase := args[1]
  ensure_user_dir user

  
  ik_dh_pub := read_text "state/$user/ik_dh_pub.b64"
  ik_sign_pub := read_text "state/$user/ik_sign_pub.b64"

  
  loaded := load_vault user passphrase
  if loaded == null:
    return
  vault := loaded["vault"]
  meta := loaded["meta"]

  ik_sign_priv := vault["ik_sign_priv"]

  
  ch_resp := get_json_once "127.0.0.1:5000" "/auth/challenge/$(user)"
  if ch_resp.contains "error":
    print "Challenge failed: $(ch_resp["error"])"
    return
  challenge := ch_resp["challenge"]

  //  sign challenge 
  sign_resp := post_json_once "$(BASE)/crypto/sign_msg" {
    "auth": AUTH,
    "ik_sign_priv": ik_sign_priv,
    "msg_b64": b64_encode challenge
  }
  if sign_resp.contains "error":
    print "sign_msg failed: $(sign_resp["error"])"
    return
  sig_b64 := sign_resp["sig_b64"]

  //  prove ownership 
  prove_resp := post_json_once "$(BASE)/auth/prove/$(user)" {
    "auth": AUTH,
    "sig_b64": sig_b64
  }
  if prove_resp.contains "error":
    print "Prove failed: $(prove_resp["error"])"
    return

  // rotate SPK + OPKs 
  pub := load_public user
  spk_id := 1
  if pub != null and pub.contains "spk_id":
    spk_id = pub["spk_id"] + 1

  spk := post_json_once "$(BASE)/crypto/keygen_x25519" {"auth": AUTH}

  spk_sig_obj := post_json_once "$(BASE)/crypto/sign_spk" {
    "auth": AUTH,
    "ik_sign_priv": ik_sign_priv,
    "spk_pub": spk["pub"]
  }
  spk_sig := spk_sig_obj["spk_sig"]

  // Fresh OPKs (we obviously replace old set)
  opks := []
  opk_priv_map := {:}
  opk_count := 5
  for i := 0; i < opk_count; i++:
    opk := post_json_once "$(BASE)/crypto/keygen_x25519" {"auth": AUTH}
    opk_id := i + 1
    opks.add {"id": opk_id, "pub": opk["pub"]}
    opk_priv_map["$opk_id"] = opk["priv"]

  // we also Update vault with new priv keys 
  spk_priv_map := vault["spk_priv"]
  spk_priv_map["$spk_id"] = spk["priv"]

  vault["spk_priv"] = spk_priv_map
  vault["opk_priv"] = opk_priv_map

  
  save_vault user passphrase meta vault

  
  save_text "state/$user/spk_pub_$(spk_id).b64" spk["pub"]

  bundle_public := {
    "ik_dh_pub": ik_dh_pub,
    "ik_sign_pub": ik_sign_pub,
    "spk_id": spk_id,
    "spk_pub": spk["pub"],
    "spk_sig": spk_sig,
    "opks": opks
  }
  save_text "state/$user/public.json" (json.encode bundle_public)

  // ofc we then  publish updated bundle
  publish := {
    "auth": AUTH,
    "ik_dh_pub": ik_dh_pub,
    "ik_sign_pub": ik_sign_pub,
    "spk_id": spk_id,
    "spk_pub": spk["pub"],
    "spk_sig": spk_sig,
    "opks": opks
  }

  resp := post_json_once "$(BASE)/bundle/$(user)" publish
  if resp.contains "error":
    print "Update failed: $(resp["error"])"
    return

  print "Updated bundle for $(user) (SPK id $(spk_id))) + vault updated."
