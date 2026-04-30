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

readable_error obj:
  if obj.contains "error":
    return obj["error"]
  return null

ensure_user_dir user:
  path := "state/$user"
  if not fs.is-directory path:
    dir.mkdir path

save_text path text:
  fs.write-contents text --path=path

read_text path:
  data := fs.read-contents path
  return data.to-string.trim

b64_encode x:
  
  if x is string:
    return base64.encode (x as string).to-byte-array
  
  return base64.encode x



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

vault_encrypt user passphrase plaintext_utf8:
  salt_b64 := random_bytes_b64 16
  nonce_b64 := random_bytes_b64 24
  key_b64 := pwhash_key_b64 passphrase salt_b64

  enc := post_json_once "$(BASE)/crypto/aead_encrypt" {
    "auth": AUTH,
    "key_b64": key_b64,
    "nonce_b64": nonce_b64,
    "plaintext_b64": b64_encode plaintext_utf8,
    "ad_b64": vault_ad_b64 user
  }

  return {
    "ciphertext_b64": enc["ciphertext_b64"],
    "salt_b64": salt_b64,
    "nonce_b64": nonce_b64
  }

main args:
  if args.size < 2:
    print "Usage: client_register.toit <user> <passphrase>"
    return

  user := args[0]
  passphrase := args[1]

  ensure_user_dir user

  
  ik_dh := post_json_once "$(BASE)/crypto/keygen_x25519" {"auth": AUTH}
  ik_sign := post_json_once "$(BASE)/crypto/keygen_ed25519" {"auth": AUTH}

 
  spk := post_json_once "$(BASE)/crypto/keygen_x25519" {"auth": AUTH}
  spk_id := 1

  spk_sig_obj := post_json_once "$(BASE)/crypto/sign_spk" {
    "auth": AUTH,
    "ik_sign_priv": ik_sign["sk"],
    "spk_pub": spk["pub"]
  }
  spk_sig := spk_sig_obj["spk_sig"]

 
  opks := []
  opk_priv_map := {:}   
  opk_count := 5
  for i := 0; i < opk_count; i++:
    opk := post_json_once "$(BASE)/crypto/keygen_x25519" {"auth": AUTH}
    opk_id := i + 1
    opks.add {"id": opk_id, "pub": opk["pub"]}
    opk_priv_map["$opk_id"] = opk["priv"]

  //  Build vault plaintext JSON 
  vault_obj := {
    "ik_dh_priv": ik_dh["priv"],
    "ik_sign_priv": ik_sign["sk"],
    "spk_priv": {"$spk_id": spk["priv"]},
    "opk_priv": opk_priv_map
  }
  vault_plain := json.encode vault_obj

  //  Encrypt vault -> secrets.enc + secrets_meta.json
  v := vault_encrypt user passphrase vault_plain
  save_text "state/$user/secrets.enc" v["ciphertext_b64"]

  meta := {
    "salt_b64": v["salt_b64"],
    "nonce_b64": v["nonce_b64"]
  }
  save_text "state/$user/secrets_meta.json" (json.encode meta)


  save_text "state/$user/ik_dh_pub.b64"  ik_dh["pub"]
  save_text "state/$user/ik_sign_pub.b64" ik_sign["pk"]
  save_text "state/$user/spk_pub_$(spk_id).b64" spk["pub"]

  bundle_public := {
    "ik_dh_pub": ik_dh["pub"],
    "ik_sign_pub": ik_sign["pk"],
    "spk_id": spk_id,
    "spk_pub": spk["pub"],
    "spk_sig": spk_sig,
    "opks": opks
  }
  save_text "state/$user/public.json" (json.encode bundle_public)

 
  publish := {
    "auth": AUTH,
    "ik_dh_pub": ik_dh["pub"],
    "ik_sign_pub": ik_sign["pk"],
    "spk_id": spk_id,
    "spk_pub": spk["pub"],
    "spk_sig": spk_sig,
    "opks": opks
  }

  resp := post_json_once "$(BASE)/bundle/$(user)" publish
  err := readable_error resp
  if err != null:
    print "Register failed: $(err)"
    return

  print "Registered $(user). Vault saved as secrets.enc (keys-at-rest protected)."
