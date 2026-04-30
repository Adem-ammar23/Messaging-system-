#include <stdint.h>
#include <string.h>

#ifdef _WIN32
  #define EXPORT __declspec(dllexport)
#else
  #define EXPORT
#endif

#include "sodium.h"


EXPORT int crypto_test32(uint8_t out[32]) {
  for (int i = 0; i < 32; i++) out[i] = (uint8_t)(i + 1);
  return 0;
}


EXPORT int sodium_init_wrapper() {
  return sodium_init();
}

EXPORT int random_bytes(uint8_t *out, size_t n) {
    randombytes_buf(out, n);
    return 0;
}



EXPORT int ed25519_keypair(uint8_t pk[32], uint8_t sk[64]) {
 
  return crypto_sign_keypair(pk, sk);
}


EXPORT int x25519_keypair(uint8_t pk[32], uint8_t sk[32]) {
 
  crypto_kx_keypair(pk, sk);
  return 0;
}

EXPORT int ed25519_sign(const uint8_t* msg, uint32_t msg_len,
                        const uint8_t sk[64], uint8_t sig[64]) {
  
  return crypto_sign_detached(sig, NULL, msg, msg_len, sk);
}


EXPORT int ed25519_verify(const uint8_t* msg, uint32_t msg_len,
                          const uint8_t pk[32], const uint8_t sig[64]) {
  return crypto_sign_verify_detached(sig, msg, msg_len, pk);
}


EXPORT int x25519_dh(uint8_t dh[32], const uint8_t sk[32], const uint8_t pk[32]) {
  
  return crypto_scalarmult_curve25519(dh, sk, pk);
}


static void x3dh_kdf(uint8_t out32[32], const uint8_t* dhs, uint32_t dhs_len) {
 
  const char prefix[] = "X3DH";
  uint8_t buf[4 + 128];
  memcpy(buf, prefix, 4);
  memcpy(buf + 4, dhs, dhs_len);
  crypto_generichash(out32, 32, buf, 4 + dhs_len, NULL, 0);
}

// Alice side derive:
// DH1 = DH(A_ik_priv,  B_spk_pub)
// DH2 = DH(A_ek_priv,  B_ik_pub)
// DH3 = DH(A_ek_priv,  B_spk_pub)
// DH4 = DH(A_ek_priv,  B_opk_pub)   (optional)

EXPORT int x3dh_derive_alice(
  uint8_t out32[32],
  const uint8_t a_ik_priv[32],
  const uint8_t a_ek_priv[32],
  const uint8_t b_ik_pub[32],
  const uint8_t b_spk_pub[32],
  const uint8_t b_opk_pub[32], 
  int opk_present
) {
  uint8_t dh[4 * 32];
  uint32_t off = 0;

  if (x25519_dh(dh + off, a_ik_priv, b_spk_pub) != 0) return -1; off += 32;
  if (x25519_dh(dh + off, a_ek_priv, b_ik_pub)  != 0) return -1; off += 32;
  if (x25519_dh(dh + off, a_ek_priv, b_spk_pub) != 0) return -1; off += 32;

  if (opk_present) {
    if (x25519_dh(dh + off, a_ek_priv, b_opk_pub) != 0) return -1;
    off += 32;
  }

  x3dh_kdf(out32, dh, off);
  sodium_memzero(dh, sizeof(dh));
  return 0;
}

// Bob side derive:
// Bob receives Alice IK_pub and EK_pub.
// DH1 = DH(B_spk_priv, A_ik_pub)
// DH2 = DH(B_ik_priv,  A_ek_pub)
// DH3 = DH(B_spk_priv, A_ek_pub)
// DH4 = DH(B_opk_priv, A_ek_pub)   ( if there is an OPK available in the server)

EXPORT int x3dh_derive_bob(
  uint8_t out32[32],
  const uint8_t b_ik_priv[32],
  const uint8_t b_spk_priv[32],
  const uint8_t b_opk_priv[32], 
  const uint8_t a_ik_pub[32],
  const uint8_t a_ek_pub[32],
  int opk_present
) {
  uint8_t dh[4 * 32];
  uint32_t off = 0;

  if (x25519_dh(dh + off, b_spk_priv, a_ik_pub) != 0) return -1; off += 32;
  if (x25519_dh(dh + off, b_ik_priv,  a_ek_pub) != 0) return -1; off += 32;
  if (x25519_dh(dh + off, b_spk_priv, a_ek_pub) != 0) return -1; off += 32;

  if (opk_present) {
    if (x25519_dh(dh + off, b_opk_priv, a_ek_pub) != 0) return -1;
    off += 32;
  }

  x3dh_kdf(out32, dh, off);
  sodium_memzero(dh, sizeof(dh));
  return 0;
}


EXPORT int hash32(
    const uint8_t *in, size_t in_len,
    uint8_t *out32
) {
    crypto_generichash(out32, 32, in, in_len, NULL, 0);
    return 0;
}

EXPORT int aead_encrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *ad, size_t ad_len,
    uint8_t *ciphertext, size_t *ct_len
) {
    return crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext, ct_len,
        plaintext, pt_len,
        ad, ad_len,
        NULL,
        nonce, key
    );
}



EXPORT int aead_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *ad, size_t ad_len,
    uint8_t *plaintext, size_t *pt_len
) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext, pt_len,
        NULL,
        ciphertext, ct_len,
        ad, ad_len,
        nonce, key
    );
}
EXPORT int pwhash_argon2id_32(
    const uint8_t *pass, size_t pass_len,
    const uint8_t *salt16,
    uint8_t *out32
) {
    
    const unsigned long long opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
    const size_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;

    int rc = crypto_pwhash(
        out32, 32,
        (const char*)pass, (unsigned long long)pass_len,
        salt16,
        opslimit, memlimit,
        crypto_pwhash_ALG_ARGON2ID13
    );

    return rc; 
}

