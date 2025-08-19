#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "optiga/optiga_util.h"
#include "optiga/optiga_crypt.h"
#include "optiga/common/optiga_lib_common.h"

#define APP_PUBKEY_OID 0xF1D0u  // application data slot for our raw pubkey

static volatile optiga_lib_status_t g_status;

static void optiga_callback(void *context, optiga_lib_status_t status)
{
    (void)context;
    g_status = status;
}

static int wait_for_completion(void)
{
    // Very simple busy-wait; in production, add timeout handling
    while (g_status == OPTIGA_LIB_BUSY) { }
    return (g_status == OPTIGA_LIB_SUCCESS) ? 0 : -1;
}

// Extract uncompressed (0x04 || X || Y) from either raw 65B or DER SPKI
static int extract_uncompressed_pubkey(const uint8_t *in, size_t in_len,
                                       uint8_t *out65 /* must be >=65 */)
{
    if (in_len == 65 && in[0] == 0x04) {
        memcpy(out65, in, 65);
        return 0;
    }
    // naive DER scan for BIT STRING of length 65 starting with 0x04
    // SPKI: SEQ { algo, BIT STRING <0x00, pubkey> }
    for (size_t i = 0; i + 2 < in_len; i++) {
        if (in[i] == 0x03 /* BIT STRING */ && i+2 < in_len) {
            size_t bitlen = in[i+1];
            size_t hdr = 2;
            if (bitlen & 0x80) {
                int n = bitlen & 0x7F;
                if (i+2+n >= in_len) return -1;
                bitlen = 0;
                for (int k=0; k<n; k++) bitlen = (bitlen<<8) | in[i+2+k];
                hdr = 2 + n;
            }
            // expect unused-bits byte 0x00 then 65 bytes starting with 0x04
            size_t j = i + hdr;
            if (j+1+65 <= in_len && in[j] == 0x00 && in[j+1] == 0x04) {
                memcpy(out65, &in[j+1], 65);
                return 0;
            }
        }
    }
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pubkey_raw_or_spki.der> <sig.der>\n", argv[0]);
        return 1;
    }

    // Load files
    FILE *f = fopen(argv[1], "rb"); if (!f) { perror("pubkey"); return 1; }
    fseek(f, 0, SEEK_END); long pk_len = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *pk_buf = malloc(pk_len); fread(pk_buf, 1, pk_len, f); fclose(f);

    f = fopen(argv[2], "rb"); if (!f) { perror("sig"); return 1; }
    fseek(f, 0, SEEK_END); long sig_len = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *sig_buf = malloc(sig_len); fread(sig_buf, 1, sig_len, f); fclose(f);

    uint8_t pubkey65[65];
    if (extract_uncompressed_pubkey(pk_buf, pk_len, pubkey65) != 0) {
        fprintf(stderr, "Failed to parse public key\n");
        return 1;
    }

    // Initialize OPTIGA
    optiga_lib_status_t status = OPTIGA_LIB_ERROR;
    g_status = OPTIGA_LIB_BUSY;

    optiga_util_t *util = optiga_util_create(0, optiga_callback, NULL);
    if (!util) { fprintf(stderr, "optiga_util_create failed\n"); return 1; }
    status = optiga_util_open_application(util, 0); if (status != OPTIGA_LIB_SUCCESS) return 1;
    if (wait_for_completion() != 0) { fprintf(stderr, "open_application failed\n"); return 1; }

    // Write the 65-byte raw pubkey to OID F1D0 (set once per boot for demo; adjust access in metadata as needed)
    g_status = OPTIGA_LIB_BUSY;
    status = optiga_util_write_data(util, APP_PUBKEY_OID, OPTIGA_UTIL_WRITE_ONLY, 0, pubkey65, sizeof(pubkey65));
    if (status != OPTIGA_LIB_SUCCESS || wait_for_completion() != 0) {
        fprintf(stderr, "write OID 0x%04X failed (maybe locked?)\n", APP_PUBKEY_OID);
        // continue; maybe it was already written
    }

    // Verify signature over SHA-256("hello world")
    const uint8_t msg[] = "hello world";
    uint8_t digest[32];

    optiga_crypt_t *crypt = optiga_crypt_create(0, optiga_callback, NULL);
    if (!crypt) { fprintf(stderr, "optiga_crypt_create failed\n"); return 1; }

    // Hash
    g_status = OPTIGA_LIB_BUSY;
    status = optiga_crypt_hash_start(crypt, OPTIGA_HASH_TYPE_SHA_256);
    if (status != OPTIGA_LIB_SUCCESS || wait_for_completion() != 0) { fprintf(stderr, "hash_start failed\n"); return 1; }

    g_status = OPTIGA_LIB_BUSY;
    status = optiga_crypt_hash_update(crypt, msg, sizeof(msg)-1);
    if (status != OPTIGA_LIB_SUCCESS || wait_for_completion() != 0) { fprintf(stderr, "hash_update failed\n"); return 1; }

    g_status = OPTIGA_LIB_BUSY;
    uint16_t dlen = sizeof(digest);
    status = optiga_crypt_hash_finalize(crypt, digest, &dlen);
    if (status != OPTIGA_LIB_SUCCESS || wait_for_completion() != 0 || dlen != 32) { fprintf(stderr, "hash_finalize failed\n"); return 1; }

    // Build verification params: public key from host
    public_key_from_host_t pk_host;
    pk_host.public_key = pubkey65;
    pk_host.length = sizeof(pubkey65);
    pk_host.key_type = OPTIGA_ECC_NIST_P_256;

    optiga_verify_sign_t verify_params;
    memset(&verify_params, 0, sizeof(verify_params));
    verify_params.p_digest = digest;
    verify_params.digest_length = 32;
    verify_params.p_signature = sig_buf;
    verify_params.signature_length = (uint16_t)sig_len;
    verify_params.public_key_source_type = OPTIGA_CRL_VERIFY_PUBLIC_KEY_FROM_HOST;
    verify_params.public_key = &pk_host;

    g_status = OPTIGA_LIB_BUSY;
    status = optiga_crypt_ecdsa_verify(crypt, &verify_params);
    if (status != OPTIGA_LIB_SUCCESS || wait_for_completion() != 0) {
        fprintf(stderr, "ECDSA verify FAILED\n");
        return 1;
    }

    printf("ECDSA verify OK ✅\n");

    // Cleanup
    optiga_crypt_destroy(crypt);
    g_status = OPTIGA_LIB_BUSY;
    optiga_util_close_application(util, 0);
    wait_for_completion();
    optiga_util_destroy(util);

    free(pk_buf); free(sig_buf);
    return 0;
}
