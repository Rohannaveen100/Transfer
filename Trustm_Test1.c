#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "optiga_util.h"
#include "optiga_crypt.h"
#include "common/optiga_lib_common.h"

#define APP_PUBKEY_OID 0xF1D0u

static volatile optiga_lib_status_t g_status;

static void optiga_callback(void *context, optiga_lib_status_t status) {
    (void)context;
    g_status = status;
}

static int wait_for_completion(void) {
    while (g_status == OPTIGA_LIB_BUSY) { }
    return (g_status == OPTIGA_LIB_SUCCESS) ? 0 : -1;
}

static int extract_uncompressed_pubkey(const uint8_t *in, size_t in_len, uint8_t *out65) {
    if (in_len == 65 && in[0] == 0x04) {
        memcpy(out65, in, 65);
        return 0;
    }
    for (size_t i = 0; i + 2 < in_len; i++) {
        if (in[i] == 0x03 && i + 2 < in_len) {
            size_t bitlen = in[i+1], hdr = 2;
            if (bitlen & 0x80) {
                int n = bitlen & 0x7F;
                if (i + 2 + n >= in_len) return -1;
                bitlen = 0;
                for (int k = 0; k < n; k++) bitlen = (bitlen << 8) | in[i+2+k];
                hdr = 2 + n;
            }
            size_t j = i + hdr;
            if (j + 1 + 65 <= in_len && in[j] == 0x00 && in[j+1] == 0x04) {
                memcpy(out65, &in[j+1], 65);
                return 0;
            }
        }
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pubkey_raw_or_spki.der> <sig.der>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("pubkey"); return 1; }
    fseek(f, 0, SEEK_END);
    long pk_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *pk_buf = malloc(pk_len);
    fread(pk_buf, 1, pk_len, f);
    fclose(f);

    f = fopen(argv[2], "rb");
    if (!f) { perror("sig"); return 1; }
    fseek(f, 0, SEEK_END);
    long sig_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *sig_buf = malloc(sig_len);
    fread(sig_buf, 1, sig_len, f);
    fclose(f);

    uint8_t pubkey65[65];
    if (extract_uncompressed_pubkey(pk_buf, pk_len, pubkey65)) {
        fprintf(stderr, "Failed to parse public key\n");
        return 1;
    }

    g_status = OPTIGA_LIB_BUSY;
    optiga_util_t *util = optiga_util_create(0, optiga_callback, NULL);
    if (!util) { fprintf(stderr, "optiga_util_create failed\n"); return 1; }
    if (optiga_util_open_application(util, 0) != OPTIGA_LIB_SUCCESS ||
        wait_for_completion() != 0) {
        fprintf(stderr, "Open application failed\n");
        return 1;
    }

    g_status = OPTIGA_LIB_BUSY;
    optiga_util_write_data(util, APP_PUBKEY_OID, OPTIGA_UTIL_WRITE_ONLY, 0, pubkey65, sizeof(pubkey65));
    wait_for_completion();

    const uint8_t msg[] = "hello world";
    uint8_t digest[32];

    g_status = OPTIGA_LIB_BUSY;
    optiga_crypt_t *crypt = optiga_crypt_create(0, optiga_callback, NULL);
    if (!crypt) { fprintf(stderr, "optiga_crypt_create failed\n"); return 1; }
    if (optiga_crypt_hash(crypt, OPTIGA_HASH_TYPE_SHA_256, OPTIGA_COMMS_RESPONSE_PROTECTION, msg, digest) != OPTIGA_LIB_SUCCESS ||
        wait_for_completion() != 0) {
        fprintf(stderr, "hash failed\n");
        return 1;
    }

    g_status = OPTIGA_LIB_BUSY;
    if (optiga_crypt_ecdsa_verify(crypt,
                                  digest,
                                  sizeof(digest),
                                  sig_buf,
                                  (uint16_t)sig_len,
                                  OPTIGA_CRYPT_HOST_DATA,
                                  pubkey65) != OPTIGA_LIB_SUCCESS ||
        wait_for_completion() != 0) {
        fprintf(stderr, "ECDSA verify FAILED\n");
        return 1;
    }

    printf("ECDSA verify OK ✅\n");

    optiga_crypt_destroy(crypt);
    g_status = OPTIGA_LIB_BUSY;
    optiga_util_close_application(util, 0);
    wait_for_completion();

    optiga_util_destroy(util);
    free(pk_buf);
    free(sig_buf);
    return 0;
}
