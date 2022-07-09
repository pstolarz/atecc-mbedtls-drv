/**
 * Copyright (c) 2022 Piotr Stolarz
 * ATECC MbedTLS driver.
 *
 * Distributed under the 2-clause BSD License (the License)
 * see accompanying file LICENSE for details.
 *
 * This software is distributed WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the License for more information.
 */

#ifndef __ATECC_MBEDTLS_DRV_H__
#define __ATECC_MBEDTLS_DRV_H__

#include <stdbool.h>
#include "mbedtls/pk.h"
#include "lib/atca_status.h"

#ifdef __cplusplus
extern "C" {
#endif

static const uint8_t PUBKEY_DER_PREF[] =
{
    /* SEQENCE (89 len) */
    0x30, 0x59,
    /* | SEQENCE (19 len) */
    0x30, 0x13,
    /* | | OBJECT IDENTIFIER (7 len): 1.2.840.10045.2.1 ecPublicKey */
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    /* | | OBJECT IDENTIFIER (8 len): 1.2.840.10045.3.1.7 prime256v1 */
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    /* | BIT STRING (66 len) */
    0x03, 0x42,
    0x00, 0x04  /* leftmost zero padding & "uncompressed" tag */

    /* X, Y coordinates start afterwards */
};

#define PUBKEY_DER_SIZE (sizeof(PUBKEY_DER_PREF) + 64)

/**
 * Initialize ATECC driver.
 *
 * @param dh_key_slot Key slot number (0..15) used for ECDH/ECDHE key exchange.
 *
 * @return ATCA_SUCCESS: success, error otherwise.
 */
ATCA_STATUS atecc_drv_init(int dh_key_slot);

/**
 * Get I2C mbed OS driver used by the library.
 */
struct I2C *atecc_drv_get_i2c(void);

/**
 * Get key slot number used for ECDH/ECDHE key exchange.
 */
int atecc_drv_get_dh_key_slot(void);

/**
 * Set key slot number (0..15) used for ECDH/ECDHE key exchange.
 *
 * @return ATCA_SUCCESS: success, ATCA_BAD_PARAM: invalid slot number.
 */
ATCA_STATUS atecc_drv_set_dh_key_slot(int dh_key_slot);

typedef uint8_t atecc_sn_t[9];

/**
 * Get device s/n.
 *
 * @return ATCA_SUCCESS: success, error otherwise.
 */
ATCA_STATUS atecc_get_sn(atecc_sn_t sn);

/**
 * Print ATECC device config zone.
 */
void atecc_drv_print_cfgzone(void);

/**
 * Get public key from a given slot.
 *
 * @param slot Slot number of a key to retrieve (0-based).
 * @param der_key Place where a key will be written in a DER format
 *     (must point to a PUBKEY_DER_SIZE size table).
 * @param print_pem If @true print a result on stdout (PEM format).
 *
 * @return ATCA_SUCCESS: success, error otherwise.
 */
ATCA_STATUS atecc_drv_get_pubkey(
    int slot, uint8_t der_key[PUBKEY_DER_SIZE], bool print_pem);

/**
 * Generate key pair for a given slot.
 *
 * @param slot Slot number the key will be ganarated for (0-based).
 * @param der_key Place where a public part of the newly generated key will
 *     be written in a DER format (must point to a PUBKEY_DER_SIZE size table).
 * @param print_pem If @true print a result on stdout (PEM format).
 *
 * @return ATCA_SUCCESS: success, error otherwise.
 */
ATCA_STATUS atecc_drv_gen_key(
    int slot, uint8_t der_key[PUBKEY_DER_SIZE], bool print_pem);

/**
 * Retrieve mbedTLS key context for an ATECC key.
 * The context allows mbedTLS PK API for ECC cryptograpty to be used together
 * with ATECC device.
 *
 * @param ctx Context to be retrieved.
 * @param slot Slot number of a key (0-based).
 *
 * @return ATCA_SUCCESS: success, error otherwise.
 */
ATCA_STATUS atecc_drv_mbedtls_pk_parse_key(mbedtls_pk_context *ctx, int slot);

#if (CONFIG_ATECC_DRV_CERT_GEN_SUPPORT != 0)

/**
 * Generate a X509v3 self-signed certificate for a key located in a given slot.
 *
 * @param slot Slot number with a key for which a certificate will be generated
 *     (0-based).
 * @param subject_name Subject name (e.g. "C=PL,CN=pstolarz").
 * @param not_before Start of a validity time; date(1) format: "YYYYmmddHHMMSS").
 * @param not_after End of a validity time; same format as for @c not_before.
 * @param serial Serial number.
 * @param ca_cert If @c true CA certificate is generated.
 * @param der_crt Place where a certificate will be written in a DER format.
 * @param len As an input indicates @c der_crt table size. As an output: length
 *     of a generated certificate size.
 * @param print_pem If @true print a result on stdout (PEM format).
 *
 * @return ATCA_SUCCESS: success, error otherwise.
 */
ATCA_STATUS atecc_drv_gen_selfsigned_crt(
    int slot, const char *subject_name, const char *not_before,
    const char *not_after, const char *serial, bool ca_cert,
    unsigned char *der_crt, size_t *len, bool print_pem);

/**
 * Generate a X509 certificate request (CSR) for a key located in a given slot.
 *
 * @param slot Slot number with a key for which a request will be generated
 *     (0-based).
 * @param subject_name Subject name (e.g. "C=PL,CN=pstolarz").
 * @param key_usage Bitmap indicating intended key usage (@c MBEDTLS_X509_KU_XXX).
 * @param der_csr Place where a request will be written in a DER format.
 * @param len As an input indicates @c der_csr table size. As an output: length
 *     of a generated request size.
 * @param print_pem If @true print a result on stdout (PEM format).
 *
 * @return ATCA_SUCCESS: success, error otherwise.
 */
ATCA_STATUS atecc_drv_gen_csr(
    int slot, const char *subject_name, unsigned char key_usage,
    unsigned char *der_csr, size_t *len, bool print_pem);

#endif /* CONFIG_ATECC_DRV_CERT_GEN_SUPPORT */

#ifdef __cplusplus
}
#endif

#endif /* __ATECC_MBEDTLS_DRV_H__ */
