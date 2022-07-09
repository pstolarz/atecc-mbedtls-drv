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

/*
 * Driver implementing bridge interface between ATECC 508/608 devices and
 * mbedTLS library. Additionally there are provided some service functions
 * which may be helpful during integration of a mbedTLS-related code
 * with the ATECC devices.
 *
 * The code uses Atmel CryptoAuth library for communication with an ATECC
 * device.
 */

#include <stdio.h>

#include "lib/basic/atca_basic.h"
#include "hal/hal_mbedos_srv.h"
#include "atecc_mbedtls_drv.h"

#if (CONFIG_ATECC_DRV_CERT_GEN_SUPPORT != 0)
# include "mbedtls/ctr_drbg.h"
# include "mbedtls/entropy.h"
# include "mbedtls/error.h"
# include "mbedtls/x509_crt.h"
# include "mbedtls/x509_csr.h"
#endif
#include "mbedtls/platform.h"

static bool atca_inited = false;
static int dh_slot = 0;

#define I2C_BUS     0
#define I2C_FREQ    100000

static ATCAIfaceCfg cfg_atecc_i2c =
{
    .iface_type             = ATCA_I2C_IFACE,
    .devtype                = CONFIG_ATECC_DRV_DEV_TYPE,
    .atcai2c.slave_address  = 0xC0,
    .atcai2c.bus            = I2C_BUS,
    .atcai2c.baud           = I2C_FREQ,
    .wake_delay             = 1500,
    .rx_retries             = 5
};

static const uint8_t SLOT_MARKER[8] = {
    'E', 'C', 'C', 'S', 'L', 'O', 'T',
    0x00    /* slot number placeholder */
};

#define __DEF_SLOT_MARKER(_m) \
    uint8_t _m[sizeof(SLOT_MARKER)]

#define __INIT_SLOT_MARKER(_m, _s) \
    memcpy((_m), SLOT_MARKER, sizeof(SLOT_MARKER)); \
    (_m)[sizeof(SLOT_MARKER) - 1] = (uint8_t)(_s)

#define __GET_MARKER_SLOT(_m) \
    (_m)[sizeof(SLOT_MARKER) - 1]

#define __CHECK_SLOT_MARKER(_m) \
    memcmp((_m), SLOT_MARKER, sizeof(SLOT_MARKER)-1)


#define __CHECK_ATCA_ERR(_err, _fnc) \
    if ((_err) != ATCA_SUCCESS) { \
        mbedtls_printf("ERROR: " _fnc " failed: 0x%04X\n", _err); \
        goto cleanup; \
    }

#define __CHECK_MBED_ERR(_err, _fnc) \
    if ((_err) != 0) { \
        mbedtls_printf("ERROR: " _fnc " failed: -0x%04x\n", -_err); \
        goto cleanup; \
    }

ATCA_STATUS atecc_drv_init(int dh_key_slot)
{
    ATCA_STATUS ret;
    int bus_num;

    if (dh_key_slot < 0 || dh_key_slot > 15)
        return ATCA_BAD_PARAM;

    bus_num = hal_mbedos_i2c_bus_num();
    if (bus_num <= I2C_BUS)
        return ATCA_GEN_FAIL;

    ret = atcab_init(&cfg_atecc_i2c);
    __CHECK_ATCA_ERR(ret, "atcab_init");

    hal_mbedos_i2c_freq(I2C_BUS, I2C_FREQ);

    dh_slot = dh_key_slot;
    atca_inited = true;
cleanup:
    return ret;
}

struct I2C *atecc_drv_get_i2c(void)
{
    return hal_mbedos_i2c_get_bus_drv(I2C_BUS);
}

int atecc_drv_get_dh_key_slot(void)
{
    return dh_slot;
}

ATCA_STATUS atecc_drv_set_dh_key_slot(int dh_key_slot)
{
    if (dh_key_slot < 0 || dh_key_slot > 15)
        return ATCA_BAD_PARAM;

    dh_slot = dh_key_slot;
    return ATCA_SUCCESS;
}

ATCA_STATUS atecc_get_sn(atecc_sn_t sn)
{
    return atcab_read_serial_number(sn);
}

void atecc_drv_print_cfgzone(void)
{
    int i;
    ATCA_STATUS aret;
    uint8_t zone[ATCA_ECC_CONFIG_SIZE];

    if (!atca_inited) {
        mbedtls_printf("ERROR: ATCA uninitialized\n");
        return;
    }

    aret = atcab_read_config_zone(zone);
    __CHECK_ATCA_ERR(aret, "atcab_read_config_zone");

    mbedtls_printf("ECC config zone:\n");
    mbedtls_printf("  SN<0:3>: %02x:%02x:%02x:%02x\n",
        zone[0], zone[1], zone[2], zone[3]);
    mbedtls_printf("  RevNum: %02x:%02x:%02x:%02x\n",
        zone[4], zone[5], zone[6], zone[7]);
    mbedtls_printf("  SN<4:8>: %02x:%02x:%02x:%02x:%02x\n",
        zone[8], zone[9], zone[10], zone[11], zone[12]);
    mbedtls_printf("  I2C_Enable: %02x\n", zone[14]);
    mbedtls_printf("  I2C_Address: %02x\n", zone[16]);
    mbedtls_printf("  OTPmode: %02x\n", zone[18]);
    mbedtls_printf("  ChipMode: %02x\n", zone[19]);


    mbedtls_printf("  SlotConfig (BE):\n");
    for (i=0; i<32; i+=2) {
        uint8_t b1=zone[20+i], b2=zone[21+i];
        mbedtls_printf("    [%d] %02x%02x: ", i/2, b2, b1);
        mbedtls_printf("WriteConfig: %01x,", (b2>>4) & 0x0f);
        mbedtls_printf("WriteKey: %01x,", b2 & 0x0f);
        mbedtls_printf("IsSecret: %01x,", (b1 >> 7) & 1);
        mbedtls_printf("EncryptRead: %01x,", (b1 >> 6) & 1);
        mbedtls_printf("LimitedUse: %01x,", (b1 >> 5) & 1);
        mbedtls_printf("NoMac: %01x,", (b1 >> 4) & 1);
        mbedtls_printf("ReadKey: %01x\n", b1 & 0x0f);
    }

    mbedtls_printf("  Counter1 (BE): ");
    for (i=0; i<8; i++) mbedtls_printf("%02x", zone[59-i]);
    mbedtls_printf("\n");

    mbedtls_printf("  Counter2 (BE): ");
    for (i=0; i<8; i++) mbedtls_printf("%02x", zone[67-i]);
    mbedtls_printf("\n");

    mbedtls_printf("  LastKeyUse:");
    for (i=0; i<16; i++) mbedtls_printf("%c%02x", (i ? ':' : ' '), zone[68+i]);
    mbedtls_printf("\n");

    mbedtls_printf("  UserExtra: %02x\n", zone[84]);
    mbedtls_printf("  Selector: %02x\n", zone[85]);
    mbedtls_printf("  LockValue: %02x\n", zone[86]);
    mbedtls_printf("  LockConfig: %02x\n", zone[87]);
    mbedtls_printf("  SlotLocked: %02x:%02x\n", zone[88], zone[89]);
    mbedtls_printf("  X509Format: %02x:%02x:%02x:%02x\n",
        zone[92], zone[93], zone[94], zone[95]);

    mbedtls_printf("  KeyConfig (BE):\n");
    for (i=0; i<32; i+=2) {
        uint8_t b1=zone[96+i], b2=zone[97+i];
        mbedtls_printf("    [%d] %02x%02x: ", i/2, b2, b1);
        mbedtls_printf("X509id: %01x,", (b2>>6) & 3);
        mbedtls_printf("IntrusionDisable: %01x,", (b2>>4) & 1);
        mbedtls_printf("AuthKey: %01x,", b2 & 0x0f);
        mbedtls_printf("ReqAuth: %01x,", (b1>>7) & 1);
        mbedtls_printf("ReqRandom: %01x,", (b1>>6) & 1);
        mbedtls_printf("Lockable: %01x,", (b1>>5) & 1);
        mbedtls_printf("KeyType: %01x,", (b1>>2) & 7);
        mbedtls_printf("PubInfo: %01x,", (b1>>1) & 1);
        mbedtls_printf("Private: %01x\n", b1 & 1);
    }

cleanup:
    return;
}

static void print_x509_pem(
    const unsigned char *buf, size_t buf_len, const char *marker, char *b64_buf)
{
    size_t i;
    size_t to_alloc = 0;
    char *b64 = b64_buf;
    size_t pem_len = (3*buf_len)/2 + 4;

    if (!b64) {
        to_alloc = pem_len;
        b64 = (char*)mbedtls_calloc(to_alloc, 1);
    }

    if (b64 != NULL &&
        atcab_base64encode(buf, buf_len, b64, &pem_len) == ATCA_SUCCESS)
    {
        mbedtls_printf(marker, "BEGIN");
        for (i=0; i<pem_len; i++) putchar(b64[i]);
        mbedtls_printf("\n");
        mbedtls_printf(marker, "END");
    }

    if (to_alloc) mbedtls_free(b64);
}

/**
 * Encode raw ATECC key into DER format.
 */
static void atecc_drv_raw2der(const uint8_t raw[ATCA_PUB_KEY_SIZE],
    uint8_t der[PUBKEY_DER_SIZE], bool print_pem)
{
    /* create DER encoded key */
    memcpy(der, PUBKEY_DER_PREF, sizeof(PUBKEY_DER_PREF));
    memcpy(&der[sizeof(PUBKEY_DER_PREF)], raw, ATCA_PUB_KEY_SIZE);

    if (print_pem) {
        char b64[(3*PUBKEY_DER_SIZE)/2 + 4] = {};
        print_x509_pem(der, PUBKEY_DER_SIZE, "-----%s PUBLIC KEY-----\n", b64);
    }
}

ATCA_STATUS atecc_drv_get_pubkey(
    int slot, uint8_t der_key[PUBKEY_DER_SIZE], bool print_pem)
{
    uint8_t pub[ATCA_PUB_KEY_SIZE];
    ATCA_STATUS ret;

    if (!atca_inited) {
        mbedtls_printf("ERROR: ATCA uninitialized\n");
        return ATCA_FUNC_FAIL;
    }

    ret = atcab_get_pubkey(slot, pub);
    __CHECK_ATCA_ERR(ret, "atcab_get_pubkey");

    atecc_drv_raw2der(pub, der_key, print_pem);

cleanup:
    return ret;
}

ATCA_STATUS atecc_drv_gen_key(
    int slot, uint8_t der_key[PUBKEY_DER_SIZE], bool print_pem)
{
    uint8_t pub[ATCA_PUB_KEY_SIZE];
    ATCA_STATUS ret;

    if (!atca_inited) {
        mbedtls_printf("ERROR: ATCA uninitialized\n");
        return ATCA_FUNC_FAIL;
    }

    ret = atcab_genkey(slot, pub);
    __CHECK_ATCA_ERR(ret, "atcab_genkey");

    atecc_drv_raw2der(pub, der_key, print_pem);

cleanup:
    return ret;
}

ATCA_STATUS atecc_drv_mbedtls_pk_parse_key(mbedtls_pk_context *ctx, int slot)
{
    int mret;
    ATCA_STATUS ret;
    mbedtls_ecp_keypair *kp;
    uint8_t der_key[PUBKEY_DER_SIZE];

    __DEF_SLOT_MARKER(mrk);
    __INIT_SLOT_MARKER(mrk, slot);

    ret = atecc_drv_get_pubkey(slot, der_key, false);
    if (ret != ATCA_SUCCESS) goto cleanup;

    ret = ATCA_FUNC_FAIL;

    mret = mbedtls_pk_parse_public_key(ctx, der_key, sizeof(der_key));
    __CHECK_MBED_ERR(mret, "mbedtls_pk_parse_public_key");

    kp = mbedtls_pk_ec(*ctx);
    mret = mbedtls_mpi_read_binary(&kp->d, mrk, sizeof(mrk));
    __CHECK_MBED_ERR(mret, "mbedtls_mpi_read_binary");

    ret = ATCA_SUCCESS;

cleanup:
    return ret;
}

#if (CONFIG_ATECC_DRV_CERT_GEN_SUPPORT != 0)

/**
 * Returned CRT/CSR are written at the end of the output buffer.
 * The routine reverse the buffer to contain proper output.
 */
static void reverse_buf(unsigned char *buf, size_t buf_len, size_t out_len)
{
    size_t i;

    for (i=0; i < out_len; i++)
        buf[i] = buf[buf_len - out_len + i];

    /* clear the buffer tail */
    for (i=out_len; i < buf_len; i++) buf[i] = 0;
}

ATCA_STATUS atecc_drv_gen_selfsigned_crt(
    int slot, const char *subject_name, const char *not_before,
    const char *not_after, const char *serial, bool ca_cert,
    unsigned char *der_crt, size_t *len, bool print_pem)
{
    mbedtls_pk_context subject_key;
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial_num;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    int mret, crt_len;
    ATCA_STATUS ret = ATCA_FUNC_FAIL;

    mbedtls_pk_init(&subject_key);
    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi_init(&serial_num);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mret = mbedtls_ctr_drbg_seed(
        &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    __CHECK_MBED_ERR(mret, "mbedtls_ctr_drbg_seed");

    mret = mbedtls_mpi_read_string(&serial_num, 10, serial);
    __CHECK_MBED_ERR(mret, "mbedtls_mpi_read_string");

    ret = atecc_drv_mbedtls_pk_parse_key(&subject_key, slot);
    if (ret != ATCA_SUCCESS) goto cleanup;

    ret = ATCA_FUNC_FAIL;

    mbedtls_x509write_crt_set_subject_key(&crt, &subject_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &subject_key);

    mret = mbedtls_x509write_crt_set_subject_name(&crt, subject_name);
    __CHECK_MBED_ERR(mret, "mbedtls_x509write_crt_set_subject_name");

    mret = mbedtls_x509write_crt_set_issuer_name(&crt, subject_name);
    __CHECK_MBED_ERR(mret, "mbedtls_x509write_crt_set_issuer_name");

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

    mret = mbedtls_x509write_crt_set_serial(&crt, &serial_num);
    __CHECK_MBED_ERR(mret, "mbedtls_x509write_crt_set_serial");

    mret = mbedtls_x509write_crt_set_validity(
        &crt, not_before, not_after);
    __CHECK_MBED_ERR(mret, "mbedtls_x509write_crt_set_validity");

    /*
     * X509v3 extensions
     */

    if (ca_cert) {
        /* CA certificate */
        mret = mbedtls_x509write_crt_set_basic_constraints(&crt, 1, -1);
        __CHECK_MBED_ERR(mret, "mbedtls_x509write_crt_set_basic_constraints");
    }

    /* subject key id */
    mret = mbedtls_x509write_crt_set_subject_key_identifier(&crt);
    __CHECK_MBED_ERR(
        mret, "mbedtls_x509write_crt_set_subject_key_identifier");

    /* identifier key id */
    mret = mbedtls_x509write_crt_set_authority_key_identifier(&crt);
    __CHECK_MBED_ERR(
        mret, "mbedtls_x509write_crt_set_authority_key_identifier");

    /* create the certificate */
    crt_len = mbedtls_x509write_crt_der(
        &crt, der_crt, *len, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (crt_len <= 0) {
        mbedtls_printf(
            "ERROR: mbedtls_x509write_crt_der failed: -0x%04X\n", -crt_len);
        goto cleanup;
    }

    reverse_buf(der_crt, *len, (size_t)crt_len);

    if (print_pem)
        print_x509_pem(der_crt, crt_len, "-----%s CERTIFICATE-----\n", NULL);

    ret = ATCA_SUCCESS;
    *len = crt_len;

cleanup:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_mpi_free(&serial_num);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&subject_key);

    return ret;
}

ATCA_STATUS atecc_drv_gen_csr(
    int slot, const char *subject_name, unsigned char key_usage,
    unsigned char *der_csr, size_t *len, bool print_pem)
{
    mbedtls_pk_context subject_key;
    mbedtls_x509write_csr csr;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    int mret, csr_len;
    ATCA_STATUS ret = ATCA_FUNC_FAIL;

    mbedtls_pk_init(&subject_key);
    mbedtls_x509write_csr_init(&csr);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mret = mbedtls_ctr_drbg_seed(
        &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    __CHECK_MBED_ERR(mret, "mbedtls_ctr_drbg_seed");

    ret = atecc_drv_mbedtls_pk_parse_key(&subject_key, slot);
    if (ret != ATCA_SUCCESS) goto cleanup;

    ret = ATCA_FUNC_FAIL;

    mbedtls_x509write_csr_set_key(&csr, &subject_key);

    mret = mbedtls_x509write_csr_set_subject_name(&csr, subject_name);
    __CHECK_MBED_ERR(mret, "mbedtls_x509write_csr_set_subject_name");

    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);

    if (key_usage) {
        mret = mbedtls_x509write_csr_set_key_usage(&csr, key_usage);
        __CHECK_MBED_ERR(mret, "mbedtls_x509write_csr_set_key_usage");
    }

    /* create the request */
    csr_len = mbedtls_x509write_csr_der(
        &csr, der_csr, *len, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (csr_len <= 0) {
        mbedtls_printf(
            "ERROR: mbedtls_x509write_csr_der failed: -0x%04X\n", -csr_len);
        goto cleanup;
    }

    reverse_buf(der_csr, *len, (size_t)csr_len);

    if (print_pem)
        print_x509_pem(der_csr, csr_len, "-----%s CERTIFICATE REQUEST-----\n",
            NULL);

    ret = ATCA_SUCCESS;
    *len = csr_len;

cleanup:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509write_csr_free(&csr);
    mbedtls_pk_free(&subject_key);

    return ret;
}

#endif /* CONFIG_ATECC_DRV_CERT_GEN_SUPPORT */

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT) && \
    (!defined(CONFIG_ATECC_DRV_ENTROPY_DISABLED) || \
     !CONFIG_ATECC_DRV_ENTROPY_DISABLED)

/*
 * Use ATECC as an entropy source
 */
int mbedtls_hardware_poll(
    void *data, unsigned char *output, size_t len, size_t *olen)
{
    int ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    size_t i=0, aerr;
    uint8_t rnd[32];

    *olen = 0;
    if (!output || !len || !atca_inited)
        return 0;

    while (*olen < len)
    {
        if (!i) {
            aerr = atcab_random(rnd);
            if (aerr != ATCA_SUCCESS) goto cleanup;
        }
        *output++ = rnd[i];

        (*olen)++;
        i = (i+1) % sizeof(rnd);
    }

    ret = 0;
cleanup:
    return ret;
}

#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT && !CONFIG_ATECC_DRV_ENTROPY_DISABLED */

#ifdef MBEDTLS_ECDH_GEN_PUBLIC_ALT

/**
 * @note The function retrieves a public part of ATECC key for a configured
 * slot (DH key slot set in @c dh_slot). As the behavior is feasible for
 * ECDH key exchange, it may be seen problematic for ECDHE ephemeral key
 * exchange, where DH keys are randomized for each TLS handshake. Therefore,
 * there is recommended to generate a new key for the DH slot before starting
 * a TLS connection using ATECC with ECDHE cipher suite. It also implies, that
 * combined use of ECDH and ECDHE cipher suites shall be avoided.
 */
int mbedtls_ecdh_gen_public(
    mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    ATCA_STATUS aret;
    int ret;

    /* uncompressed format tag followed by X, Y
       coordinates as specified in RFC8422 sec. 5.4.1 */
    uint8_t Q_bin[1 + ATCA_PUB_KEY_SIZE] = { 0x04 };

    __DEF_SLOT_MARKER(mrk);
    __INIT_SLOT_MARKER(mrk, dh_slot);

    if (!grp || !d || !Q)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* only NIST P-256 curve is supported */
    if (grp->id != MBEDTLS_ECP_DP_SECP256R1) {
        mbedtls_printf("ERROR: ATECC supports only SECP256R1 types of curves\n");
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    if (!atca_inited) {
        mbedtls_printf("ERROR: ATCA uninitialized\n");
        return MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    }

    ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    aret = atcab_get_pubkey(dh_slot, &Q_bin[1]);
    __CHECK_ATCA_ERR(aret, "atcab_get_pubkey");

    MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(grp, Q, Q_bin, sizeof(Q_bin)));

    /*
     * Checking the public key requires BIGNUM operations, therefore
     * may cause memory problems on RAM constrained devices. We may safely
     * ignore this checking since ATECC device guarantees valid key-pairs
     * generation and maintenance.
     */
    /* MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, Q)); */

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(d, mrk, sizeof(mrk)));

    ret = 0;
cleanup:
    return ret;
}

#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#ifdef MBEDTLS_ECDH_COMPUTE_SHARED_ALT

int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
    const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
    ATCA_STATUS aret;

    size_t olen;
    uint8_t secret[ATCA_KEY_SIZE] = {};
    uint8_t Q_bin[1 + ATCA_PUB_KEY_SIZE];

    int slot = -1;
    __DEF_SLOT_MARKER(mrk);

    if (!grp || !z || !Q || !d)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* only NIST P-256 curve is supported */
    if (grp->id != MBEDTLS_ECP_DP_SECP256R1) {
        mbedtls_printf("ERROR: ATECC supports only SECP256R1 types of curves\n");
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    if (!atca_inited) {
        mbedtls_printf("ERROR: ATCA uninitialized\n");
        return MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    }

    /* check d against the slot marker */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(d, mrk, sizeof(mrk)));
    if (__CHECK_SLOT_MARKER(mrk) != 0) {
        mbedtls_printf("ERROR: Private key is not of ATECC format\n");
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    slot = __GET_MARKER_SLOT(mrk);

    MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(
        grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, Q_bin, sizeof(Q_bin)));
    if (olen != sizeof(Q_bin) || Q_bin[0] != 0x04) {
        mbedtls_printf("ERROR: Invalid EC Q point passed\n");
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    aret = atcab_ecdh(slot, &Q_bin[1], secret);
    __CHECK_ATCA_ERR(aret, "atcab_ecdh");

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(z, secret, sizeof(secret)));

    if (!mbedtls_mpi_cmp_int(z, 0)) {
        /* TODO: add support for protected ECDH keys */
        mbedtls_printf(
            "ERROR: ECC key used for ECDH key exchange is protected\n");
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    ret = 0;
cleanup:
    return ret;
}

#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

#ifdef MBEDTLS_ECDSA_SIGN_ALT

int mbedtls_ecdsa_sign(
    mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
    ATCA_STATUS aret;

    int slot = -1;
    uint8_t sign[ATCA_SIG_SIZE];
    __DEF_SLOT_MARKER(mrk);

    if (!grp || !r || !s || !d || !buf)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* only NIST P-256 curve is supported */
    if (grp->id != MBEDTLS_ECP_DP_SECP256R1) {
        mbedtls_printf("ERROR: ATECC supports only SECP256R1 types of curves\n");
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    if (!atca_inited) {
        mbedtls_printf("ERROR: ATCA uninitialized\n");
        return MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    }

    if (blen != 32) {
        mbedtls_printf("ERROR: ATECC supports SHA256 only\n");
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* check d against the slot marker */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(d, mrk, sizeof(mrk)));
    if (__CHECK_SLOT_MARKER(mrk) != 0) {
        mbedtls_printf("ERROR: Private key is not of ATECC format\n");
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    slot = __GET_MARKER_SLOT(mrk);

    ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    aret =  atcab_sign(slot, buf, sign);
    __CHECK_ATCA_ERR(aret, "atcab_sign");

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(r, &sign[0], ATCA_SIG_SIZE/2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(
            s, &sign[ATCA_SIG_SIZE/2], ATCA_SIG_SIZE/2));

    ret = 0;
cleanup:
    return ret;
}

#endif /* MBEDTLS_ECDSA_SIGN_ALT */

#ifdef MBEDTLS_ECDSA_VERIFY_ALT

int mbedtls_ecdsa_verify(
    mbedtls_ecp_group *grp, const unsigned char *buf, size_t blen,
    const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s)
{
    int ret;
    ATCA_STATUS aret;
    bool ver_res = false;

    size_t olen;
    uint8_t Q_bin[1 + ATCA_PUB_KEY_SIZE];
    uint8_t sign[ATCA_SIG_SIZE];

    if (!grp || !buf || !Q || !r || !s)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* only NIST P-256 curve is supported */
    if (grp->id != MBEDTLS_ECP_DP_SECP256R1) {
        mbedtls_printf("ERROR: ATECC supports only SECP256R1 types of curves\n");
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    if (!atca_inited) {
        mbedtls_printf("ERROR: ATCA uninitialized\n");
        return MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    }

    if (blen != 32) {
        mbedtls_printf("ERROR: ATECC supports SHA256 only\n");
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(
        grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, Q_bin, sizeof(Q_bin)));
    if (olen != sizeof(Q_bin) || Q_bin[0] != 0x04) {
        mbedtls_printf("ERROR: Invalid EC Q point passed\n");
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(r, &sign[0], ATCA_SIG_SIZE/2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(
            s, &sign[ATCA_SIG_SIZE/2], ATCA_SIG_SIZE/2));

    ret = MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    aret = atcab_verify_extern((const uint8_t*)buf, sign, &Q_bin[1], &ver_res);
    __CHECK_ATCA_ERR(aret, "atcab_verify_extern");

    ret = (!ver_res ? MBEDTLS_ERR_ECP_VERIFY_FAILED : 0);

cleanup:
    return ret;
}

#endif /* MBEDTLS_ECDSA_VERIFY_ALT */
