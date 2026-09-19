/*
 * Secure Device Connection Protocol (SDCP) support unit tests
 * Copyright (C) 2025 Joshua Grisham <josh@joshuagrisham.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "test_fpi_sdcp"
#include "fpi-log.h"

#include <openssl/x509v3.h>

#define FPI_SDCP_TESTING
#include "fpi-sdcp.h"
#include "fpi-sdcp-device.h"

/* Compile the implementation into this test so the fixed-clock hook remains
 * private to test code and does not become a production API. */
#undef FP_COMPONENT
#include "../libfprint/fpi-sdcp.c"
#undef FP_COMPONENT
#define FP_COMPONENT "test_fpi_sdcp"

/* We can re-use the test payloads from virtual-sdcp */
#include "drivers/virtual-sdcp.h"

/******************************************************************************/

static const guint8 from_hex_map[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,   // 01234567
  0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 89:;<=>?
  0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,         // @abcdef
};

static GBytes *
g_bytes_from_hex (const gchar *hex)
{
  g_autoptr(GBytes) res = NULL;
  guint8 b0, b1;
  gsize bytes_len = strlen (hex) / 2;
  guint8 *bytes = g_malloc0 (bytes_len);

  for (int i = 0; i < strlen (hex) - 1; i += 2)
    {
      b0 = ((guint8) hex[i + 0] & 0x1F) ^ 0x10;
      b1 = ((guint8) hex[i + 1] & 0x1F) ^ 0x10;
      bytes[i / 2] = (guint8) (from_hex_map[b0] << 4) | from_hex_map[b1];
    }

  res = g_bytes_new_take (bytes, bytes_len);

  return g_steal_pointer (&res);
}

static GBytes *
g_bytes_with_first_byte_flipped (GBytes *bytes)
{
  gsize len = 0;
  guint8 *copy;

  g_bytes_get_data (bytes, &len);
  g_assert_cmpuint (len, >, 0);
  copy = g_malloc (len);
  memcpy (copy, g_bytes_get_data (bytes, NULL), len);
  copy[0] ^= 1;
  return g_bytes_new_take (copy, len);
}

static FpiSdcpClaim *
get_fake_sdcp_claim (void)
{
  FpiSdcpClaim *claim = g_new0 (FpiSdcpClaim, 1);

  claim->model_certificate = g_bytes_from_hex (model_certificate_hex);
  claim->device_public_key = g_bytes_from_hex (device_public_key_hex);
  claim->firmware_public_key = g_bytes_from_hex (firmware_public_key_hex);
  claim->firmware_hash = g_bytes_from_hex (firmware_hash_hex);
  claim->model_signature = g_bytes_from_hex (model_signature_hex);
  claim->device_signature = g_bytes_from_hex (device_signature_hex);
  return g_steal_pointer (&claim);
}

/******************************************************************************/

static void
test_generate_enrollment_id (void)
{
  g_autoptr(GBytes) id = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) application_secret = g_bytes_from_hex (application_secret_hex);
  g_autoptr(GBytes) nonce = g_bytes_from_hex (enrollment_nonce_hex);
  g_autoptr(GBytes) expected_id = g_bytes_from_hex (enrollment_id_hex);

  id = fpi_sdcp_generate_enrollment_id (application_secret, nonce, &error);

  g_assert (g_bytes_equal (expected_id, id));
  g_assert_null (error);
}

static void
test_verify_identify (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) application_secret = g_bytes_from_hex (application_secret_hex);
  g_autoptr(GBytes) nonce = g_bytes_from_hex (identify_nonce_hex);
  g_autoptr(GBytes) id = g_bytes_from_hex (enrollment_id_hex);
  g_autoptr(GBytes) mac = g_bytes_from_hex (identify_mac_hex);

  g_assert_true (fpi_sdcp_verify_identify (application_secret, nonce, id, mac, &error));
  g_assert_null (error);
}

static void
test_verify_reconnect (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) application_secret = g_bytes_from_hex (application_secret_hex);
  g_autoptr(GBytes) random = g_bytes_from_hex (reconnect_random_hex);
  g_autoptr(GBytes) mac = g_bytes_from_hex (reconnect_mac_hex);

  g_assert_true (fpi_sdcp_verify_reconnect (application_secret, random, mac, &error));
  g_assert_null (error);
}

static void
test_verify_connect (void)
{
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GError) error = NULL;

  g_autoptr(GBytes) host_private_key = g_bytes_from_hex (host_private_key_hex);
  g_autoptr(GBytes) host_random = g_bytes_from_hex (host_random_hex);
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) connect_mac = g_bytes_from_hex (connect_mac_hex);
  FpiSdcpClaim *claim = get_fake_sdcp_claim ();

  g_autoptr(GBytes) expected_application_secret = g_bytes_from_hex (application_secret_hex);

  g_assert_true (fpi_sdcp_verify_connect (host_private_key,
                                          host_random,
                                          device_random,
                                          claim,
                                          connect_mac,
                                          FALSE,
                                          FALSE,
                                          &application_secret,
                                          &error));

  g_assert_null (error);
  g_assert (g_bytes_get_size (application_secret) == SDCP_APPLICATION_SECRET_SIZE);

  g_assert_true (g_bytes_equal (expected_application_secret, application_secret));

  fpi_sdcp_claim_free (claim);
}

static void
test_verify_connect_validates_certificate_at_fixture_time (void)
{
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) host_private_key = g_bytes_from_hex (host_private_key_hex);
  g_autoptr(GBytes) host_random = g_bytes_from_hex (host_random_hex);
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) connect_mac = g_bytes_from_hex (connect_mac_hex);
  FpiSdcpClaim *claim = get_fake_sdcp_claim ();

  /* The historical Microsoft sample certificate is valid at this fixed test
   * instant. The clock injection is compiled only into this test translation
   * unit under FPI_SDCP_TESTING. */
  fpi_sdcp_test_set_verification_time (1672531200);

  g_assert_true (fpi_sdcp_verify_connect (host_private_key,
                                          host_random,
                                          device_random,
                                          claim,
                                          connect_mac,
                                          TRUE,
                                          FALSE,
                                          &application_secret,
                                          &error));
  g_assert_null (error);
  g_assert_nonnull (application_secret);

  fpi_sdcp_claim_free (claim);
  fpi_sdcp_test_set_verification_time (0);
}

static void
test_verify_device_signature_vector (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) device_public_key = g_bytes_from_hex (device_public_key_hex);
  g_autoptr(GBytes) firmware_hash = g_bytes_from_hex (firmware_hash_hex);
  g_autoptr(GBytes) firmware_public_key = g_bytes_from_hex (firmware_public_key_hex);
  g_autoptr(GBytes) device_signature = g_bytes_from_hex (device_signature_hex);
  EVP_PKEY *device_pkey;
  const guint8 prefix[] = { 0xc0, 0x01 };

  device_pkey = fpi_sdcp_get_public_pkey (device_public_key, &error);
  g_assert_no_error (error);
  g_assert_nonnull (device_pkey);

  g_assert_true (fpi_sdcp_verify_signature (device_pkey,
                                            prefix,
                                            sizeof (prefix),
                                            firmware_hash,
                                            firmware_public_key,
                                            device_signature,
                                            &error));
  g_assert_no_error (error);
  g_clear_pointer (&device_pkey, EVP_PKEY_free);
}

static void
test_verify_device_signature_rejects_modified_vector (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) device_public_key = g_bytes_from_hex (device_public_key_hex);
  g_autoptr(GBytes) firmware_hash = g_bytes_from_hex (firmware_hash_hex);
  g_autoptr(GBytes) firmware_public_key = g_bytes_from_hex (firmware_public_key_hex);
  g_autoptr(GBytes) device_signature = g_bytes_from_hex (device_signature_hex);
  g_autoptr(GBytes) bad_signature = g_bytes_with_first_byte_flipped (device_signature);
  EVP_PKEY *device_pkey;
  const guint8 prefix[] = { 0xc0, 0x01 };

  device_pkey = fpi_sdcp_get_public_pkey (device_public_key, &error);
  g_assert_no_error (error);
  g_assert_nonnull (device_pkey);

  g_assert_false (fpi_sdcp_verify_signature (device_pkey,
                                             prefix,
                                             sizeof (prefix),
                                             firmware_hash,
                                             firmware_public_key,
                                             bad_signature,
                                             &error));
  g_assert_nonnull (error);
  g_clear_pointer (&device_pkey, EVP_PKEY_free);
}

static void
test_verify_connect_rejects_bad_mac (void)
{
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GBytes) host_private_key = g_bytes_from_hex (host_private_key_hex);
  g_autoptr(GBytes) host_random = g_bytes_from_hex (host_random_hex);
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) connect_mac = g_bytes_from_hex (connect_mac_hex);
  g_autoptr(GBytes) bad_mac = g_bytes_with_first_byte_flipped (connect_mac);
  g_autoptr(GError) error = NULL;
  FpiSdcpClaim *claim = get_fake_sdcp_claim ();

  g_assert_false (fpi_sdcp_verify_connect (host_private_key,
                                            host_random,
                                            device_random,
                                            claim,
                                            bad_mac,
                                            FALSE,
                                            FALSE,
                                            &application_secret,
                                            &error));
  g_assert_nonnull (error);
  g_assert_null (application_secret);
  fpi_sdcp_claim_free (claim);
}

static void
test_verify_connect_rejects_modified_claim (void)
{
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GBytes) host_private_key = g_bytes_from_hex (host_private_key_hex);
  g_autoptr(GBytes) host_random = g_bytes_from_hex (host_random_hex);
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) connect_mac = g_bytes_from_hex (connect_mac_hex);
  g_autoptr(GBytes) firmware_hash = g_bytes_from_hex (firmware_hash_hex);
  g_autoptr(GError) error = NULL;
  FpiSdcpClaim *claim = get_fake_sdcp_claim ();

  g_clear_pointer (&claim->firmware_hash, g_bytes_unref);
  claim->firmware_hash = g_bytes_with_first_byte_flipped (firmware_hash);

  g_assert_false (fpi_sdcp_verify_connect (host_private_key,
                                            host_random,
                                            device_random,
                                            claim,
                                            connect_mac,
                                            FALSE,
                                            FALSE,
                                            &application_secret,
                                            &error));
  g_assert_nonnull (error);
  g_assert_null (application_secret);
  fpi_sdcp_claim_free (claim);
}

static void
test_verify_connect_rejects_wrong_key (void)
{
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GBytes) host_private_key = g_bytes_from_hex (host_private_key_hex);
  g_autoptr(GBytes) wrong_key = g_bytes_with_first_byte_flipped (host_private_key);
  g_autoptr(GBytes) host_random = g_bytes_from_hex (host_random_hex);
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) connect_mac = g_bytes_from_hex (connect_mac_hex);
  g_autoptr(GError) error = NULL;
  FpiSdcpClaim *claim = get_fake_sdcp_claim ();

  g_assert_false (fpi_sdcp_verify_connect (wrong_key,
                                            host_random,
                                            device_random,
                                            claim,
                                            connect_mac,
                                            FALSE,
                                            FALSE,
                                            &application_secret,
                                            &error));
  g_assert_nonnull (error);
  g_assert_null (application_secret);
  fpi_sdcp_claim_free (claim);
}

static void
test_verify_connect_rejects_bad_model_signature (void)
{
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GBytes) host_private_key = g_bytes_from_hex (host_private_key_hex);
  g_autoptr(GBytes) host_random = g_bytes_from_hex (host_random_hex);
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) connect_mac = g_bytes_from_hex ("6f7542a0293d36e1e0bf665d9ca9d8046f5ffa977f7517c8b3c6cd62f73d7c06");
  g_autoptr(GBytes) model_signature = g_bytes_from_hex (model_signature_hex);
  g_autoptr(GError) error = NULL;
  FpiSdcpClaim *claim = get_fake_sdcp_claim ();

  g_clear_pointer (&claim->model_signature, g_bytes_unref);
  claim->model_signature = g_bytes_with_first_byte_flipped (model_signature);
  fpi_sdcp_test_set_verification_time (1672531200);

  g_assert_false (fpi_sdcp_verify_connect (host_private_key,
                                            host_random,
                                            device_random,
                                            claim,
                                            connect_mac,
                                            TRUE,
                                            TRUE,
                                            &application_secret,
                                            &error));
  g_assert_nonnull (error);
  g_assert_null (application_secret);
  fpi_sdcp_claim_free (claim);
  fpi_sdcp_test_set_verification_time (0);
}

static void
test_verify_connect_rejects_bad_device_signature (void)
{
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GBytes) host_private_key = g_bytes_from_hex (host_private_key_hex);
  g_autoptr(GBytes) host_random = g_bytes_from_hex (host_random_hex);
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) connect_mac = g_bytes_from_hex ("d6e7f4d5d53a80ff5031ddadd72bba718cbae9551b70f0aed05d081455713387");
  g_autoptr(GBytes) device_signature = g_bytes_from_hex (device_signature_hex);
  g_autoptr(GError) error = NULL;
  FpiSdcpClaim *claim = get_fake_sdcp_claim ();

  g_clear_pointer (&claim->device_signature, g_bytes_unref);
  claim->device_signature = g_bytes_with_first_byte_flipped (device_signature);
  fpi_sdcp_test_set_verification_time (1672531200);

  g_assert_false (fpi_sdcp_verify_connect (host_private_key,
                                            host_random,
                                            device_random,
                                            claim,
                                            connect_mac,
                                            TRUE,
                                            TRUE,
                                            &application_secret,
                                            &error));
  g_assert_nonnull (error);
  g_assert_null (application_secret);
  fpi_sdcp_claim_free (claim);
  fpi_sdcp_test_set_verification_time (0);
}

static void
test_verify_connect_rejects_expired_certificate (void)
{
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GBytes) host_private_key = g_bytes_from_hex (host_private_key_hex);
  g_autoptr(GBytes) host_random = g_bytes_from_hex (host_random_hex);
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) connect_mac = g_bytes_from_hex (connect_mac_hex);
  g_autoptr(GError) error = NULL;
  FpiSdcpClaim *claim = get_fake_sdcp_claim ();

  fpi_sdcp_test_set_verification_time (1789776000); /* 2026-09-19 UTC */
  g_assert_false (fpi_sdcp_verify_connect (host_private_key,
                                            host_random,
                                            device_random,
                                            claim,
                                            connect_mac,
                                            TRUE,
                                            FALSE,
                                            &application_secret,
                                            &error));
  g_assert_nonnull (error);
  g_assert_null (application_secret);
  g_assert_nonnull (strstr (error->message, "certificate has expired"));
  g_assert_nonnull (strstr (error->message, "depth=0; notBefore="));
  g_assert_nonnull (strstr (error->message, "; notAfter="));
  g_assert_nonnull (strstr (error->message, "; subject="));
  g_assert_nonnull (strstr (error->message, "; issuer="));
  g_autofree gchar *fingerprint = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256,
                                                                claim->model_certificate);
  g_assert_nonnull (strstr (error->message, fingerprint));
  fpi_sdcp_test_set_verification_time (0);
  fpi_sdcp_claim_free (claim);
}

static void
test_expired_certificate_pin (void)
{
  g_autoptr(FpiSdcpClaim) claim = get_fake_sdcp_claim ();
  g_autofree gchar *pin = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256,
                                                        claim->model_certificate);
  const guint8 *der = g_bytes_get_data (claim->model_certificate, NULL);
  X509 *cert = d2i_X509 (NULL, &der, g_bytes_get_size (claim->model_certificate));
  g_autoptr(GError) error = NULL;

  g_assert_nonnull (cert);
  fpi_sdcp_test_set_verification_time (1789776000);
  const gchar *invalid_pins[] = {NULL, "", "1", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                                 "0000000000000000000000000000000000000000000000000000000000000000"};
  for (guint i = 0; i < G_N_ELEMENTS (invalid_pins); i++)
    {
      if (invalid_pins[i])
        g_setenv ("LIBFPRINT_SDCP_EXPIRED_MODEL_SHA256", invalid_pins[i], TRUE);
      else
        g_unsetenv ("LIBFPRINT_SDCP_EXPIRED_MODEL_SHA256");
      g_assert_false (fpi_sdcp_verify_certificate (cert, &error));
      g_assert_nonnull (strstr (error->message, "certificate has expired"));
      g_clear_error (&error);
    }

  g_setenv ("LIBFPRINT_SDCP_EXPIRED_MODEL_SHA256", pin, TRUE);
  g_assert_true (fpi_sdcp_verify_certificate (cert, &error));
  g_assert_no_error (error);

  /* The same pin cannot waive not-yet-valid dates or expired CA certificates. */
  fpi_sdcp_test_set_verification_time (1577836800); /* 2020 */
  g_assert_false (fpi_sdcp_verify_certificate (cert, &error));
  g_assert_nonnull (error);
  g_clear_error (&error);
  fpi_sdcp_test_set_verification_time (2303683200); /* 2043 */
  g_assert_false (fpi_sdcp_verify_certificate (cert, &error));
  g_assert_nonnull (strstr (error->message, "certificate has expired"));
  g_assert_nonnull (strstr (error->message, "depth="));
  g_assert_null (strstr (error->message, "depth=0;"));
  g_clear_error (&error);

  /* Even pinning the modified certificate cannot waive its broken signature. */
  fpi_sdcp_test_set_verification_time (1789776000);
  g_autoptr(GBytes) modified = NULL;
  guint8 *bytes = g_memdup2 (g_bytes_get_data (claim->model_certificate, NULL),
                            g_bytes_get_size (claim->model_certificate));
  bytes[g_bytes_get_size (claim->model_certificate) - 1] ^= 1;
  modified = g_bytes_new_take (bytes, g_bytes_get_size (claim->model_certificate));
  g_free (pin);
  pin = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256, modified);
  g_setenv ("LIBFPRINT_SDCP_EXPIRED_MODEL_SHA256", pin, TRUE);
  der = g_bytes_get_data (modified, NULL);
  X509_free (cert);
  cert = d2i_X509 (NULL, &der, g_bytes_get_size (modified));
  g_assert_nonnull (cert);
  g_assert_false (fpi_sdcp_verify_certificate (cert, &error));
  g_assert_nonnull (error);
  X509_free (cert);
  g_unsetenv ("LIBFPRINT_SDCP_EXPIRED_MODEL_SHA256");
  fpi_sdcp_test_set_verification_time (0);
}

/* Generate an independent signer and a test-only trust anchor. None of these
 * keys or certificates is embedded in the production truststore. */
static X509 *
make_test_certificate (EVP_PKEY *key)
{
  X509 *cert = X509_new ();
  X509_NAME *subject;
  X509V3_CTX context;
  const int nids[] = {NID_basic_constraints, NID_key_usage, NID_subject_key_identifier, NID_authority_key_identifier};
  const char *values[] = {"critical,CA:TRUE", "critical,keyCertSign,digitalSignature", "hash", "keyid:always"};

  g_assert_nonnull (cert);
  g_assert_cmpint (X509_set_version (cert, 2), ==, 1);
  g_assert_cmpint (ASN1_INTEGER_set (X509_get_serialNumber (cert), 1), ==, 1);
  g_assert_cmpint (ASN1_TIME_set_string (X509_getm_notBefore (cert), "20200101000000Z"), ==, 1);
  g_assert_cmpint (ASN1_TIME_set_string (X509_getm_notAfter (cert), "20400101000000Z"), ==, 1);
  g_assert_cmpint (X509_set_pubkey (cert, key), ==, 1);
  subject = X509_get_subject_name (cert);
  g_assert_cmpint (X509_NAME_add_entry_by_txt (subject, "CN", MBSTRING_ASC,
                                             (const guint8 *) "libfprint unit test", -1, -1, 0), ==, 1);
  g_assert_cmpint (X509_set_issuer_name (cert, subject), ==, 1);
  X509V3_set_ctx (&context, cert, cert, NULL, NULL, 0);
  for (guint i = 0; i < G_N_ELEMENTS (nids); i++)
    {
      X509_EXTENSION *extension = X509V3_EXT_conf_nid (NULL, &context, nids[i], values[i]);

      g_assert_nonnull (extension);
      g_assert_cmpint (X509_add_ext (cert, extension, -1), ==, 1);
      X509_EXTENSION_free (extension);
    }
  g_assert_cmpint (X509_sign (cert, key, EVP_sha256 ()), >, 0);
  return cert;
}

static GBytes *
sign_test_message (EVP_PKEY *key, const guint8 *prefix, gsize prefix_length,
                   GBytes *a, GBytes *b)
{
  EVP_MD_CTX *context = EVP_MD_CTX_new ();
  ECDSA_SIG *signature;
  g_autofree guint8 *der = NULL;
  const guint8 *cursor;
  const BIGNUM *r, *v;
  guint8 raw[SDCP_SIGNATURE_SIZE];
  size_t size;

  g_assert_cmpint (EVP_DigestSignInit (context, NULL, EVP_sha256 (), NULL, key), ==, 1);
  if (prefix_length)
    g_assert_cmpint (EVP_DigestSignUpdate (context, prefix, prefix_length), ==, 1);
  g_assert_cmpint (EVP_DigestSignUpdate (context, g_bytes_get_data (a, NULL), g_bytes_get_size (a)), ==, 1);
  if (b)
    g_assert_cmpint (EVP_DigestSignUpdate (context, g_bytes_get_data (b, NULL), g_bytes_get_size (b)), ==, 1);
  g_assert_cmpint (EVP_DigestSignFinal (context, NULL, &size), ==, 1);
  der = g_malloc (size);
  g_assert_cmpint (EVP_DigestSignFinal (context, der, &size), ==, 1);
  cursor = der;
  signature = d2i_ECDSA_SIG (NULL, &cursor, size);
  g_assert_nonnull (signature);
  ECDSA_SIG_get0 (signature, &r, &v);
  g_assert_cmpint (BN_bn2binpad (r, raw, sizeof (raw) / 2), ==, sizeof (raw) / 2);
  g_assert_cmpint (BN_bn2binpad (v, raw + sizeof (raw) / 2, sizeof (raw) / 2), ==, sizeof (raw) / 2);
  ECDSA_SIG_free (signature);
  EVP_MD_CTX_free (context);
  return g_bytes_new (raw, sizeof (raw));
}

static void
test_authenticated_connect (gconstpointer data)
{
  EVP_PKEY *model_key = EVP_EC_gen ("P-256");
  EVP_PKEY *device_key = EVP_EC_gen ("P-256");
  X509 *certificate = make_test_certificate (model_key);
  g_autoptr(FpiSdcpClaim) good_claim = get_fake_sdcp_claim ();
  g_autoptr(GBytes) host_private_key = g_bytes_from_hex (host_private_key_hex);
  g_autoptr(GBytes) host_random = g_bytes_from_hex (host_random_hex);
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) secret = g_bytes_from_hex (application_secret_hex);
  guint8 *der = NULL;
  int der_length = i2d_X509 (certificate, &der);
  const guint8 prefix[] = {0xc0, 0x01};
  const guint8 zero_signature[SDCP_SIGNATURE_SIZE] = {0};

  g_assert_cmpint (der_length, >, 0);
  g_clear_pointer (&good_claim->model_certificate, g_bytes_unref);
  good_claim->model_certificate = g_bytes_new (der, der_length);
  OPENSSL_free (der);
  g_clear_pointer (&good_claim->device_public_key, g_bytes_unref);
  good_claim->device_public_key = fpi_sdcp_get_public_key (device_key, NULL);
  g_clear_pointer (&good_claim->model_signature, g_bytes_unref);
  good_claim->model_signature = sign_test_message (model_key, NULL, 0, good_claim->device_public_key, NULL);
  g_clear_pointer (&good_claim->device_signature, g_bytes_unref);
  good_claim->device_signature = sign_test_message (device_key, prefix, sizeof (prefix),
                                                    good_claim->firmware_hash, good_claim->firmware_public_key);
  test_trust_anchor = certificate;
  g_autofree gchar *pin = g_compute_checksum_for_bytes (G_CHECKSUM_SHA256,
                                                        good_claim->model_certificate);
  if (GPOINTER_TO_INT (data))
    g_setenv ("LIBFPRINT_SDCP_EXPIRED_MODEL_SHA256", pin, TRUE);
  fpi_sdcp_test_set_verification_time (GPOINTER_TO_INT (data) ? 2240611200 : 1672531200);

  for (guint mutation = 0; mutation < 10; mutation++)
    {
      g_autoptr(FpiSdcpClaim) claim = fpi_sdcp_claim_copy (good_claim);
      g_autoptr(GBytes) hash = NULL;
      g_autoptr(GBytes) mac = NULL;
      g_autoptr(GBytes) result = NULL;
      g_autoptr(GError) error = NULL;
      gboolean accepted;

      if (mutation == 1 || mutation == 2)
        {
          GBytes **field = mutation == 1 ? &claim->model_signature : &claim->device_signature;
          g_clear_pointer (field, g_bytes_unref);
          *field = g_bytes_new_static (zero_signature, sizeof (zero_signature));
        }
      else if (mutation == 3)
        {
          GBytes *tmp = claim->model_signature;
          claim->model_signature = claim->device_signature;
          claim->device_signature = tmp;
        }
      else if (mutation == 4)
        {
          g_clear_pointer (&claim->device_signature, g_bytes_unref);
          claim->device_signature = sign_test_message (model_key, prefix, sizeof (prefix),
                                                        claim->firmware_hash, claim->firmware_public_key);
        }
      else if (mutation == 5)
        {
          g_clear_pointer (&claim->device_signature, g_bytes_unref);
          claim->device_signature = sign_test_message (device_key, (const guint8 *) "C001", 4,
                                                        claim->firmware_hash, claim->firmware_public_key);
        }
      else if (mutation == 6)
        {
          g_clear_pointer (&claim->firmware_hash, g_bytes_unref);
          claim->firmware_hash = g_bytes_with_first_byte_flipped (good_claim->firmware_hash);
        }
      else if (mutation == 7)
        {
          test_trust_anchor = NULL;
        }
      /* Recompute the transport MAC so each mutation reaches attestation. */
      hash = fpi_sdcp_hash_claim (claim, &error);
      g_assert_no_error (error);
      mac = fpi_sdcp_mac (secret, "connect", hash, NULL, &error);
      g_assert_no_error (error);
      if (mutation == 9)
        {
          GBytes *bad_mac = g_bytes_with_first_byte_flipped (mac);
          g_bytes_unref (mac);
          mac = bad_mac;
        }
      accepted = fpi_sdcp_verify_connect (host_private_key, host_random, device_random,
                                           claim, mac, mutation != 8, TRUE, &result, &error);
      g_assert_cmpint (accepted, ==, mutation == 0);
      if (mutation == 0)
        {
          g_assert_no_error (error);
          g_assert_true (g_bytes_equal (result, secret));
        }
      else
        {
          g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);
          g_assert_null (result);
          if (mutation == 8)
            g_assert_cmpstr (error->message, ==, "Signature verification requires a validated certificate");
        }
    }
  test_trust_anchor = NULL;
  g_unsetenv ("LIBFPRINT_SDCP_EXPIRED_MODEL_SHA256");
  fpi_sdcp_test_set_verification_time (0);
  X509_free (certificate);
  EVP_PKEY_free (device_key);
  EVP_PKEY_free (model_key);
}

static void
test_generate_random (void)
{
  g_autoptr(GBytes) random = NULL;
  g_autoptr(GError) error = NULL;

  random = fpi_sdcp_generate_random (&error);

  g_assert_null (error);
  g_assert (g_bytes_get_size (random) == SDCP_RANDOM_SIZE);
}

static void
test_generate_host_key (void)
{
  g_autoptr(GBytes) private_key = NULL;
  g_autoptr(GBytes) public_key = NULL;
  g_autoptr(GError) error = NULL;
  gsize len = 0;

  fpi_sdcp_generate_host_key (&private_key, &public_key, &error);

  g_assert_null (error);

  g_bytes_get_data (private_key, &len);
  g_assert (len == 32);

  g_bytes_get_data (public_key, &len);
  g_assert (len == SDCP_PUBLIC_KEY_SIZE);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_unsetenv ("LIBFPRINT_SDCP_EXPIRED_MODEL_SHA256");
  g_test_add_data_func ("/sdcp/authenticated_connect", GINT_TO_POINTER (0), test_authenticated_connect);
  g_test_add_data_func ("/sdcp/authenticated_connect_expired_pin", GINT_TO_POINTER (1), test_authenticated_connect);
  g_test_add_func ("/sdcp/expired_certificate_pin", test_expired_certificate_pin);
  g_test_add_func ("/sdcp/generate_host_key", test_generate_host_key);
  g_test_add_func ("/sdcp/generate_random", test_generate_random);
  g_test_add_func ("/sdcp/verify_connect", test_verify_connect);
  g_test_add_func ("/sdcp/verify_connect/validates_certificate_at_fixture_time",
                   test_verify_connect_validates_certificate_at_fixture_time);
  g_test_add_func ("/sdcp/verify_device_signature/vector", test_verify_device_signature_vector);
  g_test_add_func ("/sdcp/verify_device_signature/modified", test_verify_device_signature_rejects_modified_vector);
  g_test_add_func ("/sdcp/verify_connect/bad_mac", test_verify_connect_rejects_bad_mac);
  g_test_add_func ("/sdcp/verify_connect/modified_claim", test_verify_connect_rejects_modified_claim);
  g_test_add_func ("/sdcp/verify_connect/wrong_key", test_verify_connect_rejects_wrong_key);
  g_test_add_func ("/sdcp/verify_connect/bad_model_signature", test_verify_connect_rejects_bad_model_signature);
  g_test_add_func ("/sdcp/verify_connect/bad_device_signature", test_verify_connect_rejects_bad_device_signature);
  g_test_add_func ("/sdcp/verify_connect/expired_certificate", test_verify_connect_rejects_expired_certificate);
  g_test_add_func ("/sdcp/verify_reconnect", test_verify_reconnect);
  g_test_add_func ("/sdcp/verify_identify", test_verify_identify);
  g_test_add_func ("/sdcp/generate_enrollment_id", test_generate_enrollment_id);

  return g_test_run ();
}
