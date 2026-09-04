/*
 * FPC1022 (Match-on-Host) driver for libfprint
 *
 * Supports FPC Disum USB fingerprint sensors (10a5:9200).
 * These are "match on host" sensors: they capture raw fingerprint images
 * over a TLS-PSK encrypted USB channel and rely on the host for matching.
 *
 * Copyright (c) 2026 Sergey Subbotin <ssubbotin@gmail.com>
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

#include "drivers_api.h"
#include "fpc1022.h"
#include "fpi-image.h"

#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define FP_COMPONENT "fpc1022"

G_DEFINE_TYPE (FpiDeviceFpc1022, fpi_device_fpc1022, FP_TYPE_IMAGE_DEVICE);

/* Nearest-neighbor 2x upscale — gives SIGFM more pixels for keypoint detection
 * on this small sensor (112x88 → 224x176). */
static FpImage *
fpc1022_scale_nn_2x (FpImage *src)
{
  int sw = src->width * 2;
  int sh = src->height * 2;
  FpImage *dst = fp_image_new (sw, sh);
  int x, y;

  for (y = 0; y < sh; y++)
    for (x = 0; x < sw; x++)
      dst->data[y * sw + x] = src->data[(y / 2) * src->width + (x / 2)];

  dst->flags = src->flags;
  dst->ppmm = src->ppmm;
  return dst;
}

static const FpIdEntry id_table[] = {
  { .vid = 0x10A5, .pid = 0x9200 },
  { .vid = 0,      .pid = 0      },
};

/* ---- Crypto helpers ---- */

static gboolean
fpc1022_sha256 (const void *data, gsize len, guint8 *out)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  unsigned int olen = 0;
  gboolean success = FALSE;

  if (!ctx)
    return FALSE;

  if (!EVP_DigestInit_ex (ctx, EVP_sha256 (), NULL) ||
      !EVP_DigestUpdate (ctx, data, len) ||
      !EVP_DigestFinal_ex (ctx, out, &olen) ||
      olen != SHA256_DIGEST_LENGTH)
    goto out;

  success = TRUE;

out:
  EVP_MD_CTX_free (ctx);
  return success;
}

static gboolean
fpc1022_verify_tls_key_hmac (const guint8 *aad, gsize aad_len,
                             const guint8 *key, gsize key_len,
                             const guint8 *sig, gsize sig_len)
{
  guint8 hmac_key[SHA256_DIGEST_LENGTH];
  guint8 computed_sig[SHA256_DIGEST_LENGTH];
  EVP_MAC *mac;
  EVP_MAC_CTX *mctx;
  gboolean valid = FALSE;
  size_t out_len = sizeof (computed_sig);

  if (sig_len != SHA256_DIGEST_LENGTH)
    return FALSE;

  /* HMAC key = SHA256("FPC_HMAC_KEY") - 13 bytes including null terminator */
  if (!fpc1022_sha256 ("FPC_HMAC_KEY", 13, hmac_key))
    return FALSE;

  mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
  if (!mac)
    return FALSE;

  mctx = EVP_MAC_CTX_new (mac);
  if (!mctx)
    {
      EVP_MAC_free (mac);
      return FALSE;
    }

  char digest_name[] = "SHA256";
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string ("digest", digest_name, 0),
    OSSL_PARAM_construct_end ()
  };

  if (!EVP_MAC_init (mctx, hmac_key, SHA256_DIGEST_LENGTH, params) ||
      !EVP_MAC_update (mctx, aad, aad_len) ||
      !EVP_MAC_update (mctx, key, key_len) ||
      !EVP_MAC_final (mctx, computed_sig, &out_len, sizeof (computed_sig)) ||
      out_len != SHA256_DIGEST_LENGTH)
    goto out;

  valid = CRYPTO_memcmp (computed_sig, sig, SHA256_DIGEST_LENGTH) == 0;

out:
  EVP_MAC_CTX_free (mctx);
  EVP_MAC_free (mac);

  return valid;
}

static gboolean
fpc1022_decrypt_tls_psk (const guint8 *encrypted, gsize enc_len,
                         guint8 *psk_out, gsize psk_out_size, gsize *psk_len_out)
{
  guint8 sealing_key[SHA256_DIGEST_LENGTH];
  guint8 plain[FPC1022_TLS_PSK_SIZE + EVP_MAX_BLOCK_LENGTH];
  EVP_CIPHER_CTX *ctx;
  gsize total_out = 0;
  int out_len = 0;

  /* enc_len is attacker-controlled: it comes straight out of the key packet
   * the device sends. AES-256-CBC with padding disabled yields exactly enc_len
   * bytes, so reject anything that would not fit instead of decrypting first
   * and clamping afterwards. */
  if (enc_len == 0 || enc_len > psk_out_size ||
      enc_len > sizeof (plain) ||
      enc_len % FPC1022_AES_BLOCK_SIZE != 0)
    {
      fp_err ("TLS key blob has implausible length %" G_GSIZE_FORMAT, enc_len);
      return FALSE;
    }

  /* Sealing key = SHA256("FPC_SEALING_KEY") - 16 bytes including null terminator */
  if (!fpc1022_sha256 ("FPC_SEALING_KEY", 16, sealing_key))
    return FALSE;

  ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    return FALSE;

  /* Use EVP_CipherInit with NULL IV (zero IV) and direction=0 (decrypt),
   * matching the reference implementation exactly. */
  if (!EVP_CipherInit (ctx, EVP_aes_256_cbc (), sealing_key, NULL, 0))
    {
      EVP_CIPHER_CTX_free (ctx);
      return FALSE;
    }

  /* Disable PKCS7 padding — the encrypted key may not be padded.
   * Must be called AFTER CipherInit so the context is fully set up. */
  if (!EVP_CIPHER_CTX_set_padding (ctx, 0))
    {
      EVP_CIPHER_CTX_free (ctx);
      return FALSE;
    }

  out_len = 0;
  if (!EVP_CipherUpdate (ctx, plain, &out_len, encrypted, enc_len))
    {
      EVP_CIPHER_CTX_free (ctx);
      return FALSE;
    }
  total_out = out_len;

  out_len = 0;
  if (!EVP_CipherFinal (ctx, plain + total_out, &out_len))
    {
      EVP_CIPHER_CTX_free (ctx);
      return FALSE;
    }
  total_out += out_len;

  EVP_CIPHER_CTX_free (ctx);

  if (total_out > psk_out_size)
    {
      fp_err ("decrypted TLS key is %" G_GSIZE_FORMAT " bytes, expected at most %"
              G_GSIZE_FORMAT, total_out, psk_out_size);
      return FALSE;
    }

  memcpy (psk_out, plain, total_out);
  *psk_len_out = total_out;
  fp_dbg ("PSK decrypted: %" G_GSIZE_FORMAT " bytes from %" G_GSIZE_FORMAT " encrypted", *psk_len_out, enc_len);
  return TRUE;
}

/* ---- TLS-PSK callback ---- */

static unsigned int
fpc1022_psk_server_cb (SSL *ssl, const char *identity,
                       unsigned char *psk, unsigned int max_psk_len)
{
  FpiDeviceFpc1022 *self = SSL_get_app_data (ssl);

  if (self->tls_psk_len == 0 || self->tls_psk_len > max_psk_len)
    return 0;

  memcpy (psk, self->tls_psk, self->tls_psk_len);
  return self->tls_psk_len;
}

/* ---- USB control transfer helpers ---- */

static GCancellable *
fpc1022_get_transfer_cancellable (FpiDeviceFpc1022 *self, FpiSsm *ssm)
{
  if (ssm == self->open_ssm)
    return fpi_device_get_cancellable (FP_DEVICE (self));

  return self->interrupt_cancellable;
}

static void
fpc1022_ctrl_cmd_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                     gpointer user_data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fpi_ssm_next_state (transfer->ssm);
}

/* Like fpc1022_ctrl_cmd_cb but ignores errors (for deactivation commands
 * that may stall if no session is active). */
static void
fpc1022_ctrl_cmd_ignore_error_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                                  gpointer user_data, GError *error)
{
  if (error)
    {
      fp_dbg ("Ignoring control transfer error: %s", error->message);
      g_error_free (error);
    }

  fpi_ssm_next_state (transfer->ssm);
}

/* Fire-and-forget callback: just log errors, don't touch SSM. */
static void
fpc1022_ctrl_cmd_noop_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                          gpointer user_data, GError *error)
{
  if (error)
    {
      fp_dbg ("Fire-and-forget ctrl error: %s", error->message);
      g_error_free (error);
    }
}

static void
fpc1022_send_ctrl_full (FpDevice *dev, FpiSsm *ssm,
                        guint8 request, guint16 value, guint16 index,
                        const guint8 *data, gsize data_len,
                        FpiUsbTransferCallback callback)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  fpi_usb_transfer_fill_control (transfer,
                                 G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                 G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                 G_USB_DEVICE_RECIPIENT_DEVICE,
                                 request, value, index, data_len);

  if (data && data_len > 0)
    memcpy (transfer->buffer, data, data_len);

  transfer->ssm = ssm;
  fpi_usb_transfer_submit (transfer, FPC1022_CTRL_TIMEOUT,
                           fpc1022_get_transfer_cancellable (self, ssm),
                           callback, NULL);
}

static void
fpc1022_send_ctrl (FpDevice *dev, FpiSsm *ssm,
                   guint8 request, guint16 value, guint16 index,
                   const guint8 *data, gsize data_len)
{
  fpc1022_send_ctrl_full (dev, ssm, request, value, index, data, data_len,
                          fpc1022_ctrl_cmd_cb);
}

/* ---- Bulk event reception helper ---- */

static void fpc1022_capture_bulk_cb (FpiUsbTransfer *transfer,
                                     FpDevice       *dev,
                                     gpointer        user_data,
                                     GError         *error);
static void fpc1022_tls_handshake_flush_cb (FpiUsbTransfer *transfer,
                                            FpDevice       *dev,
                                            gpointer        user_data,
                                            GError         *error);

static void
fpc1022_submit_bulk_read (FpDevice *dev, FpiSsm *ssm,
                          FpiUsbTransferCallback callback,
                          guint timeout_ms)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  fpi_usb_transfer_fill_bulk (transfer, FPC1022_EP_IN, FPC1022_EP_IN_MAX_BUF_SIZE);
  transfer->ssm = ssm;
  fpi_usb_transfer_submit (transfer, timeout_ms,
                           fpc1022_get_transfer_cancellable (self, ssm),
                           callback, NULL);
}

/* ---- TLS data exchange helpers ---- */

/* Feed data received from device bulk IN (ev_tls payload) into SSL BIO input */
static gboolean
fpc1022_tls_feed_input (FpiDeviceFpc1022 *self,
                        const guint8 *data, gsize len)
{
  int written;

  if (len == 0)
    return TRUE;
  if (len > G_MAXINT)
    return FALSE;

  written = BIO_write (self->bio_in, data, (int) len);
  return written >= 0 && (gsize) written == len;
}

/* ---- Bulk event accumulation ----
 *
 * Events from the device may span multiple USB bulk transfers (max 64 bytes).
 * The event header's `len` field (big-endian) gives the total event size.
 * We accumulate into self->bulk_buf until we have the full event.
 */

static void fpc1022_process_event (FpDevice *dev, FpiSsm *ssm);
static void fpc1022_open_continue (FpDevice *dev, FpiSsm *ssm);

static gboolean
fpc1022_prepare_bulk_event (FpiDeviceFpc1022 *self,
                            FpiSsm            *ssm,
                            gboolean          *complete)
{
  guint32 event_len;

  *complete = FALSE;
  if (self->bulk_recv_len < sizeof (Fpc1022EvtHdr))
    return TRUE;

  if (self->evt_total_len == 0)
    {
      memcpy (&event_len,
              self->bulk_buf + G_STRUCT_OFFSET (Fpc1022EvtHdr, len),
              sizeof (event_len));
      self->evt_total_len = GUINT32_FROM_BE (event_len);

      if (self->evt_total_len < sizeof (Fpc1022EvtHdr) ||
          self->evt_total_len > FPC1022_BULK_EVENT_MAX_SIZE)
        {
          fp_err ("Invalid bulk event length: %" G_GSIZE_FORMAT,
                  self->evt_total_len);
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          return FALSE;
        }
    }

  *complete = self->bulk_recv_len >= self->evt_total_len;
  return TRUE;
}

static void
fpc1022_consume_bulk_event (FpiDeviceFpc1022 *self)
{
  gsize remaining;

  g_assert (self->evt_total_len > 0);
  g_assert (self->evt_total_len <= self->bulk_recv_len);
  remaining = self->bulk_recv_len - self->evt_total_len;
  memmove (self->bulk_buf,
           self->bulk_buf + self->evt_total_len,
           remaining);
  self->bulk_recv_len = remaining;
  self->evt_total_len = 0;
}

static void
fpc1022_open_bulk_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                      gpointer user_data, GError *error)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  /* Accumulate data into bulk_buf */
  if (self->bulk_recv_len + transfer->actual_length > sizeof (self->bulk_buf))
    {
      fp_err ("Bulk buffer overflow");
      self->bulk_recv_len = 0;
      self->evt_total_len = 0;
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  memcpy (self->bulk_buf + self->bulk_recv_len,
          transfer->buffer, transfer->actual_length);
  self->bulk_recv_len += transfer->actual_length;

  fpc1022_open_continue (dev, transfer->ssm);
}

static void
fpc1022_open_continue (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  gboolean complete;

  if (!fpc1022_prepare_bulk_event (self, ssm, &complete))
    return;

  if (complete)
    fpc1022_process_event (dev, ssm);
  else
    fpc1022_submit_bulk_read (dev, ssm, fpc1022_open_bulk_cb,
                              FPC1022_DATA_TIMEOUT);
}

static gboolean
fpc1022_flush_handshake_packet (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  int pending = BIO_ctrl_pending (self->bio_out);

  if (pending > 0)
    {
      guint8 buf[FPC1022_BULK_MAX_PKT];
      int n = BIO_read (self->bio_out, buf, MIN (pending, FPC1022_BULK_MAX_PKT));

      if (n > 0)
        {
          FpiUsbTransfer *t = fpi_usb_transfer_new (dev);

          fpi_usb_transfer_fill_control (t,
                                         G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                         G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                         G_USB_DEVICE_RECIPIENT_DEVICE,
                                         FPC1022_CMD_TLS_DATA, 0x0001, 0, n);
          memcpy (t->buffer, buf, n);
          t->ssm = ssm;
          fpi_usb_transfer_submit (t, FPC1022_CTRL_TIMEOUT,
                                   fpc1022_get_transfer_cancellable (self, ssm),
                                   fpc1022_tls_handshake_flush_cb, NULL);
          return TRUE;
        }
    }

  return FALSE;
}

/* Try to advance TLS handshake: flush output then read more */
static void
fpc1022_tls_handshake_step (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  int ret = SSL_do_handshake (self->ssl);

  if (ret == 1)
    {
      const SSL_CIPHER *cipher = SSL_get_current_cipher (self->ssl);
      fp_dbg ("TLS handshake completed! cipher=%s version=%s",
              cipher ? SSL_CIPHER_get_name (cipher) : "unknown",
              SSL_get_version (self->ssl));
      self->tls_established = TRUE;

      /* CRITICAL: Flush any remaining TLS handshake data (e.g. Finished)
       * to the device before proceeding. Without this, the sensor never
       * receives our final handshake messages and doesn't consider TLS
       * established, causing a reset on subsequent commands. */
      if (fpc1022_flush_handshake_packet (dev, ssm))
        return;

      fpi_ssm_next_state (ssm);
      return;
    }

  int ssl_err = SSL_get_error (self->ssl, ret);

  if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
    {
      /* Flush any pending output first */
      if (fpc1022_flush_handshake_packet (dev, ssm))
        return;

      /* Need data from device */
      fpc1022_open_continue (dev, ssm);
      return;
    }

  fp_err ("TLS handshake error: ssl_err=%d: %s", ssl_err,
          ERR_error_string (ERR_get_error (), NULL));
  fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
}

/* Process a fully received bulk event */
static void
fpc1022_process_event (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  Fpc1022EvtHdr *hdr = (Fpc1022EvtHdr *) self->bulk_buf;
  guint32 code = GUINT32_FROM_BE (hdr->code);
  guint32 len = GUINT32_FROM_BE (hdr->len);
  int ssm_state = fpi_ssm_get_cur_state (ssm);

  fp_dbg ("%s event code=0x%02x len=%u state=%d",
          G_STRFUNC, code, len, ssm_state);

  gsize event_len = self->evt_total_len;

  switch (ssm_state)
    {
    case FPC1022_OPEN_WAIT_INIT_RESULT:
      if (code == FPC1022_EVT_INIT_RESULT)
        {
          fp_dbg ("Got init result, proceeding to TLS key retrieval");
          fpc1022_consume_bulk_event (self);
          fpi_ssm_next_state (ssm);
          return;
        }
      fpc1022_consume_bulk_event (self);
      fpc1022_open_continue (dev, ssm);
      return;

    case FPC1022_OPEN_TLS_HANDSHAKE:
      if (code == FPC1022_EVT_TLS)
        {
          /* Feed TLS payload (after event header) into SSL BIO */
          gsize payload_off = sizeof (Fpc1022EvtHdr);

          if (event_len > payload_off &&
              !fpc1022_tls_feed_input (self,
                                       self->bulk_buf + payload_off,
                                       event_len - payload_off))
            {
              fpi_ssm_mark_failed (ssm,
                                   fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
              return;
            }

          fpc1022_consume_bulk_event (self);
          fpc1022_tls_handshake_step (dev, ssm);
          return;
        }
      fp_dbg ("Ignoring event 0x%02x during TLS handshake", code);
      fpc1022_consume_bulk_event (self);
      fpc1022_open_continue (dev, ssm);
      return;

    default:
      fp_dbg ("Unexpected event 0x%02x in state %d", code, ssm_state);
      fpc1022_consume_bulk_event (self);
      fpc1022_open_continue (dev, ssm);
      return;
    }
}

/* Callback for the GET_STATE control transfer */
static void
fpc1022_open_get_state_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                           gpointer user_data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (transfer->actual_length >= 4)
    {
      fp_dbg ("FPC firmware version: %d.%d.%d.%d",
              transfer->buffer[0], transfer->buffer[1],
              transfer->buffer[2], transfer->buffer[3]);
    }

  fpi_ssm_next_state (transfer->ssm);
}

/* Callback for the GET_TLS_KEY control transfer */
static void
fpc1022_open_get_tls_key_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                             gpointer user_data, GError *error)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  /* The control response buffer starts after the setup packet (8 bytes) for
   * control transfers created with fpi_usb_transfer_fill_control.
   * But libfprint's fill_control puts the response directly in transfer->buffer. */
  guint8 *data = transfer->buffer;
  gsize data_len = transfer->actual_length;
  guint32 magic;
  guint32 key_offset;
  guint32 key_len;
  guint32 aad_offset;
  guint32 aad_len;
  guint32 sig_offset;
  guint32 sig_len;

  fp_dbg ("%s received TLS key packet, %" G_GSIZE_FORMAT " bytes", G_STRFUNC, data_len);

  if (data_len < sizeof (Fpc1022TlsKeyPkt))
    {
      fp_err ("TLS key packet too short: %" G_GSIZE_FORMAT, data_len);
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  Fpc1022TlsKeyPkt *pkt = (Fpc1022TlsKeyPkt *) data;

  magic = GUINT32_FROM_LE (pkt->magic);
  key_offset = GUINT32_FROM_LE (pkt->key_offset);
  key_len = GUINT32_FROM_LE (pkt->key_len);
  aad_offset = GUINT32_FROM_LE (pkt->aad_offset);
  aad_len = GUINT32_FROM_LE (pkt->aad_len);
  sig_offset = GUINT32_FROM_LE (pkt->sig_offset);
  sig_len = GUINT32_FROM_LE (pkt->sig_len);

  if (magic != FPC1022_TLS_KEY_MAGIC)
    {
      fp_err ("TLS key packet bad magic: 0x%08x (expected 0x%08x)",
              magic, FPC1022_TLS_KEY_MAGIC);
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  /* All offsets in the packet are relative to the start of the packet.
   * Compare each length against the space remaining after its offset: adding
   * offset and length first would let a hostile packet wrap guint32 and slip
   * past the check. */
  if (aad_offset > data_len || aad_len > data_len - aad_offset ||
      key_offset > data_len || key_len > data_len - key_offset ||
      sig_offset > data_len || sig_len > data_len - sig_offset)
    {
      fp_err ("TLS key packet fields out of bounds (aad=%u+%u, key=%u+%u, sig=%u+%u, total=%" G_GSIZE_FORMAT ")",
              aad_offset, aad_len, key_offset, key_len,
              sig_offset, sig_len, data_len);
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  /* Verify AAD is "FPC TLS Keys" */
  if (aad_len != sizeof ("FPC TLS Keys") ||
      memcmp ("FPC TLS Keys", data + aad_offset, aad_len) != 0)
    {
      fp_err ("TLS key packet bad AAD");
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  /* Verify HMAC signature */
  if (!fpc1022_verify_tls_key_hmac (data + aad_offset, aad_len,
                                    data + key_offset, key_len,
                                    data + sig_offset, sig_len))
    {
      fp_err ("TLS key HMAC verification failed");
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  fp_dbg ("TLS key HMAC verified OK");

  /* Decrypt PSK */
  gsize psk_len = 0;

  if (!fpc1022_decrypt_tls_psk (data + key_offset, key_len,
                                 self->tls_psk, sizeof (self->tls_psk), &psk_len))
    {
      fp_err ("TLS PSK decryption failed");
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  self->tls_psk_len = psk_len;
  fp_dbg ("TLS PSK decrypted, %" G_GSIZE_FORMAT " bytes", self->tls_psk_len);

  fpi_ssm_next_state (transfer->ssm);
}

static void
fpc1022_open_ssm_run (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  FpiUsbTransfer *transfer;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FPC1022_OPEN_INDICATE_S_STATE:
      fp_dbg ("Sending cmd_indicate_s_state (S0)");
      fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_INDICATE_S_STATE,
                         FPC1022_S_STATE_S0, 0, NULL, 0);
      break;

    case FPC1022_OPEN_GET_STATE:
      fp_dbg ("Sending cmd_get_state");
      transfer = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     FPC1022_CMD_GET_STATE, 0, 0, 72);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer, FPC1022_CTRL_TIMEOUT,
                               fpc1022_get_transfer_cancellable (self, ssm),
                               fpc1022_open_get_state_cb, NULL);
      break;

    case FPC1022_OPEN_CMD_INIT:
      {
        fp_dbg ("Sending cmd_init");
        guint8 init_data[FPC1022_INIT_DATA_SIZE] = { FPC1022_ARM_OP_INIT, 0x2f, 0x11, 0x17 };
        fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_INIT, 0x0001, 0,
                           init_data, sizeof (init_data));
      }
      break;

    case FPC1022_OPEN_WAIT_INIT_RESULT:
      fp_dbg ("Waiting for init result on bulk IN");
      fpc1022_open_continue (dev, ssm);
      break;

    case FPC1022_OPEN_GET_TLS_KEY:
      fp_dbg ("Sending cmd_get_tls_key");
      transfer = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     FPC1022_CMD_GET_TLS_KEY, 0, 0, 1000);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer, FPC1022_CTRL_TIMEOUT,
                               fpc1022_get_transfer_cancellable (self, ssm),
                               fpc1022_open_get_tls_key_cb, NULL);
      break;

    case FPC1022_OPEN_TLS_INIT:
      {
        fp_dbg ("Initializing TLS-PSK");

        /* Create SSL context - we are the server, sensor is client */
        self->ssl_ctx = SSL_CTX_new (TLS_server_method ());
        if (!self->ssl_ctx)
          {
            fp_err ("SSL_CTX_new failed");
            fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
            return;
          }

        SSL_CTX_set_options (self->ssl_ctx, SSL_OP_NO_COMPRESSION);
        if (!SSL_CTX_use_psk_identity_hint (self->ssl_ctx, NULL))
          {
            fp_err ("Failed to configure TLS PSK identity hint");
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
            return;
          }
        SSL_CTX_set_psk_server_callback (self->ssl_ctx, fpc1022_psk_server_cb);

        /* Allow PSK and ECDHE-PSK cipher suites.
         * The sensor's mbedTLS prefers ECDHE-PSK-WITH-AES-128-CBC-SHA256. */
        if (!SSL_CTX_set_cipher_list (self->ssl_ctx,
                                      "ECDHE-PSK-AES128-CBC-SHA256:"
                                      "ECDHE-PSK-AES256-CBC-SHA384:"
                                      "PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA384:"
                                      "PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA:"
                                      "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384"))
          {
            fp_err ("Failed to configure TLS cipher list");
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
            return;
          }

        /* Create SSL connection */
        self->ssl = SSL_new (self->ssl_ctx);
        if (!self->ssl)
          {
            fp_err ("SSL_new failed");
            fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
            return;
          }

        SSL_set_app_data (self->ssl, self);

        /* Create memory BIOs for data exchange */
        self->bio_in = BIO_new (BIO_s_mem ());
        self->bio_out = BIO_new (BIO_s_mem ());
        if (!self->bio_in || !self->bio_out)
          {
            fp_err ("BIO_new failed");
            BIO_free (self->bio_in);
            BIO_free (self->bio_out);
            self->bio_in = NULL;
            self->bio_out = NULL;
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
            return;
          }
        BIO_set_mem_eof_return (self->bio_in, -1);
        BIO_set_mem_eof_return (self->bio_out, -1);
        SSL_set_bio (self->ssl, self->bio_in, self->bio_out);

        /* Set as server and start accepting */
        SSL_set_accept_state (self->ssl);

        /* Match reference: limit TLS record size to 4096 bytes */
        if (!SSL_set_max_send_fragment (self->ssl, 4096))
          {
            fp_err ("Failed to configure TLS fragment size");
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
            return;
          }

        /* Send cmd_tls_init to the device to start TLS handshake */
        fp_dbg ("Sending cmd_tls_init");
        fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_TLS_INIT, 0x0001, 0, NULL, 0);
      }
      break;

    case FPC1022_OPEN_TLS_HANDSHAKE:
      fpc1022_tls_handshake_step (dev, ssm);
      break;

    default:
      g_assert_not_reached ();
    }
}

/* The TLS handshake flush callback needs to loop back to reading,
 * not advance the SSM. Override the behavior by jumping back. */
static void
fpc1022_tls_handshake_flush_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                                gpointer user_data, GError *error)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  /* Check if more to send */
  if (fpc1022_flush_handshake_packet (dev, transfer->ssm))
    return;

  /* All flushed */
  if (self->tls_established)
    {
      /* Post-handshake flush complete — advance SSM */
      fp_dbg ("TLS handshake flush complete, advancing SSM");
      fpi_ssm_next_state (transfer->ssm);
    }
  else
    {
      /* Mid-handshake flush — read more from device */
      fpc1022_open_continue (dev, transfer->ssm);
    }
}

static GError *
fpc1022_cleanup_resources (FpImageDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  GError *error = NULL;

  /* Cancel any pending operations */
  g_cancellable_cancel (self->interrupt_cancellable);
  g_clear_object (&self->interrupt_cancellable);

  /* Free TLS resources */
  if (self->ssl)
    {
      SSL_free (self->ssl); /* also frees bio_in and bio_out */
      self->ssl = NULL;
      self->bio_in = NULL;
      self->bio_out = NULL;
    }
  if (self->ssl_ctx)
    {
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
    }

  /* Free image buffer */
  g_clear_pointer (&self->tls_rx_buf, g_byte_array_unref);

  /* Clear PSK */
  memset (self->tls_psk, 0, sizeof (self->tls_psk));
  self->tls_psk_len = 0;
  self->tls_established = FALSE;
  self->bulk_recv_len = 0;
  self->evt_total_len = 0;

  /* Release USB interface */
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                  0, 0, &error);

  return error;
}

static void
fpc1022_open_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  self->open_ssm = NULL;

  if (error)
    {
      g_autoptr(GError) cleanup_error = NULL;

      cleanup_error = fpc1022_cleanup_resources (FP_IMAGE_DEVICE (dev));
      if (cleanup_error)
        fp_warn ("Failed to clean up after open error: %s",
                 cleanup_error->message);
    }

  fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
}

/* ---- Capture SSM ----
 *
 * After TLS is established, ALL sensor events (finger_down, image, etc.)
 * arrive encrypted inside ev_tls (0x05) frames on the USB bulk endpoint.
 * We must:
 *   1. Read raw USB bulk data and accumulate complete events
 *   2. For ev_tls events: feed payload into SSL BIO, then SSL_read
 *   3. Parse the decrypted data as inner fpc_event structures
 *   4. Handle inner events (finger_down → get image, image → submit)
 */

/* Forward declarations */
static void fpc1022_capture_process_event (FpDevice *dev,
                                           FpiSsm   *ssm);
static void fpc1022_process_tls_data (FpDevice *dev,
                                      FpiSsm   *ssm);
static void fpc1022_start_deactivation (FpImageDevice *dev);
static void fpc1022_capture_continue (FpDevice *dev, FpiSsm *ssm);

/* Send any pending TLS output (from bio_out) to the device.
 * After TLS handshake, SSL_read rarely produces output, but handle it. */
static void
fpc1022_flush_tls_output (FpDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  int pending = BIO_ctrl_pending (self->bio_out);

  while (pending > 0)
    {
      guint8 buf[FPC1022_BULK_MAX_PKT];
      int n = BIO_read (self->bio_out, buf, MIN (pending, FPC1022_BULK_MAX_PKT));

      if (n <= 0)
        break;

      FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_control (t,
                                     G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     FPC1022_CMD_TLS_DATA, 0x0001, 0, n);
      memcpy (t->buffer, buf, n);
      fpi_usb_transfer_submit (t, FPC1022_CTRL_TIMEOUT,
                               self->interrupt_cancellable,
                               fpc1022_ctrl_cmd_noop_cb, NULL);

      pending = BIO_ctrl_pending (self->bio_out);
    }
}

static void
fpc1022_capture_bulk_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                         gpointer user_data, GError *error)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  if (error)
    {
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          g_error_free (error);
          if (self->deactivating)
            fpi_ssm_mark_completed (transfer->ssm);
          return;
        }
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  /* Accumulate data into bulk_buf (events may span multiple USB packets) */
  if (self->bulk_recv_len + transfer->actual_length > sizeof (self->bulk_buf))
    {
      fp_err ("Bulk buffer overflow in capture");
      self->bulk_recv_len = 0;
      self->evt_total_len = 0;
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  memcpy (self->bulk_buf + self->bulk_recv_len,
          transfer->buffer, transfer->actual_length);
  self->bulk_recv_len += transfer->actual_length;

  fpc1022_capture_continue (dev, transfer->ssm);
}

static void
fpc1022_capture_continue (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  gboolean complete;
  gboolean waiting_finger;
  guint timeout;

  if (!fpc1022_prepare_bulk_event (self, ssm, &complete))
    return;

  if (complete)
    {
      fpc1022_capture_process_event (dev, ssm);
      return;
    }

  waiting_finger = fpi_ssm_get_cur_state (ssm) == FPC1022_CAPTURE_ARM_SENSOR;
  timeout = waiting_finger ? FPC1022_FINGER_TIMEOUT : FPC1022_DATA_TIMEOUT;
  fpc1022_submit_bulk_read (dev, ssm, fpc1022_capture_bulk_cb, timeout);
}

/* Process a complete USB bulk event during capture.
 * After TLS, all meaningful events come as ev_tls (0x05). */
static void
fpc1022_capture_process_event (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  Fpc1022EvtHdr *hdr = (Fpc1022EvtHdr *) self->bulk_buf;
  guint32 code = GUINT32_FROM_BE (hdr->code);
  gsize event_len = self->evt_total_len;
  int state = fpi_ssm_get_cur_state (ssm);

  fp_dbg ("capture USB event: code=0x%02x len=%u state=%d",
          code, (guint) event_len, state);

  if (code == FPC1022_EVT_TLS)
    {
      /* Feed TLS payload into SSL BIO */
      gsize payload_off = sizeof (Fpc1022EvtHdr);

      if (event_len > payload_off &&
          !fpc1022_tls_feed_input (self,
                                   self->bulk_buf + payload_off,
                                   event_len - payload_off))
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          return;
        }

      fpc1022_consume_bulk_event (self);

      /* Decrypt and process inner events */
      fpc1022_process_tls_data (dev, ssm);
      return;
    }

  /* Handle raw (non-TLS) events.
   * Some firmware versions may send finger_down etc. as raw events. */
  switch (code)
    {
    case FPC1022_EVT_FINGER_DOWN:
      fp_dbg ("Finger detected (raw event)!");
      fpc1022_consume_bulk_event (self);
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
      fpi_ssm_jump_to_state (ssm, FPC1022_CAPTURE_GET_IMAGE);
      return;

    case FPC1022_EVT_FINGER_UP:
      fp_dbg ("Finger up (raw event)");
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
      break;

    case FPC1022_EVT_ARM_RESULT:
      fp_dbg ("Arm result (raw event)");
      break;

    case FPC1022_EVT_HELLO:
      fp_dbg ("Hello event (raw), sensor is alive");
      break;

    default:
      fp_dbg ("Unhandled raw event 0x%02x during capture (state=%d)", code, state);
      break;
    }

  fpc1022_consume_bulk_event (self);
  fpc1022_capture_continue (dev, ssm);
}

/* Read decrypted data from SSL and process inner TLS messages.
 * Firmware 11.x TLS inner messages: {cmdid(4B BE), total_len(4B BE), ...metadata...}
 * Messages may be split or coalesced across SSL_read() calls. */
static void
fpc1022_process_tls_data (FpDevice *dev, FpiSsm *ssm)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  int state = fpi_ssm_get_cur_state (ssm);
  guint8 ssl_buf[8192];
  int ssl_err;
  int n;

  while ((n = SSL_read (self->ssl, ssl_buf, sizeof (ssl_buf))) > 0)
    {
      fp_dbg ("SSL_read: %d decrypted bytes (state=%d)", n, state);
      g_byte_array_append (self->tls_rx_buf, ssl_buf, n);
    }

  ssl_err = SSL_get_error (self->ssl, n);
  if (ssl_err != SSL_ERROR_WANT_READ)
    {
      fp_err ("SSL_read error: %d: %s", ssl_err,
              ERR_error_string (ERR_get_error (), NULL));
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  while (self->tls_rx_buf->len >= 8)
    {
      guint32 cmdid;
      guint32 total_len;

      memcpy (&cmdid, self->tls_rx_buf->data, sizeof (cmdid));
      memcpy (&total_len, self->tls_rx_buf->data + sizeof (cmdid),
              sizeof (total_len));
      cmdid = GUINT32_FROM_BE (cmdid);
      total_len = GUINT32_FROM_BE (total_len);

      if (total_len < 8)
        {
          fp_err ("Invalid TLS inner message length: %u", total_len);
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          return;
        }

      if (total_len > FPC1022_TLS_MSG_MAX_SIZE)
        {
          fp_err ("Oversized TLS inner message: %u", total_len);
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          return;
        }

      if (self->tls_rx_buf->len < total_len)
        break;

      fp_dbg ("TLS inner message: cmdid=%u total_len=%u", cmdid, total_len);

      switch (cmdid)
        {
        case FPC1022_EVT_DEAD_PIXEL_REPORT:
          fp_dbg ("Dead pixel report (via TLS), len=%u", total_len);
          break;

        case FPC1022_EVT_IMAGE:
          {
            g_autoptr(FpImage) img = NULL;
            FpImage *scaled;

            if (total_len != FPC1022_TLS_MSG_HDR_SIZE + FPC1022_IMG_SIZE)
              {
                fp_err ("Invalid TLS image message length: %u", total_len);
                fpi_ssm_mark_failed (ssm,
                                     fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
                return;
              }

            img = fp_image_new (FPC1022_IMG_WIDTH, FPC1022_IMG_HEIGHT);
            memcpy (img->data,
                    self->tls_rx_buf->data + FPC1022_TLS_MSG_HDR_SIZE,
                    FPC1022_IMG_SIZE);
            img->flags = 0;
            scaled = fpc1022_scale_nn_2x (img);

            g_byte_array_remove_range (self->tls_rx_buf, 0, total_len);
            fpi_image_device_image_captured (FP_IMAGE_DEVICE (dev), scaled);
            fpi_ssm_mark_completed (ssm);
            return;
          }

        case FPC1022_EVT_ARM_RESULT:
          fp_dbg ("Arm result (via TLS)");
          break;

        case FPC1022_EVT_FINGER_DOWN:
          fp_dbg ("Finger detected (via TLS)!");
          g_byte_array_remove_range (self->tls_rx_buf, 0, total_len);
          fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
          fpi_ssm_jump_to_state (ssm, FPC1022_CAPTURE_GET_IMAGE);
          return;

        case FPC1022_EVT_FINGER_UP:
          fp_dbg ("Finger up (via TLS)");
          fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
          break;

        case FPC1022_EVT_USB_LOGS:
          fp_dbg ("USB logs (via TLS)");
          break;

        default:
          fp_dbg ("Unknown TLS cmdid %u, ignoring", cmdid);
          break;
        }

      g_byte_array_remove_range (self->tls_rx_buf, 0, total_len);
    }

  /* Continue reading */
  fpc1022_flush_tls_output (dev);
  fpc1022_capture_continue (dev, ssm);
}

static void
fpc1022_capture_ssm_run (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FPC1022_CAPTURE_STOP_ARM:
      {
        /* Reference implementation does stop→abort→session_off→start after TLS.
         * Send arm with stop flag (0x12) to reset sensor state. */
        fp_dbg ("Stopping sensor (arm 0x12)");
        guint8 stop_data[FPC1022_INIT_DATA_SIZE] = { FPC1022_ARM_OP_STOP, 0x2f, 0x11, 0x17 };
        fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_ARM, 0x0001, 0,
                           stop_data, FPC1022_INIT_DATA_SIZE);
      }
      break;

    case FPC1022_CAPTURE_STOP_ABORT:
      fp_dbg ("Sending abort");
      fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_ABORT, 1, 0, NULL, 0);
      break;

    case FPC1022_CAPTURE_STOP_SESSION_OFF:
      {
        /* session_off may stall if no session is active - ignore errors */
        fp_dbg ("Sending session_off (fingerprint_off)");
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        fpi_usb_transfer_fill_control (t,
                                       G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                       G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                       G_USB_DEVICE_RECIPIENT_DEVICE,
                                       FPC1022_CMD_FINGERPRINT_OFF, 0, 0, 0);
        t->ssm = ssm;
        fpi_usb_transfer_submit (t, FPC1022_CTRL_TIMEOUT,
                                 fpc1022_get_transfer_cancellable (self, ssm),
                                 fpc1022_ctrl_cmd_ignore_error_cb, NULL);
      }
      break;

    case FPC1022_CAPTURE_ARM_SENSOR:
      {
        fp_dbg ("Arming sensor for finger detection");
        self->bulk_recv_len = 0;
        self->evt_total_len = 0;

        /* Submit bulk read BEFORE arm to catch events */
        fpc1022_capture_continue (dev, ssm);

        /* Send arm command (fire-and-forget, bulk cb handles transitions) */
        guint8 arm_data[FPC1022_INIT_DATA_SIZE] = { FPC1022_ARM_OP_START, 0x2f, 0x11, 0x17 };
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        fpi_usb_transfer_fill_control (t,
                                       G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                       G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                       G_USB_DEVICE_RECIPIENT_DEVICE,
                                       FPC1022_CMD_ARM, 0x0001, 0,
                                       FPC1022_INIT_DATA_SIZE);
        memcpy (t->buffer, arm_data, FPC1022_INIT_DATA_SIZE);
        fpi_usb_transfer_submit (t, FPC1022_CTRL_TIMEOUT,
                                 fpc1022_get_transfer_cancellable (self, ssm),
                                 fpc1022_ctrl_cmd_noop_cb, NULL);
      }
      break;

    case FPC1022_CAPTURE_GET_IMAGE:
      fp_dbg ("Requesting image capture");
      fpc1022_send_ctrl (dev, ssm, FPC1022_CMD_GET_IMG, 0x0000, 0, NULL, 0);
      break;

    case FPC1022_CAPTURE_RECV_IMAGE:
      fp_dbg ("Receiving image data via TLS");
      fpc1022_capture_continue (dev, ssm);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
fpc1022_capture_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  self->capture_ssm = NULL;

  if (self->deactivating)
    {
      if (error)
        g_error_free (error);
      fpc1022_start_deactivation (FP_IMAGE_DEVICE (dev));
      return;
    }

  if (error)
    {
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev), error);
      return;
    }

  /* Report finger off and restart capture loop */
  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);

  if (self->deactivating)
    return;

  /* Start next capture cycle */
  self->capture_ssm = fpi_ssm_new (dev, fpc1022_capture_ssm_run,
                                   FPC1022_CAPTURE_NUM_STATES);
  fpi_ssm_start (self->capture_ssm, fpc1022_capture_ssm_done);
}

/* ---- Deactivate SSM ---- */

static void
fpc1022_deact_ssm_run (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FPC1022_DEACT_ARM_STOP:
      {
        fp_dbg ("Stopping sensor (arm stop)");
        guint8 stop_data[FPC1022_INIT_DATA_SIZE] = { FPC1022_ARM_OP_STOP, 0x2f, 0x11, 0x17 };
        fpc1022_send_ctrl_full (dev, ssm, FPC1022_CMD_ARM, 0x0001, 0,
                                stop_data, sizeof (stop_data),
                                fpc1022_ctrl_cmd_ignore_error_cb);
      }
      break;

    case FPC1022_DEACT_ABORT:
      fp_dbg ("Sending abort");
      fpc1022_send_ctrl_full (dev, ssm, FPC1022_CMD_ABORT, 1, 0, NULL, 0,
                              fpc1022_ctrl_cmd_ignore_error_cb);
      break;

    case FPC1022_DEACT_SESSION_OFF:
      fp_dbg ("Sending fingerprint session off");
      fpc1022_send_ctrl_full (dev, ssm, FPC1022_CMD_FINGERPRINT_OFF, 0, 0, NULL, 0,
                              fpc1022_ctrl_cmd_ignore_error_cb);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
fpc1022_deact_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    fp_err ("Deactivation error: %s", error->message);

  fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
fpc1022_start_deactivation (FpImageDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  FpiSsm *ssm;

  g_clear_object (&self->interrupt_cancellable);
  self->interrupt_cancellable = g_cancellable_new ();

  ssm = fpi_ssm_new (FP_DEVICE (dev), fpc1022_deact_ssm_run,
                     FPC1022_DEACT_NUM_STATES);
  fpi_ssm_start (ssm, fpc1022_deact_ssm_done);
}

/* ---- FpImageDevice vfuncs ---- */

static void
fpc1022_img_open (FpImageDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);
  GError *error = NULL;

  fp_dbg ("Opening FPC1022 device");

  /* Claim USB interface 0 */
  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                     0, 0, &error))
    {
      fpi_image_device_open_complete (dev, error);
      return;
    }

  self->tls_rx_buf = g_byte_array_new ();
  self->bulk_recv_len = 0;
  self->evt_total_len = 0;
  self->tls_established = FALSE;
  self->deactivating = FALSE;
  self->interrupt_cancellable = g_cancellable_new ();

  /* Start open SSM */
  self->open_ssm = fpi_ssm_new (FP_DEVICE (dev), fpc1022_open_ssm_run,
                                FPC1022_OPEN_NUM_STATES);
  fpi_ssm_start (self->open_ssm, fpc1022_open_ssm_done);
}

static void
fpc1022_img_close (FpImageDevice *dev)
{
  GError *error;

  fp_dbg ("Closing FPC1022 device");

  error = fpc1022_cleanup_resources (dev);
  fpi_image_device_close_complete (dev, error);
}

static void
fpc1022_activate (FpImageDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  fp_dbg ("Activating FPC1022 device");

  self->deactivating = FALSE;

  if (!self->tls_established)
    {
      fpi_image_device_activate_complete (dev,
                                          fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }

  fpi_image_device_activate_complete (dev, NULL);

  if (self->deactivating)
    return;

  /* Start capture loop */
  self->capture_ssm = fpi_ssm_new (FP_DEVICE (dev), fpc1022_capture_ssm_run,
                                   FPC1022_CAPTURE_NUM_STATES);
  fpi_ssm_start (self->capture_ssm, fpc1022_capture_ssm_done);
}

static void
fpc1022_deactivate (FpImageDevice *dev)
{
  FpiDeviceFpc1022 *self = FPI_DEVICE_FPC1022 (dev);

  fp_dbg ("Deactivating FPC1022 device");

  self->deactivating = TRUE;

  /* Cancel any pending capture */
  if (self->capture_ssm)
    {
      g_cancellable_cancel (self->interrupt_cancellable);
      return;
    }

  fpc1022_start_deactivation (dev);
}

/* ---- GObject boilerplate ---- */

static void
fpi_device_fpc1022_init (FpiDeviceFpc1022 *self)
{
}

static void
fpi_device_fpc1022_class_init (FpiDeviceFpc1022Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  dev_class->id = "fpc1022";
  dev_class->full_name = "FPC1022 Fingerprint Sensor";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  img_class->img_open = fpc1022_img_open;
  img_class->img_close = fpc1022_img_close;
  img_class->activate = fpc1022_activate;
  img_class->deactivate = fpc1022_deactivate;

  img_class->img_width = FPC1022_IMG_WIDTH * FPC1022_IMG_SCALE;
  img_class->img_height = FPC1022_IMG_HEIGHT * FPC1022_IMG_SCALE;
  img_class->algorithm = FPI_DEVICE_ALGO_SIGFM;
  img_class->score_threshold = FPC1022_SCORE_THRESHOLD;
}
