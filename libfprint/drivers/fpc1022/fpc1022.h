/*
 * FPC1022 (Match-on-Host) driver for libfprint
 *
 * Supports FPC Disum USB fingerprint sensors (10a5:9200).
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

#pragma once

#include "fpi-image-device.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"

#include <openssl/ssl.h>
#include <openssl/evp.h>

/* USB parameters */
#define FPC1022_EP_IN (2 | FPI_USB_ENDPOINT_IN)              /* 0x82 */
#define FPC1022_EP_IN_MAX_BUF_SIZE 2048
#define FPC1022_CTRL_TIMEOUT 2000
#define FPC1022_DATA_TIMEOUT 15000
#define FPC1022_FINGER_TIMEOUT 600000      /* 10 min for finger wait */
#define FPC1022_BULK_MAX_PKT 64
#define FPC1022_EVT_HDR_SIZE 12
#define FPC1022_TLS_RECORD_MAX_SIZE ((16 * 1024) + 2048)
#define FPC1022_BULK_EVENT_MAX_SIZE (FPC1022_EVT_HDR_SIZE + FPC1022_TLS_RECORD_MAX_SIZE)
#define FPC1022_BULK_ACCUM_SIZE (FPC1022_BULK_EVENT_MAX_SIZE + FPC1022_EP_IN_MAX_BUF_SIZE)

/* Sensor image dimensions (FPC1022: 112x88, 1 byte per pixel) */
#define FPC1022_IMG_WIDTH 112
#define FPC1022_IMG_HEIGHT 88
#define FPC1022_IMG_SIZE (FPC1022_IMG_WIDTH * FPC1022_IMG_HEIGHT)
#define FPC1022_IMG_SCALE 2

/* TLS inner message header size (cmdid + total_len + metadata) */
#define FPC1022_TLS_MSG_HDR_SIZE 24
#define FPC1022_TLS_MSG_MAX_SIZE (FPC1022_TLS_MSG_HDR_SIZE + FPC1022_IMG_SIZE)

/* Commands (bRequest in USB control transfer) */
#define FPC1022_CMD_INIT 0x01
#define FPC1022_CMD_ARM 0x02
#define FPC1022_CMD_ABORT 0x03
#define FPC1022_CMD_TLS_INIT 0x05
#define FPC1022_CMD_TLS_DATA 0x06
#define FPC1022_CMD_INDICATE_S_STATE 0x08
#define FPC1022_CMD_GET_IMG 0x09
#define FPC1022_CMD_GET_TLS_KEY 0x0B
#define FPC1022_CMD_FINGERPRINT_OFF 0x12
#define FPC1022_CMD_GET_STATE 0x50

/* Events (code field in bulk IN event header) */
#define FPC1022_EVT_HELLO 0x01
#define FPC1022_EVT_INIT_RESULT 0x02
#define FPC1022_EVT_ARM_RESULT 0x03
#define FPC1022_EVT_DEAD_PIXEL_REPORT 0x04
#define FPC1022_EVT_TLS 0x05
#define FPC1022_EVT_FINGER_DOWN 0x06
#define FPC1022_EVT_FINGER_UP 0x07
#define FPC1022_EVT_IMAGE 0x08
#define FPC1022_EVT_USB_LOGS 0x09

/* TLS key packet magic */
#define FPC1022_TLS_KEY_MAGIC 0x0DEC0DED

/* Derived PSK size: SHA-256 output */
#define FPC1022_TLS_PSK_SIZE 32

/* AES-256-CBC block size, used to sanity-check the sealed key length */
#define FPC1022_AES_BLOCK_SIZE 16

/* S-state values */
#define FPC1022_S_STATE_S0 0x0010

/* Sensor init/arm/stop data (4-byte payloads for CMD_INIT and CMD_ARM) */
#define FPC1022_INIT_DATA_SIZE 4
#define FPC1022_ARM_OP_INIT 0x10
#define FPC1022_ARM_OP_START 0x11
#define FPC1022_ARM_OP_STOP 0x12

/* SIGFM matching threshold (minimum number of consistent geometric angle pairs) */
#define FPC1022_SCORE_THRESHOLD 10

/* Event header (received on bulk IN endpoint) - network byte order */
typedef struct __attribute__((packed))
{
  guint32 code;
  guint32 len;
  guint32 unknown;
} Fpc1022EvtHdr;

/* TLS key packet header (all offsets are from start of packet) */
typedef struct __attribute__((packed))
{
  guint32 magic;
  guint32 key_offset;
  guint32 key_len;
  guint32 aad_offset;
  guint32 aad_len;
  guint32 sig_offset;
  guint32 sig_len;
} Fpc1022TlsKeyPkt;

/* SSM states for device open */
typedef enum {
  FPC1022_OPEN_INDICATE_S_STATE = 0,
  FPC1022_OPEN_GET_STATE,
  FPC1022_OPEN_CMD_INIT,
  FPC1022_OPEN_WAIT_INIT_RESULT,
  FPC1022_OPEN_GET_TLS_KEY,
  FPC1022_OPEN_TLS_INIT,
  FPC1022_OPEN_TLS_HANDSHAKE,
  FPC1022_OPEN_NUM_STATES,
} Fpc1022OpenState;

/* SSM states for image capture */
typedef enum {
  FPC1022_CAPTURE_STOP_ARM = 0,
  FPC1022_CAPTURE_STOP_ABORT,
  FPC1022_CAPTURE_STOP_SESSION_OFF,
  FPC1022_CAPTURE_ARM_SENSOR,
  FPC1022_CAPTURE_GET_IMAGE,
  FPC1022_CAPTURE_RECV_IMAGE,
  FPC1022_CAPTURE_NUM_STATES,
} Fpc1022CaptureState;

/* SSM states for deactivate */
typedef enum {
  FPC1022_DEACT_ARM_STOP = 0,
  FPC1022_DEACT_ABORT,
  FPC1022_DEACT_SESSION_OFF,
  FPC1022_DEACT_NUM_STATES,
} Fpc1022DeactState;

G_DECLARE_FINAL_TYPE (FpiDeviceFpc1022, fpi_device_fpc1022, FPI,
                      DEVICE_FPC1022, FpImageDevice)

struct _FpiDeviceFpc1022
{
  FpImageDevice parent;

  /* USB bulk event reception */
  guint8 bulk_buf[FPC1022_BULK_ACCUM_SIZE];
  gsize  bulk_recv_len;
  gsize  evt_total_len;

  /* TLS */
  guint8   tls_psk[FPC1022_TLS_PSK_SIZE];
  gsize    tls_psk_len;
  SSL_CTX *ssl_ctx;
  SSL     *ssl;
  BIO     *bio_in;       /* we write device data here, SSL reads from it */
  BIO     *bio_out;      /* SSL writes here, we read and send to device */
  gboolean tls_established;
  GByteArray *tls_rx_buf;

  /* State */
  FpiSsm       *open_ssm;
  FpiSsm       *capture_ssm;
  gboolean      deactivating;
  GCancellable *interrupt_cancellable;
};
