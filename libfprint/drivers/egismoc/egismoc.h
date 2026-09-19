/*
 * Driver for Egis Technology (LighTuning) Match-On-Chip sensors
 * Copyright (C) 2023-2025 Joshua Grisham <josh@joshuagrisham.com>
 *
 * Portions of code and logic inspired from the elanmoc libfprint driver
 * which is copyright (C) 2021 Elan Microelectronics Inc (see elanmoc.c)
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

#include "fpi-ssm.h"

#include "fpi-sdcp-device.h"

G_DECLARE_FINAL_TYPE (FpiDeviceEgisMoc, fpi_device_egismoc, FPI, DEVICE_EGISMOC, FpSdcpDevice)

#define EGISMOC_DRIVER_FULLNAME "Egis Technology (LighTuning) Match-on-Chip"

#define EGISMOC_DRIVER_CHECK_PREFIX_TYPE1 (1 << 0)
#define EGISMOC_DRIVER_CHECK_PREFIX_TYPE2 (1 << 1)
#define EGISMOC_DRIVER_MAX_ENROLL_STAGES_20 (1 << 2)
#define EGISMOC_DRIVER_MAX_ENROLL_STAGES_15 (1 << 3)

#define EGISMOC_EP_CMD_OUT (0x02 | FPI_USB_ENDPOINT_OUT)
#define EGISMOC_EP_CMD_IN (0x81 | FPI_USB_ENDPOINT_IN)
#define EGISMOC_EP_CMD_INTERRUPT_IN 0x83

#define EGISMOC_USB_CONTROL_TIMEOUT 5000
#define EGISMOC_USB_SEND_TIMEOUT 5000
#define EGISMOC_USB_RECV_TIMEOUT 5000
#define EGISMOC_USB_INTERRUPT_TIMEOUT 60000

#define EGISMOC_USB_IN_RECV_LENGTH 4096
#define EGISMOC_USB_INTERRUPT_IN_RECV_LENGTH 64

#define EGISMOC_MAX_ENROLL_STAGES_DEFAULT 10
#define EGISMOC_MAX_ENROLL_NUM 10
#define EGISMOC_FINGER_ON_SENSOR_TIMEOUT_USEC (10 * G_USEC_PER_SEC)

#define EGISMOC_CONNECT_RESPONSE_PREFIX_SIZE 15
#define EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE 14
#define EGISMOC_ENROLL_STARTING_RESPONSE_PREFIX_SIZE 14
#define EGISMOC_LIST_RESPONSE_PREFIX_SIZE 14
#define EGISMOC_LIST_RESPONSE_SUFFIX_SIZE 2

/* standard prefixes for all read/writes */

static const guint8 egismoc_write_prefix[] = {'E', 'G', 'I', 'S', 0x00, 0x00, 0x00, 0x01};

static const guint8 egismoc_read_prefix[] = {'S', 'I', 'G', 'E', 0x00, 0x00, 0x00, 0x01};


/* hard-coded command payloads */

static const guint8 cmd_fw_version[] = {0x00, 0x00, 0x00, 0x07, 0x50, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x0c};
static const guint8 rsp_fw_version_suffix[] = {0x90, 0x00};

static const guint8 rsp_sensor_has_finger_suffix[] = {0x90, 0x00, 0x90, 0x00};

/* Empty List response in the captured Egis protocol. */
static const guint8 rsp_list_empty_suffix[] = {0x65, 0xfe};

static const guint8 cmd_list[] = {0x00, 0x00, 0x00, 0x07, 0x50, 0x19, 0x04, 0x00, 0x00, 0x01, 0x40};

static const guint8 cmd_sensor_reset[] = {0x00, 0x00, 0x00, 0x04, 0x50, 0x1a, 0x00, 0x00};

static const guint8 cmd_sensor_check[] = {0x00, 0x00, 0x00, 0x04, 0x50, 0x17, 0x02, 0x00};

static const guint8 cmd_sensor_identify[] = {0x00, 0x00, 0x00, 0x04, 0x50, 0x17, 0x01, 0x01};
static const guint8 rsp_identify_match_suffix[] = {0x90, 0x00};
static const guint8 rsp_identify_notmatch_suffix[] = {0x90, 0x04};

static const guint8 cmd_sensor_enroll[] = {0x00, 0x00, 0x00, 0x04, 0x50, 0x17, 0x01, 0x00};

static const guint8 cmd_enroll_starting[] = {0x00, 0x00, 0x00, 0x07, 0x50, 0x16, 0x01, 0x00, 0x00, 0x00, 0x20};
static const guint8 rsp_enroll_starting_suffix[] = {0x90, 0x00};

static const guint8 cmd_sensor_start_capture[] = {0x00, 0x00, 0x00, 0x04, 0x50, 0x16, 0x02, 0x01};

static const guint8 cmd_capture_post_wait_finger[] = {0x00, 0x00, 0x00, 0x07, 0x50, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x80};

static const guint8 cmd_read_capture[] = {0x00, 0x00, 0x00, 0x07, 0x50, 0x16, 0x02, 0x02, 0x00, 0x00, 0x02};
static const guint8 rsp_read_success_suffix[] = {0x90, 0x00};
static const guint8 rsp_read_offcenter_suffix[] = {0x64, 0x91};
static const guint8 rsp_read_dirty_prefix[] = {0x00, 0x00, 0x00, 0x02, 0x64};

static const guint8 cmd_commit_starting[] = {0x00, 0x00, 0x00, 0x07, 0x50, 0x16, 0x05, 0x00, 0x00, 0x00, 0x20};
static const guint8 rsp_commit_success_suffix[] = {0x90, 0x00};


/* commands which exist on the device but are currently not used */
/*
   static guchar cmd_sensor_cancel[] = {0x00, 0x00, 0x00, 0x04, 0x50, 0x16, 0x04, 0x00};
   static gsize cmd_sensor_cancel_len = sizeof(cmd_sensor_cancel) / sizeof(cmd_sensor_cancel[0]);

   static guchar cmd_sensor_verify[] = {0x00, 0x00, 0x00, 0x04, 0x50, 0x04, 0x01, 0x00};
   static gsize cmd_sensor_verify_len = sizeof(cmd_sensor_verify) / sizeof(cmd_sensor_verify[0]);

   static guchar cmd_read_verify[] = {0x00, 0x00, 0x00, 0x04, 0x50, 0x04, 0x02, 0x00};
   static gsize cmd_read_verify_len = sizeof(cmd_read_verify) / sizeof(cmd_read_verify[0]);
 */


/* prefixes/suffixes and other things for dynamically created command payloads */

#define EGISMOC_CHECK_BYTES_LENGTH 2

static const guint8 cmd_sdcp_connect_prefix[] = {0x00, 0x00, 0x00, 0x6b, 0x50, 0x57, 0x01, 0x00, 0x00, 0x00, 0x62, 0x20};
static const guint8 cmd_sdcp_connect_suffix[] = {0x00, 0x00};
static const guint8 rsp_sdcp_connect_success_suffix[] = {0x90, 0x00};

static const guint8 cmd_new_print_prefix[] = {0x00, 0x00, 0x00, 0x27, 0x50, 0x16, 0x03, 0x00, 0x00, 0x00, 0x20};

static const guint8 cmd_delete_prefix[] = {0x50, 0x18, 0x04, 0x00, 0x00};
static const guint8 rsp_delete_success_prefix[] = {0x00, 0x00, 0x00, 0x02, 0x90, 0x00};

static const guint8 cmd_check_prefix_type1[] = {0x50, 0x17, 0x03, 0x00, 0x00};
static const guint8 cmd_check_prefix_type2[] = {0x50, 0x17, 0x03, 0x80, 0x00};
static const guint8 cmd_check_suffix[] = {0x00, 0x40};
static const guint8 rsp_check_not_yet_enrolled_suffix[] = {0x90, 0x04};


/* SSM task states and various status enums */

typedef enum {
  CMD_SEND,
  CMD_GET,
  CMD_STATES,
} CommandStates;

typedef enum {
  DEV_INIT_CONTROL1,
  DEV_INIT_CONTROL2,
  DEV_INIT_CONTROL3,
  DEV_INIT_CONTROL4,
  DEV_INIT_CONTROL5,
  DEV_GET_FW_VERSION,
  DEV_INIT_STATES,
} DeviceInitStates;

typedef enum {
  CONNECT,
  CONNECT_RESPONSE,
  CONNECT_STATES,
} ConnectStates;

typedef enum {
  WAIT_FINGER_NOT_ON_SENSOR,
  WAIT_FINGER_ON_SENSOR,
  WAIT_FINGER_STATES,
} WaitFingerStates;

typedef enum {
  IDENTIFY_GET_ENROLLED_IDS,
  IDENTIFY_CHECK_ENROLLED_NUM,
  IDENTIFY_SENSOR_RESET,
  IDENTIFY_SENSOR_IDENTIFY,
  IDENTIFY_WAIT_FINGER,
  IDENTIFY_SENSOR_CHECK,
  IDENTIFY_CHECK,
  IDENTIFY_STATES,
} IdentifyStates;

typedef enum {
  ENROLL_GET_ENROLLED_IDS,
  ENROLL_CHECK_ENROLLED_NUM,
  ENROLL_SENSOR_RESET,
  ENROLL_SENSOR_ENROLL,
  ENROLL_WAIT_FINGER,
  ENROLL_SENSOR_CHECK,
  ENROLL_CHECK,
  ENROLL_START,
  ENROLL_CAPTURE_SENSOR_RESET,
  ENROLL_CAPTURE_SENSOR_START_CAPTURE,
  ENROLL_CAPTURE_WAIT_FINGER,
  ENROLL_CAPTURE_POST_WAIT_FINGER,
  ENROLL_CAPTURE_READ_RESPONSE,
  ENROLL_COMMIT_START,
  ENROLL_COMMIT,
  ENROLL_STATES,
} EnrollStates;

typedef enum {
  ENROLL_STATUS_DEVICE_FULL,
  ENROLL_STATUS_DUPLICATE,
  ENROLL_STATUS_PARTIAL_OK,
  ENROLL_STATUS_RETRY,
} EnrollStatus;

typedef enum {
  LIST_GET_ENROLLED_IDS,
  LIST_RETURN_ENROLLED_PRINTS,
  LIST_STATES,
} ListStates;

typedef enum {
  DELETE_GET_ENROLLED_IDS,
  DELETE_DELETE,
  DELETE_STATES,
} DeleteStates;
