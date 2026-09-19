/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exercise the actual driver parser without a USB device. */
#include "../libfprint/drivers/egismoc/egismoc.c"

#define CONNECT_SIZE (EGISMOC_CONNECT_RESPONSE_PREFIX_SIZE + SDCP_RANDOM_SIZE + 2 + 1 + \
                      2 * SDCP_PUBLIC_KEY_SIZE + 2 * SDCP_SIGNATURE_SIZE + 2 * SDCP_MAC_SIZE + 2)

static void
set_frame_length (guint8 *buffer, gsize length)
{
  guint32 payload = GUINT32_TO_BE (length - 14);

  memcpy (buffer + 10, &payload, sizeof (payload));
}

static void
make_connect (guint8 *buffer)
{
  memset (buffer, 0, CONNECT_SIZE);
  memcpy (buffer, egismoc_read_prefix, G_N_ELEMENTS (egismoc_read_prefix));
  set_frame_length (buffer, CONNECT_SIZE);
  buffer[14] = SDCP_RANDOM_SIZE;
  buffer[48] = 1; /* One byte opaque certificate; crypto validation is separate. */
  buffer[49] = 0x30;
  buffer[CONNECT_SIZE - 2] = 0x90;
}

static void
assert_connect_rejected (const guint8 *buffer, gsize length)
{
  g_autoptr(GBytes) random = NULL;
  g_autoptr(GBytes) mac = NULL;
  g_autoptr(FpiSdcpClaim) claim = NULL;

  g_assert_false (egismoc_parse_connect (buffer, length, &random, &claim, &mac));
  g_assert_null (random);
  g_assert_null (claim);
  g_assert_null (mac);
}

static void
test_connect_parser (void)
{
  guint8 buffer[CONNECT_SIZE + 1];
  g_autoptr(GBytes) random = NULL;
  g_autoptr(GBytes) mac = NULL;
  g_autoptr(FpiSdcpClaim) claim = NULL;

  make_connect (buffer);
  g_assert_true (egismoc_parse_connect (buffer, CONNECT_SIZE, &random, &claim, &mac));
  g_assert_cmpuint (g_bytes_get_size (random), ==, SDCP_RANDOM_SIZE);
  g_assert_cmpuint (g_bytes_get_size (claim->model_certificate), ==, 1);
  g_assert_cmpuint (g_bytes_get_size (claim->device_public_key), ==, SDCP_PUBLIC_KEY_SIZE);
  g_assert_cmpuint (g_bytes_get_size (claim->firmware_public_key), ==, SDCP_PUBLIC_KEY_SIZE);
  g_assert_cmpuint (g_bytes_get_size (claim->firmware_hash), ==, SDCP_MAC_SIZE);
  g_assert_cmpuint (g_bytes_get_size (claim->model_signature), ==, SDCP_SIGNATURE_SIZE);
  g_assert_cmpuint (g_bytes_get_size (claim->device_signature), ==, SDCP_SIGNATURE_SIZE);
  g_assert_cmpuint (g_bytes_get_size (mac), ==, SDCP_MAC_SIZE);

  assert_connect_rejected (NULL, 0);
  for (gsize length = 0; length < CONNECT_SIZE; length++)
    {
      /* Exact allocation makes over-reads observable under ASan. */
      g_autofree guint8 *short_reply = g_memdup2 (buffer, length);

      assert_connect_rejected (short_reply, length);
      if (length >= 17)
        {
          /* Also exercise inner field boundaries with a consistent envelope. */
          set_frame_length (short_reply, length);
          short_reply[length - 2] = 0x90;
          short_reply[length - 1] = 0x00;
          assert_connect_rejected (short_reply, length);
        }
    }

  buffer[47] = 0xff;
  buffer[48] = 0xff;
  assert_connect_rejected (buffer, CONNECT_SIZE);
  buffer[47] = buffer[48] = 0;
  assert_connect_rejected (buffer, CONNECT_SIZE);
  make_connect (buffer);
  buffer[0] ^= 1;
  assert_connect_rejected (buffer, CONNECT_SIZE);
  make_connect (buffer);
  buffer[14] = SDCP_RANDOM_SIZE - 1;
  assert_connect_rejected (buffer, CONNECT_SIZE);
  make_connect (buffer);
  buffer[CONNECT_SIZE - 1] = 1;
  assert_connect_rejected (buffer, CONNECT_SIZE);
  make_connect (buffer);
  buffer[CONNECT_SIZE - 2] = 0;
  buffer[CONNECT_SIZE - 1] = 0x90;
  buffer[CONNECT_SIZE] = 0;
  set_frame_length (buffer, CONNECT_SIZE + 1);
  assert_connect_rejected (buffer, CONNECT_SIZE + 1);
  assert_connect_rejected (buffer, EGISMOC_USB_IN_RECV_LENGTH + 1);
}

static void
test_response_bounds (void)
{
  const guint8 prefix[] = {0x12, 0x34};
  const guint8 suffix[] = {0x90, 0x00};
  guint8 buffer[16] = {0};

  memcpy (buffer, egismoc_read_prefix, G_N_ELEMENTS (egismoc_read_prefix));
  memcpy (buffer + 10, prefix, sizeof (prefix));
  memcpy (buffer + 14, suffix, sizeof (suffix));
  for (gsize length = 0; length < 12; length++)
    {
      g_autofree guint8 *short_reply = g_memdup2 (buffer, length);

      g_assert_false (egismoc_validate_response_prefix (short_reply, length, prefix, sizeof (prefix)));
    }
  g_assert_true (egismoc_validate_response_prefix (buffer, sizeof (buffer), prefix, sizeof (prefix)));
  g_assert_false (egismoc_validate_response_suffix (NULL, 0, suffix, sizeof (suffix)));
  g_assert_false (egismoc_validate_response_suffix (buffer, 1, suffix, sizeof (suffix)));
  g_assert_true (egismoc_validate_response_suffix (buffer, sizeof (buffer), suffix, sizeof (suffix)));
  set_frame_length (buffer, sizeof (buffer));
  g_assert_true (egismoc_validate_response (buffer, sizeof (buffer)));
  buffer[13]++;
  g_assert_false (egismoc_validate_response (buffer, sizeof (buffer)));
}

static void
ssm_noop (FpiSsm *ssm,
          FpDevice *device)
{
  (void) ssm;
  (void) device;
}

typedef struct
{
  guint called;
  GError *error;
} SsmCompletion;

static void
ssm_completion (FpiSsm *ssm,
                FpDevice *device,
                GError *error)
{
  SsmCompletion *completion = fpi_ssm_get_data (ssm);

  (void) device;
  completion->called++;
  egismoc_task_ssm_done (ssm, device, NULL);
  completion->error = error;
}

static void
test_cancel_drains_wait_ssm (void)
{
  g_autoptr(FpDevice) device = g_object_new (fpi_device_egismoc_get_type (), NULL);
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  SsmCompletion completion = { 0 };

  self->interrupt_cancellable = g_cancellable_new ();

  self->task_ssm = fpi_ssm_new (device, ssm_noop, 1);
  fpi_ssm_set_data (self->task_ssm, &completion, NULL);
  fpi_ssm_start (self->task_ssm, ssm_completion);

  self->wait_finger_start = 42;
  self->wait_finger_ssm = fpi_ssm_new (device, ssm_noop, 1);
  fpi_ssm_start (self->wait_finger_ssm, egismoc_wait_finger_ssm_done);
  egismoc_cancel (device);
  g_assert_true (g_cancellable_is_cancelled (self->interrupt_cancellable));
  g_assert_nonnull (self->wait_finger_ssm);
  g_assert_nonnull (self->task_ssm);
  g_assert_cmpuint (completion.called, ==, 0);
  /* Model the outstanding interrupt transfer draining after cancellation. */
  FpiUsbTransfer transfer = { .ssm = self->wait_finger_ssm };
  egismoc_finger_on_sensor_cb (&transfer, device, NULL,
                               g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                    "cancelled"));
  g_clear_object (&self->interrupt_cancellable);

  g_assert_cmpuint (completion.called, ==, 1);
  g_assert_error (completion.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_clear_error (&completion.error);
  g_assert_null (self->task_ssm);
  g_assert_null (self->wait_finger_ssm);
  g_assert_cmpint (self->wait_finger_start, ==, 0);
}

static void
test_delete_missing_id_done (void)
{
  g_autoptr(FpDevice) device = g_object_new (fpi_device_egismoc_get_type (), NULL);
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autoptr(FpPrint) print = fp_print_new (device);
  SsmCompletion completion = { 0 };
  gsize length = 0;
  g_autoptr(GBytes) invalid_id = g_bytes_new_static ("short", 5);

  g_object_ref_sink (print);
  fpi_sdcp_device_set_print_id (print, invalid_id);
  self->task_ssm = fpi_ssm_new (device, ssm_noop, 1);
  fpi_ssm_set_data (self->task_ssm, &completion, NULL);
  fpi_ssm_start (self->task_ssm, ssm_completion);

  g_assert_null (egismoc_get_delete_cmd (device, print, &length));
  g_assert_cmpuint (completion.called, ==, 1);
  g_assert_error (completion.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_assert_cmpuint (length, ==, 0);
  g_clear_error (&completion.error);
  g_assert_null (self->task_ssm);
}

typedef struct
{
  FpiDeviceEgisMoc parent;
} TestEgisDevice;

typedef struct
{
  FpiDeviceEgisMocClass parent_class;
} TestEgisDeviceClass;

static GType test_egis_device_get_type (void);

G_DEFINE_TYPE (TestEgisDevice, test_egis_device, fpi_device_egismoc_get_type ())

static void
test_egis_open (FpDevice *device)
{
  fpi_device_open_complete (device, NULL);
}

static void
test_egis_close (FpDevice *device)
{
  fpi_device_close_complete (device, NULL);
}

static void
test_empty_clear_run_state (FpiSsm *ssm,
                            FpDevice *device)
{
  if (fpi_ssm_get_cur_state (ssm) == DELETE_GET_ENROLLED_IDS)
    {
      fpi_ssm_jump_to_state (ssm, DELETE_DELETE);
      return;
    }

  egismoc_delete_run_state (ssm, device);
}

static void
test_egis_clear_storage (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  self->enrolled_ids = g_ptr_array_new_with_free_func (g_free);
  self->task_ssm = fpi_ssm_new (device, test_empty_clear_run_state, DELETE_STATES);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
}

static void
test_egis_device_class_init (TestEgisDeviceClass *klass)
{
  FpDeviceClass *device_class = FP_DEVICE_CLASS (klass);

  device_class->type = FP_DEVICE_TYPE_VIRTUAL;
  device_class->open = test_egis_open;
  device_class->close = test_egis_close;
  device_class->clear_storage = test_egis_clear_storage;
}

static void
test_egis_device_init (TestEgisDevice *self)
{
  (void) self;
}

static void
test_empty_clear_completes (void)
{
  g_autoptr(FpDevice) device = g_object_new (test_egis_device_get_type(), NULL);
  g_autoptr(GError) error = NULL;

  g_assert_true (fp_device_open_sync (device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_clear_storage_sync (device, NULL, &error));
  g_assert_no_error (error);
  g_assert_cmpint (fpi_device_get_current_action (device), ==, FPI_DEVICE_ACTION_NONE);
  g_assert_true (fp_device_close_sync (device, NULL, &error));
  g_assert_no_error (error);
}

static void
test_transport_result (FpDevice *device, guchar *buffer, gsize length, GError *error)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  guint count = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (device), "completions"));

  g_object_set_data (G_OBJECT (device), "completions", GUINT_TO_POINTER (count + 1));
  g_assert_null (self->cmd_ssm);
  if (error)
    fpi_ssm_mark_failed (self->task_ssm, error);
  else
    {
      g_assert_nonnull (buffer);
      g_assert_cmpuint (length, ==, 16);
      fpi_ssm_mark_completed (self->task_ssm);
      fpi_device_clear_storage_complete (device, NULL);
    }
}

static void
test_transport_clear (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  guint mode = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (device), "mode"));
  CommandData *data = g_new0 (CommandData, 1);
  FpiUsbTransfer transfer = { 0 };
  GError *error = NULL;

  self->task_ssm = fpi_ssm_new (device, ssm_noop, 1);
  fpi_ssm_start (self->task_ssm, egismoc_task_ssm_done);
  self->cmd_ssm = fpi_ssm_new (device, ssm_noop, 1);
  data->callback = test_transport_result;
  fpi_ssm_set_data (self->cmd_ssm, data, g_free);
  fpi_ssm_start (self->cmd_ssm, egismoc_cmd_ssm_done);
  self->interrupt_cancellable = g_cancellable_new ();

  transfer.ssm = self->cmd_ssm;
  transfer.buffer = g_malloc0 (16);
  transfer.actual_length = 16;
  memcpy (transfer.buffer, egismoc_read_prefix, G_N_ELEMENTS (egismoc_read_prefix));
  set_frame_length (transfer.buffer, 16);
  transfer.buffer[14] = 0x90;
  if (mode == 1)
    {
      /* Cancellation wins even if USB has already completed successfully. */
      g_cancellable_cancel (fpi_device_get_cancellable (device));
      egismoc_cancel (device);
      g_assert_nonnull (self->cmd_ssm);
      g_assert_nonnull (self->task_ssm);
    }
  else if (mode == 2 || mode == 3)
    error = g_error_new_literal (G_USB_DEVICE_ERROR,
                                 mode == 2 ? G_USB_DEVICE_ERROR_TIMED_OUT : G_USB_DEVICE_ERROR_NO_DEVICE,
                                 "injected USB failure");
  else if (mode == 4)
    transfer.actual_length = 1;

  egismoc_cmd_receive_cb (&transfer, device, data, error);
  g_free (transfer.buffer);
  g_clear_object (&self->interrupt_cancellable);
  g_assert_null (self->cmd_ssm);
  g_assert_null (self->task_ssm);
}

static void
test_transport_completion (void)
{
  g_autoptr(FpDevice) device = g_object_new (test_egis_device_get_type (), NULL);
  FpDeviceClass *klass = FP_DEVICE_GET_CLASS (device);
  g_autoptr(GError) error = NULL;

  g_assert_true (fp_device_open_sync (device, NULL, &error));
  g_assert_no_error (error);
  klass->clear_storage = test_transport_clear;
  for (guint mode = 0; mode < 5; mode++)
    {
      gboolean success;

      g_object_set_data (G_OBJECT (device), "mode", GUINT_TO_POINTER (mode));
      g_object_set_data (G_OBJECT (device), "completions", NULL);
      success = fp_device_clear_storage_sync (device, NULL, &error);
      g_assert_cmpint (success, ==, mode == 0);
      if (mode == 0)
        g_assert_no_error (error);
      else if (mode == 1)
        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
      else if (mode == 2 || mode == 3)
        g_assert_error (error, G_USB_DEVICE_ERROR,
                        (mode == 2 ? G_USB_DEVICE_ERROR_TIMED_OUT : G_USB_DEVICE_ERROR_NO_DEVICE));
      else
        g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL);
      g_clear_error (&error);
      g_assert_cmpuint (GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (device), "completions")), ==, 1);
      g_assert_cmpint (fpi_device_get_current_action (device), ==, FPI_DEVICE_ACTION_NONE);
    }
  klass->clear_storage = test_egis_clear_storage;
  g_assert_true (fp_device_close_sync (device, NULL, &error));
  g_assert_no_error (error);
}

static void
test_delete_command_lengths (void)
{
  g_autoptr(FpDevice) device = g_object_new (test_egis_device_get_type(), NULL);
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  self->enrolled_ids = g_ptr_array_new_with_free_func (g_free);
  for (guint n = 0; n <= EGISMOC_MAX_ENROLL_NUM; n++)
    {
      gsize length;
      g_autofree guint8 *command = egismoc_get_delete_cmd (device, NULL, &length);
      FpiByteReader reader = FPI_BYTE_READER_INIT (command, length);
      guint16 outer, inner;
      g_assert_true (fpi_byte_reader_skip (&reader, 2));
      g_assert_true (fpi_byte_reader_get_uint16_be (&reader, &outer));
      g_assert_true (fpi_byte_reader_skip (&reader, G_N_ELEMENTS (cmd_delete_prefix)));
      g_assert_true (fpi_byte_reader_get_uint16_be (&reader, &inner));
      g_assert_cmpuint (outer, ==, n * SDCP_ENROLLMENT_ID_SIZE + 7);
      g_assert_cmpuint (inner, ==, n * SDCP_ENROLLMENT_ID_SIZE);
      g_ptr_array_add (self->enrolled_ids, g_malloc0 (SDCP_ENROLLMENT_ID_SIZE));
    }
  g_clear_pointer (&self->enrolled_ids, g_ptr_array_unref);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/egismoc/connect-parser", test_connect_parser);
  g_test_add_func ("/egismoc/delete-command-lengths", test_delete_command_lengths);
  g_test_add_func ("/egismoc/response-bounds", test_response_bounds);
  g_test_add_func ("/egismoc/cancel-drains-wait-ssm", test_cancel_drains_wait_ssm);
  g_test_add_func ("/egismoc/delete-invalid-id", test_delete_missing_id_done);
  g_test_add_func ("/egismoc/empty-clear", test_empty_clear_completes);
  g_test_add_func ("/egismoc/transport-completion", test_transport_completion);
  return g_test_run ();
}
