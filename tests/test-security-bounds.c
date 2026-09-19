/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "drivers_api.h"
static unsigned int completions;
static gboolean expected_error;
static void idle_state (FpiSsm *ssm, FpDevice *device) {}
static void completed (FpiSsm *ssm, FpDevice *device, GError *error)
{
  completions++;
  g_assert_cmpint (error != NULL, ==, expected_error);
  g_clear_error (&error);
}
static G_GNUC_UNUSED FpiSsm *pending (FpDevice *device, int state)
{
  FpiSsm *ssm = fpi_ssm_new (device, idle_state, state + 2);
  completions = 0;
  expected_error = TRUE;
  fpi_ssm_start (ssm, completed);
  fpi_ssm_jump_to_state (ssm, state);
  return ssm;
}
/* Include the implementation to exercise private parsers without hardware. */
#if defined(TEST_GOODIXMOC)
#include "../libfprint/drivers/goodixmoc/goodix_proto.c"
#include "../libfprint/drivers/goodixmoc/goodix.c"
static void check_bounds (void)
{
  guint8 bytes[256] = {0};
  pack_header header;
  template_format_t finger;
  gxfp_cmd_response_t response;
  for (int n = 0; n <= 4; n++)
    {
      FpiByteReader reader = FPI_BYTE_READER_INIT (bytes, 8);
      bytes[4] = n;
      g_assert_cmpint (gx_proto_parse_header (&reader, &header), ==, n < 4 ? -1 : 0);
    }
  g_autoptr(FpDevice) device = g_object_new (fpi_device_goodixmoc_get_type (), NULL);
  CommandData cmd = {0};
  FpiUsbTransfer transfer = { .buffer = bytes, .actual_length = 8 };
  /* The header declares a CRC but no CRC bytes arrived. */
  transfer.ssm = pending (device, 0);
  fp_cmd_receive_cb (&transfer, device, &cmd, NULL);
  g_assert_cmpuint (completions, ==, 1);
  memset (bytes, 0, sizeof bytes);
  bytes[0] = 67;
  for (int n = 56; n <= 57; n++)
    {
      FpiByteReader reader = FPI_BYTE_READER_INIT (bytes, sizeof bytes);
      bytes[68] = n;
      g_assert_cmpint (gx_proto_parse_fingerid (&reader, &finger), ==, n == 56 ? 0 : -1);
    }
  memset (bytes, 0, sizeof bytes);
  bytes[1] = 21;
  FpiByteReader reader = FPI_BYTE_READER_INIT (bytes, 2);
  g_assert_cmpint (gx_proto_parse_body (MOC_CMD0_GETFINGERLIST << 8, &reader, &response), ==, -1);
  bytes[1] = 0;
  fpi_byte_reader_set_pos (&reader, 0);
  g_assert_cmpint (gx_proto_parse_body (MOC_CMD0_GETFINGERLIST << 8, &reader, &response), ==, 0);
}
#elif defined(TEST_SYNAPTICS)
#include "../libfprint/drivers/synaptics/bmkt_message.c"
static void check_bounds (void)
{
  uint8_t bytes[8] = {BMKT_MESSAGE_HEADER_ID, 0, 0, 4, 0, 0, 2, 0};
  bmkt_msg_resp_t msg = {0};
  bmkt_response_t response = {0};
  for (int n = 0; n < 8; n++)
    g_assert_cmpint (bmkt_parse_message_header (bytes, n, &msg), !=, BMKT_SUCCESS);
  g_assert_cmpint (bmkt_parse_message_header (bytes, 8, &msg), ==, BMKT_SUCCESS);
  /* Two metadata bytes followed by an incomplete three-byte record. */
  g_assert_cmpint (parse_get_enrolled_users_report (&msg, &response), !=, BMKT_SUCCESS);
  msg.payload_len = 2;
  g_assert_cmpint (parse_get_enrolled_users_report (&msg, &response), ==, BMKT_SUCCESS);
}
#elif defined(TEST_UPEKTC_IMG)
#include "../libfprint/drivers/upektc_img.c"
static void check_bounds (void)
{
  guint8 bytes[32] = {0}, image[16] = {0};
  const guint8 subtypes[] = {0x24, 0x2c, 0x20};
  const guint8 overhead[] = {1, 11, 5};
  for (guint i = 0; i < G_N_ELEMENTS (subtypes); i++)
    {
      bytes[7] = subtypes[i];
      bytes[6] = overhead[i] - 1;
      g_assert_cmpint (upektc_img_process_image_frame (image, sizeof image, bytes, sizeof bytes), ==, -1);
      bytes[6] = overhead[i] + 1;
      g_assert_cmpint (upektc_img_process_image_frame (image, 1, bytes, sizeof bytes), ==, 1);
      g_assert_cmpint (upektc_img_process_image_frame (image, 0, bytes, sizeof bytes), ==, -1);
      g_assert_cmpint (upektc_img_process_image_frame (image, sizeof image, bytes, 7), ==, -1);
    }
}
#elif defined(TEST_ETES603)
#include "../libfprint/drivers/etes603.c"
static void check_bounds (void)
{
  struct egis_msg req = {0}, ans = {0};
  FpiDeviceEtes603 device = { .req = &req, .ans = &ans };
  req.egis_readreg.nb = 1;
  memcpy (ans.magic, "SIGE\x0a", 5);
  ans.cmd = CMD_OK;
  ans.sige_readreg.regs[0] = 123;
  for (int n = 0; n < MSG_HDR_SIZE + 1; n++)
    {
      device.ans_len = n;
      g_assert_cmpint (msg_parse_regs (&device), ==, -1);
    }
  device.ans_len = MSG_HDR_SIZE + 1;
  g_assert_cmpint (msg_parse_regs (&device), ==, 0);
  g_assert_cmpuint (device.regs[0], ==, 123);
}
#elif defined(TEST_ELAN)
#include "../libfprint/drivers/elan.c"
static void check_bounds (void)
{
  unsigned short pixels[10] = {0};
  GSList *frames = NULL;
  assembling_ctx.frame_width = 10;
  assembling_ctx.frame_height = 1;
  elan_process_frame_linear (pixels, &frames);
  elan_process_frame_thirds (pixels, &frames);
  for (int i = 0; i < 10; i++) pixels[i] = i < 5 ? 0 : 255;
  elan_process_frame_linear (pixels, &frames);
  elan_process_frame_thirds (pixels, &frames);
  g_assert_cmpuint (g_slist_length (frames), ==, 4);
  g_slist_free_full (frames, g_free);
}
#elif defined(TEST_UPEKTS)
#include "../libfprint/drivers/upekts.c"
static void message_done (FpDevice *device, enum read_msg_type type,
                         guint8 seq, unsigned char subcmd, unsigned char *data,
                         size_t length, void *user_data, GError *error)
{
  completions++;
  g_assert_cmpint (error != NULL, ==, expected_error);
  if (!error) g_assert_cmpuint (length, ==, 0);
  g_clear_error (&error);
}
static void check_bounds (void)
{
  for (int n = 2; n <= 4; n++)
    {
      struct read_msg_data *msg = g_new0 (struct read_msg_data, 1);
      msg->buffer = g_malloc0 (15);
      msg->buflen = 15;
      msg->callback = message_done;
      msg->buffer[6] = 6;
      msg->buffer[7] = 0x28;
      msg->buffer[8] = n;
      guint16 crc = udf_crc (msg->buffer + 4, 9);
      msg->buffer[13] = crc;
      msg->buffer[14] = crc >> 8;
      expected_error = n != 3;
      completions = 0;
      __handle_incoming_msg (NULL, msg);
      g_assert_cmpuint (completions, ==, 1);
    }
}
#elif defined(TEST_REALTEK)
#include "../libfprint/drivers/realtek/realtek.c"
static void check_bounds (void)
{
  g_autoptr(FpDevice) device = g_object_new (fpi_device_realtek_get_type (), NULL);
  FpiDeviceRealtek *self = FPI_DEVICE_REALTEK (device);
  guint8 bytes[1] = {0};
  CommandData cmd = {0};
  for (int n = 1; n <= 2; n++)
    {
      FpiUsbTransfer transfer = { .buffer = bytes, .actual_length = 1 };
      self->trans_data_len = n;
      transfer.ssm = pending (device, FP_RTK_CMD_TRANS_DATA);
      fp_cmd_receive_cb (&transfer, device, &cmd, NULL);
      if (n == 1)
        {
          g_assert_cmpuint (completions, ==, 0);
          g_assert_cmpuint (self->read_data[0], ==, 0);
          g_clear_pointer (&self->read_data, g_free);
          expected_error = FALSE;
          fpi_ssm_mark_completed (transfer.ssm);
        }
      g_assert_cmpuint (completions, ==, 1);
    }
}
#elif defined(TEST_VFS101)
#include "../libfprint/drivers/vfs101.c"
static void check_bounds (void)
{
  g_autoptr(FpDevice) device = g_object_new (fpi_device_vfs101_get_type (), NULL);
  FpiSsm *ssm = pending (device, M_INIT_4_CHECK_CONTRAST);
  m_init_state (ssm, device);
  g_assert_cmpuint (completions, ==, 1);
}
#elif defined(TEST_VFS0050)
#include "../libfprint/drivers/vfs0050.c"
static void check_bounds (void)
{
  g_autoptr(FpDevice) device = g_object_new (fpi_device_vfs0050_get_type (), NULL);
  FpDeviceVfs0050 *self = FPI_DEVICE_VFS0050 (device);
  FpiUsbTransfer transfer = { .actual_length = 1 };
  self->bytes = 8 * 1024 * 1024;
  transfer.ssm = pending (device, 0);
  receive_callback (&transfer, device, NULL, NULL);
  g_assert_cmpuint (completions, ==, 1);
}
#elif defined(TEST_URU4000)
#include "../libfprint/drivers/uru4000.c"
static void check_bounds (void)
{
  g_autoptr(FpDevice) device = g_object_new (fpi_device_uru4000_get_type (), NULL);
  FpiDeviceUru4000 *self = FPI_DEVICE_URU4000 (device);
  self->img_data = g_new0 (struct uru4k_image, 1);
  self->img_data_actual_length = sizeof (struct uru4k_image);
  ((struct uru4k_image *) self->img_data)->num_lines = 200;
  for (int n = 0; n < 3; n++)
    {
      ((struct uru4k_image *) self->img_data)->block_info[n].num_lines = 100;
      ((struct uru4k_image *) self->img_data)->block_info[n].flags = BLOCKF_NOT_PRESENT;
    }
  FpiSsm *ssm = pending (device, IMAGING_SEND_INDEX);
  imaging_run_state (ssm, device);
  g_assert_cmpuint (completions, ==, 1);
  g_clear_pointer (&self->img_data, g_free);
}
#elif defined(TEST_FOCALTECH_MOC)
#include "../libfprint/drivers/focaltech_moc/focaltech_moc.c"
typedef struct { FpiDeviceFocaltechMoc parent; } TestFocal;
typedef struct { FpiDeviceFocaltechMocClass parent; } TestFocalClass;
GType test_focal_get_type (void);
G_DEFINE_TYPE (TestFocal, test_focal, fpi_device_focaltech_moc_get_type ())
static void test_open (FpDevice *device) { fpi_device_open_complete (device, NULL); }
static void test_close (FpDevice *device) { fpi_device_close_complete (device, NULL); }
static void delete_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  FPI_DEVICE_FOCALTECH_MOC (device)->task_ssm = NULL;
  completions++;
  fpi_device_delete_complete (device, error);
}
static void test_delete (FpDevice *device)
{
  FpiDeviceFocaltechMoc *self = FPI_DEVICE_FOCALTECH_MOC (device);
  FpActionData *data = g_new0 (FpActionData, 1);
  data->enrolled_info = g_new0 (struct EnrolledInfo, 1);
  data->list_result = g_ptr_array_new_with_free_func (g_object_unref);
  self->task_ssm = fpi_ssm_new (device, idle_state, MOC_DELETE_NUM_STATES);
  fpi_ssm_set_data (self->task_ssm, data, (GDestroyNotify) fp_action_ssm_done_data_free);
  fpi_ssm_start (self->task_ssm, delete_done);
  fpi_ssm_jump_to_state (self->task_ssm, MOC_DELETE_BY_UID);
  focaltech_delete_run_state (self->task_ssm, device);
  if (self->task_ssm) fpi_ssm_mark_completed (self->task_ssm);
}
static void test_focal_class_init (TestFocalClass *klass)
{
  FpDeviceClass *device = FP_DEVICE_CLASS (klass);
  device->type = FP_DEVICE_TYPE_VIRTUAL;
  device->open = test_open;
  device->close = test_close;
  device->delete = test_delete;
}
static void test_focal_init (TestFocal *self) {}
static void check_bounds (void)
{
  g_autoptr(FpDevice) device = g_object_new (test_focal_get_type (), NULL);
  guint8 uid[33];
  memset (uid, 0x55, sizeof uid);
  g_assert_true (fp_device_open_sync (device, NULL, NULL));
  const gsize sizes[] = {0, 7, 31, 32, 33};
  for (guint i = 0; i < G_N_ELEMENTS (sizes); i++)
    {
      g_autoptr(FpPrint) print = g_object_ref_sink (fp_print_new (device));
      g_autoptr(GError) error = NULL;
      fpi_print_set_type (print, FPI_PRINT_RAW);
      g_object_set (print, "fpi-data",
                    g_variant_new ("(@ay)", g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, uid, sizes[i], 1)), NULL);
      completions = 0;
      g_assert_cmpint (fp_device_delete_print_sync (device, print, NULL, &error), ==, sizes[i] == 32);
      if (sizes[i] != 32) g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
      else g_assert_no_error (error);
      g_assert_cmpuint (completions, ==, 1);
    }
  g_assert_true (fp_device_close_sync (device, NULL, NULL));
}
#elif defined(TEST_VFS301)
#include "../libfprint/drivers/vfs301_proto.c"
#include "../libfprint/drivers/vfs301.c"
static void check_bounds (void)
{
  FpDeviceVfs301 device = {0};
  vfs301_line_t line = {0};
  g_assert_cmpint (img_process_data (TRUE, &device, (const guint8 *) &line, sizeof line), ==, VFS301_ONGOING);
  device.scanline_count = 1024 * 1024 / VFS301_FP_OUTPUT_WIDTH;
  g_assert_cmpint (img_process_data (FALSE, &device, (const guint8 *) &line, sizeof line), ==, VFS301_FAILURE);
  g_free (device.scanline_buf);

  g_autoptr(FpDevice) object = g_object_new (fpi_device_vfs301_get_type (), NULL);
  FpDeviceVfs301 *self = FPI_DEVICE_VFS301 (object);
  g_autofree guint8 *buffer = g_malloc0 (VFS301_FP_RECV_LEN_2);
  FpiUsbTransfer transfer = { .buffer = buffer, .length = VFS301_FP_RECV_LEN_2,
                             .actual_length = VFS301_FP_RECV_LEN_2 };
  self->scanline_count = 1024 * 1024 / VFS301_FP_OUTPUT_WIDTH;
  vfs301_proto_process_event_cb (&transfer, object, NULL, NULL);
  g_assert_cmpint (self->recv_progress, ==, VFS301_FAILURE);
  FpiSsm *ssm = pending (object, M_READ_PRINT_POLL);
  m_loop_state (ssm, object);
  g_assert_cmpuint (completions, ==, 1);
  transfer.actual_length = 0;
  vfs301_proto_process_event_cb (&transfer, object, NULL, NULL);
  g_assert_cmpint (self->recv_progress, ==, VFS301_ENDED);
}
#elif defined(TEST_FPCMOC)
#include "../libfprint/drivers/fpcmoc/fpc.c"
G_STATIC_ASSERT (G_STRUCT_OFFSET (evt_enum_fids_t, fid_data) == 20);
G_STATIC_ASSERT (sizeof (fpc_fid_data_t) == 77);
static void check_bounds (void)
{
  fpc_fid_data_t data = { .identity_size = SECURITY_MAX_SID_SIZE + 1 };
  g_assert_null (fpc_print_from_data (NULL, &data));
  g_autoptr(FpDevice) device = g_object_new (fpi_device_fpcmoc_get_type (), NULL);
  guint8 bytes[sizeof (fpc_cmd_response_t) + 1] = {0};
  CommandData cmd = { .cmdtype = FPC_CMDTYPE_TO_DEVICE_EVTDATA };
  FpiUsbTransfer transfer = { .buffer = bytes, .actual_length = sizeof bytes };
  transfer.ssm = pending (device, FP_CMD_GET_DATA);
  fpc_cmd_receive_cb (&transfer, device, &cmd, NULL);
  g_assert_cmpuint (completions, ==, 1);
  data.identity_size = SECURITY_MAX_SID_SIZE;
  g_autoptr(FpPrint) print = g_object_ref_sink (fpc_print_from_data (FPI_DEVICE_FPCMOC (device), &data));
  g_assert_nonnull (print);
}
#else
#include "drivers_api.h"
#include "fpi-print.h"
static void check_bounds (void)
{
  const guchar bytes[] = "FP3";
  for (gsize n = 0; n <= 3; n++)
    {
      g_autoptr(GError) error = NULL;
      g_assert_null (fp_print_deserialize (bytes, n, &error));
      g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
    }
  g_autoptr(GError) error = NULL;
  g_assert_null (fp_print_deserialize (NULL, 4, &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
  g_clear_error (&error);
  g_autoptr(FpPrint) print = g_object_ref_sink (g_object_new (FP_TYPE_PRINT, "driver", "test", "device-id", "test", NULL));
  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", g_variant_new_string ("control"), NULL);
  g_autofree guchar *serialized = NULL;
  gsize length;
  g_assert_true (fp_print_serialize (print, &serialized, &length, &error));
  g_assert_no_error (error);
  g_autoptr(FpPrint) parsed = fp_print_deserialize (serialized, length, &error);
  g_assert_no_error (error);
  g_assert_true (fp_print_equal (print, parsed));
}
#endif

int main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/security/bounds", check_bounds);
  return g_test_run ();
}
