#!/usr/bin/python3
# The recorded sensor certificate expired on 2023-04-04. The original replay
# used to pass because time and signature checks were ineffective. Keep this
# recording as a fail-closed regression, not a successful hardware claim.
import gi

gi.require_version('FPrint', '2.0')
from gi.repository import FPrint, GLib

context = FPrint.Context()
context.enumerate()
devices = context.get_devices()
assert len(devices) == 1
device = devices[0]
assert device.get_driver() == 'egismoc'
try:
    device.open_sync()
except GLib.Error as error:
    assert error.matches(FPrint.DeviceError.quark(), FPrint.DeviceError.UNTRUSTED)
    assert 'certificate has expired' in error.message, error.message
else:
    raise AssertionError('The expired recorded certificate was accepted')
assert not device.is_open()
