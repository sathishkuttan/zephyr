#!/usr/bin/env python3
#
# Copyright (c) 2020 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# Author: Sathish Kuttan <sathish.k.kuttan@intel.com>

# This script is the top level script that an user can invoke to
# download a Zephyr application binary from a Linux host connected
# over SPI to Intel Sue Creek S1000 target during development.

import os
import sys
import hashlib
import argparse
import device
import messenger

msg = messenger.Message()

def check_arguments():
    """
    Check whether file name host type are provided.
    If not print usage instruction and exit.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("host", choices=["rpi", "upsq"],
            help="Host System Type (Raspberry Pi* or UP Squared* board")
    parser.add_argument("binary_file", help="Zephyr Binary File")
    args = parser.parse_args()
    return args.host, args.binary_file

def calc_firmware_sha(file):
    """
    Open firmware image file and calculate file size
    Pad file size to a multiple of 64 bytes
    Caculate SHA256 hash of the padded contents
    """
    with open(file, 'rb') as firmware:
       firmware.seek(0, 2)
       size = firmware.tell()

       # pad firmware to round upto 64 byte boundary
       padding = (size % 64)
       if padding != 0:
           padding = (64 - padding)
       size += padding

       firmware.seek(0, 0)
       sha256 = hashlib.sha256()
       for block in iter(lambda: firmware.read(4096), b""):
           sha256.update(block)
       firmware.close()

       if padding != 0:
           sha256.update(b'\0' * padding)
           print('Firmware (%s): %d bytes, will be padded to %d bytes.'
                   % (os.path.basename(file), size - padding, size))
       else:
           print('Firmware file size: %d bytes.' % size)
       print('SHA: ' + sha256.hexdigest())
       return (size, padding, sha256.digest())

def setup_device(device):
    """
    Configure SPI master device
    Reset target and send initialization commands
    """
    device.configure_device(spi_mode=3, order='msb', bits=8)
    device.reset_device()

    command = msg.create_memwrite_cmd((0x71d14, 0, 0x71d24, 0,
            0x304628, 0xd, 0x71fd0, 0x3))
    response = device.send_receive(command)
    msg.print_response(response)

def load_firmware(device, binary, size, padding, sha):
    """
    Send command to load firmware
    Transfer binary file contents including padding
    """
    command = msg.create_loadfw_cmd(size, sha)
    response = device.send_receive(command)
    msg.print_response(response)

    with open(binary, 'rb') as firmware:
        firmware.seek(0, 0)
        block_size = msg.get_bulk_message_size()
        transferred = 0
        for block in iter(lambda: firmware.read(block_size), b""):
            if len(block) < block_size:
                block += b'\0' * padding
            bulk_msg = msg.create_bulk_message(block)
            device.send_bulk(bulk_msg)
            transferred += len(bulk_msg)
            sys.stdout.write('\r%d of %d bytes transferred to %s.'
                    % (transferred, size, device.name))
        print('')
        firmware.close()

    device.check_device_ready()

    command = msg.create_null_cmd()
    response = device.send_receive(command)
    msg.print_response(response)

def execute_firmware(device):
    """
    Send command to start execution
    """
    command = msg.create_memwrite_cmd((0x71d10, 0, 0x71d20, 0))
    response = device.send_receive(command)
    msg.print_response(response)

    command = msg.create_execfw_cmd()
    response = device.send_receive(command, wait=False)
    msg.print_response(response)

def main():
    """
    Check arguments to ensure binary file is provided.
    Calculate SHA of the binary image
    Setup the SPI master device and GPIOs on the host
    Download Firmware
    """
    (host, binary) = check_arguments()
    (size, padding, sha) = calc_firmware_sha(binary)
    sue_creek = device.Device(host)
    setup_device(sue_creek)
    load_firmware(sue_creek, binary, size, padding, sha)
    execute_firmware(sue_creek)
    sue_creek.close()

if __name__ == '__main__':
    main()
