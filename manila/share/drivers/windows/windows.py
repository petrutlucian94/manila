# Copyright (c) 2015 Cloudbase Solutions SRL
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os

from oslo_log import log
from oslo_utils import units

from manila import exception
from manila.i18n import _LW
from manila.share import driver as base_driver
from manila.share.drivers import generic
from manila.share.drivers.windows import service_instance
from manila.share.drivers.windows import windows_smb_helper
from manila.share.drivers.windows import windows_utils
from manila.share.drivers.windows import winrm_helper


LOG = log.getLogger(__name__)


class WindowsSMBDriver(generic.GenericShareDriver):
    # NOTE(lpetrut): The first partition will be reserved by the OS.
    _DEFAULT_SHARE_PARTITION = 2

    def __init__(self, *args, **kwargs):
        super(WindowsSMBDriver, self).__init__(*args, **kwargs)

        self._remote_execute = winrm_helper.WinRMHelper(
            configuration=self.configuration).execute
        self._windows_utils = windows_utils.WindowsUtils(
            remote_execute=self._remote_execute)
        self._smb_helper = windows_smb_helper.WindowsSMBHelper(
            remote_execute=self._remote_execute,
            configuration=self.configuration)

    def _update_share_stats(self, data=None):
        base_driver.ShareDriver._update_share_stats(
            self, data=dict(storage_protocol="CIFS"))

    def _setup_service_instance_manager(self):
        self.service_instance_manager = (
            service_instance.WindowsServiceInstanceManager(
                driver_config=self.configuration))

    def _setup_helpers(self):
        self._helpers = {key: self._smb_helper for key in ("SMB", "CIFS")}

    def _teardown_server(self, server_details, security_services=None):
        security_service = (
            self.service_instance_manager.get_valid_security_service(
                security_services))
        if server_details.get('joined_domain') and security_service:
            try:
                self._windows_utils.unjoin_domain(server_details,
                                                  security_service['user'],
                                                  security_service['password'])
            except Exception as exc:
                LOG.warn(_LW("Failed to remove service instance "
                             "%(instance_id)s from domain %(domain)s. "
                             "Exception: %(exc)s"),
                         dict(instance_id=server_details['instance_id'],
                              domain=security_service['domain'],
                              exc=exc))
        super(WindowsSMBDriver, self)._teardown_server(server_details,
                                                       security_services)

    def _format_device(self, server_details, volume):
        disk_number = self._get_disk_number(server_details, volume)
        self._windows_utils.initialize_disk(server_details, disk_number)
        self._windows_utils.create_partition(server_details, disk_number)
        self._windows_utils.format_partition(
            server_details, disk_number,
            self._DEFAULT_SHARE_PARTITION)

    def _mount_device(self, share, server_details, volume):
        mount_path = self._get_mount_path(share)
        if not self._is_device_mounted(mount_path, server_details, volume):
            disk_number = self._get_disk_number(server_details, volume)
            self._windows_utils.ensure_directory_exists(server_details,
                                                        mount_path)
            self._windows_utils.add_access_path(server_details,
                                                mount_path,
                                                disk_number,
                                                self._DEFAULT_SHARE_PARTITION)
            self._ensure_disk_online_and_writable(server_details, disk_number)

    def _unmount_device(self, share, server_details):
        mount_path = self._get_mount_path(share)
        disk_number = self._windows_utils.get_disk_number_by_mount_path(
            server_details, mount_path)

        self._windows_utils.remove(server_details, mount_path,
                                   is_junction=True)
        if disk_number:
            self._windows_utils.set_disk_online_status(
                server_details, disk_number, online=False)

    def _resize_filesystem(self, server_details, volume):
        disk_number = self._get_disk_number(server_details, volume)
        self._ensure_disk_online_and_writable(server_details, disk_number)

        max_size_bytes = self._windows_utils.get_partition_maximum_size(
            server_details, disk_number, self._DEFAULT_SHARE_PARTITION)

        self._windows_utils.resize_partition(server_details,
                                             max_size_bytes,
                                             disk_number,
                                             self._DEFAULT_SHARE_PARTITION)

    def _ensure_disk_online_and_writable(self, server_details, disk_number):
        self._windows_utils.update_disk(server_details, disk_number)
        self._windows_utils.set_disk_online_status(
            server_details, disk_number, online=True)
        self._windows_utils.set_disk_readonly_status(
            server_details, disk_number, readonly=False)

    def _get_mounted_share_size(self, mount_path, server_details):
        total_size_bytes = self._windows_utils.get_disk_size_by_path(
            server_details, mount_path)
        return int(total_size_bytes) / units.Gi

    def _get_mount_path(self, share):
        mount_path = os.path.join(self.configuration.share_mount_path,
                                  share['name'])
        return self._windows_utils.normalize_path(mount_path)

    def _get_disk_number(self, server_details, volume):
        disk_number = self._windows_utils.get_disk_number_by_serial_number(
            server_details, volume['id'])
        if disk_number is None:
            LOG.debug("Could not identify the mounted disk by serial number "
                      "using the volume id. Attempting to retrieve it by "
                      "the volume mount point.")
            # Assumes the mount_point will be something like /dev/hdX
            mount_point = volume['mountpoint']
            disk_number = ord(mount_point[-1]) - ord('a')
        return disk_number

    def _is_device_mounted(self, mount_path, server_details, volume=None):
        disk_number = self._windows_utils.get_disk_number_by_mount_path(
            server_details, mount_path)
        if disk_number is None:
            return False

        if volume:
            expected_disk_number = (
                self._windows_utils.get_disk_number_by_serial_number(
                    server_details, volume['id']))
            if disk_number != expected_disk_number:
                err_msg = _("Unexpected disk mounted at %(mount_path)s. "
                            "Expected disk number: %(expected_disk_number)s "
                            "Actual disk number: %(disk_number)s")
                raise exception.ShareBackendException(
                    err_msg,
                    dict(mount_path=mount_path,
                         expected_disk_number=expected_disk_number,
                         disk_number=disk_number))
        return True
