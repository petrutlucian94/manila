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

from manila.common import constants
from manila import exception
from manila.i18n import _, _LI
from manila.share.drivers import helpers
from manila.share.drivers.windows import windows_utils

LOG = log.getLogger(__name__)


class WindowsSMBHelper(helpers.NASHelperBase):
    _SHARE_ACCESS_RIGHT_MAP = {
        constants.ACCESS_LEVEL_RW: "Change",
        constants.ACCESS_LEVEL_RO: "Read"}

    def __init__(self, remote_execute, configuration):
        self._remote_exec = remote_execute
        self.configuration = configuration
        self._windows_utils = windows_utils.WindowsUtils(
            remote_execute=remote_execute)

    def init_helper(self, server):
        self._remote_exec(server, "Get-SmbShare")

    def create_export(self, server, share_name, recreate=False):
        export_location = '\\\\%s\\%s' % (server['public_address'],
                                          share_name)
        if not self._share_exists(server, share_name):
            share_path = self._windows_utils.normalize_path(
                os.path.join(self.configuration.share_mount_path,
                             share_name))
            cmd = ['New-SmbShare', '-Name', share_name, '-Path', share_path]
            self._remote_exec(server, cmd)
        else:
            LOG.info(_LI("Skipping creating export %s as it already exists."),
                     share_name)
        return export_location

    def remove_export(self, server, share_name):
        if self._share_exists(server, share_name):
            cmd = ['Remove-SmbShare', '-Name', share_name, "-Force"]
            self._remote_exec(server, cmd)
        else:
            LOG.debug("Skipping removing export %s as it does not exist.",
                      share_name)

    def _get_volume_path_by_share_name(self, server, share_name):
        share_path = self._get_share_path_by_name(server, share_name)
        volume_path = self._windows_utils.get_volume_path_by_mount_path(
            server, share_path)
        return volume_path

    def allow_access(self, server, share_name, access_type, access_level,
                     access_to):
        """Add access for share."""
        if access_type != 'user':
            reason = _('Only user access type allowed.')
            raise exception.InvalidShareAccess(reason=reason)

        self._grant_share_access(server, share_name, access_level, access_to)

    def _grant_share_access(self, server, share_name, access_level, access_to):
        access_right = self._SHARE_ACCESS_RIGHT_MAP[access_level]
        cmd = ["Grant-SmbShareAccess", "-Name", share_name,
               "-AccessRight", access_right,
               "-AccountName", access_to, "-Force"]
        self._remote_exec(server, cmd)
        self._refresh_acl(server, share_name)

    def _refresh_acl(self, server, share_name):
        cmd = ['Set-SmbPathAcl', '-ShareName', share_name]
        self._remote_exec(server, cmd)

    def deny_access(self, server, share_name, access, force=False):
        access_to = access['access_to']
        self._revoke_share_access(server, share_name, access_to)

    def _revoke_share_access(self, server, share_name, access_to):
        cmd = ['Revoke-SmbShareAccess', '-Name', share_name,
               '-AccountName', access_to, '-Force']
        self._remote_exec(server, cmd)
        self._refresh_acl(server, share_name)

    def _get_share_name(self, export_location):
        return self._windows_utils.normalize_path(
            export_location).split('\\')[-1]

    def get_exports_for_share(self, server, old_export_location):
        share_name = self._get_share_name(old_export_location)
        data = dict(ip=server['public_address'], share_name=share_name)
        return ['\\\\%(ip)s\\%(share_name)s' % data]

    def _get_share_path_by_name(self, server, share_name,
                                ignore_missing=False):
        cmd = ('Get-SmbShare -Name %s -ErrorAction SilentlyContinue | '
               'Select-Object -ExpandProperty Path' % share_name)
        (share_path, err) = self._remote_exec(server, cmd)
        share_path = share_path.strip() if share_path else None

        if not share_path or ignore_missing:
            raise exception.ShareNotFound(share_id=share_name)

        return share_path

    def get_share_path_by_export_location(self, server, export_location):
        share_name = self._get_share_name(export_location)
        return self._get_share_path_by_name(server, share_name)

    def _share_exists(self, server, share_name):
        share_path = self._get_share_path_by_name(server, share_name,
                                                  ignore_missing=True)
        return bool(share_path)
