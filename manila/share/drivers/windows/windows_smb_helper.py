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

import json
import os

from oslo_log import log

from manila.common import constants
from manila import exception
from manila.i18n import _LI, _LW
from manila.share.drivers import helpers
from manila.share.drivers.windows import windows_utils

LOG = log.getLogger(__name__)


class WindowsSMBHelper(helpers.NASHelperBase):
    _SHARE_ACCESS_RIGHT_MAP = {
        constants.ACCESS_LEVEL_RW: "Change",
        constants.ACCESS_LEVEL_RO: "Read"}

    _WIN_ACL_ALLOW = 0
    _WIN_ACL_DENY = 1

    _WIN_ACCESS_RIGHT_FULL = 0
    _WIN_ACCESS_RIGHT_CHANGE = 1
    _WIN_ACCESS_RIGHT_READ = 2
    _WIN_ACCESS_RIGHT_CUSTOM = 3

    _ACCESS_LEVEL_CUSTOM = 'custom'

    _WIN_ACL_MAP = {
        _WIN_ACCESS_RIGHT_CHANGE: constants.ACCESS_LEVEL_RW,
        _WIN_ACCESS_RIGHT_FULL: constants.ACCESS_LEVEL_RW,
        _WIN_ACCESS_RIGHT_READ: constants.ACCESS_LEVEL_RO,
        _WIN_ACCESS_RIGHT_CUSTOM: _ACCESS_LEVEL_CUSTOM,
    }

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

    def _get_acls(self, server, share_name):
        cmd = ('Get-SmbShareAccess -Name %(share_name)s | '
               'Select-Object @("Name", "AccountName", '
               '"AccessControlType", "AccessRight") | '
               'ConvertTo-JSON -Compress')
        (out, err) = self._remote_cmd(server, cmd)

        raw_acls = json.loads(out)
        return raw_acls

    def get_access_rules(self, server, share_name):
        raw_acls = self._get_acls(server, share_name)
        acls = []

        for raw_acl in raw_acls:
            access_to = raw_acl['AccountName']
            access_level = self._WIN_ACL_MAP[raw_acl['AccessRight']]
            access_allow = raw_acl["AccessControlType"] == self._WIN_ACL_ALLOW

            if not access_allow:
                if access_to.lower() == 'everyone' and len(raw_acls) == 1:
                    LOG.debug("No access rules are set yet for share %s",
                              share_name)
                else:
                    LOG.warning(
                        _LW("Found explicit deny ACE rule that was not "
                            "created by Manila and will be ignored: %s"),
                        raw_acl)
                continue
            if access_level == self._ACCESS_LEVEL_CUSTOM:
                LOG.warning(
                    _LW("Found 'custom' ACE rule that will be ignored: %s"),
                    raw_acl)
                continue

            acl = dict(access_to=access_to,
                       access_level=access_level,
                       access_type='user')
            acls.append(acl)
        return acls

    def _grant_share_access(self, server, share_name, access_level, access_to):
        LOG.info(_LI("Granting %(access_level)s acess to %(acess_to)s "
                     "on share %(share_name)s"),
                 dict(access_level=access_level,
                      acess_to=access_to,
                      share_name=share_name))

        access_right = self._SHARE_ACCESS_RIGHT_MAP[access_level]
        cmd = ["Grant-SmbShareAccess", "-Name", share_name,
               "-AccessRight", access_right,
               "-AccountName", access_to, "-Force"]
        self._remote_exec(server, cmd)
        self._refresh_acl(server, share_name)

    def _refresh_acl(self, server, share_name):
        cmd = ['Set-SmbPathAcl', '-ShareName', share_name]
        self._remote_exec(server, cmd)

    def _revoke_share_access(self, server, share_name, access_to):
        LOG.info(_LI("Revoking acess to %(acess_to)s "
                     "on share %(share_name)s"),
                 dict(acess_to=access_to,
                      share_name=share_name))

        cmd = ['Revoke-SmbShareAccess', '-Name', share_name,
               '-AccountName', access_to, '-Force']
        self._remote_exec(server, cmd)
        self._refresh_acl(server, share_name)

    def update_access(self, server, share_name, access_rules, add_rules,
                      delete_rules):
        all_rules = [access_rules, add_rules, delete_rules]
        self.validate_access_rules(
            all_rules, ('user',),
            (constants.ACCESS_LEVEL_RO, constants.ACCESS_LEVEL_RW))

        if not (add_rules or delete_rules):
            existing_rules = self.get_access_rules(server, share_name)
            (add_rules,
             delete_rules) = self._get_rule_updates(existing_rules,
                                                    access_rules)
        for added_rule in add_rules:
            self._grant_share_access(server, share_name,
                                     added_rule['access_type'],
                                     added_rule['access_level'],
                                     added_rule['access_to'])

        for deleted_rule in delete_rules:
            self._revoke_share_access(server, share_name,
                                      deleted_rule['access_to'])

    def _subtract_access_rules(self, access_rules, subtracted_rules):
        # Account names are case insensitive on Windows.
        filter_rules = lambda rules: set(
            dict(access_to=access_rule['access_to'].lower(),
                 access_level=access_rule['access_level'],
                 access_type=access_rule['access_type'])
            for access_rule in rules)

        return filter_rules(access_rules).difference(
            filter_rules(subtracted_rules))

    def _get_rule_updates(self, existing_rules, requested_rules):
        added_rules = self._subtract_access_rules(requested_rules,
                                                  existing_rules)
        deleted_rules = self._subtract_access_rules(existing_rules,
                                                    requested_rules)
        return added_rules, deleted_rules

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
