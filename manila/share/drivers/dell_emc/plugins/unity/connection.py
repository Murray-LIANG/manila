# Copyright (c) 2016 EMC Corporation.
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
"""Unity backend for the EMC Manila driver."""
import collections
import random

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import netutils

storops = importutils.try_import('storops')
if storops:
    # pylint: disable=import-error
    from storops import exception as storops_ex
    from storops.unity import enums

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.common.enas import utils as enas_utils
from manila.share.drivers.dell_emc.plugins import base as driver
from manila.share.drivers.dell_emc.plugins.unity import client
from manila.share.drivers.dell_emc.plugins.unity import utils as unity_utils
from manila.share import utils as share_utils
from manila import utils

"""Version history:
     7.0.0 - Supports DHSS=False mode
     7.0.1 - Fix parsing management IPv6 address
     7.0.2 - Bugfix: failed to delete CIFS share if wrong access was set
     8.0.0 - Supports manage/unmanage share server/share/snapshot
"""

VERSION = "8.0.0"

LOG = log.getLogger(__name__)
SUPPORTED_NETWORK_TYPES = (None, 'flat', 'vlan')

UNITY_OPTS = [
    cfg.StrOpt('unity_server_meta_pool',
               required=True,
               deprecated_name='emc_nas_server_pool',
               help='Pool to persist the meta-data of NAS server.'),
    cfg.ListOpt('unity_share_data_pools',
                deprecated_name='emc_nas_pool_names',
                help='Comma separated list of pools that can be used to '
                     'persist share data.'),
    cfg.ListOpt('unity_ethernet_ports',
                deprecated_name='emc_interface_ports',
                help='Comma separated list of ports that can be used for '
                     'share server interfaces. Members of the list '
                     'can be Unix-style glob expressions.'),
    cfg.StrOpt('emc_nas_server_container',
               deprecated_for_removal=True,
               deprecated_reason='Unity driver supports nas server auto load '
                                 'balance.',
               help='Storage processor to host the NAS server. Obsolete.'),
    cfg.StrOpt('unity_share_server',
               help='NAS server used for creating share when driver '
                    'is in DHSS=False mode. It is required when '
                    'driver_handles_share_servers=False in manila.conf.'),
    cfg.StrOpt('unity_replication_rpo',
               default=60,
               help='Maximum time in minute to wait before syncing the '
                    'replication source and destination. It could be set to '
                    '`0` which means the created replication is a sync one. '
                    'Make sure a sync type replication connection is set up '
                    'before using it. Refer to configuration doc for more '
                    'detail.'),
    cfg.StrOpt('unity_enable_local_replication',
               default=False,
               help='A flag to specify whether local replication is enabled '
                    'or not. Default is False. Set it to True carefully '
                    'because it could cause some replica out_of_sync in some '
                    'cases. Refer to unity driver document for detail.'),
]

CONF = cfg.CONF
CONF.register_opts(UNITY_OPTS)


@enas_utils.decorate_all_methods(enas_utils.log_enter_exit,
                                 debug_only=True)
class UnityStorageConnection(driver.StorageConnection):
    """Implements Unity specific functionality for EMC Manila driver."""

    IP_ALLOCATIONS = 1

    @enas_utils.log_enter_exit
    def __init__(self, *args, **kwargs):
        super(UnityStorageConnection, self).__init__(*args, **kwargs)
        if 'configuration' in kwargs:
            kwargs['configuration'].append_config_values(UNITY_OPTS)

        self.client = None
        self.pool_set = None
        self.nas_server_pool = None
        self.reserved_percentage = None
        self.max_over_subscription_ratio = None
        self.port_ids_conf = None
        self.unity_share_server = None
        self.ipv6_implemented = True
        self.revert_to_snap_support = True
        self.shrink_share_support = True
        self.manage_existing_support = True
        self.manage_existing_with_server_support = True
        self.manage_existing_snapshot_support = True
        self.manage_snapshot_with_server_support = True
        self.manage_server_support = True
        self.get_share_server_network_info_support = True
        self.choose_share_server_compatible_with_share_group_support = True
        self.share_group_replication_support = True
        self.replication_rpo = 60
        self.local_replication_enabled = False

        # props from super class.
        self.driver_handles_share_servers = (True, False)

    def connect(self, emc_share_driver, context):
        """Connect to Unity storage."""
        config = emc_share_driver.configuration
        storage_ip = enas_utils.convert_ipv6_format_if_needed(
            config.emc_nas_server)
        username = config.emc_nas_login
        password = config.emc_nas_password
        self.client = client.UnityClient(storage_ip, username, password)

        pool_conf = config.safe_get('unity_share_data_pools')
        self.pool_set = self._get_managed_pools(pool_conf)

        self.reserved_percentage = config.safe_get(
            'reserved_share_percentage')
        if self.reserved_percentage is None:
            self.reserved_percentage = 0

        self.max_over_subscription_ratio = config.safe_get(
            'max_over_subscription_ratio')
        self.port_ids_conf = config.safe_get('unity_ethernet_ports')
        self.unity_share_server = config.safe_get('unity_share_server')
        self.driver_handles_share_servers = config.safe_get(
            'driver_handles_share_servers')
        if (not self.driver_handles_share_servers) and (
                not self.unity_share_server):
            msg = ("Make sure there is NAS server name "
                   "configured for share creation when driver "
                   "is in DHSS=False mode.")
            raise exception.BadConfigurationException(reason=msg)
        self.validate_port_configuration(self.port_ids_conf)
        pool_name = config.unity_server_meta_pool
        self._config_pool(pool_name)

        self.replication_rpo = config.safe_get('unity_replication_rpo')
        self.local_replication_enabled = config.safe_get(
            'unity_enable_local_replication')

    def get_server_name(self, share_server=None):
        if not self.driver_handles_share_servers:
            return self.unity_share_server
        else:
            return self._get_server_name(share_server)

    def validate_port_configuration(self, port_ids_conf):
        """Initializes the SP and ports based on the port option."""

        ports = self.client.get_file_ports()

        sp_ports_map, unmanaged_port_ids = unity_utils.match_ports(
            ports, port_ids_conf)

        if not sp_ports_map:
            msg = (_("All the specified storage ports to be managed "
                     "do not exist. Please check your configuration "
                     "unity_ethernet_ports in manila.conf. "
                     "The available ports in the backend are %s.") %
                   ",".join([port.get_id() for port in ports]))
            raise exception.BadConfigurationException(reason=msg)

        if unmanaged_port_ids:
            LOG.info("The following specified ports are not managed by "
                     "the backend: %(unmanaged)s. This host will only "
                     "manage the storage ports: %(exist)s",
                     {'unmanaged': ",".join(unmanaged_port_ids),
                      'exist': ",".join(map(",".join,
                                            sp_ports_map.values()))})
        else:
            LOG.debug("Ports: %s will be managed.",
                      ",".join(map(",".join, sp_ports_map.values())))

        if len(sp_ports_map) == 1:
            LOG.info("Only ports of %s are configured. Configure ports "
                     "of both SPA and SPB to use both of the SPs.",
                     list(sp_ports_map)[0])

        return sp_ports_map

    def check_for_setup_error(self):
        """Check for setup error."""

    def manage_existing(self, share, driver_options, share_server=None):
        """Manages a share that exists on backend.

        :param share: Share that will be managed.
        :param driver_options: Driver-specific options provided by admin.
        :param share_server: Share server name provided by admin in DHSS=True.
        :returns: Returns a dict with share size and export location.
        """
        export_locations = share['export_locations']
        if not export_locations:
            message = ("Failed to manage existing share: %s, missing "
                       "export locations." % share['id'])
            raise exception.ManageInvalidShare(reason=message)

        try:
            share_size = int(driver_options.get("size", 0))
        except (ValueError, TypeError):
            msg = _("The driver options' size to manage the share "
                    "%(share_id)s, should be an integer, in format "
                    "driver-options size=<SIZE>. Value specified: "
                    "%(size)s.") % {'share_id': share['id'],
                                    'size': driver_options.get("size")}
            raise exception.ManageInvalidShare(reason=msg)

        if not share_size:
            msg = _("Share %(share_id)s has no specified size. "
                    "Using default value 1, set size in driver options if you "
                    "want.") % {'share_id': share['id']}
            LOG.warning(msg)
            share_size = 1

        share_id = unity_utils.get_share_backend_id(share)
        backend_share = self.client.get_share(share_id,
                                              share['share_proto'])
        if not backend_share:
            message = ("Could not find the share in backend, please make sure "
                       "the export location is right.")
            raise exception.ManageInvalidShare(reason=message)

        # Check the share server when in DHSS=true mode
        if share_server:
            backend_share_server = self._get_server_name(share_server)
            if not backend_share_server:
                message = ("Could not find the backend share server: %s, "
                           "please make sure that share server with the "
                           "specified name exists in the backend.",
                           share_server)
                raise exception.BadConfigurationException(message)
        LOG.info("Share %(shr_path)s is being managed with ID "
                 "%(shr_id)s.",
                 {'shr_path': share['export_locations'][0]['path'],
                  'shr_id': share['id']})
        # export_locations was not changed, return original value
        return {"size": share_size, 'export_locations': {
            'path': share['export_locations'][0]['path']}}

    def manage_existing_with_server(self, share, driver_options, share_server):
        return self.manage_existing(share, driver_options, share_server)

    def manage_existing_snapshot(self, snapshot, driver_options,
                                 share_server=None):
        """Brings an existing snapshot under Manila management."""
        try:
            snapshot_size = int(driver_options.get("size", 0))
        except (ValueError, TypeError):
            msg = _("The size in driver options to manage snapshot "
                    "%(snap_id)s should be an integer, in format "
                    "driver-options size=<SIZE>. Value passed: "
                    "%(size)s.") % {'snap_id': snapshot['id'],
                                    'size': driver_options.get("size")}
            raise exception.ManageInvalidShareSnapshot(reason=msg)

        if not snapshot_size:
            msg = _("Snapshot %(snap_id)s has no specified size. "
                    "Use default value 1, set size in driver options if you "
                    "want.") % {'snap_id': snapshot['id']}
            LOG.info(msg)
            snapshot_size = 1
        provider_location = snapshot.get('provider_location')
        snap = self.client.get_snapshot(provider_location)
        if not snap:
            message = ("Could not find a snapshot in the backend with "
                       "provider_location: %s, please make sure "
                       "the snapshot exists in the backend."
                       % provider_location)
            raise exception.ManageInvalidShareSnapshot(reason=message)

        LOG.info("Snapshot %(provider_location)s in Unity will be managed "
                 "with ID %(snapshot_id)s.",
                 {'provider_location': snapshot.get('provider_location'),
                  'snapshot_id': snapshot['id']})
        return {"size": snapshot_size, "provider_location": provider_location}

    def manage_existing_snapshot_with_server(self, snapshot, driver_options,
                                             share_server):
        return self.manage_existing_snapshot(snapshot, driver_options,
                                             share_server)

    def manage_server(self, context, share_server, identifier, driver_options):
        """Manage the share server and return compiled back end details.

        :param context: Current context.
        :param share_server: Share server model.
        :param identifier: A driver-specific share server identifier
        :param driver_options: Dictionary of driver options to assist managing
            the share server
        :return: Identifier and dictionary with back end details to be saved
            in the database.

        Example::

            'my_new_server_identifier',{'server_name': 'my_old_server'}

        """
        nas_server = self.client.get_nas_server(identifier)
        if not nas_server:
            message = ("Could not find the backend share server by server "
                       "name: %s, please make sure  the share server is "
                       "existing in the backend." % identifier)
            raise exception.ManageInvalidShare(reason=message)
        return identifier, driver_options

    def get_share_server_network_info(
            self, context, share_server, identifier, driver_options):
        """Obtain network allocations used by share server.

        :param context: Current context.
        :param share_server: Share server model.
        :param identifier: A driver-specific share server identifier
        :param driver_options: Dictionary of driver options to assist managing
            the share server
        :return: The containing IP address allocated in the backend, Unity
            only supports single IP address
        Example::

            ['10.10.10.10'] or ['fd11::2000']

        """
        containing_ips = []
        nas_server = self.client.get_nas_server(identifier)
        if nas_server:
            for file_interface in nas_server.file_interface:
                containing_ips.append(file_interface.ip_address)
        return containing_ips

    def create_share(self, context, share, share_server=None):
        """Create a share and export it based on protocol used."""
        share_name = share['id']
        size = share['size']

        # Check share's protocol.
        # Throw an exception immediately if it is an invalid protocol.
        share_proto = share['share_proto'].upper()
        proto_enum = self._get_proto_enum(share_proto)

        # Get pool name from share host field
        pool_name = self._get_pool_name_from_host(share['host'])
        # Get share server name from share server or manila.conf.
        server_name = self.get_server_name(share_server)
        pool = self.client.get_pool(pool_name)
        try:
            nas_server = self.client.get_nas_server(server_name)
        except storops_ex.UnityResourceNotFoundError:
            message = (_("Failed to get NAS server %(server)s when "
                         "creating the share %(share)s.") %
                       {'server': server_name, 'share': share_name})
            LOG.exception(message)
            raise exception.EMCUnityError(err=message)

        locations = None
        if share_proto == 'CIFS':
            filesystem = self.client.create_filesystem(
                pool, nas_server, share_name,
                size, proto=proto_enum)
            self.client.create_cifs_share(filesystem, share_name)

            locations = self._get_cifs_location(
                nas_server.file_interface, share_name)
        elif share_proto == 'NFS':
            self.client.create_nfs_filesystem_and_share(
                pool, nas_server, share_name, size)

            locations = self._get_nfs_location(
                nas_server.file_interface, share_name)

        return locations

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Create a share from a snapshot - clone a snapshot."""
        share_name = share['id']

        # Check share's protocol.
        # Throw an exception immediately if it is an invalid protocol.
        share_proto = share['share_proto'].upper()
        self._validate_share_protocol(share_proto)

        # Get share server name from share server
        server_name = self.get_server_name(share_server)

        try:
            nas_server = self.client.get_nas_server(server_name)
        except storops_ex.UnityResourceNotFoundError:
            message = (_("Failed to get NAS server %(server)s when "
                         "creating the share %(share)s.") %
                       {'server': server_name, 'share': share_name})
            LOG.exception(message)
            raise exception.EMCUnityError(err=message)
        snapshot_id = unity_utils.get_snapshot_id(snapshot)
        backend_snap = self.client.create_snap_of_snap(snapshot_id,
                                                       share_name)

        locations = None
        if share_proto == 'CIFS':
            self.client.create_cifs_share(backend_snap, share_name)

            locations = self._get_cifs_location(
                nas_server.file_interface, share_name)
        elif share_proto == 'NFS':
            self.client.create_nfs_share(backend_snap, share_name)

            locations = self._get_nfs_location(
                nas_server.file_interface, share_name)

        return locations

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        share_name = unity_utils.get_share_backend_id(share)
        try:
            backend_share = self.client.get_share(share_name,
                                                  share['share_proto'])
        except storops_ex.UnityResourceNotFoundError:
            LOG.warning("Share %s is not found when deleting the share",
                        share_name)
            return

        # Share created by the API create_share_from_snapshot()
        if self._is_share_from_snapshot(backend_share):
            filesystem = backend_share.snap.filesystem
            self.client.delete_snapshot(backend_share.snap)
        else:
            filesystem = backend_share.filesystem
            self.client.delete_share(backend_share)

        if self._is_isolated_filesystem(filesystem):
            self.client.delete_filesystem(filesystem)

    def extend_share(self, share, new_size, share_server=None):
        share_id = unity_utils.get_share_backend_id(share)
        backend_share = self.client.get_share(share_id,
                                              share['share_proto'])

        if not self._is_share_from_snapshot(backend_share):
            self.client.extend_filesystem(backend_share.filesystem,
                                          new_size)
        else:
            share_id = share['id']
            reason = ("Driver does not support extending a "
                      "snapshot based share.")
            raise exception.ShareExtendingError(share_id=share_id,
                                                reason=reason)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks a share to new size.

        :param share: Share that will be shrunk.
        :param new_size: New size of share.
        :param share_server: Data structure with share server information.
            Not used by this driver.
        """
        share_id = unity_utils.get_share_backend_id(share)
        backend_share = self.client.get_share(share_id,
                                              share['share_proto'])
        if self._is_share_from_snapshot(backend_share):
            reason = ("Driver does not support shrinking a "
                      "snapshot based share.")
            raise exception.ShareShrinkingError(share_id=share_id,
                                                reason=reason)
        self.client.shrink_filesystem(share_id, backend_share.filesystem,
                                      new_size)
        LOG.info("Share %(shr_id)s successfully shrunk to "
                 "%(shr_size)sG.",
                 {'shr_id': share_id,
                  'shr_size': new_size})

    def create_snapshot(self, context, snapshot, share_server=None,
                        replicated_to=None):
        """Create snapshot from share."""
        share = snapshot['share']
        share_name = unity_utils.get_share_backend_id(
            share) if share else snapshot['share_id']
        share_proto = snapshot['share']['share_proto']
        backend_share = self.client.get_share(share_name, share_proto)

        snapshot_name = snapshot['id']
        if self._is_share_from_snapshot(backend_share):
            if replicated_to:
                LOG.warning('Not support to replicate the copied snapshot '
                            '%(new)s. This snapshot is copied from snap '
                            '%(from)s. Ignoring `replicated_to` parameter.',
                            {'new': snapshot_name,
                             'from': backend_share.snap.get_id()})
            self.client.create_snap_of_snap(backend_share.snap, snapshot_name)
        else:
            self.client.create_snapshot(backend_share.filesystem,
                                        snapshot_name,
                                        replicated_to=replicated_to)
        return {'provider_location': snapshot_name}

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        snapshot_id = unity_utils.get_snapshot_id(snapshot)
        snap = self.client.get_snapshot(snapshot_id)
        self.client.delete_snapshot(snap)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        # adding rules
        if add_rules:
            for rule in add_rules:
                self.allow_access(context, share, rule, share_server)

        # deleting rules
        if delete_rules:
            for rule in delete_rules:
                self.deny_access(context, share, rule, share_server)

        # recovery mode
        if not (add_rules or delete_rules):
            white_list = []
            for rule in access_rules:
                self.allow_access(context, share, rule, share_server)
                white_list.append(rule['access_to'])
            self.clear_access(share, white_list)

    def clear_access(self, share, white_list=None):
        share_proto = share['share_proto'].upper()
        share_name = unity_utils.get_share_backend_id(share)
        if share_proto == 'CIFS':
            self.client.cifs_clear_access(share_name, white_list)
        elif share_proto == 'NFS':
            self.client.nfs_clear_access(share_name, white_list)

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to a share."""
        access_level = access['access_level']
        if access_level not in const.ACCESS_LEVELS:
            raise exception.InvalidShareAccessLevel(level=access_level)

        share_proto = share['share_proto'].upper()

        self._validate_share_protocol(share_proto)
        self._validate_share_access_type(share, access)

        if share_proto == 'CIFS':
            self._cifs_allow_access(share, access)
        elif share_proto == 'NFS':
            self._nfs_allow_access(share, access)

    def deny_access(self, context, share, access, share_server):
        """Deny access to a share."""
        share_proto = share['share_proto'].upper()

        self._validate_share_protocol(share_proto)
        self._validate_share_access_type(share, access)

        if share_proto == 'CIFS':
            self._cifs_deny_access(share, access)
        elif share_proto == 'NFS':
            self._nfs_deny_access(share, access)

    def ensure_share(self, context, share, share_server):
        """Ensure that the share is exported."""
        share_name = unity_utils.get_share_backend_id(share)
        share_proto = share['share_proto']

        backend_share = self.client.get_share(share_name, share_proto)
        if not backend_share.existed:
            raise exception.ShareNotFound(share_id=share_name)

    def update_share_stats(self, stats_dict):
        """Communicate with EMCNASClient to get the stats."""
        stats_dict['driver_version'] = VERSION
        stats_dict['pools'] = []

        for pool in self.client.get_pool():
            if pool.name in self.pool_set:
                # the unit of following numbers are GB
                total_size = float(pool.size_total)
                used_size = float(pool.size_used)

                pool_stat = {
                    'pool_name': pool.name,
                    'thin_provisioning': True,
                    'total_capacity_gb': total_size,
                    'free_capacity_gb': total_size - used_size,
                    'allocated_capacity_gb': used_size,
                    'provisioned_capacity_gb': float(pool.size_subscribed),
                    'qos': False,
                    'reserved_percentage': self.reserved_percentage,
                    'max_over_subscription_ratio':
                        self.max_over_subscription_ratio,
                }
                stats_dict['pools'].append(pool_stat)

        if not stats_dict.get('pools'):
            message = _("Failed to update storage pool.")
            LOG.error(message)
            raise exception.EMCUnityError(err=message)

        # For replication, Unity driver only supports:
        # 1) share group replication as the share replication cannot be
        #   operated individually but the group of share replications in the
        #   nas server.
        # 2) to enable share group replication in DHSS=True mode.
        # 3) only the `dr` type of replications due to the destination share
        #   in the replication cannot be mounted for read or write.
        if self.driver_handles_share_servers:
            group_stats = stats_dict['share_group_stats']
            group_stats[
                'group_replication_type'] = const.GROUP_REPLICATION_TYPE_DR
            group_stats['max_group_replicas_count_on_same_backend'] = 1
            group_stats['local_group_replication_support'] = (
                self.local_replication_enabled)

    def get_pool(self, share):
        """Get the pool name of the share."""
        backend_share = self.client.get_share(
            share['id'], share['share_proto'])

        return backend_share.filesystem.pool.name

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        return self.IP_ALLOCATIONS

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""

        server_name = network_info['server_id']

        if metadata and metadata.get('for_new_share_group_replica', False):
            LOG.info('The server %s is used as the destination of a nas '
                     'server replication. And its setup will be postponed to '
                     'the replication session creating. So, skip the setup '
                     'here.', server_name)
            return {'share_server_name': server_name}

        segmentation_id = network_info['segmentation_id']
        network = self.validate_network(network_info)
        mtu = network['mtu']
        tenant = self.client.get_tenant(network_info['server_id'],
                                        segmentation_id)

        sp_ports_map = unity_utils.find_ports_by_mtu(
            self.client.get_file_ports(),
            self.port_ids_conf, mtu)

        sp = self._choose_sp(sp_ports_map)
        nas_server = self.client.create_nas_server(server_name,
                                                   sp,
                                                   self.nas_server_pool,
                                                   tenant=tenant)
        sp = nas_server.home_sp
        port_id = self._choose_port(sp_ports_map, sp)
        try:
            self._create_network_interface(nas_server, network, port_id)

            self._handle_security_services(
                nas_server, network_info['security_services'])

            return {'share_server_name': server_name}

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Could not setup server.')
                server_details = {'share_server_name': server_name}
                self.teardown_server(
                    server_details, network_info['security_services'])

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        if not server_details:
            LOG.debug('Server details are empty.')
            return

        server_name = server_details.get('share_server_name')
        if not server_name:
            LOG.debug('No share server found for server %s.',
                      server_details.get('instance_id'))
            return

        username = None
        password = None
        for security_service in security_services:
            if security_service['type'] == 'active_directory':
                username = security_service['user']
                password = security_service['password']
                break

        self.client.delete_nas_server(server_name, username, password)

    def _cifs_allow_access(self, share, access):
        """Allow access to CIFS share."""
        self.client.cifs_allow_access(
            share['id'], access['access_to'], access['access_level'])

    def _cifs_deny_access(self, share, access):
        """Deny access to CIFS share."""
        self.client.cifs_deny_access(share['id'], access['access_to'])

    def _config_pool(self, pool_name):
        try:
            self.nas_server_pool = self.client.get_pool(pool_name)
        except storops_ex.UnityResourceNotFoundError:
            message = (_("The storage pools %s to store NAS server "
                         "configuration do not exist.") % pool_name)
            LOG.exception(message)
            raise exception.BadConfigurationException(reason=message)

    @staticmethod
    def validate_network(network_info):
        network = network_info['network_allocations'][0]
        if network['network_type'] not in SUPPORTED_NETWORK_TYPES:
            msg = _('The specified network type %s is unsupported by '
                    'the EMC Unity driver')
            raise exception.NetworkBadConfigurationException(
                reason=msg % network['network_type'])
        return network

    def _create_network_interface(self, nas_server, network, port_id):
        kargs = {'ip_addr': network['ip_address'],
                 'gateway': network['gateway'],
                 'vlan_id': network['segmentation_id'],
                 'port_id': port_id}

        if netutils.is_valid_ipv6_cidr(kargs['ip_addr']):
            kargs['netmask'] = None
            kargs['prefix_length'] = str(utils.cidr_to_prefixlen(
                network['cidr']))
        else:
            kargs['netmask'] = utils.cidr_to_netmask(network['cidr'])

        # Create the interfaces on NAS server
        self.client.create_interface(nas_server, **kargs)

    def _choose_sp(self, sp_ports_map):
        sp = None
        if len(sp_ports_map.keys()) == 1:
            # Only one storage processor has usable ports,
            # create NAS server on that SP.
            sp = self.client.get_storage_processor(
                sp_id=list(sp_ports_map.keys())[0])
            LOG.debug('All the usable ports belong to  %s. '
                      'Creating NAS server on this SP without '
                      'load balance.', sp.get_id())
        return sp

    @staticmethod
    def _choose_port(sp_ports_map, sp):
        ports = sp_ports_map[sp.get_id()]
        return random.choice(list(ports))

    @staticmethod
    def _get_cifs_location(file_interfaces, share_name):
        return [
            {'path': r'\\%(interface)s\%(share_name)s' % {
                'interface': enas_utils.export_unc_path(interface.ip_address),
                'share_name': share_name}
             }
            for interface in file_interfaces
        ]

    def _get_managed_pools(self, pool_conf):
        # Get the real pools from the backend storage
        real_pools = set(pool.name for pool in self.client.get_pool())

        if not pool_conf:
            LOG.debug("No storage pool is specified, so all pools in storage "
                      "system will be managed.")
            return real_pools

        matched_pools, unmanaged_pools = unity_utils.do_match(real_pools,
                                                              pool_conf)

        if not matched_pools:
            msg = (_("All the specified storage pools to be managed "
                     "do not exist. Please check your configuration "
                     "emc_nas_pool_names in manila.conf. "
                     "The available pools in the backend are %s") %
                   ",".join(real_pools))
            raise exception.BadConfigurationException(reason=msg)

        if unmanaged_pools:
            LOG.info("The following specified storage pools "
                     "are not managed by the backend: "
                     "%(un_managed)s. This host will only manage "
                     "the storage pools: %(exist)s",
                     {'un_managed': ",".join(unmanaged_pools),
                      'exist': ",".join(matched_pools)})
        else:
            LOG.debug("Storage pools: %s will be managed.",
                      ",".join(matched_pools))

        return matched_pools

    @staticmethod
    def _get_nfs_location(file_interfaces, share_name):
        return [
            {'path': '%(interface)s:/%(share_name)s' % {
                'interface': enas_utils.convert_ipv6_format_if_needed(
                    interface.ip_address),
                'share_name': share_name}
             }
            for interface in file_interfaces
        ]

    @staticmethod
    def _get_pool_name_from_host(host):
        pool_name = share_utils.extract_host(host, level='pool')
        if not pool_name:
            message = (_("Pool is not available in the share host %s.") %
                       host)
            raise exception.InvalidHost(reason=message)

        return pool_name

    @staticmethod
    def _get_proto_enum(share_proto):
        share_proto = share_proto.upper()
        UnityStorageConnection._validate_share_protocol(share_proto)

        if share_proto == 'CIFS':
            return enums.FSSupportedProtocolEnum.CIFS
        elif share_proto == 'NFS':
            return enums.FSSupportedProtocolEnum.NFS

    @staticmethod
    def _get_server_name(share_server):
        if not share_server:
            msg = _('Share server not provided.')
            raise exception.InvalidInput(reason=msg)
        # Try to get share server name from property 'identifier' first in
        # case this is managed share server.
        server_name = share_server.get('identifier') or share_server.get(
            'backend_details', {}).get('share_server_name')

        if server_name is None:
            msg = (_("Name of the share server %s not found.")
                   % share_server['id'])
            LOG.error(msg)
            raise exception.InvalidInput(reason=msg)

        return server_name

    def _handle_security_services(self, nas_server, security_services):
        kerberos_enabled = False
        # Support 'active_directory' and 'kerberos'
        for security_service in security_services:
            service_type = security_service['type']
            if service_type == 'active_directory':
                # Create DNS server for NAS server
                domain = security_service['domain']
                dns_ip = security_service['dns_ip']
                self.client.create_dns_server(nas_server,
                                              domain,
                                              dns_ip)

                # Enable CIFS service
                username = security_service['user']
                password = security_service['password']
                self.client.enable_cifs_service(nas_server,
                                                domain=domain,
                                                username=username,
                                                password=password)
            elif service_type == 'kerberos':
                # Enable NFS service with kerberos
                kerberos_enabled = True
                # TODO(jay.xu): enable nfs service with kerberos
                LOG.warning('Kerberos is not supported by '
                            'EMC Unity manila driver plugin.')
            elif service_type == 'ldap':
                LOG.warning('LDAP is not supported by '
                            'EMC Unity manila driver plugin.')
            else:
                LOG.warning('Unknown security service type: %s.',
                            service_type)

        if not kerberos_enabled:
            # Enable NFS service without kerberos
            self.client.enable_nfs_service(nas_server)

    def _nfs_allow_access(self, share, access):
        """Allow access to NFS share."""
        self.client.nfs_allow_access(
            share['id'], access['access_to'], access['access_level'])

    def _nfs_deny_access(self, share, access):
        """Deny access to NFS share."""
        self.client.nfs_deny_access(share['id'], access['access_to'])

    @staticmethod
    def _is_isolated_filesystem(filesystem):
        filesystem.update()
        return (
            not filesystem.has_snap() and
            not (filesystem.cifs_share or filesystem.nfs_share)
        )

    @staticmethod
    def _is_share_from_snapshot(share):
        return True if share.snap else False

    @staticmethod
    def _validate_share_access_type(share, access):
        reason = None
        share_proto = share['share_proto'].upper()

        if share_proto == 'CIFS' and access['access_type'] != 'user':
            reason = _('Only user access type allowed for CIFS share.')
        elif share_proto == 'NFS' and access['access_type'] != 'ip':
            reason = _('Only IP access type allowed for NFS share.')

        if reason:
            raise exception.InvalidShareAccess(reason=reason)

    @staticmethod
    def _validate_share_protocol(share_proto):
        if share_proto not in ('NFS', 'CIFS'):
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.') %
                        share_proto))

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        """Reverts a share (in place) to the specified snapshot."""
        snapshot_id = unity_utils.get_snapshot_id(snapshot)
        return self.client.restore_snapshot(snapshot_id)

    @enas_utils.log_enter_exit
    def choose_share_server_compatible_with_share_group(
            self, context, share_servers, share_group_instance,
            share_group_snapshot=None):

        # NOTE(RyanLiang): Only DHSS=True mode uses this function.

        if share_group_instance.get('group_replication_type'):
            # share_group_instance could be the first instance of the share
            # group or a creating replica of a share group. For both cases,
            # return None to create a new share server.
            LOG.debug('Share group instance %(instance)s will be involved in '
                      'a %(rep_type)s replication, creating a share server '
                      'for it.',
                      {'instance': share_group_instance['id'],
                       'rep_type': share_group_instance.get(
                           'group_replication_type')})
            return None
        else:
            share_server = share_servers[0] if share_servers else None
            LOG.debug('Share group instance %(instance)s is not involved in '
                      'replication, returning the first available share '
                      'server %(server)s for it.',
                      {'instance': share_group_instance['id'],
                       'server': share_server['id'] if share_server else None})
            return share_server

    @staticmethod
    def _setup_replica_client(replica):
        backend_name = share_utils.extract_host(replica['host'],
                                                level='backend_name')
        conf = unity_utils.get_backend_config(CONF, backend_name)
        return client.UnityClient(conf.emc_nas_server,
                                  conf.emc_nas_login,
                                  conf.emc_nas_password)

    @staticmethod
    def _get_active_share_replica(share_replica, share_replicas_all):
        if share_replica['replica_state'] == const.REPLICA_STATE_ACTIVE:
            return share_replica
        replicas_of_same_share = [
            r for r in share_replicas_all
            if r['share_id'] == share_replica['share_id']]
        return [r for r in replicas_of_same_share
                if r['replica_state'] == const.REPLICA_STATE_ACTIVE][0]

    @staticmethod
    def _build_share_replicas_update(share_replicas,
                                     share_replicas_all, fs_replications,
                                     with_export_locations=False,
                                     with_access_rules_status=False):
        share_replicas_update = []
        for share_replica in share_replicas:
            # Both shares on Unity for active and dr replica are with the same
            # name which is the active replica's id and it's different from the
            # dr replica's id. So, we need to use the active share replica's id
            # to locate the share of dr replica and its filesystem on unity.
            # Filesystem's name and share's are same on unity.
            try:
                active_share_replica = (
                    UnityStorageConnection._get_active_share_replica(
                        share_replica, share_replicas_all))
            except IndexError:
                LOG.warning('No active share replica for share replica %s. '
                            'No update returned for it.',
                            share_replica['id'])
                continue

            fs_name = unity_utils.get_share_backend_id(active_share_replica)
            replica_state = (const.REPLICA_STATE_IN_SYNC
                             if fs_replications[fs_name].is_in_sync
                             else const.REPLICA_STATE_OUT_OF_SYNC)

            update = {'id': share_replica['id'],
                      'replica_state': replica_state}
            if with_export_locations:
                # Copy the active share replica's export_locations to the dr
                # replica. Because the dr replica's id is different from the
                # name on Unity, we need to use export_locations to locate the
                # correct share on Unity.
                update['export_locations'] = active_share_replica.get(
                    'export_locations')
            if with_access_rules_status:
                update['access_rules_status'] = const.ACCESS_STATE_ACTIVE
            share_replicas_update.append(update)
        return share_replicas_update

    @enas_utils.log_enter_exit
    def create_share_group_replica(self, context,
                                   group_replica_creating, group_replicas_all,
                                   share_replicas_creating,
                                   share_replicas_all,
                                   share_access_rules_dict,
                                   group_replica_snapshots,
                                   share_replica_snapshots,
                                   share_server=None,
                                   share_server_network_info=None):
        """Replicates the active replica to a new replica on this backend.

        Unity only supports share group replication and the `dr` type of
        replications due to the destination share in the replication cannot be
        mounted for read or write, and supports share group replication in
        DHSS=True mode.

        This call is made on the host that the new replica is being created
        upon.
        """
        active_replica = share_utils.get_active_replica(group_replicas_all)
        if active_replica is None:
            raise exception.InvalidInput(
                reason='No active replica in the share group replicas.')

        active_client = self._setup_replica_client(active_replica)

        if (len(group_replicas_all) > 2 and
                not active_client.is_unity_version('5.1.0')):
            # The count of all replicas greater than 2, means that there is at
            # least one replica except the active one and creating one. It
            # is not supported if the active Unity OE is prior to 5.1.0.
            raise exception.EMCUnityError(
                err='OE version of the active Unity is %s, which does not '
                    'support to create more than 1 replica for the same nas '
                    'server. Upgrade Unity OE to 5.1.0 or later.'
                    % active_client.system.system_version)

        active_nas_server_name = active_replica['share_server_id']

        if share_server is None:
            raise exception.InvalidInput(
                reason='share_server of create_share_group_replica cannot be '
                       'None.')

        dr_nas_server_name = share_server['id']
        dr_pool_name = share_utils.extract_host(group_replica_creating['host'],
                                                level='pool')
        # The file interface on the destination nas server will be the same as
        # the source's. Need to override it using its expected ip address.
        dr_new_ip_addr = share_server_network_info[
            'network_allocations'][0]['ip_address']
        nas_rep, fs_reps = active_client.enable_replication(
            self.client, active_nas_server_name, dr_nas_server_name,
            self.replication_rpo, dr_pool_name=dr_pool_name,
            dr_new_ip_addr=dr_new_ip_addr, replicate_existing_snaps=True)

        group_replica_update = {
            'replica_state':
                const.REPLICA_STATE_IN_SYNC if nas_rep.is_in_sync
                else const.REPLICA_STATE_OUT_OF_SYNC,
        }

        share_replicas_update = self._build_share_replicas_update(
            share_replicas_creating, share_replicas_all, fs_reps,
            with_export_locations=True, with_access_rules_status=True)
        return group_replica_update, share_replicas_update

    @enas_utils.log_enter_exit
    def delete_share_group_replica(self, context,
                                   group_replica_deleting, group_replicas_all,
                                   share_replicas_deleting,
                                   share_replicas_all,
                                   group_replica_snapshots,
                                   share_replica_snapshots,
                                   share_server=None):
        active_replica = share_utils.get_active_replica(group_replicas_all)
        if active_replica is None:
            LOG.info('No active replica in the share group replicas. Share '
                     'group replica %s deletion skipped.',
                     group_replica_deleting['id'])
            return None, None

        active_client = self._setup_replica_client(active_replica)
        active_nas_server_name = active_replica['share_server_id']
        dr_nas_server_name = group_replica_deleting['share_server_id']
        active_client.disable_replication(self.client, active_nas_server_name,
                                          dr_nas_server_name)
        return None, None

    @enas_utils.log_enter_exit
    def promote_share_group_replica(self, context,
                                    group_replica_promoting,
                                    group_replicas_all,
                                    share_replicas_promoting,
                                    share_replicas_all,
                                    share_access_rules_dict,
                                    share_server=None):
        """Promotes a nas server to 'active'.

        Always fail over a replication session and resume it. So normally
        there is no replication session under failed over status.

        1. If the source system of the replication session is available, fail
            it over with sync (aka. planned fail-over), then resume.
        2. Otherwise, fail it over directly (aka. unplanned fail-over), then
            resume.
        """

        if (len(group_replicas_all) > 2 and
                not self.client.is_unity_version('5.1.0')):
            # There are at least three replicas (one active, two dr), which
            # means the promoting dr system will have more than two
            # replications after the promotion completes. It is not supported
            # if the promoting Unity OE is prior to 5.1.0.
            raise exception.EMCUnityError(
                err='OE version of the promoting Unity is %s, which does not '
                    'support to hold more than 1 replica for the same nas '
                    'server. Upgrade Unity OE to 5.1.0 or later.'
                    % self.client.system.system_version)

        active_replica = share_utils.get_active_replica(group_replicas_all)
        if active_replica is None:
            raise exception.InvalidInput(
                reason='No active replica in the share group replicas.')

        active_client = self._setup_replica_client(active_replica)
        active_nas_server_name = active_replica['share_server_id']
        dr_nas_server_name = group_replica_promoting['share_server_id']
        active_client.failover_replication(self.client, active_nas_server_name,
                                           dr_nas_server_name)

        # If there are other dr replicas except the original active and
        # promoting replicas, we need to tear down all the replications from
        # original active replica to these replicas, and then build up
        # replications from the new active replica.
        replicated_systems = {
            active_client.get_serial_number(): active_nas_server_name}
        for replica in group_replicas_all:
            if replica['id'] in (active_replica['id'],
                                 group_replica_promoting['id']):
                continue

            rep_nas_server = replica['share_server_id']
            rep_client = self._setup_replica_client(replica)

            only_tear_down = False
            rep_system = rep_client.get_serial_number()
            if rep_system in replicated_systems:
                LOG.warning('Not support to create two or more replications '
                            'to the same Unity for the same nas server '
                            '%(nas)s. Unity %(unity)s already hosts the '
                            'replica nas server %(rep)s. Cannot set up the '
                            'second replica nas server %(sec)s on the same '
                            'Unity. Then the second replica %(sec_rep)s will '
                            'be always out_of_sync.',
                            {'nas': dr_nas_server_name, 'unity': rep_system,
                             'rep': replicated_systems[rep_system],
                             'sec': rep_nas_server, 'sec_rep': replica['id']})
                only_tear_down = True
            else:
                replicated_systems[rep_system] = rep_nas_server

            self.client.rebuild_replication(
                new_active_nas_name=dr_nas_server_name, dr_client=rep_client,
                dr_nas_server_name=rep_nas_server,
                orig_active_client=active_client,
                orig_active_nas_name=active_nas_server_name,
                max_out_of_sync_minutes=self.replication_rpo,
                only_tear_down=only_tear_down)

        # Only change original active share group replica and share replicas'
        # replica_state to in_sync. share/manager will set the promoting share
        # group replica and share replicas' replica_state to active.
        share_replicas_update = []
        for share_replica in share_replicas_promoting:
            try:
                active_share_replica = self._get_active_share_replica(
                    share_replica, share_replicas_all)
            except IndexError:
                LOG.warning('No active share replica for share replica %s. '
                            'No update returned for it.',
                            share_replica['id'])
                continue
            share_replicas_update.append(
                {'id': active_share_replica['id'],
                 'replica_state': const.REPLICA_STATE_IN_SYNC})

        return ([{'id': active_replica['id'],
                  'replica_state': const.REPLICA_STATE_IN_SYNC}],
                share_replicas_update)

    @enas_utils.log_enter_exit
    def update_share_group_replica_state(self, context,
                                         group_replica_updating,
                                         group_replicas_all,
                                         share_replicas_updating,
                                         share_replicas_all,
                                         share_access_rules_dict,
                                         group_replica_snapshots,
                                         share_replica_snapshots,
                                         share_server=None):
        active_replica = share_utils.get_active_replica(group_replicas_all)
        if active_replica is None:
            raise exception.InvalidInput(
                reason='No active replica in the share group replicas.')

        active_client = self._setup_replica_client(active_replica)
        active_nas_server_name = active_replica['share_server_id']
        dr_nas_server_name = group_replica_updating['share_server_id']
        nas_rep, fs_reps = active_client.get_nas_server_and_fs_replications(
            self.client, active_nas_server_name, dr_nas_server_name)

        if nas_rep is None and fs_reps is None:
            # Replication session cannot be found, then set the replicas's
            # status to out_of_sync.
            return (const.REPLICA_STATE_OUT_OF_SYNC,
                    [{'id': share_replica['id'],
                      'replica_state': const.REPLICA_STATE_OUT_OF_SYNC}
                     for share_replica in share_replicas_updating])

        group_replica_update = (const.REPLICA_STATE_IN_SYNC
                                if nas_rep.is_in_sync
                                else const.REPLICA_STATE_OUT_OF_SYNC)
        share_replicas_states = self._build_share_replicas_update(
            share_replicas_updating, share_replicas_all, fs_reps,
            with_export_locations=False, with_access_rules_status=False)
        return group_replica_update, share_replicas_states

    @enas_utils.log_enter_exit
    def create_replicated_share_group_snapshot(self, context,
                                               group_replicas_all,
                                               group_replica_snapshots,
                                               share_replicas_all,
                                               share_replica_snapshots,
                                               share_server=None):

        # This call is made on the 'active' share group replica's host.
        # So, `self` is connecting to the 'active' Unity.

        active_group_rep = share_utils.get_active_replica(group_replicas_all)
        if active_group_rep is None:
            raise exception.InvalidInput(
                reason='No active replica in the share group replicas.')

        active_share_reps = [
            r for r in share_replicas_all
            if r['share_group_instance_id'] == active_group_rep['id']]

        dr_group_reps = [r for r in group_replicas_all
                         if r['id'] != active_group_rep['id']]
        dr_info = {r['id']: (r, self._setup_replica_client(r))
                   for r in dr_group_reps}
        remote_systems = [
            self.client.get_remote_system(_client.get_serial_number())
            for _, _client in dr_info.values()]

        share_rep_snaps_by_rep_id = collections.defaultdict(list)
        for snap in share_replica_snapshots:
            share_rep_snaps_by_rep_id[snap['share_instance_id']].append(snap)

        share_rep_snaps_update = []

        local_replicated_snaps = []
        # Create share snapshots on Unity for active share replicas and
        # replicate these new snapshots to destination Unity.
        for active_share_rep in active_share_reps:
            active_rep_id = active_share_rep['id']
            for share_rep_snap in share_rep_snaps_by_rep_id[active_rep_id]:
                # Only one snapshot for each share replica actually.

                active_snap = self.create_snapshot(
                    context, share_rep_snap, replicated_to=remote_systems)

                # provider_location for snapshot is returned by
                # `create_snapshot`, we need to return it to manager to update
                # snapshot's DB.
                active_share_snap_update = {'id': share_rep_snap['id']}
                active_share_snap_update.update(active_snap)
                share_rep_snaps_update.append(active_share_snap_update)

                LOG.debug('Collecting provider_location for dr share replicas '
                          'snapshots.')

                for dr_group_rep_id, (_, dr_client) in dr_info.items():
                    dr_shr_rep = [
                        r for r in share_replicas_all
                        if r['share_group_instance_id'] == dr_group_rep_id
                        and r['share_id'] == active_share_rep['share_id']][0]

                    for share_rep_snap in (
                            share_rep_snaps_by_rep_id[dr_shr_rep['id']]):

                        # Local replication is a special case here. Snapshot
                        # xxx is replicated to snapshot xxx_20200907020101 for
                        # local replication. To get the correct name
                        # xxx_20200907020101 we need to sync the replication
                        # session and then try to get the replicated snapshot.
                        if self.client.is_local_replication(dr_client):
                            local_replicated_snaps.append(
                                (share_rep_snap['id'],
                                 active_snap['provider_location'],
                                 dr_client))
                        else:
                            dr_share_snap_update = {'id': share_rep_snap['id']}
                            dr_share_snap_update.update(active_snap)
                            share_rep_snaps_update.append(dr_share_snap_update)

        # Sync all the replication sessions to refresh snapshots on the
        # destination system. Or the snapshots cannot be found on the
        # destination until RPO (default 60 min or time set by
        # `unity_replication_rpo`) later.
        for dr_group_rep, dr_client in dr_info.values():
            nas_rep, _ = self.client.get_nas_server_and_fs_replications(
                dr_client, active_group_rep['share_server_id'],
                dr_group_rep['share_server_id'])
            nas_rep.sync()

        for share_rep_snap_id, snap_name, dr_client in local_replicated_snaps:
            unity_snap = dr_client.get_replicated_snapshot(snap_name, True)
            share_rep_snaps_update.append(
                {'id': share_rep_snap_id,
                 'provider_location': unity_snap.name})

        return None, share_rep_snaps_update

    @enas_utils.log_enter_exit
    def delete_replicated_share_group_snapshot(self, context,
                                               group_replicas_all,
                                               group_replica_snapshots,
                                               share_replicas_all,
                                               share_replica_snapshots,
                                               share_server=None):
        # This call is made on the 'active' share group replica's host.
        # So, `self` is connecting to the 'active' Unity.

        def _delete_snapshot_on_system(_client, replica_snap):
            # Rely on `provider_location` which is populated during creation.
            snapshot_id = unity_utils.get_snapshot_id(replica_snap)
            try:
                snap = _client.get_snapshot(snapshot_id)
                _client.delete_snapshot(snap)
            except storops_ex.UnityResourceNotFoundError:
                LOG.info('Snapshot %s not found. Deleting skipped.',
                         snapshot_id)

        active_group_rep = share_utils.get_active_replica(group_replicas_all)
        if active_group_rep is None:
            raise exception.InvalidInput(
                reason='No active replica in the share group replicas.')

        share_rep_snaps_by_rep_id = collections.defaultdict(list)
        for snap in share_replica_snapshots:
            share_rep_snaps_by_rep_id[snap['share_instance_id']].append(snap)

        for group_rep in group_replicas_all:
            unity_client = self._setup_replica_client(group_rep)
            for share_rep in [r for r in share_replicas_all if
                              r['share_group_instance_id'] == group_rep['id']]:
                for share_rep_snap in share_rep_snaps_by_rep_id.get(
                        share_rep['id'], []):
                    _delete_snapshot_on_system(unity_client, share_rep_snap)

    @enas_utils.log_enter_exit
    def update_replicated_share_group_snapshot(self, context,
                                               group_replica,
                                               group_replicas_all,
                                               group_replica_snap_updating,
                                               group_replica_snaps_all,
                                               share_replicas,
                                               share_replicas_all,
                                               share_replica_snaps_updating,
                                               share_replica_snaps_all,
                                               share_server=None):
        # This call is made on the host where the updating share group replica
        # snapshot locates. `self` is connecting to one of the DR Unity
        # systems, not the active one.

        active_group_rep = share_utils.get_active_replica(group_replicas_all)
        if active_group_rep is None:
            raise exception.InvalidInput(
                reason='No active replica in the share group replicas.')

        active_client = self._setup_replica_client(active_group_rep)

        share_rep_snaps_update = []
        updating_client = self._setup_replica_client(group_replica)
        is_local_rep = active_client.is_local_replication(updating_client)
        active_group_rep_id = active_group_rep['id']
        for share_rep_snap in share_replica_snaps_updating:
            if share_rep_snap.get('status') == const.STATUS_DELETING:
                # We don't check whether the snapshot is deleted from Unity.
                # The snapshot will be deleted eventually.
                update = {'id': share_rep_snap['id'],
                          'status': const.STATUS_DELETED}
                share_rep_snaps_update.append(update)
            else:
                # For creating or other state.
                update = {'id': share_rep_snap['id']}
                if share_rep_snap.get('status') == const.STATUS_CREATING:
                    update['status'] = const.STATUS_AVAILABLE
                if not share_rep_snap.get('provider_location'):
                    active_rep = [
                        r for r in share_replicas_all
                        if r['share_group_instance_id'] == active_group_rep_id
                        and r['share_id'] == share_rep_snap['share_id']][0]
                    active_rep_snap = [
                        s for s in share_replica_snaps_all
                        if s['share_instance_id'] == active_rep['id']][0]
                    unity_snap = updating_client.get_replicated_snapshot(
                        active_rep_snap['provider_location'], is_local_rep)
                    update['provider_location'] = unity_snap.name
                share_rep_snaps_update.append(update)

        new_status = group_replica_snap_updating.get('status')
        if new_status == const.STATUS_CREATING:
            new_status = const.STATUS_AVAILABLE
        if new_status == const.STATUS_DELETING:
            new_status = const.STATUS_DELETED
        group_rep_snap_update = {'id': group_replica_snap_updating['id'],
                                 'status': new_status}

        return group_rep_snap_update, share_rep_snaps_update
