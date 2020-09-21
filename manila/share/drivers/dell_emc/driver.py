# Copyright (c) 2019 EMC Corporation.
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

"""
EMC specific NAS storage driver. This driver is a pluggable driver
that allows specific EMC NAS devices to be plugged-in as the underlying
backend. Use the Manila configuration variable "share_backend_name"
to specify, which backend plugins to use.
"""

from oslo_config import cfg
from oslo_log import log

from manila.share import driver
from manila.share.drivers.dell_emc import plugin_manager as manager

EMC_NAS_OPTS = [
    cfg.StrOpt('emc_nas_login',
               help='User name for the EMC server.'),
    cfg.StrOpt('emc_nas_password',
               help='Password for the EMC server.'),
    cfg.HostAddressOpt('emc_nas_server',
                       help='EMC server hostname or IP address.'),
    cfg.PortOpt('emc_nas_server_port',
                default=8080,
                help='Port number for the EMC server.'),
    cfg.BoolOpt('emc_nas_server_secure',
                default=True,
                help='Use secure connection to server.'),
    cfg.StrOpt('emc_share_backend',
               ignore_case=True,
               choices=['isilon', 'vnx', 'unity', 'vmax', 'powermax'],
               help='Share backend.'),
    cfg.StrOpt('emc_nas_root_dir',
               help='The root directory where shares will be located.'),
    cfg.BoolOpt('emc_ssl_cert_verify',
                default=True,
                help='If set to False the https client will not validate the '
                     'SSL certificate of the backend endpoint.'),
    cfg.StrOpt('emc_ssl_cert_path',
               help='Can be used to specify a non default path to a '
                    'CA_BUNDLE file or directory with certificates of trusted '
                    'CAs, which will be used to validate the backend.')
]

LOG = log.getLogger(__name__)

CONF = cfg.CONF
CONF.register_opts(EMC_NAS_OPTS)


class EMCShareDriver(driver.ShareDriver):
    """EMC specific NAS driver. Allows for NFS and CIFS NAS storage usage."""

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.get('configuration', None)
        if self.configuration:
            self.configuration.append_config_values(EMC_NAS_OPTS)
            self.backend_name = self.configuration.safe_get(
                'emc_share_backend')
        else:
            self.backend_name = CONF.emc_share_backend
        self.backend_name = self.backend_name or 'EMC_NAS_Storage'
        self.plugin_manager = manager.EMCPluginManager(
            namespace='manila.share.drivers.dell_emc.plugins')
        if self.backend_name == 'vmax':
            LOG.warning("Configuration option 'emc_share_backend=vmax' will "
                        "remain a valid option until the V release of "
                        "OpenStack. After that, only "
                        "'emc_share_backend=powermax' will be excepted.")
            self.backend_name = 'powermax'
        self.plugin = self.plugin_manager.load_plugin(
            self.backend_name,
            configuration=self.configuration)
        super(EMCShareDriver, self).__init__(
            self.plugin.driver_handles_share_servers, *args, **kwargs)

        if hasattr(self.plugin, 'ipv6_implemented'):
            self.ipv6_implemented = self.plugin.ipv6_implemented

        if hasattr(self.plugin, 'revert_to_snap_support'):
            self.revert_to_snap_support = self.plugin.revert_to_snap_support
        else:
            self.revert_to_snap_support = False

        if hasattr(self.plugin, 'shrink_share_support'):
            self.shrink_share_support = self.plugin.shrink_share_support
        else:
            self.shrink_share_support = False

        if hasattr(self.plugin, 'manage_existing_support'):
            self.manage_existing_support = self.plugin.manage_existing_support
        else:
            self.manage_existing_support = False

        if hasattr(self.plugin, 'manage_existing_with_server_support'):
            self.manage_existing_with_server_support = (
                self.plugin.manage_existing_with_server_support)
        else:
            self.manage_existing_with_server_support = False

        if hasattr(self.plugin, 'manage_existing_snapshot_support'):
            self.manage_existing_snapshot_support = (
                self.plugin.manage_existing_snapshot_support)
        else:
            self.manage_existing_snapshot_support = False

        if hasattr(self.plugin, 'manage_snapshot_with_server_support'):
            self.manage_snapshot_with_server_support = (
                self.plugin.manage_snapshot_with_server_support)
        else:
            self.manage_snapshot_with_server_support = False

        if hasattr(self.plugin, 'manage_server_support'):
            self.manage_server_support = self.plugin.manage_server_support
        else:
            self.manage_server_support = False

        if hasattr(self.plugin, 'get_share_server_network_info_support'):
            self.get_share_server_network_info_support = (
                self.plugin.get_share_server_network_info_support)
        else:
            self.get_share_server_network_info_support = False

        if hasattr(self.plugin,
                   'choose_share_server_compatible_with_share_group_support'):
            self.choose_share_server_compatible_with_share_group_support = (
                self.plugin
                    .choose_share_server_compatible_with_share_group_support)
        else:
            self.choose_share_server_compatible_with_share_group_support = (
                False)

        if hasattr(self.plugin, 'share_group_replication_support'):
            self.share_group_replication_support = (
                self.plugin.share_group_replication_support)
        else:
            self.share_group_replication_support = False

    def manage_existing(self, share, driver_options):
        """manage an existing share"""
        if self.manage_existing_support:
            return self.plugin.manage_existing(share, driver_options)
        else:
            return NotImplementedError()

    def manage_existing_with_server(self, share, driver_options,
                                    share_server=None):
        """manage an existing share"""
        if self.manage_existing_with_server_support:
            return self.plugin.manage_existing_with_server(
                share, driver_options, share_server)
        else:
            return NotImplementedError()

    def manage_existing_snapshot(self, snapshot, driver_options):
        """manage an existing share snapshot"""
        if self.manage_existing_snapshot_support:
            return self.plugin.manage_existing_snapshot(snapshot,
                                                        driver_options)
        else:
            return NotImplementedError()

    def manage_existing_snapshot_with_server(self, snapshot, driver_options,
                                             share_server=None):
        """manage an existing share snapshot"""
        if self.manage_snapshot_with_server_support:
            return self.plugin.manage_existing_snapshot_with_server(
                snapshot, driver_options, share_server=None)
        else:
            return NotImplementedError()

    def manage_server(self, context, share_server, identifier,
                      driver_options):
        if self.manage_server_support:
            return self.plugin.manage_server(context, share_server,
                                             identifier, driver_options)
        else:
            return NotImplementedError()

    def get_share_server_network_info(
            self, context, share_server, identifier, driver_options):
        if self.get_share_server_network_info_support:
            return self.plugin.get_share_server_network_info(
                context, share_server, identifier, driver_options)
        else:
            return NotImplementedError()

    def unmanage_server(self, server_details, security_services=None):
        LOG.info('Dell EMC driver will unmanage share server: %s out of '
                 'OpenStack.', server_details.get('server_id'))

    def unmanage(self, share):
        LOG.info('Dell EMC driver will unmanage share: %s out of '
                 'OpenStack.', share.get('id'))

    def unmanage_with_server(self, share, share_server=None):
        LOG.info('Dell EMC driver will unmanage share: %s out of '
                 'OpenStack.', share.get('id'))

    def unmanage_snapshot(self, snapshot):
        LOG.info('Dell EMC driver will unmanage snapshot: %s out of '
                 'OpenStack.', snapshot.get('id'))

    def unmanage_snapshot_with_server(self, snapshot, share_server=None):
        LOG.info('Dell EMC driver will unmanage snapshot: %s out of '
                 'OpenStack.', snapshot.get('id'))

    def create_share(self, context, share, share_server=None):
        """Is called to create share."""
        location = self.plugin.create_share(context, share, share_server)

        return location

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Is called to create share from snapshot."""
        location = self.plugin.create_share_from_snapshot(
            context, share, snapshot, share_server)

        return location

    def extend_share(self, share, new_size, share_server=None):
        """Is called to extend share."""
        self.plugin.extend_share(share, new_size, share_server)

    def shrink_share(self, share, new_size, share_server=None):
        """Is called to shrink share."""
        if self.shrink_share_support:
            self.plugin.shrink_share(share, new_size, share_server)
        else:
            raise NotImplementedError()

    def create_snapshot(self, context, snapshot, share_server=None):
        """Is called to create snapshot."""
        return self.plugin.create_snapshot(context, snapshot, share_server)

    def delete_share(self, context, share, share_server=None):
        """Is called to remove share."""
        self.plugin.delete_share(context, share, share_server)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Is called to remove snapshot."""
        self.plugin.delete_snapshot(context, snapshot, share_server)

    def ensure_share(self, context, share, share_server=None):
        """Invoked to sure that share is exported."""
        self.plugin.ensure_share(context, share, share_server)

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        self.plugin.allow_access(context, share, access, share_server)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        self.plugin.deny_access(context, share, access, share_server)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access to the share."""
        self.plugin.update_access(context, share, access_rules, add_rules,
                                  delete_rules, share_server)

    def check_for_setup_error(self):
        """Check for setup error."""
        self.plugin.check_for_setup_error()

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""
        self.plugin.connect(self, context)

    def _update_share_stats(self):
        """Retrieve stats info from share."""

        backend_name = self.configuration.safe_get(
            'share_backend_name') or "EMC_NAS_Storage"
        data = dict(
            share_backend_name=backend_name,
            vendor_name='Dell EMC',
            storage_protocol='NFS_CIFS',
            snapshot_support=True,
            create_share_from_snapshot_support=True,
            revert_to_snapshot_support=self.revert_to_snap_support,
            replication_type=None,
            share_group_stats=dict(
                consistent_snapshot_support=False,
                group_replication_type=None,
            )
        )

        # NOTE(RyanLiang): replication_domain/group_replication_domain will be
        # updated by base's _update_share_stats. Plugins need to report
        # replication_type/group_replication_type by themselves.
        self.plugin.update_share_stats(data)
        super(EMCShareDriver, self)._update_share_stats(data)

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        return self.plugin.get_network_allocations_number()

    def _setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""
        return self.plugin.setup_server(network_info, metadata)

    def _teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        return self.plugin.teardown_server(server_details, security_services)

    def get_configured_ip_versions(self):
        if self.ipv6_implemented:
            return [4, 6]
        else:
            return [4]

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        if self.revert_to_snap_support:
            return self.plugin.revert_to_snapshot(context, snapshot,
                                                  share_access_rules,
                                                  snapshot_access_rules,
                                                  share_server)
        else:
            raise NotImplementedError()

    def choose_share_server_compatible_with_share_group(
            self, context, share_servers, share_group_instance,
            share_group_snapshot=None):
        if self.choose_share_server_compatible_with_share_group_support:
            return self.plugin.choose_share_server_compatible_with_share_group(
                context, share_servers, share_group_instance,
                share_group_snapshot=share_group_snapshot,
            )
        else:
            return super(EMCShareDriver, self
                         ).choose_share_server_compatible_with_share_group(
                context, share_servers, share_group_instance,
                share_group_snapshot=share_group_snapshot,
            )

    def create_share_group_replica(self, context,
                                   group_replica_creating, group_replicas_all,
                                   share_replicas_creating, share_replicas_all,
                                   share_access_rules_dict,
                                   group_replica_snapshots,
                                   share_replica_snapshots,
                                   share_server=None,
                                   share_server_network_info=None):
        """Creates a share group replica.

        This call is made on the host that hosts the replica being created.
        Refer to the method of ``ShareDriver`` for parameters detail.
        """
        if self.share_group_replication_support:
            return self.plugin.create_share_group_replica(
                context, group_replica_creating, group_replicas_all,
                share_replicas_creating, share_replicas_all,
                share_access_rules_dict, group_replica_snapshots,
                share_replica_snapshots, share_server=share_server,
                share_server_network_info=share_server_network_info)
        else:
            return super(EMCShareDriver, self).create_share_group_replica(
                context, group_replica_creating, group_replicas_all,
                share_replicas_creating, share_replicas_all,
                share_access_rules_dict, group_replica_snapshots,
                share_replica_snapshots, share_server=share_server,
                share_server_network_info=share_server_network_info)

    def delete_share_group_replica(self, context,
                                   group_replica_deleting, group_replicas_all,
                                   share_replicas_deleting, share_replicas_all,
                                   group_replica_snapshots,
                                   share_replica_snapshots,
                                   share_server=None):
        """Deletes a share group replica.

        This call is made on the host that hosts the replica being deleted.
        Refer to the method of ``ShareDriver`` for parameters detail.
        """
        if self.share_group_replication_support:
            return self.plugin.delete_share_group_replica(
                context, group_replica_deleting, group_replicas_all,
                share_replicas_deleting, share_replicas_all,
                group_replica_snapshots, share_replica_snapshots,
                share_server=share_server)
        else:
            return super(EMCShareDriver, self).delete_share_group_replica(
                context, group_replica_deleting, group_replicas_all,
                share_replicas_deleting, share_replicas_all,
                group_replica_snapshots, share_replica_snapshots,
                share_server=share_server)

    def promote_share_group_replica(self, context,
                                    group_replica_promoting,
                                    group_replicas_all,
                                    share_replicas_promoting,
                                    share_replicas_all,
                                    share_access_rules_dict,
                                    share_server=None):
        """Promotes a share group replica to active state.

        This call is made on the host that hosts the replica being promoted.
        Refer to the method of ``ShareDriver`` for parameters detail.
        """
        if self.share_group_replication_support:
            return self.plugin.promote_share_group_replica(
                context, group_replica_promoting, group_replicas_all,
                share_replicas_promoting, share_replicas_all,
                share_access_rules_dict, share_server=share_server)
        else:
            return super(EMCShareDriver, self).promote_share_group_replica(
                context, group_replica_promoting, group_replicas_all,
                share_replicas_promoting, share_replicas_all,
                share_access_rules_dict, share_server=share_server)

    def update_share_group_replica_state(self, context,
                                         group_replica_updating,
                                         group_replicas_all,
                                         share_replicas_updating,
                                         share_replicas_all,
                                         share_access_rules_dict,
                                         group_replica_snapshots,
                                         share_replica_snapshots,
                                         share_server=None):
        """Updates a share group replica's replica state.

        This call is made on the host that hosts the replica being updated.
        Refer to the method of ``ShareDriver`` for parameters detail.
        """
        if self.share_group_replication_support:
            return self.plugin.update_share_group_replica_state(
                context, group_replica_updating, group_replicas_all,
                share_replicas_updating, share_replicas_all,
                share_access_rules_dict, group_replica_snapshots,
                share_replica_snapshots, share_server=share_server)
        else:
            return super(EMCShareDriver,
                         self).update_share_group_replica_state(
                context, group_replica_updating, group_replicas_all,
                share_replicas_updating, share_replicas_all,
                share_access_rules_dict, group_replica_snapshots,
                share_replica_snapshots, share_server=share_server)

    def create_replicated_share_group_snapshot(self, context,
                                               group_replicas_all,
                                               group_replica_snapshots,
                                               share_replicas_all,
                                               share_replica_snapshots,
                                               share_server=None):
        """Creates a share group snapshot on active share group replica and

        update across all replicas.

        This call is made on the 'active' share group replica's host.
        Drivers are expected to transfer the snapshot created to the
        respective replicas.
        """
        if self.share_group_replication_support:
            return self.plugin.create_replicated_share_group_snapshot(
                context, group_replicas_all, group_replica_snapshots,
                share_replicas_all, share_replica_snapshots,
                share_server=share_server)
        else:
            return super(EMCShareDriver,
                         self).create_replicated_share_group_snapshot(
                context, group_replicas_all, group_replica_snapshots,
                share_replicas_all, share_replica_snapshots,
                share_server=share_server)

    def delete_replicated_share_group_snapshot(self, context,
                                               group_replicas_all,
                                               group_replica_snapshots,
                                               share_replicas_all,
                                               share_replica_snapshots,
                                               share_server=None):
        """Deletes a share group snapshot by deleting its instances across

        the replicas.

        This call is made on the 'active' share group replica's host, since
        drivers may not be able to delete the snapshot from an individual
        replica.
        """
        if self.share_group_replication_support:
            return self.plugin.delete_replicated_share_group_snapshot(
                context, group_replicas_all, group_replica_snapshots,
                share_replicas_all, share_replica_snapshots,
                share_server=share_server)
        else:
            return super(EMCShareDriver,
                         self).delete_replicated_share_group_snapshot(
                context, group_replicas_all, group_replica_snapshots,
                share_replicas_all, share_replica_snapshots,
                share_server=share_server)

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
        """Updates the status of a share group snapshot instance that lives on

        a share group replica.

        This call is made on the share group replica's host and not the
        'active' share group replica's host.
        """
        if self.share_group_replication_support:
            return self.plugin.update_replicated_share_group_snapshot(
                context, group_replica, group_replicas_all,
                group_replica_snap_updating, group_replica_snaps_all,
                share_replicas, share_replicas_all,
                share_replica_snaps_updating, share_replica_snaps_all,
                share_server=share_server)
        else:
            return super(EMCShareDriver,
                         self).update_replicated_share_group_snapshot(
                context, group_replica, group_replicas_all,
                group_replica_snap_updating, group_replica_snaps_all,
                share_replicas, share_replicas_all,
                share_replica_snaps_updating, share_replica_snaps_all,
                share_server=share_server)
