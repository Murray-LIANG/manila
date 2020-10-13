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
from distutils import version
import six
import time

from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils

storops = importutils.try_import('storops')
if storops:
    # pylint: disable=import-error
    from storops import exception as storops_ex
    from storops.unity import enums

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.common.enas import utils as enas_utils
from manila.share.drivers.dell_emc.plugins.unity import utils
from manila import utils as manila_utils

LOG = log.getLogger(__name__)

# TODO(RyanLiang): delete it.
NAME_PREFIX_DR_NAS_SERVER = 'OS-DR_'


class UnityClient(object):
    def __init__(self, host, username, password):
        if storops is None:
            LOG.error('StorOps is required to run EMC Unity driver.')
        self.system = storops.UnitySystem(host, username, password)
        self.unity_host = host

    def create_cifs_share(self, resource, share_name):
        """Create CIFS share from the resource.

        :param resource: either UnityFilesystem or UnitySnap object
        :param share_name: CIFS share name
        :return: UnityCifsShare object
        """
        try:
            share = resource.create_cifs_share(share_name)
            try:
                # bug on unity: the enable ace API has bug for snap
                # based share.  Log the internal error if it happens.
                share.enable_ace()
            except storops_ex.UnityException:
                msg = ('Failed to enabled ACE for share: {}.')
                LOG.exception(msg.format(share_name))
            return share
        except storops_ex.UnitySmbShareNameExistedError:
            return self.get_share(share_name, 'CIFS')

    def create_nfs_share(self, resource, share_name):
        """Create NFS share from the resource.

        :param resource: either UnityFilesystem or UnitySnap object
        :param share_name: NFS share name
        :return: UnityNfsShare object
        """
        try:
            return resource.create_nfs_share(share_name)
        except storops_ex.UnityNfsShareNameExistedError:
            return self.get_share(share_name, 'NFS')

    def create_nfs_filesystem_and_share(self, pool, nas_server,
                                        share_name, size_gb):
        """Create filesystem and share from pool/NAS server.

        :param pool: pool for file system creation
        :param nas_server: nas server for file system creation
        :param share_name: file system and share name
        :param size_gb: file system size
        """
        size = utils.gib_to_byte(size_gb)
        pool.create_nfs_share(
            nas_server, share_name, size, user_cap=True)

    def get_share(self, name, share_proto):
        # Validate the share protocol
        proto = share_proto.upper()

        if proto == 'CIFS':
            return self.system.get_cifs_share(name=name)
        elif proto == 'NFS':
            return self.system.get_nfs_share(name=name)
        else:
            raise exception.BadConfigurationException(
                reason=_('Invalid NAS protocol supplied: %s.') % share_proto)

    @staticmethod
    def delete_share(share):
        share.delete()

    def create_filesystem(self, pool, nas_server, share_name, size_gb, proto):
        try:
            size = utils.gib_to_byte(size_gb)
            return pool.create_filesystem(nas_server,
                                          share_name,
                                          size,
                                          proto=proto,
                                          user_cap=True)
        except storops_ex.UnityFileSystemNameAlreadyExisted:
            LOG.debug('Filesystem %s already exists, '
                      'ignoring filesystem creation.', share_name)
            return self.system.get_filesystem(name=share_name)

    @staticmethod
    def delete_filesystem(filesystem, force_snap_delete=False):
        try:
            filesystem.delete(force_snap_delete=force_snap_delete)
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('Filesystem %s is already removed.', filesystem.name)

    @manila_utils.retry(storops_ex.UnityDeleteResourceInReplicationError,
                        interval=3, retries=3)
    def delete_filesystem_wait_replication_deletion(self, filesystem):
        self.delete_filesystem(filesystem, force_snap_delete=True)

    def create_nas_server(self, name, sp, pool, tenant=None):
        try:
            return self.system.create_nas_server(name, sp, pool,
                                                 tenant=tenant)
        except storops_ex.UnityNasServerNameUsedError:
            LOG.info('Share server %s already exists, ignoring share '
                     'server creation.', name)
            return self.get_nas_server(name)

    def get_nas_server(self, name):
        try:
            return self.system.get_nas_server(name=name)
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('NAS server %s not found.', name)
            raise

    def delete_nas_server(self, name, username=None, password=None):
        tenant = None
        try:
            nas_server = self.get_nas_server(name=name)
            tenant = nas_server.tenant
            nas_server.delete(username=username, password=password)
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('NAS server %s not found.', name)

        if tenant is not None:
            self._delete_tenant(tenant)

    @staticmethod
    def _delete_tenant(tenant):
        if tenant.nas_servers:
            LOG.debug('There are NAS servers belonging to the tenant %s. '
                      'Do not delete it.',
                      tenant.get_id())
            return
        try:
            tenant.delete(delete_hosts=True)
        except storops_ex.UnityException as ex:
            LOG.warning('Delete tenant %(tenant)s failed with error: '
                        '%(ex)s. Leave the tenant on the system.',
                        {'tenant': tenant.get_id(),
                         'ex': ex})

    @manila_utils.retry(storops_ex.UnityDeleteResourceInReplicationError,
                        interval=3, retries=3)
    def delete_nas_server_wait_replication_deletion(self, name):
        self.delete_nas_server(name)

    @staticmethod
    def create_dns_server(nas_server, domain, dns_ip):
        try:
            nas_server.create_dns_server(domain, dns_ip)
        except storops_ex.UnityOneDnsPerNasServerError:
            LOG.info('DNS server %s already exists, '
                     'ignoring DNS server creation.', domain)

    @staticmethod
    def create_interface(nas_server, ip_addr, netmask, gateway, port_id,
                         vlan_id=None, prefix_length=None):
        try:
            nas_server.create_file_interface(port_id,
                                             ip_addr,
                                             netmask=netmask,
                                             v6_prefix_length=prefix_length,
                                             gateway=gateway,
                                             vlan_id=vlan_id)
        except storops_ex.UnityIpAddressUsedError:
            raise exception.IPAddressInUse(ip=ip_addr)

    @staticmethod
    def enable_cifs_service(nas_server, domain, username, password):
        try:
            nas_server.enable_cifs_service(
                nas_server.file_interface,
                domain=domain,
                domain_username=username,
                domain_password=password)
        except storops_ex.UnitySmbNameInUseError:
            LOG.info('CIFS service on NAS server %s is '
                     'already enabled.', nas_server.name)

    @staticmethod
    def enable_nfs_service(nas_server):
        try:
            nas_server.enable_nfs_service()
        except storops_ex.UnityNfsAlreadyEnabledError:
            LOG.info('NFS service on NAS server %s is '
                     'already enabled.', nas_server.name)

    @staticmethod
    def create_snapshot(filesystem, name, replicated_to=None):
        access_type = enums.FilesystemSnapAccessTypeEnum.CHECKPOINT
        try:
            return filesystem.create_snap(name, fs_access_type=access_type,
                                          replicated_to=replicated_to)
        except storops_ex.UnitySnapNameInUseError:
            LOG.info('Snapshot %(snap)s on Filesystem %(fs)s already '
                     'exists.', {'snap': name, 'fs': filesystem.name})

    def create_snap_of_snap(self, src_snap, dst_snap_name):
        if isinstance(src_snap, six.string_types):
            snap = self.get_snapshot(name=src_snap)
        else:
            snap = src_snap

        try:
            return snap.create_snap(dst_snap_name)
        except storops_ex.UnitySnapNameInUseError:
            return self.get_snapshot(dst_snap_name)

    def get_snapshot(self, name=None):
        return self.system.get_snap(name=name)

    @staticmethod
    def delete_snapshot(snap):
        try:
            snap.delete()
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('Snapshot %s is already removed.', snap.name)

    def get_pool(self, name=None):
        return self.system.get_pool(name=name)

    def get_storage_processor(self, sp_id=None):
        sp = self.system.get_sp(sp_id)
        if sp_id is None:
            # `sp` is a list of SPA and SPB.
            return [s for s in sp if s is not None and s.existed]
        else:
            return sp if sp.existed else None

    def cifs_clear_access(self, share_name, white_list=None):
        share = self.system.get_cifs_share(name=share_name)
        share.clear_access(white_list)

    def nfs_clear_access(self, share_name, white_list=None):
        share = self.system.get_nfs_share(name=share_name)
        share.clear_access(white_list, force_create_host=True)

    def cifs_allow_access(self, share_name, user_name, access_level):
        share = self.system.get_cifs_share(name=share_name)

        if access_level == const.ACCESS_LEVEL_RW:
            cifs_access = enums.ACEAccessLevelEnum.WRITE
        else:
            cifs_access = enums.ACEAccessLevelEnum.READ

        share.add_ace(user=user_name, access_level=cifs_access)

    def nfs_allow_access(self, share_name, host_ip, access_level):
        share = self.system.get_nfs_share(name=share_name)
        host_ip = enas_utils.convert_ipv6_format_if_needed(host_ip)
        if access_level == const.ACCESS_LEVEL_RW:
            share.allow_read_write_access(host_ip, force_create_host=True)
            share.allow_root_access(host_ip, force_create_host=True)
        else:
            share.allow_read_only_access(host_ip, force_create_host=True)

    def cifs_deny_access(self, share_name, user_name):
        share = self.system.get_cifs_share(name=share_name)

        try:
            share.delete_ace(user=user_name)
        except storops_ex.UnityAclUserNotFoundError:
            LOG.debug('ACL User "%(user)s" does not exist.',
                      {'user': user_name})

    def nfs_deny_access(self, share_name, host_ip):
        share = self.system.get_nfs_share(name=share_name)

        try:
            share.delete_access(host_ip)
        except storops_ex.UnityHostNotFoundException:
            LOG.info('%(host)s access to %(share)s is already removed.',
                     {'host': host_ip, 'share': share_name})

    def get_file_ports(self):
        ports = self.system.get_file_port()
        link_up_ports = []
        for port in ports:
            if port.is_link_up and self._is_external_port(port.id):
                link_up_ports.append(port)

        return link_up_ports

    def extend_filesystem(self, fs, new_size_gb):
        size = utils.gib_to_byte(new_size_gb)
        try:
            fs.extend(size, user_cap=True)
        except storops_ex.UnityNothingToModifyError:
            LOG.debug('The size of the file system %(id)s is %(size)s '
                      'bytes.', {'id': fs.get_id(), 'size': size})
        return size

    def shrink_filesystem(self, share_id, fs, new_size_gb):
        size = utils.gib_to_byte(new_size_gb)
        try:
            fs.shrink(size, user_cap=True)
        except storops_ex.UnityNothingToModifyError:
            LOG.debug('The size of the file system %(id)s is %(size)s '
                      'bytes.', {'id': fs.get_id(), 'size': size})
        except storops_ex.UnityShareShrinkSizeTooSmallError:
            LOG.error('The used size of the file system %(id)s is '
                      'bigger than input shrink size,'
                      'it may cause date loss.', {'id': fs.get_id()})
            raise exception.ShareShrinkingPossibleDataLoss(share_id=share_id)
        return size

    @staticmethod
    def _is_external_port(port_id):
        return 'eth' in port_id or '_la' in port_id

    def get_tenant(self, name, vlan_id):
        if not vlan_id:
            # Do not create vlan for flat network
            return None

        tenant = None
        try:
            tenant_name = "vlan_%(vlan_id)s_%(name)s" % {'vlan_id': vlan_id,
                                                         'name': name}
            tenant = self.system.create_tenant(tenant_name, vlans=[vlan_id])
        except (storops_ex.UnityVLANUsedByOtherTenantError,
                storops_ex.UnityTenantNameInUseError,
                storops_ex.UnityVLANAlreadyHasInterfaceError):
            with excutils.save_and_reraise_exception() as exc:
                tenant = self.system.get_tenant_use_vlan(vlan_id)
                if tenant is not None:
                    LOG.debug("The VLAN %s is already added into a tenant. "
                              "Use the existing VLAN tenant.", vlan_id)
                    exc.reraise = False
        except storops_ex.SystemAPINotSupported:
            LOG.info("This system doesn't support tenant.")

        return tenant

    def restore_snapshot(self, snap_name):
        snap = self.get_snapshot(snap_name)
        return snap.restore(delete_backup=True)

    def _get_nas_server_with_rep_role(self, name, role):
        """Gets nas server with specified replication role.

        :param name: could be xxx or OS-DR_xxx.
        :param role: could be `active` or `dr`.
        """
        # TODO(RyanLiang): delete it
        if name.startswith(NAME_PREFIX_DR_NAS_SERVER):
            dr_name = name
            active_name = name[len(NAME_PREFIX_DR_NAS_SERVER):]
        else:
            dr_name = NAME_PREFIX_DR_NAS_SERVER + name
            active_name = name

        def _is_role_match(s):
            if role == 'active':
                return not s.is_replication_destination
            else:
                return s.is_replication_destination

        nas_server = None
        for name in [active_name, dr_name]:
            try:
                nas_server = self.get_nas_server(name)
                if _is_role_match(nas_server):
                    break
                else:
                    LOG.debug('Nas server with name %(name)s found but not '
                              '%(role)s.', {'name': name, 'role': role})
                    nas_server = None
            except storops_ex.UnityResourceNotFoundError:
                LOG.debug(
                    'Nas server with name %(name)s not found. Will try '
                    'another name %(alt)s.',
                    {'name': name,
                     'alt': dr_name if name == active_name else active_name})

        if not nas_server:
            raise exception.EMCUnityError(
                err='No %(role)s nas server found with any name in '
                    '%(names)s.' % {'role': role, 'names': (active_name, name)}
            )
        LOG.debug('Nas server: name=%(name)s,role=%(role)s returned.',
                  {'name': nas_server.name, 'role': role})
        return nas_server

    def get_active_nas_server(self, name):
        """Returns the active nas server.

        For the nas server involved in a local replication, the name of the
        active nas server could be xxx or OS-DR_xxx.
        """
        # TODO(RyanLiang): delete it
        # return self._get_nas_server_with_rep_role(name, 'active')

    def get_dr_nas_server(self, name):
        """Returns the dr nas server.

        For the nas server involved in a local replication, the name of the
        dr nas server could be xxx or OS-DR_xxx. Try OS-DR_xxx first.
        """
        # TODO(RyanLiang): delete it
        # return self._get_nas_server_with_rep_role(name, 'dr')

    def get_serial_number(self):
        return self.system.serial_number

    def get_remote_system(self, name):
        return self.system.get_remote_system(name=name)

    def is_local_replication(self, dr_client):
        return self.get_serial_number() == dr_client.get_serial_number()

    @staticmethod
    def _zip_active_dr_filesystems(active_filesystems, dr_filesystems):
        return zip(sorted(active_filesystems or [], key=lambda fs: fs.name),
                   sorted(dr_filesystems or [], key=lambda fs: fs.name))

    @staticmethod
    def _get_fs_replications(active_nas_server, dr_nas_server, remote_system):
        fs_reps = {}
        for active_fs, dr_fs in UnityClient._zip_active_dr_filesystems(
                active_nas_server.filesystems, dr_nas_server.filesystems):
            try:
                fs_reps[active_fs.name] = active_fs.get_replications(
                    remote_system=remote_system, dst_filesystem=dr_fs)[0]
            except IndexError:
                LOG.info('Replication session not exist from fs %(src)s to '
                         'fs %(dst)s on unity %(remote)s.',
                         {'src': active_fs.name, 'dst': dr_fs.name,
                          'remote': remote_system.name})
        return fs_reps

    def _get_dr_nas_server_name(self, dr_client, active_nas_server_name):
        # 1) For nas server in local replication, if source's name is xxx, then
        # destination's name is OS-DR_xxx, otherwise, source's name is
        # OS-DR_xxx, and destination's name is xxx.
        # 2) For nas server in remote replication, the name of source and
        # destination is the same.
        # TODO(RyanLiang): delete it
        if self.is_local_replication(dr_client):
            prefix = NAME_PREFIX_DR_NAS_SERVER
            return (active_nas_server_name[len(prefix):]
                    if active_nas_server_name.startswith(prefix)
                    else (prefix + active_nas_server_name))
        return active_nas_server_name

    def enable_replication(self, dr_client, active_nas_server_name,
                           dr_nas_server_name, max_out_of_sync_minutes,
                           dr_pool_name=None, dr_new_ip_addr=None,
                           reuse_dr_resources=False):
        """Enables the nas server replication from this client to dr_client.

        dr_pool_name could be None only when reuse_dr_resources=True and there
        is an existing nas server and/or filesystem usable.

        dr_client could connect to the same Unity for local replications.

        reuse_dr_resources will be ignored by storops when Unity OE is prior to
        5.1.0.
        """
        active_nas_server = self.get_nas_server(active_nas_server_name)
        dr_pool_id = None
        if dr_pool_name:
            dr_pool_id = dr_client.get_pool(name=dr_pool_name).get_id()
        remote_system = None
        dst_sp = None
        if not self.is_local_replication(dr_client):
            remote_system = self.get_remote_system(
                dr_client.get_serial_number())
            # Required for remote replications.
            dst_sp = active_nas_server.home_sp.to_node_enum()
        active_filesystems = active_nas_server.filesystems or []
        nas_rep = active_nas_server.replicate_with_dst_resource_provisioning(
            max_out_of_sync_minutes, dst_pool_id=dr_pool_id,
            dst_nas_server_name=dr_nas_server_name,
            remote_system=remote_system, dst_sp=dst_sp,
            filesystems=active_filesystems,
            reuse_dst_resource=reuse_dr_resources,
        )

        # Manual sync the nas server replication session to make sure the share
        # is created on the destination system.
        nas_rep.sync()

        dr_nas_server = dr_client.get_nas_server(dr_nas_server_name)

        # The file interface on the destination nas server will be the same as
        # the source's. Need to override it using its expected ip address.
        if dr_new_ip_addr:
            dr_nas_server.file_interface[0].modify(ip=dr_new_ip_addr)

        return nas_rep, self._get_fs_replications(active_nas_server,
                                                  dr_nas_server, remote_system)

    def disable_replication(self, dr_client, active_nas_server_name,
                            dr_nas_server_name, keep_dr_resources=False):
        """Disables the nas server replication."""
        try:
            dr_nas_server = dr_client.get_nas_server(dr_nas_server_name)
        except storops_ex.UnityResourceNotFoundError:
            LOG.warning('DR side nas server %s not found. Skipping '
                        'deleting this replication and all related filesystem '
                        'replications, nas server, filesystems, shares '
                        'from DR Unity.',
                        dr_nas_server_name)
            return
        except storops_ex.StoropsConnectTimeoutError:
            LOG.warning('DR Unity %s is down. Skipping deleting this '
                        'replication and all related filesystem replications, '
                        'nas server, filesystems shares from DR Unity.',
                        dr_client.unity_host)
            return

        try:
            active_nas_server = self.get_nas_server(active_nas_server_name)

            remote_system = self.get_remote_system(
                dr_client.get_serial_number())

            # Delete the replication sessions on filesystems.
            for active_fs, dr_fs in self._zip_active_dr_filesystems(
                    active_nas_server.filesystems, dr_nas_server.filesystems):
                active_fs.delete_replications(remote_system=remote_system,
                                              dst_filesystem=dr_fs)

            # Delete the replication session on nas server.
            active_nas_server.delete_replications(remote_system=remote_system,
                                                  dst_nas_server=dr_nas_server)

        except storops_ex.StoropsConnectTimeoutError:
            LOG.info('Active Unity %s is down. Unable to disable the '
                     'replication from the active side. Deleting the '
                     'replication and all related filesystem replications, '
                     'nas server, filesystems shares from DR Unity.',
                     'without sync', self.unity_host)

            for dr_fs in (dr_nas_server.filesystems or []):
                # It's safe because there must be only one replications to the
                # dr filesystem.
                dr_fs.delete_replications()

            # It's safe because there must be only one replications to the
            # dr nas server.
            dr_nas_server.delete_replications()

        if not keep_dr_resources:
            # Delete dr side filesystems then nas server. No need to delete the
            # shares on the dr destination nas server. They will be deleted
            # together with filesystems.
            for fs in (dr_nas_server.filesystems or []):
                dr_client.delete_filesystem_wait_replication_deletion(fs)
            dr_client.delete_nas_server_wait_replication_deletion(
                dr_nas_server_name)

        # Return this information for replication rebuild.
        return {'dr_pool': dr_nas_server.pool,
                'dr_file_interface': dr_nas_server.file_interface[0]}

    def failover_replication(self, dr_client, active_nas_server_name,
                             dr_nas_server_name):
        try:
            # Planned fail over which fails over with sync from active side.
            active_nas_server = self.get_nas_server(active_nas_server_name)
            remote_system = self.get_remote_system(
                dr_client.get_serial_number())
            dr_nas_server = dr_client.get_nas_server(dr_nas_server_name)

            rep_session = active_nas_server.get_replications(
                remote_system=remote_system, dst_nas_server=dr_nas_server)[0]

            rep_session.failover(sync=True)

            # Resume can only be done on the original dr side.
            rep_session = dr_client.system.get_replication_sessions(
                _id=rep_session.get_id())
            rep_session.resume()

        except storops_ex.StoropsConnectTimeoutError:
            # Unplanned fail over which fails over without sync from dr side.
            # Because the active side is down.
            LOG.info('Active Unity %s is down. Unable to fail over the '
                     'replication with sync. Using unplanned fail over '
                     'without sync', self.unity_host)

            # Cannot use active_nas_server or other resources of active side
            # which is down.
            dr_nas_server = dr_client.get_nas_server(dr_nas_server_name)
            rep_session = dr_client.system.get_replication_sessions(
                dst_resource_id=dr_nas_server.get_id())[0]
            rep_session.failover(sync=False)
            rep_session.resume()

    def rebuild_replication(self, new_active_nas_name,
                            dr_client, dr_nas_server_name,
                            orig_active_client, orig_active_nas_name,
                            max_out_of_sync_minutes, only_tear_down=False):
        """Rebuilds the replication for DR nas server.

        The DR nas server with name=`dr_nas_server_name` is with replication
        from the original active nas server with name=`orig_active_nas_name` on
        the Unity to which `orig_active_client` is connecting before
        rebuilding. The rebuild will tear down the original replication and
        build up a new one from the nas server with name=`new_active_nas_name`
        on the Unity to which `self` is connecting.
        """
        dr_resource = orig_active_client.disable_replication(
            dr_client, orig_active_nas_name, dr_nas_server_name,
            keep_dr_resources=self.is_unity_version('5.1.0'))

        if only_tear_down:
            return

        if self.is_unity_version('5.1.0'):
            self.enable_replication(
                dr_client, new_active_nas_name, dr_nas_server_name,
                max_out_of_sync_minutes, reuse_dr_resources=True)
        else:
            self.enable_replication(
                dr_client, new_active_nas_name, dr_nas_server_name,
                max_out_of_sync_minutes,
                dr_pool_name=dr_resource['dr_pool'].name,
                dr_new_ip_addr=dr_resource['dr_file_interface'].ip_address)

    def get_nas_server_and_fs_replications(self, dr_client,
                                           active_nas_server_name,
                                           dr_nas_server_name):
        try:
            active_nas_server = self.get_nas_server(active_nas_server_name)
        except storops_ex.StoropsConnectTimeoutError:
            LOG.info('Active Unity %s is down. Cannot get the replication '
                     'sessions.', self.unity_host)
            return None, None

        dr_nas_server = dr_client.get_nas_server(dr_nas_server_name)
        remote_system = self.get_remote_system(dr_client.get_serial_number())
        try:
            nas_server_rep = active_nas_server.get_replications(
                remote_system=remote_system, dst_nas_server=dr_nas_server)[0]
        except IndexError:
            LOG.info('Replication session not exist from nas server '
                     '%(active)s to nas server %(dr)s on unity %(remote)s.',
                     {'active': active_nas_server.name,
                      'dr': dr_nas_server_name,
                      'remote': remote_system.name})
            return None, None

        return nas_server_rep, self._get_fs_replications(active_nas_server,
                                                         dr_nas_server,
                                                         remote_system)

    def get_replicated_snapshot(self, name, is_local_replication):
        """Gets the replicated filesystem snapshot.

        :param name: the replicated snapshot's name is the same as the source's
            for remote replicated filesystems. But the replicated snapshot's
            name could be <fake-uuid>_20200907020101 while the source's is
            <fake-uuid> for local replicated filesystems. This parameter `name`
            is <fake-uuid> part. It's safe because it's UUID.
        :return: the replicated snapshot with name <fake-uuid> or
            <fake-uuid>_20200907020101.
        """
        @manila_utils.retry(storops_ex.UnityResourceNotFoundError,
                            interval=3, retries=3)
        def _get_with_retry(name):
            # Could raise `UnityResourceNotFoundError` when the replicated
            # snapshot doesn't appear.

            if is_local_replication:
                name = name + '_'
                snaps = [snap for snap in self.get_snapshot()
                         if snap['name'].startswith(name)]
                if len(snaps) != 1:
                    raise exception.EMCUnityError(
                        err='There should be only one snapshot starting with '
                            'name %(name)s, but %(count)s '
                            'found.' % {'name': name, 'count': len(snaps)})
                return snaps[0]
            else:
                return self.get_snapshot(name)

        return _get_with_retry(name)

    def is_unity_version(self, min_version, max_version=None):
        """Returns True if min_version <= Unity OE version < max_version."""
        curr_version = self.system.system_version
        return (version.LooseVersion(min_version)
                <= version.LooseVersion(curr_version)
                and (not max_version or
                     version.LooseVersion(curr_version)
                     < version.LooseVersion(max_version)))
