# Copyright (c) 2015 Alex Meade
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
Handles all requests relating to share groups.
"""

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import strutils
from oslo_utils import timeutils
import six

from manila.common import constants
from manila.db import base
from manila import exception
from manila.i18n import _
from manila import quota
from manila.scheduler import rpcapi as scheduler_rpcapi
from manila import share
from manila.share import rpcapi as share_rpcapi
from manila.share import share_types

CONF = cfg.CONF
LOG = log.getLogger(__name__)
QUOTAS = quota.QUOTAS


class API(base.Base):
    """API for interacting with the share manager."""

    def __init__(self, db_driver=None):
        self.scheduler_rpcapi = scheduler_rpcapi.SchedulerAPI()
        self.share_rpcapi = share_rpcapi.ShareAPI()
        self.share_api = share.API()
        super(API, self).__init__(db_driver)

    def create(self, context, name=None, description=None,
               share_type_ids=None, source_share_group_snapshot_id=None,
               share_network_id=None, share_group_type_id=None,
               availability_zone_id=None, availability_zone=None):
        """Create new share group."""

        share_group_snapshot = None
        original_share_group = None
        # NOTE(gouthamr): share_server_id is inherited from the
        # parent share group if a share group snapshot is specified,
        # else, it will be set in the share manager.
        share_server_id = None
        source_share_group_snapshot_instance_id = None
        if source_share_group_snapshot_id:
            share_group_snapshot = self.db.share_group_snapshot_get(
                context, source_share_group_snapshot_id)
            if share_group_snapshot['status'] != constants.STATUS_AVAILABLE:
                msg = (_("Share group snapshot status must be %s.")
                       % constants.STATUS_AVAILABLE)
                raise exception.InvalidShareGroupSnapshot(reason=msg)

            # TODO(RyanLiang): lock the source share group when the new group
            # is created from it. Or `share_group_snapshot.instance` would be
            # incorrect when the source share group is undergoing failover.
            source_share_group_snapshot_instance_id = (
                share_group_snapshot.instance['id'])
            original_share_group = self.db.share_group_get(
                context, share_group_snapshot['share_group_id'])
            share_type_ids = [
                s['share_type_id']
                for s in original_share_group['share_types']]
            share_network_id = original_share_group['share_network_id']
            share_server_id = original_share_group['share_server_id']
            availability_zone_id = original_share_group['availability_zone_id']

        # Get share_type_objects
        share_type_objects = []
        driver_handles_share_servers = None
        for share_type_id in (share_type_ids or []):
            try:
                share_type_object = share_types.get_share_type(
                    context, share_type_id)
            except exception.ShareTypeNotFound:
                msg = _("Share type with id %s could not be found.")
                raise exception.InvalidInput(msg % share_type_id)
            share_type_objects.append(share_type_object)

            extra_specs = share_type_object.get('extra_specs')
            if extra_specs:
                share_type_handle_ss = strutils.bool_from_string(
                    extra_specs.get(
                        constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS))
                if driver_handles_share_servers is None:
                    driver_handles_share_servers = share_type_handle_ss
                elif not driver_handles_share_servers == share_type_handle_ss:
                    # NOTE(ameade): if the share types have conflicting values
                    #  for driver_handles_share_servers then raise bad request
                    msg = _("The specified share_types cannot have "
                            "conflicting values for the "
                            "driver_handles_share_servers extra spec.")
                    raise exception.InvalidInput(reason=msg)

                if (not share_type_handle_ss) and share_network_id:
                    msg = _("When using a share types with the "
                            "driver_handles_share_servers extra spec as "
                            "False, a share_network_id must not be provided.")
                    raise exception.InvalidInput(reason=msg)

        try:
            if share_network_id:
                self.db.share_network_get(context, share_network_id)
        except exception.ShareNetworkNotFound:
            msg = _("The specified share network does not exist.")
            raise exception.InvalidInput(reason=msg)

        if (driver_handles_share_servers and
                not (source_share_group_snapshot_id or share_network_id)):
            msg = _("When using a share type with the "
                    "driver_handles_share_servers extra spec as "
                    "True, a share_network_id must be provided.")
            raise exception.InvalidInput(reason=msg)

        try:
            share_group_type = self.db.share_group_type_get(
                context, share_group_type_id)
        except exception.ShareGroupTypeNotFound:
            msg = _("The specified share group type %s does not exist.")
            raise exception.InvalidInput(reason=msg % share_group_type_id)

        supported_share_types = set(
            [x['share_type_id'] for x in share_group_type['share_types']])
        supported_share_type_objects = [
            share_types.get_share_type(context, share_type_id) for
            share_type_id in supported_share_types
        ]

        if not set(share_type_ids or []) <= supported_share_types:
            msg = _("The specified share types must be a subset of the share "
                    "types supported by the share group type.")
            raise exception.InvalidInput(reason=msg)

        # Grab share type AZs for scheduling
        share_types_of_new_group = (
            share_type_objects or supported_share_type_objects
        )
        stype_azs_of_new_group = []
        stypes_unsupported_in_az = []
        for stype in share_types_of_new_group:
            stype_azs = stype.get('extra_specs', {}).get(
                'availability_zones', '')
            if stype_azs:
                stype_azs = stype_azs.split(',')
                stype_azs_of_new_group.extend(stype_azs)
                if availability_zone and availability_zone not in stype_azs:
                    # If an AZ is requested, it must be supported by the AZs
                    # configured in each of the share types requested
                    stypes_unsupported_in_az.append((stype['name'],
                                                     stype['id']))

        if stypes_unsupported_in_az:
            msg = _("Share group cannot be created since the following share "
                    "types are not supported within the availability zone "
                    "'%(az)s': (%(stypes)s)")
            payload = {'az': availability_zone, 'stypes': ''}
            for type_name, type_id in set(stypes_unsupported_in_az):
                if payload['stypes']:
                    payload['stypes'] += ', '
                type_name = '%s ' % (type_name or '')
            payload['stypes'] += type_name + '(ID: %s)' % type_id
            raise exception.InvalidInput(reason=msg % payload)

        share_replication_type_dict = {
            '{name}(ID: {id})'.format(name=st['name'], id=st['id']):
                st.get('extra_specs', {}).get('replication_type', None)
            for st in share_types_of_new_group}
        share_replication_types = set(share_replication_type_dict.values())
        if len(share_replication_types) > 1:
            # NOTE(RyanLiang): It changes the behavior. The mixed
            # replication_type of share types in a group will fail the group
            # creation by this change.
            msg = _("The share types of the new group cannot have conflict "
                    "replication_type extra spec. The detail of "
                    "replication_type supported by each share type: %s.")
            raise exception.InvalidInput(
                reason=msg % share_replication_type_dict)

        share_replication_type = None
        if share_replication_types:
            share_replication_type = list(share_replication_types)[0]

        group_replication_type = share_group_type.get(
            'group_specs', {}).get('group_replication_type', None)

        # NOTE(RyanLiang): It's meaningless to have different values for
        # share_replication_type and group_replication_type. For example,
        # in the case share_replication_type=dr and
        # group_replication_type=readable, the user cannot create share
        # replicas but share group replicas. And the default implementation of
        # create_share_group_replica of share driver is creating share replicas
        # in the group one by one. It is reasonable to keep
        # share_replication_type and group_replication_type the same for the
        # the default implementation of create_share_group_replica.
        # The case of share_replication_type=None but
        # group_replication_type is not None is valid for any share driver
        # which only supports share group replications but share replications.
        if (all((share_replication_type, group_replication_type))
                and share_replication_type != group_replication_type):
            msg = _("The share replication type %(share_rep)s supported by "
                    "share types of the new group cannot be conflict with "
                    "the group spec group_replication_type %(group_rep)s.")
            raise exception.InvalidInput(
                reason=msg % {'share_rep': share_replication_type,
                              'group_rep': group_replication_type})

        deltas = {'share_groups': 1}
        if group_replication_type:
            deltas['share_group_replicas'] = 1

        try:
            reservations = QUOTAS.reserve(context, **deltas)
        except exception.OverQuota as e:
            self._raise_if_share_group_quotas_exceeded(context, e)
            raise exception.ShareGroupsLimitExceeded()

        options = {
            'share_group_type_id': share_group_type_id,
            'source_share_group_snapshot_instance_id':
                source_share_group_snapshot_instance_id,
            'share_network_id': share_network_id,
            'share_server_id': share_server_id,
            'availability_zone_id': availability_zone_id,
            'name': name,
            'description': description,
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_CREATING,
            'share_types': share_type_ids or supported_share_types,
            'group_replication_type': group_replication_type,
        }
        if original_share_group:
            options['host'] = original_share_group['host']

        share_group = {}
        try:
            # This will create the share group instance in db too.
            share_group = self.db.share_group_create(context, options)
            if share_group_snapshot:
                # Members got based on `share_group_snapshot.instance`.
                members = self.db.share_group_snapshot_members_get_all(
                    context, source_share_group_snapshot_id)
                for member in members:
                    share_instance = self.db.share_instance_get(
                        context, member['share_instance_id'])
                    share_type = share_types.get_share_type(
                        context, share_instance['share_type_id'])
                    self.share_api.create(
                        context,
                        member['share_proto'],
                        member['size'],
                        None,
                        None,
                        share_group_id=share_group['id'],
                        share_group_snapshot_member=member,
                        share_type=share_type,
                        availability_zone=availability_zone_id,
                        share_network_id=share_network_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                if share_group:
                    if share_group.get('instance'):
                        share_group_instance_id = share_group['instance']['id']
                        self.db.share_group_instance_delete(
                            context.elevated(), share_group_instance_id)
                    else:
                        self.db.share_group_destroy(
                            context.elevated(), share_group['id'])
                QUOTAS.rollback(context, reservations)

        try:
            QUOTAS.commit(context, reservations)
        except Exception:
            with excutils.save_and_reraise_exception():
                QUOTAS.rollback(context, reservations)

        share_group_instance = share_group['instance']

        if share_group_snapshot and original_share_group:
            self.share_rpcapi.create_share_group_instance(
                context, share_group_instance, original_share_group['host'])
        else:
            request_spec = {
                'share_group_instance_id': share_group_instance['id'],
                'share_group_id': share_group['id']}
            request_spec.update(options)
            request_spec['availability_zones'] = set(stype_azs_of_new_group)
            request_spec['share_types'] = share_type_objects
            request_spec['resource_type'] = share_group_type

            self.scheduler_rpcapi.create_share_group_instance(
                context, request_spec=request_spec, filter_properties={}
            )

        return share_group

    def delete(self, context, share_group):
        """Delete share group."""

        share_group_id = share_group['id']

        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR)
        if not share_group['status'] in statuses:
            msg = (_("Share group status must be one of %(statuses)s")
                   % {"statuses": statuses})
            raise exception.InvalidShareGroup(reason=msg)

        # NOTE(ameade): check for group_snapshots in the group
        if self.db.count_share_group_snapshots_in_share_group(
                context, share_group_id):
            msg = (_("Cannot delete a share group with snapshots"))
            raise exception.InvalidShareGroup(reason=msg)

        # NOTE(ameade): check for shares in the share group
        if self.db.count_shares_in_share_group(context, share_group_id):
            msg = (_("Cannot delete a share group with shares"))
            raise exception.InvalidShareGroup(reason=msg)

        if share_group.has_replicas:
            msg = _("Share group %s has replicas. Remove the replicas before "
                    "deleting the share group.") % share_group_id
            raise exception.Conflict(err=msg)

        share_group_instance = share_group.instance
        if not share_group_instance:
            self.db.share_group_destroy(context.elevated(), share_group_id)
            return

        share_group_instance_id = share_group_instance['id']

        if not share_group_instance['host']:
            self.db.share_group_instance_delete(context,
                                                share_group_instance_id)
            return

        try:
            reservations = QUOTAS.reserve(
                context,
                share_groups=-1,
                project_id=share_group['project_id'],
                user_id=share_group['user_id'],
            )
        except exception.OverQuota as e:
            reservations = None
            LOG.exception(
                "Failed to update quota for deleting share group: %s", e)

        # Only need to update share group instance 's status in db because
        # share group's status shares its active instance's.
        share_group_instance = self.db.share_group_instance_update(
            context, share_group_instance_id,
            {'status': constants.STATUS_DELETING,
             'terminated_at': timeutils.utcnow()})

        try:
            self.share_rpcapi.delete_share_group_instance(context,
                                                          share_group_instance)
        except Exception:
            with excutils.save_and_reraise_exception():
                QUOTAS.rollback(context, reservations)

        if reservations:
            QUOTAS.commit(
                context, reservations,
                project_id=share_group['project_id'],
                user_id=share_group['user_id'],
            )

    def update(self, context, group, fields):
        return self.db.share_group_update(context, group['id'], fields)

    def get(self, context, share_group_id):
        return self.db.share_group_get(context, share_group_id)

    def get_all(self, context, detailed=True, search_opts=None, sort_key=None,
                sort_dir=None):

        if search_opts is None:
            search_opts = {}

        LOG.debug("Searching for share_groups by: %s",
                  six.text_type(search_opts))

        # Get filtered list of share_groups
        if search_opts.pop('all_tenants', 0) and context.is_admin:
            share_groups = self.db.share_group_get_all(
                context, detailed=detailed, filters=search_opts,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            share_groups = self.db.share_group_get_all_by_project(
                context, context.project_id, detailed=detailed,
                filters=search_opts, sort_key=sort_key, sort_dir=sort_dir)

        return share_groups

    def _db_share_group_snapshot_member_create(self, context,
                                               share, share_instance,
                                               group_snap_instance):
        member_options = {
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_CREATING,
            'size': share['size'],
            'share_proto': share['share_proto'],
            'share_instance_id': share_instance['id'],
            'share_group_snapshot_instance_id': group_snap_instance['id'],
        }
        self.db.share_group_snapshot_member_create(context, member_options)

    def create_share_group_snapshot(self, context, name=None, description=None,
                                    share_group_id=None):
        """Create new share group snapshot."""
        options = {
            'share_group_id': share_group_id,
            'name': name,
            'description': description,
            'user_id': context.user_id,
            'project_id': context.project_id,
            'status': constants.STATUS_CREATING,
        }
        share_group = self.db.share_group_get(context, share_group_id)
        # Check status of group, must be active
        if not share_group['status'] == constants.STATUS_AVAILABLE:
            msg = (_("Share group status must be %s")
                   % constants.STATUS_AVAILABLE)
            raise exception.InvalidShareGroup(reason=msg)

        options['share_group_instance_id'] = share_group.instance['id']

        # Create members for every share in the group
        shares = self.db.share_get_all_by_share_group_id(
            context, share_group_id)

        # Check status of all shares, they must be active in order to snap
        # the group
        for s in shares:
            if not s['status'] == constants.STATUS_AVAILABLE:
                msg = (_("Share %(s)s in share group must have status "
                         "of %(status)s in order to create a group snapshot")
                       % {"s": s['id'],
                          "status": constants.STATUS_AVAILABLE})
                raise exception.InvalidShareGroup(reason=msg)

        try:
            reservations = QUOTAS.reserve(context, share_group_snapshots=1)
        except exception.OverQuota as e:
            self._raise_if_share_group_quotas_exceeded(context, e)
            raise exception.ShareGroupSnapshotsLimitExceeded()

        snap = {}
        try:
            # This will create share group snapshot instance too.
            snap = self.db.share_group_snapshot_create(context, options)
            for s in shares:
                self._db_share_group_snapshot_member_create(context, s,
                                                            s.instance,
                                                            snap.instance)

            # Cast to share manager
            if share_group.has_replicas:
                # Create share group snapshot instance and members for each
                # share group replica.
                group_replicas = (
                    self.db.share_group_replica_get_all_by_share_group(
                        context, share_group_id))
                active_group_replica_id = share_group.instance['id']
                group_snap_instance_data = {
                    'user_id': context.user_id,
                    'project_id': context.project_id,
                    'status': constants.STATUS_CREATING,
                }
                for group_replica in group_replicas:
                    if group_replica['id'] == active_group_replica_id:
                        continue

                    group_snap_instance_data.update(
                        {'share_group_instance_id': group_replica['id']})
                    replica_snap_instance = (
                        self.db.share_group_snapshot_instance_create(
                            context, snap['id'], group_snap_instance_data))

                    for s in shares:
                        for share_instance in s.instances:
                            if (share_instance['share_group_instance_id']
                                    == group_replica['id']):
                                self._db_share_group_snapshot_member_create(
                                    context, s, share_instance,
                                    replica_snap_instance)
                                break

                self.share_rpcapi.create_replicated_share_group_snapshot(
                    context, share_group, snap)
            else:
                self.share_rpcapi.create_share_group_snapshot_instance(
                    context, snap.instance, share_group['host'])
        except Exception:
            with excutils.save_and_reraise_exception():
                # This will delete the snapshot instance, all of it's members
                # and the snapshot if the snapshot instance is the last
                # instance of the snapshot.
                if snap:
                    self.db.share_group_snapshot_instance_delete(
                        context, snap.instance['id'])
                QUOTAS.rollback(context, reservations)

        try:
            QUOTAS.commit(context, reservations)
        except Exception:
            with excutils.save_and_reraise_exception():
                QUOTAS.rollback(context, reservations)

        return snap

    def delete_share_group_snapshot(self, context, snap):
        """Delete share group snapshot."""
        snap_id = snap['id']
        statuses = (constants.STATUS_AVAILABLE, constants.STATUS_ERROR)
        share_group = self.db.share_group_get(context, snap['share_group_id'])
        if not snap['status'] in statuses:
            msg = (_("Share group snapshot status must be one of"
                     " %(statuses)s") % {"statuses": statuses})
            raise exception.InvalidShareGroupSnapshot(reason=msg)

        group_snap_instances = self.db.share_group_snapshot_instance_get_all(
            context, filters={'share_group_snapshot_id': snap_id},
            with_snapshot_members=True)
        for group_snap_instance in group_snap_instances:
            self.db.share_group_snapshot_instance_update(
                context, group_snap_instance['id'],
                {'status': constants.STATUS_DELETING})
            for share_snap_instance in group_snap_instance.get(
                    'share_group_snapshot_members', []):
                self.db.share_snapshot_instance_update(
                    context, share_snap_instance['id'],
                    {'status': constants.STATUS_DELETING})

        try:
            reservations = QUOTAS.reserve(
                context,
                share_group_snapshots=-1,
                project_id=snap['project_id'],
                user_id=snap['user_id'],
            )
        except exception.OverQuota as e:
            reservations = None
            LOG.exception(
                ("Failed to update quota for deleting share group snapshot: "
                 "%s"), e)

        # Cast to share manager
        if share_group.has_replicas:
            self.share_rpcapi.delete_replicated_share_group_snapshot(
                context, share_group, snap)
        else:
            self.share_rpcapi.delete_share_group_snapshot_instance(
                context, snap.instance, share_group['host'])

        if reservations:
            QUOTAS.commit(
                context, reservations,
                project_id=snap['project_id'],
                user_id=snap['user_id'],
            )

    def update_share_group_snapshot(self, context, share_group_snapshot,
                                    fields):
        return self.db.share_group_snapshot_update(
            context, share_group_snapshot['id'], fields)

    def get_share_group_snapshot(self, context, snapshot_id):
        return self.db.share_group_snapshot_get(context, snapshot_id)

    def get_all_share_group_snapshots(self, context, detailed=True,
                                      search_opts=None, sort_key=None,
                                      sort_dir=None):
        if search_opts is None:
            search_opts = {}
        LOG.debug("Searching for share group snapshots by: %s",
                  six.text_type(search_opts))

        # Get filtered list of share group snapshots
        if search_opts.pop('all_tenants', 0) and context.is_admin:
            share_group_snapshots = self.db.share_group_snapshot_get_all(
                context, detailed=detailed, filters=search_opts,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            share_group_snapshots = (
                self.db.share_group_snapshot_get_all_by_project(
                    context, context.project_id, detailed=detailed,
                    filters=search_opts, sort_key=sort_key, sort_dir=sort_dir,
                )
            )

        # To keep compatible with showing members in the detail view.
        if detailed:
            for snap in share_group_snapshots:
                members = self.get_all_share_group_snapshot_members(
                    context, snap['id'])
                snap['share_group_snapshot_members'] = members
        return share_group_snapshots

    def get_all_share_group_snapshot_members(self, context,
                                             share_group_snapshot_id):
        members = self.db.share_group_snapshot_members_get_all(
            context, share_group_snapshot_id)
        return members

    def get_share_group_replica(self, context, group_replica_id,
                                with_replica_members=False):
        return self.db.share_group_replica_get(
            context, group_replica_id,
            with_replica_members=with_replica_members)

    def get_all_share_group_replicas(self, context, filters=None,
                                     with_replica_members=False,
                                     sort_key=None, sort_dir=None):
        all_tenants = filters.pop('all_tenants', False)
        if all_tenants:
            db_get = self.db.share_group_replica_get_all_in_all_tenants
        else:
            db_get = self.db.share_group_replica_get_all

        share_group_id = filters.get('share_group_id')
        if share_group_id:
            LOG.debug('Searching for share group replicas of group: %s',
                      share_group_id)
        else:
            LOG.debug('Searching for all share group replicas.')
        return db_get(context, filters=filters,
                      with_replica_members=with_replica_members,
                      sort_key=sort_key, sort_dir=sort_dir)

    @staticmethod
    def _raise_if_share_group_quotas_exceeded(context, quota_exception,
                                              shares_count=0, shares_size=0):
        overs = quota_exception.kwargs['overs']
        usages = quota_exception.kwargs['usages']
        quotas = quota_exception.kwargs['quotas']

        def _consumed(name):
            return usages[name]['reserved'] + usages[name]['in_use']

        if 'share_groups' in overs:
            LOG.warning('Quota exceeded for "%(s_uid)s" user in "%(s_pid)s" '
                        'project, unable to create share group '
                        '(%(d_consumed)d of %(d_quota)d already consumed).',
                        {'s_pid': context.project_id,
                         's_uid': context.user_id,
                         'd_consumed': _consumed('share_groups'),
                         'd_quota': quotas['share_groups']})
            raise exception.ShareGroupsLimitExceeded()
        elif 'share_group_snapshots' in overs:
            LOG.warning('Quota exceeded for "%(s_uid)s" user in "%(s_pid)s" '
                        'project, unable to create share group snapshot '
                        '(%(d_consumed)d of %(d_quota)d already consumed).',
                        {'s_pid': context.project_id,
                         's_uid': context.user_id,
                         'd_consumed': _consumed('share_group_snapshots'),
                         'd_quota': quotas['share_group_snapshots']})
            raise exception.ShareGroupSnapshotsLimitExceeded()
        elif 'share_group_replicas' in overs:
            LOG.warning('Quota share_group_replicas exceeded for '
                        '"%(s_uid)s" user in "%(s_pid)s" project, unable '
                        'to create share group replica (%(d_consumed)d of '
                        '%(d_quota)d already consumed).',
                        {'s_pid': context.project_id,
                         's_uid': context.user_id,
                         'd_consumed': _consumed('share_group_replicas'),
                         'd_quota': quotas['share_group_replicas']})
            raise exception.ShareGroupReplicasLimitExceeded()
        elif 'share_replicas' in overs:
            LOG.warning('Quota share_replicas exceeded for "%(s_pid)s" '
                        'user in "%(s_pid)s" project, unable to create '
                        'replica of share group with %(s_count)d shares '
                        'in it (%(d_consumed)d share replicas of '
                        '%(d_quota)d already consumed).',
                        {'s_pid': context.project_id,
                         's_uid': context.user_id,
                         's_count': shares_count,
                         'd_consumed': _consumed('share_replicas'),
                         'd_quota': quotas['share_replicas']})
            raise exception.ShareReplicasLimitExceeded()
        elif 'replica_gigabytes' in overs:
            LOG.warning('Quota replica_gigabytes exceeded for "%(s_pid)s" '
                        'user in "%(s_pid)s" project, unable to create '
                        'share group replica size of %(s_size)sG '
                        '(%(d_consumed)dG of %(d_quota)dG already '
                        'consumed).',
                        {'s_pid': context.project_id,
                         's_uid': context.user_id,
                         's_size': shares_size,
                         'd_consumed': _consumed('share_replicas'),
                         'd_quota': quotas['share_replicas']})
            raise exception.ShareReplicaSizeExceedsAvailableQuota()

    def create_share_group_replica(self, context, share_group_id,
                                   availability_zone=None):
        """Creates a new share group replica."""
        share_group = self.db.share_group_get(context, share_group_id)
        if not share_group.get('group_replication_type'):
            msg = _('Replication not supported for share group %s.')
            raise exception.InvalidShareGroup(message=msg % share_group_id)

        active_replica = (
            self.db.share_group_replica_get_available_active_replica(
                context, share_group_id)
        )
        if not active_replica:
            msg = _('Share group %s does not have any active replica in '
                    'available state.')
            raise exception.ShareGroupReplicationException(
                reason=msg % share_group_id)

        group_type_id = share_group.get('share_group_type_id', None)
        try:
            share_group_type = self.db.share_group_type_get(context,
                                                            group_type_id)
        except exception.ShareGroupTypeNotFound:
            msg = _('The specified share group type %s does not exist.')
            raise exception.InvalidInput(reason=msg % group_type_id)

        share_type_ids = set(x['share_type_id']
                             for x in share_group_type['share_types'])

        all_share_types = [share_types.get_share_type(context, share_type_id)
                           for share_type_id in share_type_ids]
        all_azs = []
        for share_type in all_share_types:
            azs = share_type.get('extra_specs', {}).get('availability_zones',
                                                        '')
            all_azs.extend([t for t in azs.split(',') if azs])
            if availability_zone and azs and availability_zone not in azs:
                # If an AZ is requested, it must be supported by the AZs
                # configured in each of the share types of the share group.
                msg = _('Share group replica cannot be created since the '
                        'share type %(type)s of the share group is not '
                        'supported within the availability zone chosen %(az)s.'
                        )
                type_name = '%s' % (share_type['name'] or '')
                type_id = '(ID: %s)' % share_type['id']
                payload = {'type': '%s%s' % (type_name, type_id),
                           'az': availability_zone}
                raise exception.InvalidInput(message=msg % payload)

        shares = self.db.share_get_all_by_share_group_id(context,
                                                         share_group_id)
        shares_size = sum(s['size'] for s in shares)

        # Check status of all shares, they must be active in order to replicate
        # the group
        for s in shares:
            if not s['status'] == constants.STATUS_AVAILABLE:
                msg = _('Share %(s)s in share group must have status of '
                        '%(status)s in order to create a group replica') % {
                    's': s['id'], 'status': constants.STATUS_AVAILABLE}
                raise exception.InvalidShareGroup(reason=msg)
        try:
            # TODO(RyanLiang): need to reserve by share_type?
            reservations = QUOTAS.reserve(context, share_group_replicas=1,
                                          share_replicas=len(shares),
                                          replica_gigabytes=shares_size)
        except exception.OverQuota as e:
            self._raise_if_share_group_quotas_exceeded(
                context, e, shares_count=len(shares), shares_size=shares_size)
            raise

        az_id = None
        if availability_zone:
            az_id = self.db.availability_zone_get(context,
                                                  availability_zone).id
        host = ''
        share_network_id = share_group['share_network_id']
        share_server_id = share_group['share_server_id']
        cast_rules_to_readonly = (share_group['group_replication_type']
                                  == constants.GROUP_REPLICATION_TYPE_READABLE)
        group_instance_values = {
            'user_id': context.user_id,
            'project_id': context.project_id,
            'availability_zone_id': az_id,
            'host': host,
            'share_group_id': share_group_id,
            'share_group_type_id': share_group['share_group_type_id'],
            'share_network_id': share_network_id,
            'share_server_id': share_server_id,
            'status': constants.STATUS_CREATING,
        }

        new_group_replica = {}
        new_group_snap_instances = []
        try:
            new_group_replica = self.db.share_group_instance_create(
                context, share_group_id, group_instance_values)

            existing_group_snapshots = self.db.share_group_snapshot_get_all(
                context, filters={'share_group_id': share_group_id})
            group_snap_instance_data = {
                'status': constants.STATUS_CREATING,
                'share_group_instance_id': new_group_replica['id'],
            }
            for group_snapshot in existing_group_snapshots:
                new_group_snap_instances.append(
                    self.db.share_group_snapshot_instance_create(
                        context, group_snapshot[id],
                        group_snap_instance_data)['id'])

            for shr in shares:
                new_share_instance = self.db.share_instance_create(
                    context, shr['id'],
                    {'share_network_id': share_network_id,
                     'status': constants.STATUS_CREATING,
                     'scheduled_at': timeutils.utcnow(),
                     'host': host,
                     'availability_zone_id': az_id,
                     'share_type_id': shr['instance']['share_type_id'],
                     'cast_rules_to_readonly': cast_rules_to_readonly,
                     'share_group_instance_id': new_group_replica['id']},)

                for new_group_snap_instance in new_group_snap_instances:
                    self._db_share_group_snapshot_member_create(
                        context, shr, new_share_instance,
                        new_group_snap_instance)

            # TODO(RyanLiang): handle individual snapshots of shares in the
            # group, or disable the creation of share snapshot if the share is
            # in a group, let the user create share group snapshot instead.

            QUOTAS.commit(context, reservations)
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    # It will delete the group snapshot instance and all of
                    # it's members - the share snapshot instances.
                    for new_group_snap_instance in new_group_snap_instances:
                        self.db.share_group_snapshot_instance_delete(
                            context, new_group_snap_instance['id'])

                    # It will delete the group replica and all of it's members
                    # - the share replicas.
                    if new_group_replica:
                        self.db.share_group_replica_delete(
                            context, new_group_replica['id'])
                finally:
                    QUOTAS.rollback(context, reservations)

        self.db.share_group_replica_update(
            context, new_group_replica['id'],
            {'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC})

        request_spec = {'share_group_instance_id': new_group_replica['id']}
        request_spec.update(group_instance_values)
        request_spec['availability_zones'] = set(all_azs)
        request_spec['share_types'] = all_share_types
        request_spec['resource_type'] = share_group_type

        all_replicas = self.db.share_group_replica_get_all_by_share_group(
            context, share_group_id)
        request_spec['active_group_replica_host'] = active_replica['host']
        request_spec['all_group_replica_hosts'] = ','.join(
            replica['host'] for replica in all_replicas)

        self.scheduler_rpcapi.create_share_group_replica(
            context, request_spec=request_spec, filter_properties={}
        )
        return new_group_replica

    def delete_share_group_replica(self, context, group_replica):
        """Deletes the share group replica."""
        # Disallow deletion of ONLY active replica, *even* when this
        # operation is forced.
        group_replicas = self.db.share_group_replica_get_all_by_share_group(
            context, group_replica['share_group_id'])
        active_replicas = list(filter(
            lambda x: x['replica_state'] == constants.REPLICA_STATE_ACTIVE,
            group_replicas))
        if (group_replica.get('replica_state') ==
                constants.REPLICA_STATE_ACTIVE and len(active_replicas) == 1):
            msg = _('Cannot delete last active replica.')
            raise exception.ShareGroupReplicationException(reason=msg)

        group_replica_id = group_replica['id']
        LOG.info('Deleting share group replica %s.', group_replica_id)

        self.db.share_group_replica_update(
            context, group_replica_id, {'status': constants.STATUS_DELETING})

        for share_replica in group_replica.get(
                'share_group_replica_members', []):
            self.db.share_replica_update(context, share_replica['id'],
                                         {'status': constants.STATUS_DELETING})

        if not group_replica['host']:
            group_snap_instances = (
                self.db.share_group_snapshot_instance_get_all(
                    context,
                    filters={'share_group_instance_id': group_replica_id}))
            for group_snap_instance in group_snap_instances:
                self.db.share_group_snapshot_instance_delete(
                    context, group_snap_instance['id'])

            # TODO(RyanLiang): handle individual snapshots of shares in the
            # group, or disable the creation of share snapshot if the share is
            # in a group, let the user create share group snapshot instead.

            # Delete the group replica from the database.
            self.db.share_group_replica_delete(context, group_replica_id)
        else:

            self.share_rpcapi.delete_share_group_replica(context,
                                                         group_replica)

    def promote_share_group_replica(self, context, share_group_replica):
        share_group_replica_id = share_group_replica['id']
        if share_group_replica.get('status') != constants.STATUS_AVAILABLE:
            raise exception.ShareGroupReplicationException(
                reason='Share group replica %(id)s must be in available state '
                       'to be promoted.' % {'id': share_group_replica_id})

        if (share_group_replica['replica_state'] in (
                constants.REPLICA_STATE_OUT_OF_SYNC, constants.STATUS_ERROR)
                and not context.is_admin):
            raise exception.AdminRequired(
                message=_('Promoting a share group replica with '
                          '"replica_state": %s requires administrator '
                          'privileges.') % share_group_replica['replica_state']
            )

        self.db.share_group_replica_update(
            context, share_group_replica_id,
            {'status': constants.STATUS_REPLICATION_CHANGE})

        for share_replica in share_group_replica.get(
                'share_group_replica_members', []):
            self.db.share_replica_update(
                context, share_replica['id'],
                {'status': constants.STATUS_REPLICATION_CHANGE})

        self.share_rpcapi.promote_share_group_replica(context,
                                                      share_group_replica)
        return self.db.share_group_replica_get(context, share_group_replica_id,
                                               with_replica_members=True)

    def update_share_group_replica(self, context, share_group_replica):
        if not share_group_replica['host']:
            raise exception.InvalidHost(reason='Share group replica does not '
                                               'have a valid host.')

        self.share_rpcapi.update_share_group_replica(context,
                                                     share_group_replica)
