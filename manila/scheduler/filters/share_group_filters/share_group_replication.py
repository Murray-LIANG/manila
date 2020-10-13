# Copyright (c) 2020 Ryan Liang
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

from oslo_log import log

from manila.scheduler.filters import base_host
from manila.share import utils as share_utils

LOG = log.getLogger(__name__)


class ShareGroupReplicationFilter(base_host.BaseHostFilter):
    """Filters hosts based on share group replication support."""

    def host_passes(self, host_state, filter_properties):
        """Returns True if the host meets the replication related requirements.

        Design of this filter:

            - All backends that can replicate between each other must share the
                same 'group_replication_domain'.
            - For scheduling a share group that can be replicated in the
                future, this filter checks for 'group_replication_type'
                capability.
            - For scheduling a share group replica, it checks for the
              'group_replication_domain' compatibility.

        """

        group_replication_type = filter_properties.get(
            'resource_type', {}).get(
            'group_specs', {}).get('group_replication_type')
        if not group_replication_type:
            # The host passes this filter for a request not creating a
            # replication-enabled share group or a share group replica.
            return True

        host_replication_domain = host_state.group_replication_domain
        if not host_replication_domain:
            LOG.debug(
                'The host %s failed to pass the ShareGroupReplicationFilter '
                'because its group_replication_domain is not set on host.',
                host_state.host)
            return False

        active_group_replica_host = filter_properties.get(
            'request_spec', {}).get('active_group_replica_host')
        if not active_group_replica_host:
            # For scheduling a share group that can be replicated in the
            # future, this filter checks for 'group_replication_type'
            # capability.
            return group_replication_type == host_state.group_replication_type

        # For scheduling a share group replica, checks for the
        # 'group_replication_domain' compatibility.
        active_group_replication_domain = filter_properties.get(
            'group_replication_domain')
        if active_group_replication_domain != host_replication_domain:
            LOG.debug(
                "The group replication domain of host %(host)s is "
                "'%(host_domain)s' and it does not match the group "
                "replication domain of the 'active' group replica's host: "
                "%(active_group_replica_host)s, which is '%(active_domain)s'.",
                {'host': host_state.host,
                 'host_domain': host_replication_domain,
                 'active_group_replica_host': active_group_replica_host,
                 'active_domain': active_group_replication_domain})
            return False

        existing_replica_hosts = filter_properties.get(
            'request_spec', {}).get('all_group_replica_hosts', '').split(',')
        if host_state.host in existing_replica_hosts:
            LOG.debug('Skipping host %s since it already hosts a replica for '
                      'this share group.', host_state.host)
            return False

        # Host could report None, then means no limit on group replicas counts.
        max_count_allowed = host_state.max_group_replicas_count_on_same_backend
        if max_count_allowed:
            # Allow schedule to the active replica's host one more time
            # if the backend supports local replication.
            if host_state.local_group_replication_support:
                LOG.debug('Local group replication is support on host %s. '
                          'One more group replica will be scheduled to it.',
                          host_state.host)
                existing_replica_hosts.remove(active_group_replica_host)

            existing_replica_backends = [
                share_utils.extract_host(existing_host, level='backend')
                for existing_host in existing_replica_hosts]

            host_backend = share_utils.extract_host(host_state.host,
                                                    level='backend')
            existing_count = existing_replica_backends.count(host_backend)
            if existing_count >= max_count_allowed:
                LOG.debug(
                    'Skipping host %(host)s since it does not support '
                    'max %(allow)s count of share group replicas on the same '
                    'backend and the count of existing replicas on its '
                    'backend %(backend)s is %(count)s.',
                    {'host': host_state.host, 'allow': max_count_allowed,
                     'backend': host_backend, 'count': existing_count})
                return False

        return group_replication_type == host_state.group_replication_type
