# Copyright 2020 Ryan Liang
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

from manila.api import common


class ShareGroupReplicaViewBuilder(common.ViewBuilder):
    """Model a share group replica API response as a python dictionary."""

    _collection_name = 'share_group_replicas'
    _collection_links = 'share_group_replica_links'

    def summary_list(self, request, share_group_replicas):
        """Show a list of share_group_replicas without many details."""
        return self._list_view(self.summary, request, share_group_replicas)

    def detail_list(self, request, share_group_replicas):
        """Detailed view of a list of share_group_snapshots."""
        return self._list_view(self.detail, request, share_group_replicas)

    def member_list(self, request, members):
        """Show a list of share replicas as members of a share group replica.
        """
        members_list = [
            {
                'id': replica.get('id'),
                'share_group_replica_id':
                    replica.get('share_group_replica_id'),
                'share_id': replica.get('share_id'),
                'availability_zone': replica.get('availability_zone'),
                'created_at': replica.get('created_at'),
                'status': replica.get('status'),
                'share_network_id': replica.get('share_network_id'),
                'replica_state': replica.get('replica_state'),
                'updated_at': replica.get('updated_at'),
            } for replica in members
        ]

        members_dict = {"share_group_replica_members": members_list}

        members_links = self._get_collection_links(
            request, members, "share_group_replica_id")
        if members_links:
            members_dict["share_group_snapshot_members_links"] = members_links

        return members_dict

    def summary(self, request, share_group_replica):
        """Generic, non-detailed view of a share group replica."""
        return {
            'share_group_replica': {
                'id': share_group_replica.get('id'),
                'share_group_id': share_group_replica.get('share_group_id'),
                'status': share_group_replica.get('status'),
                'replica_state': share_group_replica.get('replica_state'),
                'links':
                    self._get_links(request, share_group_replica.get('id')),
            }
        }

    def detail(self, request, share_group_replica):
        """Detailed view of a single share group replica."""

        members = [
            {
                'id': member.get('id'),
                'share_id': member.get('share_instance', {}).get('share_id'),
            } for member in share_group_replica.get(
                'share_group_replica_members')
        ]
        share_group_replica_dict = {
            'id': share_group_replica.get('id'),
            'share_group_id': share_group_replica.get('share_group_id'),
            'availability_zone': share_group_replica.get('availability_zone'),
            'status': share_group_replica.get('status'),
            'replica_state': share_group_replica.get('replica_state'),
            'created_at': share_group_replica.get('created_at'),
            'updated_at': share_group_replica.get('updated_at'),
            'members': members,
            'links':
                self._get_links(request, share_group_replica.get('id')),
        }
        return {'share_group_replica': share_group_replica_dict}

    def _list_view(self, func, request, share_group_replicas):
        """Provide a view for a list of share group replicas."""
        replica_list = [func(request, replica)["share_group_replica"]
                        for replica in share_group_replicas]
        replica_links = self._get_collection_links(request,
                                                   share_group_replicas,
                                                   self._collection_name)
        replica_dict = {self._collection_name: replica_list}

        if replica_links:
            replica_dict[self._collection_links] = replica_links

        return replica_dict
