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


class ShareGroupInstanceViewBuilder(common.ViewBuilder):
    """Model a share group instance API response as a python dictionary."""

    _collection_name = 'share_group_instances'
    _collection_links = 'share_group_instance_links'

    def summary_list(self, request, share_group_instances):
        """Show a list of share_group_instances without many details."""
        return self._list_view(self.summary, request, share_group_instances)

    def detail_list(self, request, share_group_instances):
        """Detailed view of a list of share_group_instances."""
        return self._list_view(self.detail, request, share_group_instances)

    def summary(self, request, share_group_instance):
        """Generic, non-detailed view of a share group instance."""
        return {
            'share_group_instance': {
                'id': share_group_instance.get('id'),
                'links':
                    self._get_links(request, share_group_instance.get('id')),
            }
        }

    def detail(self, request, share_group_instance):
        """Detailed view of a single share group instance."""

        share_group_instance_dict = {
            'id': share_group_instance.get('id'),
            'host': share_group_instance.get('host'),
            'progress': share_group_instance.get('progress'),
            'replica_state': share_group_instance.get('replica_state'),
            'share_group_id': share_group_instance.get('share_group_id'),
            'share_group_type_id': share_group_instance.get(
                'share_group_type_id'),
            'share_network_id': share_group_instance.get('share_network_id'),
            'share_server_id': share_group_instance.get('share_server_id'),
            'status': share_group_instance.get('status'),
            'links':
                self._get_links(request, share_group_instance.get('id')),

            'availability_zone': share_group_instance.get('availability_zone'),
            'created_at': share_group_instance.get('created_at'),
            'updated_at': share_group_instance.get('updated_at'),

        }
        return {'share_group_instance': share_group_instance_dict}

    def _list_view(self, func, request, share_group_instances):
        """Provide a view for a list of share group instances."""
        instance_list = [func(request, instance)['share_group_instance']
                         for instance in share_group_instances]
        instance_links = self._get_collection_links(request,
                                                    share_group_instances,
                                                    self._collection_name)
        instance_dict = {self._collection_name: instance_list}

        if instance_links:
            instance_dict[self._collection_links] = instance_links

        return instance_dict
