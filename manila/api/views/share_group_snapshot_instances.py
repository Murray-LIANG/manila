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


class ShareGroupSnapshotInstanceViewBuilder(common.ViewBuilder):
    """Model a share group snapshot instance API response as a python dict.

    """

    _collection_name = 'share_group_snapshot_instances'
    _collection_links = 'share_group_snapshot_instance_links'

    def summary_list(self, request, share_group_snapshot_instances):
        """Show a list of share_group_snapshot_instances without many details.

        """
        return self._list_view(self.summary, request,
                               share_group_snapshot_instances)

    def detail_list(self, request, share_group_snapshot_instances):
        """Detailed view of a list of share_group_snapshot_instances."""
        return self._list_view(self.detail, request,
                               share_group_snapshot_instances)

    def summary(self, request, share_group_snapshot_instance):
        """Generic, non-detailed view of a share group snapshot instance."""
        return {
            'share_group_snapshot_instance': {
                'id': share_group_snapshot_instance.get('id'),
                'links': self._get_links(
                    request, share_group_snapshot_instance.get('id')),
            }
        }

    def detail(self, request, share_group_snapshot_instance):
        """Detailed view of a single share group snapshot instance."""

        instance_dict = {
            'id': share_group_snapshot_instance.get('id'),
            'share_group_instance_id': share_group_snapshot_instance.get(
                'share_group_instance_id'),
            'share_group_snapshot_id': share_group_snapshot_instance.get(
                'share_group_snapshot_id'),
            'status': share_group_snapshot_instance.get('status'),
            'links': self._get_links(request,
                                     share_group_snapshot_instance.get('id')),
        }
        return {'share_group_snapshot_instance': instance_dict}

    def _list_view(self, func, request, share_group_snapshot_instances):
        """Provide a view for a list of share group snapshot instances."""
        instance_list = [
            func(request, instance)['share_group_snapshot_instance']
            for instance in share_group_snapshot_instances]
        instance_links = self._get_collection_links(
            request, share_group_snapshot_instances, self._collection_name)
        instance_dict = {self._collection_name: instance_list}

        if instance_links:
            instance_dict[self._collection_links] = instance_links

        return instance_dict
