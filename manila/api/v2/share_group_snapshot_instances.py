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

from oslo_log import log
from webob import exc

from manila.api.views import share_group_snapshot_instances
import manila.share_group.api as share_group_api
from manila import db
from manila import exception
from manila.api import common
from manila.api.openstack import wsgi
from manila.i18n import _

LOG = log.getLogger(__name__)

MIN_SUPPORTED_API_VERSION = '2.56'


class ShareGroupSnapshotInstanceController(wsgi.Controller,
                                           wsgi.AdminActionsMixin):
    """The share group snapshot instances API controller for the OpenStack API.
    """

    resource_name = 'share_group_snapshot_instance'
    _view_builder_class = (
        share_group_snapshot_instances.ShareGroupSnapshotInstanceViewBuilder)

    def __init__(self):
        super(ShareGroupSnapshotInstanceController, self).__init__()
        self.share_group_api = share_group_api.API()

    def _get_share_group_snapshot_instance(self, context,
                                           group_snapshot_instance_id):
        try:
            return self.share_group_api.get_share_group_instance(
                context, group_snapshot_instance_id)
        except exception.NotFound:
            msg = _('Share group snapshot instance %s not found.'
                    ) % group_snapshot_instance_id
            raise exc.HTTPNotFound(explanation=msg)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Returns data about the given share group snapshot instance."""
        context = req.environ['manila.context']
        group_snap_instance = self._get_share_group_snapshot_instance(
            context, id)
        return self._view_builder.detail(req, group_snap_instance)

    @wsgi.Controller.authorize('get_all')
    def _get_share_group_snapshot_instances(self, req, is_detail=False):
        """Returns a list of share group snapshot instances."""
        context = req.environ['manila.context']

        filters = {}
        filters.update(req.GET)
        sort_key = filters.pop('sort_key', None)
        sort_dir = filters.pop('sort_dir', None)

        share_group_snap_id = req.params.get('share_group_snapshot_id')
        if share_group_snap_id:
            filters['share_group_snapshot_id'] = share_group_snap_id
        try:
            group_snaps_instances = (
                self.share_group_api.get_all_share_group_snapshot_instances(
                    context, filters=filters, sort_key=sort_key,
                    sort_dir=sort_dir))
        except exception.NotFound:
            msg = _('Share group snapshot instances of share group snapshot '
                    'ID %s not found.') % share_group_snap_id
            raise exc.HTTPNotFound(explanation=msg)

        limited_list = common.limited(group_snaps_instances, req)

        if is_detail:
            return self._view_builder.detail_list(req, limited_list)
        else:
            return self._view_builder.summary_list(req, limited_list)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize('get_all')
    def index(self, req):
        """Returns a summary list of share group snapshot instances."""
        return self._get_share_group_snapshot_instances(req, is_detail=False)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize('get_all')
    def detail(self, req):
        """Returns a detailed list of share group snapshot instances."""
        return self._get_share_group_snapshot_instances(req, is_detail=True)

    def _update(self, *args, **kwargs):
        db.share_group_snapshot_instance_update(*args, **kwargs)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('reset_status')
    def reset_status(self, req, id, body):
        """Resets the 'status' attribute in the database."""
        return self._reset_status(req, id, body)

    def _get(self, *args, **kwargs):
        return self.share_group_api.get_share_group_snapshot_instance(*args,
                                                                      **kwargs)

    def _delete(self, context, resource, force=True):
        db.share_group_snapshot_instance_delete(context.elevated(),
                                                resource['id'])

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('force_delete')
    def force_delete(self, req, id, body):
        """Force deletion on the database, attempt on the backend."""
        return self._force_delete(req, id, body)


def create_resource():
    return wsgi.Resource(ShareGroupSnapshotInstanceController())
