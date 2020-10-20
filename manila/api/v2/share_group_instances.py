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

import manila.api.views.share_group_instances as share_group_instances_views
import manila.share_group.api as share_group_api
from manila import db
from manila import exception
from manila.api import common
from manila.api.openstack import wsgi
from manila.i18n import _

LOG = log.getLogger(__name__)

MIN_SUPPORTED_API_VERSION = '2.56'


class ShareGroupInstanceController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The share group instances API controller for the OpenStack API."""

    resource_name = 'share_group_instance'
    _view_builder_class = (
        share_group_instances_views.ShareGroupInstanceViewBuilder)

    def __init__(self):
        super(ShareGroupInstanceController, self).__init__()
        self.share_group_api = share_group_api.API()

    def _get_share_group_instance(self, context, group_instance_id):
        try:
            return self.share_group_api.get_share_group_instance(
                context, group_instance_id)
        except exception.NotFound:
            msg = _('Share group instance %s not found.') % group_instance_id
            raise exc.HTTPNotFound(explanation=msg)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Returns data about the given share group instance."""
        context = req.environ['manila.context']
        group_instance = self._get_share_group_instance(context, id)
        return self._view_builder.detail(req, group_instance)

    @wsgi.Controller.authorize('get_all')
    def _get_share_group_instances(self, req, is_detail=False):
        """Returns a list of share group instances."""
        context = req.environ['manila.context']

        filters = {}
        filters.update(req.GET)
        sort_key = filters.pop('sort_key', None)
        sort_dir = filters.pop('sort_dir', None)

        share_group_id = req.params.get('share_group_id')
        if share_group_id:
            filters['share_group_id'] = share_group_id
        try:
            group_instances = (
                self.share_group_api.get_all_share_group_instances(
                    context, filters=filters, sort_key=sort_key,
                    sort_dir=sort_dir))
        except exception.NotFound:
            msg = _('Share group instances of share group ID %s not found.'
                    ) % share_group_id
            raise exc.HTTPNotFound(explanation=msg)

        limited_list = common.limited(group_instances, req)

        if is_detail:
            return self._view_builder.detail_list(req, limited_list)
        else:
            return self._view_builder.summary_list(req, limited_list)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize('get_all')
    def index(self, req):
        """Returns a summary list of share group instances."""
        return self._get_share_group_instances(req, is_detail=False)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize('get_all')
    def detail(self, req):
        """Returns a detailed list of share group instances."""
        return self._get_share_group_instances(req, is_detail=True)

    def _update(self, *args, **kwargs):
        db.share_group_instance_update(*args, **kwargs)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('reset_status')
    def reset_status(self, req, id, body):
        """Resets the 'status' attribute in the database."""
        return self._reset_status(req, id, body)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('reset_replica_state')
    @wsgi.Controller.authorize
    def reset_replica_state(self, req, id, body):
        """Resets the 'replica_state' attribute in the database."""
        return self._reset_status(req, id, body, status_attr='replica_state')

    def _get(self, *args, **kwargs):
        return self.share_group_api.get_share_group_instance(*args, **kwargs)

    def _delete(self, context, resource, force=True):
        db.share_group_instance_delete(context.elevated(), resource['id'])

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('force_delete')
    def force_delete(self, req, id, body):
        """Force deletion on the database, attempt on the backend."""
        return self._force_delete(req, id, body)


def create_resource():
    return wsgi.Resource(ShareGroupInstanceController())
