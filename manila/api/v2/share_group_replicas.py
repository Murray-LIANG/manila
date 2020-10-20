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
from oslo_utils import uuidutils
import six
from six.moves import http_client
import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
import manila.api.views.share_group_replicas as share_group_replicas_views
from manila.common import constants
from manila import db
from manila import exception
from manila.i18n import _
import manila.share_group.api as share_group_api

LOG = log.getLogger(__name__)


MIN_SUPPORTED_API_VERSION = '2.56'


class ShareGroupReplicaController(wsgi.Controller, wsgi.AdminActionsMixin):
    """The share group replicas API controller for the OpenStack API."""

    resource_name = 'share_group_replica'
    _view_builder_class = (
        share_group_replicas_views.ShareGroupReplicaViewBuilder)

    def __init__(self):
        super(ShareGroupReplicaController, self).__init__()
        self.share_group_api = share_group_api.API()

    def _get_share_group_replica(self, context, group_replica_id,
                                 with_replica_members=False):
        try:
            return self.share_group_api.get_share_group_replica(
                context, group_replica_id,
                with_replica_members=with_replica_members)
        except exception.NotFound:
            msg = _('Share group replica %s not found.') % group_replica_id
            raise exc.HTTPNotFound(explanation=msg)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize('get')
    def show(self, req, id):
        """Returns data about the given share group replica."""
        context = req.environ['manila.context']
        group_replica = self._get_share_group_replica(
            context, id, with_replica_members=True)
        return self._view_builder.detail(req, group_replica)

    @wsgi.Controller.authorize('get_all')
    def _get_share_group_replicas(self, req, is_detail=False):
        """Returns a list of share group replicas."""
        context = req.environ['manila.context']

        filters = {}
        filters.update(req.GET)
        sort_key = filters.pop('sort_key', None)
        sort_dir = filters.pop('sort_dir', None)

        share_group_id = req.params.get('share_group_id')
        if share_group_id:
            filters['share_group_id'] = share_group_id
        try:
            group_replicas = self.share_group_api.get_all_share_group_replicas(
                context, filters=filters, with_replica_members=is_detail,
                sort_key=sort_key, sort_dir=sort_dir)
        except exception.NotFound:
            msg = _('Share group replicas of share group ID %s not found.'
                    ) % share_group_id
            raise exc.HTTPNotFound(explanation=msg)

        limited_list = common.limited(group_replicas, req)

        if is_detail:
            return self._view_builder.detail_list(req, limited_list)
        else:
            return self._view_builder.summary_list(req, limited_list)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize('get_all')
    def index(self, req):
        """Returns a summary list of share group replicas."""
        return self._get_share_group_replicas(req, is_detail=False)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize('get_all')
    def detail(self, req):
        """Returns a detailed list of share group replicas."""
        return self._get_share_group_replicas(req, is_detail=True)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.response(202)
    @wsgi.Controller.authorize
    def create(self, req, body):
        """Creates a new share group replica."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share_group_replica'):
            msg = _('"share_group_replica" is missing from the request body.')
            raise exc.HTTPUnprocessableEntity(explanation=msg)

        share_group_replica = body['share_group_replica']

        share_group_id = share_group_replica.get('share_group_id')
        if not share_group_id:
            msg = _('Must supply "share_group_id" attribute.')
            raise exc.HTTPBadRequest(explanation=msg)
        if not uuidutils.is_uuid_like(share_group_id):
            msg = _('The "share_group_id" attribute must be a uuid.')
            raise exc.HTTPBadRequest(explanation=msg)

        availability_zone = share_group_replica.get('availability_zone')

        try:
            new_replica = self.share_group_api.create_share_group_replica(
                context, share_group_id=share_group_id,
                availability_zone=availability_zone)
        except exception.ShareGroupNotFound as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))
        except exception.InvalidShareGroup as e:
            raise exc.HTTPConflict(explanation=six.text_type(e))

        return self._view_builder.detail(req, dict(new_replica.items()))

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.Controller.authorize
    def delete(self, req, id):
        """Deletes a share group replica."""
        context = req.environ['manila.context']
        LOG.info('Deleting share group replica with id: %s',
                 id, context=context)
        try:
            group_replica = self._get_share_group_replica(
                context, id, with_replica_members=True)
        except exception.ShareGroupReplicaNotFound:
            msg = _('No group replica exists with ID %s.')
            raise exc.HTTPNotFound(explanation=msg % id)

        try:
            self.share_group_api.delete_share_group_replica(
                context, group_replica)
        except exception.ShareGroupReplicationException as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))
        return webob.Response(status_int=http_client.ACCEPTED)

    def _update(self, *args, **kwargs):
        db.share_group_replica_update(*args, **kwargs)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('reset_status')
    def reset_status(self, req, id, body):
        """Resets the 'status' attribute in the database."""
        return self._reset_status(req, id, body)

    def _get(self, *args, **kwargs):
        return self.share_group_api.get_share_group_replica(*args, **kwargs)

    def _delete(self, context, resource, force=True):
        db.share_group_replica_delete(context.elevated(), resource['id'])

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('force_delete')
    def force_delete(self, req, id, body):
        """Force deletion on the database, attempt on the backend."""
        return self._force_delete(req, id, body)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('promote')
    @wsgi.response(202)
    @wsgi.Controller.authorize
    def promote(self, req, id, body):
        """Promotes a share group replica to active state."""
        context = req.environ['manila.context']

        try:
            group_replica = db.share_group_replica_get(
                context, id, with_replica_members=True)
        except exception.ShareGroupReplicaNotFound:
            msg = _('No share group replica exists with ID %s.')
            raise exc.HTTPNotFound(explanation=msg % id)

        if group_replica.get('replica_state'
                             ) == constants.REPLICA_STATE_ACTIVE:
            return webob.Response(status_int=http_client.OK)

        try:
            group_replica = self.share_group_api.promote_share_group_replica(
                context, group_replica)
        except exception.ShareGroupReplicationException as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))
        except exception.AdminRequired as e:
            raise exc.HTTPForbidden(explanation=six.text_type(e))

        return self._view_builder.detail(req, group_replica)

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('reset_replica_state')
    @wsgi.Controller.authorize
    def reset_replica_state(self, req, id, body):
        """Resets the 'replica_state' attribute in the database."""
        return self._reset_status(req, id, body, status_attr='replica_state')

    @wsgi.Controller.api_version(MIN_SUPPORTED_API_VERSION, experimental=True)
    @wsgi.action('resync')
    @wsgi.response(202)
    @wsgi.Controller.authorize
    def resync(self, req, id, body):
        """Attempts to update/sync the replica with its source."""
        context = req.environ['manila.context']
        try:
            group_replica = db.share_group_replica_get(context, id)
        except exception.ShareGroupReplicaNotFound:
            msg = _('No share group replica exists with ID %s.')
            raise exc.HTTPNotFound(explanation=msg % id)

        if group_replica.get('replica_state'
                             ) == constants.REPLICA_STATE_ACTIVE:
            return webob.Response(status_int=http_client.OK)

        try:
            self.share_group_api.update_share_group_replica(context,
                                                            group_replica)
        except exception.InvalidHost as e:
            raise exc.HTTPBadRequest(explanation=six.text_type(e))


def create_resource():
    return wsgi.Resource(ShareGroupReplicaController())