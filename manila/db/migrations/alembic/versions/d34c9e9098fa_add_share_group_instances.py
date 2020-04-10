# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""add_share_group_instances

Revision ID: d34c9e9098fa
Revises: e6d88547b381
Create Date: 2020-03-31 17:19:30.698067

"""
import sqlalchemy as sa
from alembic import op

from manila.db.migrations import utils

# revision identifiers, used by Alembic.
revision = 'd34c9e9098fa'
down_revision = 'e6d88547b381'


def _create_share_group_instances_table(connection):
    # Create 'share_group_instances' table.
    share_group_instances_table = op.create_table(
        'share_group_instances',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.String(length=36), default='False'),
        sa.Column('id',
                  sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('availability_zone_id',
                  sa.String(length=36), sa.ForeignKey('availability_zones.id'),
                  nullable=True),
        sa.Column('host', sa.String(length=255)),
        sa.Column('replica_state', sa.String(length=255), nullable=True),
        sa.Column('share_group_id',
                  sa.String(length=36), sa.ForeignKey('share_groups.id')),
        sa.Column('share_group_type_id',
                  sa.String(length=36), sa.ForeignKey('share_group_types.id'),
                  nullable=True),
        sa.Column('share_network_id',
                  sa.String(length=36), sa.ForeignKey('share_networks.id'),
                  nullable=True),
        sa.Column('share_server_id',
                  sa.String(length=36), sa.ForeignKey('share_servers.id'),
                  nullable=True),
        sa.Column('status', sa.String(length=255)),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    # Migrate data from 'share_groups' to 'share_group_instances'.
    share_group_instances = []
    share_groups_table = utils.load_table('share_groups', connection)
    for share_group in connection.execute(share_groups_table.select()):
        share_group_instances.append({
            'created_at': share_group.created_at,
            'updated_at': share_group.updated_at,
            'deleted_at': share_group.deleted_at,
            'deleted': share_group.deleted,
            'id': share_group.id,
            'availability_zone_id': share_group.availability_zone_id,
            'host': share_group.host,
            'share_group_id': share_group.id,
            'share_group_type_id': share_group.share_group_type_id,
            'share_network_id': share_group.share_network_id,
            'share_server_id': share_group.share_server_id,
            'status': share_group.status,
        })
    op.bulk_insert(share_group_instances_table, share_group_instances)

    # Remove columns moved to 'share_group_instances' table,
    # and add new columns to 'share_group' table.
    with op.batch_alter_table("share_groups") as batch_op:
        for fk in share_groups_table.foreign_keys:
            batch_op.drop_constraint(fk.name, type_='foreignkey')

        batch_op.drop_column('availability_zone_id')
        batch_op.drop_column('host')
        batch_op.drop_column('share_group_type_id')
        batch_op.drop_column('share_network_id')
        batch_op.drop_column('share_server_id')
        batch_op.drop_column('status')

        batch_op.add_column(sa.Column('group_replication_type',
                                      sa.String(255), nullable=True))


def upgrade():
    connection = op.get_bind()

    _create_share_group_instances_table(connection)


def _remove_share_group_instances_table(connection):
    with op.batch_alter_table("share_groups") as batch_op:
        batch_op.add_column(sa.Column('availability_zone_id',
                                      sa.String(length=36),
                                      sa.ForeignKey('availability_zones.id'),
                                      nullable=True))
        batch_op.add_column(sa.Column('host', sa.String(length=255)))
        batch_op.add_column(sa.Column('share_group_type_id',
                                      sa.String(length=36),
                                      sa.ForeignKey('share_group_types.id'),
                                      nullable=True))
        batch_op.add_column(sa.Column('share_network_id',
                                      sa.String(length=36),
                                      sa.ForeignKey('share_networks.id'),
                                      nullable=True))
        batch_op.add_column(sa.Column('share_server_id',
                                      sa.String(length=36),
                                      sa.ForeignKey('share_servers.id'),
                                      nullable=True))
        batch_op.add_column(sa.Column('status', sa.String(length=255)))

        batch_op.drop_column('group_replication_type')

    share_groups_table = utils.load_table('share_groups', connection)
    share_group_instances_table = utils.load_table('share_group_instances',
                                                   connection)

    for share_group in connection.execute(share_groups_table.select()):
        instance = connection.execute(
            share_group_instances_table.select().where(
                share_group_instances_table.c.share_group_id == share_group.id)
        ).first()

        # pylint: disable=no-value-for-parameter
        op.execute(
            share_groups_table.update().where(
                share_groups_table.c.id == share_group.id
            ).values(
                {
                    'availability_zone_id': instance.availability_zone_id,
                    'host': instance.host,
                    'share_group_type_id': instance.share_group_type_id,
                    'share_network_id': instance.share_network_id,
                    'share_server_id': instance.share_server_id,
                    'status': instance.status,
                }
            )
        )

    op.drop_table('share_group_instances')


def downgrade():
    connection = op.get_bind()

    _remove_share_group_instances_table(connection)
