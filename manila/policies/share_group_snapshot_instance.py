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

from oslo_policy import policy

from manila.policies import base


BASE_POLICY_NAME = 'share_group_snapshot_instance:%s'

share_group_snapshot_instance_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.RULE_DEFAULT,
        description="Get all share group snapshot instances.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-snapshot-instances',
            },
            {
                'method': 'GET',
                'path': '/share-group-snapshot-instances/detail',
            },
            {
                'method': 'GET',
                'path': '/share-group-snapshot-instances/detail'
                        '?share_group_snapshot_id={share_group_snapshot_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get',
        check_str=base.RULE_DEFAULT,
        description="Get details of a share group snapshot instance.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-snapshot-instances/'
                        '{share_group_snapshot_instance_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_delete',
        check_str=base.RULE_ADMIN_API,
        description="Force delete a share group snapshot instance.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-snapshot-instances/'
                        '{share_group_snapshot_instance_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.RULE_ADMIN_API,
        description="Reset share group snapshot instance's status.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-snapshot-instances/'
                        '{share_group_snapshot_instance_id}/action',
            }
        ]),
]


def list_rules():
    return share_group_snapshot_instance_policies
