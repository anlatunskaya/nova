# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 Intel, Inc.
# Copyright (c) 2011-2012 OpenStack Foundation
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

from nova import compute
from nova.scheduler import filters
from nova import context
from nova.openstack.common.gettextutils import _
from oslo.config import cfg
from keystoneclient.v2_0 import client
from nova import utils
import base64
import shutil
import tempfile
import hashlib
from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


opts = [
    cfg.StrOpt('auth_host',
               default='127.0.0.1',
               help='Host providing the admin Identity API endpoint'),
    cfg.IntOpt('auth_port',
               default=35357,
               help='Port of the admin Identity API endpoint'),
    cfg.StrOpt('auth_protocol',
               default='https',
               help='Protocol of the admin Identity API endpoint'
               '(http or https)'),
    cfg.StrOpt('admin_user',
               help='Keystone account username'),
    cfg.StrOpt('admin_password',
               secret=True,
               help='Keystone account password'),
    cfg.StrOpt('admin_tenant_name',
               default='admin',
               help='Keystone service account tenant name to validate'
               ' user tokens'),
    cfg.StrOpt('auth_version',
               default='2.0',
               help='API version of the admin Identity API endpoint')
]
CONF.register_opts(opts, group='keystone_authtoken')


class Attestation(object):

    def __init__(self, kc):
        self.host_api = compute.HostAPI()
        self.kc = kc

    def _validate(self, id, salted_hash, salt):
        return self.kc.attestation.validate(id, salted_hash, salt)['valid']

    def get_quote(self, nova_context, host, salt):
        host_key = self.kc.attestation.find(hostname = host, service = "compute")
        if not host_key['valid']:
          LOG.debug(_('Quoting %s on %s with %s using key %s'), salt, host, host_key['PCRs'], host_key['uuid'])
          quote = self.host_api.quote_tpm(nova_context, host, salt, host_key['PCRs'], host_key['uuid'])
          is_valid = self._validate(host_key['id'], quote, salt)
        else:
          is_valid = host_key['valid']
        return is_valid


class AttestationFilter(filters.BaseHostFilter):

    def __init__(self):
        request_url = '%s://%s:%s/v%s' % (CONF.keystone_authtoken['auth_protocol'], CONF.keystone_authtoken['auth_host'], CONF.keystone_authtoken['auth_port'], CONF.keystone_authtoken['auth_version'])
        request_user = CONF.keystone_authtoken['admin_user']
        request_password = CONF.keystone_authtoken['admin_password']
        request_tenant = CONF.keystone_authtoken['admin_tenant_name']
        kc = client.Client(username=request_user,tenant_name=request_tenant,auth_url=request_url,password=request_password)
        self.attestation = Attestation(kc)

    def host_passes(self, host_state, filter_properties):
        nova_context = context.get_admin_context()
        host = host_state.host
        salt = nova_context.to_dict()['request_id']
        return self.attestation.get_quote(nova_context, host, salt)
