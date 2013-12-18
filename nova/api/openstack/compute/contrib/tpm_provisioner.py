#   Copyright 2013 OpenStack Foundation
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.


from webob import exc

from nova.api.openstack import common
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import compute
from nova import exception
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging
from nova.openstack.common import strutils
from nova import utils

LOG = logging.getLogger(__name__)

authorize = extensions.extension_authorizer('compute', 'tpmprovisioner')
class ProvisionController(object):
    def __init__(self):
        self.host_api = compute.HostAPI()
        super(ProvisionController, self).__init__()

    def create(self, req, body):
        #{'host':'hostname','pcrs':["0","1","6","19"]}
        context = req.environ['nova.context']
        authorize(context)
        host=body['host']
        pcrs=body['pcrs']
        try:
            self.host_api.service_get_by_compute_host(context, host)
        except exception.NotFound:
            msg = _("Compute host %s not found.") % host
            raise exc.HTTPNotFound(explanation=msg)

        LOG.info(_('Provisioning host %s with PCRs %s'), host, pcrs)
        type,pcrhash,pkey,uuid=self.host_api.provision_tpm(context, host, pcrs)
        return { "hostname": host, "pcrs": pcrs, "auth_type": type, "uuid": uuid, "pkey": pkey, "pure_hash": pcrhash }


class Tpm_provisioner(extensions.ExtensionDescriptor):
    """TPM provisioner"""

    name = "TPM-provisioner"
    alias = "os-tpmprovision"
    namespace = "http://docs.openstack.org/compute/ext/tpmprovision/api/v2"
    updated = "2013-01-06T00:00:00+00:00"

    def __init__(self, ext_mgr):
        ext_mgr.register(self)


    def get_resources(self):
        resources = [extensions.ResourceExtension('os-tpmprovision',
                ProvisionController())]
        return resources

