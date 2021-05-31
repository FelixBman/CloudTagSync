"""
maintainer: czangerle@barracuda.com
This module retrieves ip addresses based on the tags of the associated vm and creates a network object containing all ips with the same tag in a cc.
For this script to work the followint variables need to be set in the environment:
- AZURE_CLIENT_ID
- AZURE_CLIENT_SECRET
- AZURE_TENANT_ID
- AZURE_SUBSCRIPTION_ID
"""

import os
import logging
import requests
from functools import reduce
import json
from urllib.parse import urljoin
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.identity import ClientSecretCredential

LOG = logging.getLogger(__name__)

with open('JSON-Settings-File.json') as json_file:
    credentials = json.load(json_file)

client_id = credentials.get('client_id', os.getenv("AZURE_CLIENT_ID"))
secret = credentials.get('client_secret', os.getenv("AZURE_CLIENT_SECRET"))
tenant = credentials.get('tenant_id', os.getenv("AZURE_TENANT_ID"))
subscription_id = credentials.get('subscription_id', os.getenv("AZURE_SUBSCRIPTION_ID"))

azure_credentials = ClientSecretCredential(
    client_id=client_id,
    client_secret=secret,
    tenant_id=tenant,
)
data = ("grant_type=client_credentials&client_id={}&client_secret={"
        "}&resource=https%3A%2F%2Fmanagement.azure.com%2F "
        ).format(client_id, secret)

network_client = NetworkManagementClient(
    azure_credentials, subscription_id
)
compute_client = ComputeManagementClient(
    azure_credentials, subscription_id
)


def get_ips(vm_name=None, tags=None):
    """Scrape the entire Azure account for vms with the defined tags and extract their ips into a dictonary"""
    if tags is None:
        tags = list()
    ips = dict()
    for vm in compute_client.virtual_machines.list_all():
        vm_name_match = vm.name == vm_name or vm_name is None
        tag_match = True if tags is None else False
        resource_group = vm.id.split('/')[4]

        if tags and vm.tags:
            tag_match = any([tag in map(str.lower, vm.tags) for tag in map(str.lower, tags)])

        if vm_name_match and tag_match:
            for interface in vm.network_profile.network_interfaces:
                name = " ".join(interface.id.split('/')[-1:])
                sub = "".join(interface.id.split('/')[4])
                try:
                    ip_configurations = network_client.network_interfaces.get(sub, name).ip_configurations
                    for configuration in ip_configurations:
                        public_ip_config = configuration.public_ip_address if hasattr(configuration.public_ip_address,
                                                                                      'ip_address') else configuration.public_ip_address
                        public_ip = None
                        if public_ip_config:
                            ip_name = public_ip_config.id.split('/')[-1]
                            public_ip = network_client.public_ip_addresses.get(resource_group, ip_name).ip_address
                        ips[name] = {
                            'public_ip': public_ip,
                            'private_ip': configuration.private_ip_address,
                            'filter_tags': [tag for tag in tags if tag in vm.tags]
                        }
                except Exception as e:
                    LOG.error(e)
    return ips


def cloud2cc(cc_url, tags, token):
    """Register ip addresses based on the tags used on their vms into a network object on a cc"""
    if not all([cc_url, tags, token]):
        LOG.info('please provide the required parameters')
        return
    headers = {'X-API-Token': token, 'accept': '*/*'}
    tags_ = tags.split(',')
    ip_objects = get_ips(tags=tags_)
    if not ip_objects:
        LOG.info('No ips found for the provided tags. Please verify you are in the right subscription.')
        return
    payloads = list()
    resps = list()
    for tag in tags_:
        ips = {'{}-{}'.format(name, type_): ip for name, data in ip_objects.items() for type_, ip in data.items() if
               isinstance(ip, str) and tag in data.get('filter_tags')}
        payload = {
            'name': tag,
            'comment': 'This object is maintained by the Barracuda Cloud Scraper',
            'included': [
                {
                    'entry': {
                        'ip': ip,
                        'comment': name
                    }
                }
                for name, ip in ips.items()]
        }
        LOG.info(payload)
        obj_url = reduce(urljoin, [cc_url, tag])
        obj_request = requests.get(obj_url, verify=False, headers=headers)
        if obj_request.ok:
            LOG.info('updating existing object: {}'.format(obj_url))
            resp = requests.put(obj_url, verify=False, headers=headers, json=payload)
        else:
            LOG.info('creating new object: {}'.format(payload.get('name')))
            resp = requests.post(cc_url, verify=False, headers=headers, json=payload)
        if resp.ok:
            LOG.info('Operation successfull')
        else:
            LOG.info(resp.text)
        resps.append(resp.text)


if __name__ == '__main__':
    cc_url: str = f'https://{credentials.get("cc-name")}:8443/rest/cc/v1/config/global/firewall/objects/networks/'
    tags: str = credentials.get("tags")
    cc_token: str = credentials.get("restkey")
    cloud2cc(cc_url, tags, cc_token)
