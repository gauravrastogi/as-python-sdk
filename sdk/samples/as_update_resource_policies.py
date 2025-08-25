"""
# Copyright 2025 Andromeda Security, Inc.

This script updates the resource policies used for resource set JIT.

Step1:
    fetch the api token from the Andromeda UI and run the script with the api token
Step2:
    export AS_SESSION_COOKIE=<session token> or
    export AS_API_TOKEN=<api token>
Example:
    python3 sdk/samples/as_update_resource_policies.py --resource_policies_location=/tmp/resource_policies.json --provider_id=aws_provider_id
"""

import argparse
import logging
import json
import os
import time
from sdk.api_utils import APIUtils, InvalidInputException
from sdk.as_inventory import AndromedaInventory
import requests

logger = logging.getLogger(__name__)


def _setup_args() -> argparse.Namespace:
    help_str = """
    This script updates the resource policies used for resource set JIT.

    Step1:
        fetch the api token from the Andromeda UI and run the script with the api token
    Step2:
       export AS_SESSION_COOKIE=<session token> or
       export AS_API_TOKEN=<api token>
    Example:
        # update resource policies for resource set JIT
        python3 sdk/samples/as_update_resource_policies.py --resource_policies_location=/tmp/resource_policies.json --provider_id=aws_provider_id
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=(help_str)
    )
    parser.add_argument('--as_api_token', '-t',
                        help='API token for Andromeda')
    parser.add_argument('--as_session_token', '-s',
                        help='Session token for Andromeda')
    parser.add_argument('--as_api_endpoint',
                        default="https://api.live.andromedasecurity.com",
                        help='GQL endpoint for the inventory')
    parser.add_argument('--as_gql_endpoint',
                        default="https://api.live.andromedasecurity.com/graphql",
                        help='GQL endpoint for the inventory')
    parser.add_argument('--resource_policies_location',
                        help='location of the resource policies to be updated. The location is the json file',
                        required=True)
    parser.add_argument('--provider_id',
                        help='provider id to update the resource policies for',
                        required=True)

    return parser.parse_args()

def _setup_logging():
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(module)s:%(lineno)s: %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


def _get_api_session(api_endpoint: str, as_session_token: str, as_api_token: str) -> requests.Session:
    """
    Get the API session from the arguments or environment variables
    Args:
        args: argparse.ArgumentParser
    Returns:
        APIUtils
    """
    au = APIUtils(api_endpoint=api_endpoint)
    as_session_token = as_session_token or os.getenv("AS_SESSION_COOKIE", "")
    if as_session_token:
        return au.get_api_session_w_cookie(as_session_token)
    as_api_token = as_api_token or os.getenv("AS_API_TOKEN", "")
    if as_api_token:
        return au.get_api_session_w_api_token(as_api_token)
    raise InvalidInputException(
        "Either as_api_token or as_session_token must be provided")

def update_resource_policies(
        as_inventory: AndromedaInventory,
        api_session: requests.Session,
        as_api_endpoint: str,
        resource_policies_location: str,
        provider_id: str) -> None:
    """
    Update the resource policies used for resource set JIT.
    """
    with open(resource_policies_location, 'r', encoding='utf-8') as f:
        resource_policies = json.load(f)
    logger.info("Resource policies: %s", len(resource_policies))

    provider = next(as_inventory.cloud_provider_itr(
        filters={"type": {"equals": "PROVIDER_TYPE_AWS"}, "id": {"equals": provider_id}}))
    assert provider['type'] == "PROVIDER_TYPE_AWS", f"Provider is not of type AWS {provider['type']}"
    # get the resource policies for the provider
    for resource_policy in resource_policies:
        # check if the resource policy already exists
        resource_policy["name"] = f"{resource_policy['name']}"
        filters = {"policyName": { "equals": resource_policy["name"] },
                   "eligibilityType": { "equals": "RESOURCE_SET_ELIGIBILITY" }}
        policy_obj = next(as_inventory.provider_assignable_policies_itr(
            provider_id, provider, filters=filters), None)
        op = "put" if policy_obj else "post"
        # check if the data is stringified json
        resource_policy["type"] = "CUSTOM"
        data = resource_policy["policyDocument"]["data"]
        if isinstance(data, str):
            try:
                data = json.loads(data)
                #resource_policy["policyDocument"]["data"] = data
            except json.JSONDecodeError:
                logger.error("Invalid JSON data for resource policy: %s", resource_policy)
                raise
        elif isinstance(data, dict):
            resource_policy["policyDocument"]["data"] = json.dumps(data)
        else:
            logger.error("Invalid data type for resource policy: %s", resource_policy)
            raise InvalidInputException(
                f"Invalid data type for resource policy: {resource_policy}")
        #logger.info("Creating or updating resource policy: %s \n%s",
        #            name, json.dumps(resource_policy, indent=2))

        if op == 'put':
            assert policy_obj, f"Policy not found for {resource_policy['name']}"
            #logger.info("Updating resource policy: %s from %s", resource_policy['name'], json.dumps(policy_obj, indent=2))
            url = f"{as_api_endpoint}/providers/{provider['id']}/resource-policies/{policy_obj['policyId']}"
            response = api_session.get(url)
            response.raise_for_status()
            resource_policy_obj = response.json()
            resource_policy_obj['policyDocument'] = resource_policy['policyDocument']
            logger.info("Resource policy: %s", json.dumps(resource_policy_obj, indent=2))
            response = api_session.put(url, json=resource_policy_obj)
            response.raise_for_status()
            resource_policy = response.json()
        else:
            #logger.info("Creating resource policy: %s", resource_policy['name'])
            url = f"{as_api_endpoint}/providers/{provider['id']}/resource-policies"
            response = api_session.post(url, json=resource_policy)
            response.raise_for_status()
            resource_policy = response.json()
            time.sleep(2)
        logger.info("Resource policy: op %s: %s", op, json.dumps(resource_policy, indent=2))

if __name__ == '__main__':
    args = _setup_args()
    _setup_logging()
    as_api_endpoint = args.as_api_endpoint
    api_session = _get_api_session(args.as_api_endpoint, args.as_session_token, args.as_api_token)
    if not api_session:
        raise ValueError("API session not found")
    as_inventory = AndromedaInventory(
        None, api_session=api_session,
        output_dir="/tmp/andromeda-inventory",
        as_endpoint=as_api_endpoint, gql_endpoint=args.as_gql_endpoint)
    api_utils = APIUtils(api_endpoint=args.as_api_endpoint)
    update_resource_policies(
        as_inventory, api_session, as_api_endpoint,
        args.resource_policies_location, args.provider_id)
