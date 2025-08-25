# Copyright 2025 Andromeda Security, Inc.
#
"""
This script updates the idp applications with the access management mode

Step1:
    fetch the api token from the Andromeda UI and run the script with the api token
Step2:
    export AS_SESSION_COOKIE=<session token> or
    export AS_API_TOKEN=<api token>
Example:
    python3 sdk/samples/andromeda_idp_provider_mode.py --idp_applications=Figma,Miro --access_management_mode=IDENTITY_ACCESS_VIA_GROUP_BINDING_CUSTOM_GROUP
    python3 sdk/samples/andromeda_idp_provider_mode.py --idp_applications=Figma,Miro --access_management_mode=PRINCIPAL_DIRECT_BINDING
"""
import argparse
import logging
import json
import os
from datetime import datetime, timedelta
from sdk.api_utils import APIUtils, InvalidInputException
from sdk.as_inventory import AndromedaInventory
import requests

logger = logging.getLogger(__name__)


def _setup_args() -> argparse.Namespace:
    help_str = """
    This script get list of identities matching a significance / insight

    Step1:
        fetch the api token from the Andromeda UI and run the script with the api token
    Step2:
       export AS_SESSION_COOKIE=<session token> or
       export AS_API_TOKEN=<api token>
    Example:
        python3 sdk/samples/andromeda_idp_provider_mode.py --idp_applications=Figma,Miro --access_management_mode=IDENTITY_ACCESS_VIA_GROUP_BINDING_CUSTOM_GROUP
        python3 sdk/samples/andromeda_idp_provider_mode.py --idp_applications=Figma,Miro --access_management_mode=PRINCIPAL_DIRECT_BINDING

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
    parser.add_argument('--idp_applications',
                        help='names of idp applications to be updated. If * then all idp applications will be updated')
    parser.add_argument('--idp_application_ids',
                        help='ids of idp applications to be updated. If * then all idp applications will be updated')
    parser.add_argument('--access_management_mode',
                        default="PRINCIPAL_DIRECT_BINDING",
                        help='IDP application mode',
                        choices=["PRINCIPAL_DIRECT_BINDING", "IDENTITY_ACCESS_VIA_GROUP_BINDING_CUSTOM_GROUP"])

    return parser.parse_args()

def _setup_logging():
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(lineno)s: %(message)s')
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

def _update_idp_applications(
        ai: AndromedaInventory, api_session: requests.Session,
        idp_applications: str, idp_application_ids: str,
        access_management_mode: str) -> None:
    """
    Update the idp applications with the access management mode
    Filter the idp applications based on the idp_applications filter
    Update the idp applications with the access management mode
    """
    idp_applications_filter = {}
    if idp_application_ids:
        idp_applications_filter = {"id": {"in": idp_application_ids.split(",")}}
    elif idp_applications:
        if idp_applications != "*":
            idp_applications_filter = {"name": {"in": idp_applications.split(",")}}
    else:
        raise InvalidInputException("Either idp_applications or idp_application_ids must be provided")
    logger.info("IDP applications filter: %s", idp_applications_filter)
    for idp_application in ai.app_provider_itr(filters=idp_applications_filter):
        logger.info("Updating idp application %s with access management mode %s",
                    idp_application["name"], access_management_mode)
        # get the idp application id
        idp_application_id = idp_application["id"]
        # get the idp application
        url = f"{ai.as_endpoint}/providers/{idp_application_id}/idpapplication/config"
        response = api_session.get(url)
        response.raise_for_status()
        idp_app_config_data = response.json()
        logger.info("IDP application config data: %s", idp_app_config_data)
        provisioning_config = {
            "provisioningPolicy": "PRINCIPAL_DIRECT_BINDING"
        }
        idp_app_config_data["mode"] = "ENFORCEMENT"
        if access_management_mode == "PRINCIPAL_DIRECT_BINDING":
            provisioning_config["provisioningPolicy"] = "PRINCIPAL_DIRECT_BINDING"
        elif access_management_mode == "IDENTITY_ACCESS_VIA_GROUP_BINDING_CUSTOM_GROUP":
            provisioning_config["provisioningPolicy"] = "IDENTITY_ACCESS_VIA_GROUP_BINDING"
            provisioning_config["managedProvisioningGroupConfig"] = {
                "matchType": "CUSTOM_GROUP"
            }
        else:
            raise InvalidInputException("Invalid access management mode %s", access_management_mode)
        if (idp_app_config_data["mode"] == "ENFORCEMENT" and
                idp_app_config_data["accessRequestProvisioningConfig"]['provisioningPolicy'] == provisioning_config['provisioningPolicy']):
            logger.info("IDP application %s is already in enforcement mode with the same provisioning policy", idp_application["name"])
            continue
        else:
            logger.info("IDP application %s is not in enforcement mode or the provisioning policy is different", idp_application["name"])
        idp_app_config_data["accessRequestProvisioningConfig"] = provisioning_config
        response = api_session.put(url, json=idp_app_config_data)
        response.raise_for_status()
        logger.info("Updated idp application %s with access management mode %s",
                    idp_app_config_data["name"], idp_app_config_data["accessRequestProvisioningConfig"])


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

    _update_idp_applications(
        as_inventory, api_session, args.idp_applications, args.idp_application_ids, args.access_management_mode)
