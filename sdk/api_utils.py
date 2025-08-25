# Copyright 2025 Andromeda Security, Inc.
#
"""
Andromeda Security API Utilities Module

This module provides utility classes and functions for interacting with the Andromeda Security API.
It includes functionality for:

- API authentication and session management
- Provider configuration and management (AWS, Azure, GCP, Okta, etc.)
- Resource creation, updates, and retrieval
- Policy rule management
- Environment and broker management

Classes:
    APIUtils: Main utility class for API operations
    InvalidInputException: Exception for invalid input parameters
    APISessionException: Exception for API session errors

The module supports various cloud providers and identity systems including:

Example usage:
    api_utils = APIUtils(api_endpoint="https://api.andromedasecurity.com")
    session = api_utils.get_api_session_w_api_token(login_token)
    status, provider = api_utils.create_or_update_base_provider(session, provider_obj)
"""

import logging
import traceback

import requests

logger = logging.getLogger(__name__)


class InvalidInputException(Exception):
    """
    Exception raised for invalid input parameters.
    """
    pass

class APISessionException(Exception):
    """
    Exception raised for API session errors.
    """
    pass


class APIUtils:
    def __init__(self, api_endpoint: str = "https://api.staging.andromedasecurity.com", api_session: requests.Session=None) -> None:
        self.api_endpoint = api_endpoint
        self.api_session = api_session

    def get_api_session_w_api_token(self, login_token: str) -> requests.Session:
        """
        This function returns a requests session object with the correct headers
        to authenticate with the Andromeda API
        """
        response = None
        try:
            session = requests.Session()
            data = {
                'code': login_token
            }
            response = session.post(
                f"{self.api_endpoint}/login/access-key", json=data,
                verify=False, headers={'Content-Type': 'application/json'})
        except Exception as exc:
            logger.error('Failed to login to API server %s', self.api_endpoint)
            logger.error('exception %s\n %s', exc, traceback.format_exc())
            raise exc
        if response.status_code != 200:
            logger.error('Failed to login to API server %s', self.api_endpoint)
            logger.error('API Response: %s', response.text)
        self.api_session = session
        return session

    def get_api_session_w_cookie(self, cookie: str) -> requests.Session:
        """
        This function returns a requests session object with the correct headers
        to authenticate with the Andromeda API
        """
        session = requests.Session()
        session.cookies.set('DS', cookie)
        return session


    def get_resource_url(self, resoure_type: str, resource_name: str = "", resource_id: str = "", subresource_path: str = "",
                         subresource_id: str = ""):
        """
        Eg. https://app.staging.andromeda.com/providers/1234/aws/config
        will be resource_type=providers, resource_id=1234, subresource_path=aws/config
        """
        url = f"{self.api_endpoint}/{resoure_type}"
        if resource_id:
            url = f"{url}/{resource_id}"
            if subresource_path:
                url = "/".join([url, subresource_path])
                if subresource_id:
                    url = "/".join([url, subresource_id])
        elif resource_name:
            if subresource_path:
                raise InvalidInputException(
                    "Cannot have subresource path without resource id")
            url = "?".join([url, f"filter= name = {resource_name}"])
        return url

    def create_or_update_resource(
            self, api_session: requests.Session, resource_type: str,
            resource_id: str = "", resource_name: str = "", obj: dict = None) -> tuple[int, dict]:
        try:
            status_code = 200
            logger.info("resource_type %s resource_name %s resource_id %s",
                         resource_type, resource_name, resource_id)
            if resource_name and not resource_id:
                status_code, existing_obj = self.get_resource_by_name(
                    api_session, resource_type, resource_name)
                if status_code == 200 and existing_obj:
                    existing_obj.update(obj)
                    obj = existing_obj
                    op = 'put'
                    url = self.get_resource_url(
                        resoure_type=resource_type, resource_id=obj['id'])
                    #logger.debug("found existing resource %s with id %s status_code %s",
                    #            resource_name, existing_obj, status_code)
                else:
                    # did not find the object so create it. Note cannot be subresource here
                    #logger.debug("creating new resource %s", resource_name)
                    op = 'post'
                    url = self.get_resource_url(
                        resoure_type=resource_type)
            elif resource_id:
                op = 'put'
                url = self.get_resource_url(
                    resoure_type=resource_type, resource_id=resource_id)
            else:
                op = 'post'
                url = self.get_resource_url(
                    resoure_type=resource_type, resource_id=resource_id)

            response = getattr(api_session, op)(url, json=obj, verify=False)
            status_code, obj = response.status_code, response.json()
            logger.debug("url:%s op:%s status_code:%s obj:%s", url, op, status_code, obj)
        except Exception as exc:
            logger.error('Failed to create provider object')
            logger.error('exception %s\n %s', exc, traceback.format_exc())
            raise exc
        return status_code, obj

    def get_resource_by_name(self, api_session: requests.Session, resource_type: str, resource_name: str) -> (int, dict):
        """
        This function returns a resource by name
        """
        response = api_session.get(self.get_resource_url(
            resoure_type=resource_type, resource_name=resource_name))
        resource_obj = None
        status_code = response.status_code
        if status_code == 200:
            if response.json()['results']:
                # adding a hack to iterate over the results because sometimes the filters don't work
                r = [r for r in response.json()['results'] if r['name'] == resource_name]
                if r :
                    resource_obj = r[0]
                    logger.debug("found resource %s %s",resource_type, resource_obj['name'])
                else:
                    status_code = 404
            else:
                status_code = 404
        return status_code, resource_obj

    def get_resources(self, api_session: requests.Session, resource_type: str) -> tuple[int, dict]:
        """
        This function returns all resources of a given type
        """
        response = api_session.get(self.get_resource_url(
            resoure_type=resource_type))
        return response.status_code, response.json()['results']

    def create_or_update_base_provider(self, api_session: requests.Session, provider_obj: dict) -> tuple[int, dict]:
        return self.create_or_update_resource(
            api_session, resource_type='providers', resource_id=provider_obj.get('id', ""),
            resource_name=provider_obj.get('name'),
            obj=provider_obj)

    def create_or_update_azure_provider_config(self, api_session: requests.Session, provider_id: str, azure_provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        #logger.info("creating azure config for provider %s,  %s", provider_id, azure_provider_obj)
        # check if the aws config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/azure/config")
        return self.create_or_update_provider(
            api_session=api_session, provider_id=provider_id, provider_config=azure_provider_obj,
            provider_url=url)

    def create_or_update_entra_provider_config(self, api_session: requests.Session, provider_id: str, azure_provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        #logger.debug("creating entra config for provider %s", provider_id)
        # check if the aws config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/entra/config")
        return self.create_or_update_provider(
            api_session=api_session, provider_id=provider_id, provider_config=azure_provider_obj,
            provider_url=url)

    def create_or_update_aws_provider_config(self, api_session: requests.Session, provider_id: str, aws_provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        #logger.debug("creating aws config for provider %s data %s", provider_id, aws_provider_obj)
        # check if the aws config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/aws/config")

        return self.create_or_update_provider(
            api_session=api_session,
            provider_id=provider_id, provider_config=aws_provider_obj, provider_url=url)


    def create_or_update_okta_provider_config(self, api_session: requests.Session, provider_id: str, okta_provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        #logger.debug("creating okta config for provider %s", provider_id)
        # check if the aws config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/okta/config")

        return self.create_or_update_provider(
            api_session=api_session,
            provider_id=provider_id, provider_config=okta_provider_obj, provider_url=url)

    def create_or_update_customapp_provider_config(self, api_session: requests.Session, provider_id: str, customapp_provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        return self.create_or_update_provider_config(
            api_session=api_session, provider_id=provider_id,
            provider_obj=customapp_provider_obj, provider_type="customapp")

    def create_or_update_workday_provider_config(self, andromeda_base_url, api_session: requests.Session, provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        config_url = f"{andromeda_base_url}/integrations/{provider_obj['id']}/workday"

        # Base data always includes name
        data = {
            "name": provider_obj['name'],
        }

        # Add workday configuration if present
        if 'workdayConfiguration' in provider_obj:
            workday_config = provider_obj['workdayConfiguration']
            data.update(workday_config)

        # Add fileId only if present (for CSV mode)
        if 'fileId' in provider_obj:
            data["fileId"] = provider_obj['fileId']

        response = api_session.get(config_url)
        resource_id = ""
        if response.status_code == 200 and response.json():
            resource_id = response.json()['id']
            new_config = response.json()
            # For updates, start fresh with just the existing config and carefully merge
            # Remove any fields that might cause duplicates
            if 'api_config' in new_config:
                del new_config['api_config']
            if 'apiConfig' in new_config:
                del new_config['apiConfig']
            # Update with new data
            for key, value in data.items():
                new_config[key] = value
            # Remove immutable fields for PUT operations (mode)
            if 'defaultMode' in new_config:
                del new_config['defaultMode']
            if 'userDataMappingProfile' in new_config:
                del new_config['userDataMappingProfile']
        else:
            new_config = data

        op = "put" if resource_id else "post"

        response = getattr(api_session, op)(config_url, json=new_config, verify=False)
        if response.status_code != 200:
            logger.error("config for provider op %s url %s provider %s status %s obj %s response %s",
                        op, config_url, provider_obj['id'], response.status_code, new_config, response.json())
        else:
            logger.debug("config for provider op %s url %s provider %s status %s response %s",
                        op, config_url, provider_obj['id'], response.status_code, response.json())
        return response.status_code, response.json()


    def create_or_update_provider_config(self, api_session: requests.Session, provider_id: str, provider_obj: dict, provider_type: str) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        #logger.info("creating %s config for provider %s", provider_type, provider_id)
        # check if the aws config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/{provider_type}/config")

        return self.create_or_update_provider(
            api_session=api_session,
            provider_id=provider_id, provider_config=provider_obj, provider_url=url)


    def create_or_update_provider(self,
            api_session: requests.Session,
            provider_id,
            provider_config,
            provider_url: str) -> tuple[int, dict]:
        # check if the aws config is already present
        response = api_session.get(provider_url)
        #logger.debug("config for provider %s status %s obj %s",
        #            provider_url, response.status_code, response.json())
        resource_id = ""
        if response.status_code == 200 and response.json():
            resource_id = response.json()['id']
            provider_config['id'] = resource_id
            provider_config['updatedAt'] = response.json()['updatedAt']
            #logger.debug("existing provider found -  provider config %s", response.json())
        op = "put" if resource_id else "post"
        response = getattr(api_session, op)(provider_url, json=provider_config, verify=False)
        if response.status_code != 200:
            logger.error("provider op:%s url:%s provider:%s status:%s obj:%s response:%s",
                        op, provider_url, provider_id, response.status_code, provider_config,
                        response.json())
        return response.status_code, response.json()

    def create_or_update_environment(self, api_session: requests.Session, environment_obj: dict) -> (int, dict):
        logger.debug("creating environment %s", environment_obj['name'])
        return self.create_or_update_resource(
            api_session, resource_type=f"environments", resource_name=environment_obj['name'], obj=environment_obj)

    def patch_policy_rules(self, patch: dict, policy: dict) -> dict:
        """
        works for following policies
        environmentmappingpolicies
        sensitivitymappingpolicies
        ownersmappingpolicies
        The patch should have list of rules as
        add_rules:
        delete_rules:

        The delete takes the precedence. Rule name is used to identity the rules. In case
        rule is already present then it would simply update with what has been passed down.
        """
        # find if rule exists
        deletion_rules = set([rule['name'] for rule in patch.get("delete_rules", [])])
        new_rules_map = {}
        for rule in patch.get('add_rules', []):
            new_rules_map[rule['name']] = rule
        result_rules = []
        for rule in policy['rules']:
            if rule['name'] in deletion_rules:
                continue
            if rule['name'] in new_rules_map:
                rule.update(new_rules_map[rule['name']])
                del new_rules_map[rule['name']]
            result_rules.append(rule)
        # now we are left with only new_rules that need to be added
        addition_rules = []
        for rule in patch.get('add_rules', []):
            if rule['name'] in new_rules_map:
                # it is truly new
                addition_rules.append(rule)
        policy['rules'] = addition_rules + result_rules
        return policy

    def get_provider_entra_config_object(self, auth_mode: str, azure_tenant_id: str, application_id: str, sec_acc_key: str) -> dict:

        """ Create azure provider config object """
        azure_provider = {
              "entraTenantId": azure_tenant_id,
              "authConfig": {
                  "authMode": auth_mode,
              }
        }
        if auth_mode == "AZURE_AUTHMODE_STATIC_CREDENTIALS":
            assumeRoleWithCredentials = {
                "applicationId": application_id,
                "secret": sec_acc_key
            }

            azure_provider['authConfig'][
                'staticCredentials'] = assumeRoleWithCredentials
        return azure_provider

    def get_provider_active_directory_config_object(self) -> dict:
        """ Create ad provider config object """
        ad_provider = {
            "authConfig": {
                "authMode": "AD_AUTHMODE_STATIC_CREDENTIALS",
                "staticCredentials": {
                    "password": "AD_PASSWORD",
                }
            },
            "activeDirectoryEndpoint": "ldaps://ec2-54-202-124-224.us-west-2.compute.amazonaws.com:636",
            "bindDn": "cn=Administrator,cn=Users,dc=example,dc=org",
            "baseDn": "dc=example,dc=org",
            "brokers": ["e7bcf2fb-dd19-41cd-9091-386634a05c6a"]
        }
        return ad_provider


    def get_provider_azure_config_object(self, auth_mode: str, azure_tenant_id: str, application_id: str, sec_acc_key: str) -> dict:

        """ Create azure provider config object """
        azure_provider = {
              "azureTenantId": azure_tenant_id,
              "authConfig": {
                  "authMode": auth_mode,
              }
        }
        if auth_mode == "AZURE_AUTHMODE_STATIC_CREDENTIALS":
            assumeRoleWithCredentials = {
                "applicationId": application_id,
                "secret": sec_acc_key
            }


            azure_provider['authConfig'][
                'staticCredentials'] = assumeRoleWithCredentials
        return azure_provider

    def get_provider_azure_log_config_object(self, logs_config: dict, application_id: str, sec_acc_key: str) -> dict:
        if logs_config is None:
            return logs_config
        azure_log_cred = {
            "applicationId": application_id,
            "secret": sec_acc_key
        }
        if logs_config.get("eventHub") != None and logs_config.get("eventHub").get("eventHubConfigs") != None:
            if len(logs_config.get("eventHub").get("eventHubConfigs")) > 0 and logs_config.get("eventHub").get("eventHubConfigs")[0].get("authConfig") != None:
                logs_config["eventHub"]["eventHubConfigs"][0]["authConfig"]["staticCredentials"] = azure_log_cred
        if logs_config.get("blobStorage") != None and logs_config.get("blobStorage").get("blobStorageConfigs") != None:
            if len(logs_config.get("blobStorage").get("blobStorageConfigs")) > 0 and logs_config.get("blobStorage").get("blobStorageConfigs")[0].get("authConfig") != None:
                logs_config["blobStorage"]["blobStorageConfigs"][0]["authConfig"]["staticCredentials"] = azure_log_cred
        return logs_config


    def get_provider_aws_config_object(
            self, auth_mode: str, mgmt_account_id: str, role_name: str,
            acc_key_id: str, sec_acc_key: str, trails: list,
            external_id: str="andromeda-test", iam_sso_integration_data: dict = None,
            deployment_modes: list = None, enable_resource_inventory: bool = False) -> dict:
        """ Create provider config object """
        # auth_mode = "AWS_AUTHMODE_ASSUME_ROLE_WITH_CREDENTIALS"
        aws_provider = {
            "accountsConfig": {
                "accounts": [
                    {
                        "accountId": mgmt_account_id,
                        "isManagementAccount": True
                    },
                ],
            },

            "cloudtrailConfig": {
                "trails": [],
            },
            "authConfig": {
                "authMode": auth_mode
            },
            "enableResourceInventory": enable_resource_inventory
        }
        if deployment_modes:
            aws_provider["deploymentModes"] = deployment_modes

        if auth_mode == "AWS_AUTHMODE_ASSUME_ROLE_WITH_CREDENTIALS":
            assumeRoleWithCredentials = {
                "accessKeyId": acc_key_id,
                "secretAccessKey": sec_acc_key,
                "roleName": role_name,
                "roleAccountId": "*",
            }
            aws_provider['authConfig'][
                'assumeRoleWithCredentials'] = assumeRoleWithCredentials
        elif auth_mode == "AWS_AUTHMODE_ASSUME_ROLE":
            assumeRole = {
                "roleName": role_name,
                "roleAccountID": "*",
                "externalId": external_id
            }
            aws_provider['authConfig']['assumeRole'] = assumeRole

        for trail in trails:
            trail_obj = {
                "trailArn": trail['arn'],
            }
            if trail.get('s3_bucket_account_id', ""):
                trail_obj['s3BucketAccountId'] = trail['s3_bucket_account_id']
            aws_provider['cloudtrailConfig']['trails'].append(trail_obj)
        if iam_sso_integration_data:
            aws_provider['iamSsoIntegration'] = iam_sso_integration_data
        return aws_provider

    def get_iam_provider_config_object(
            self, auth_mode: str, account_id: str, role_name: str,
            acc_key_id: str, sec_acc_key: str, trails: list,
            external_id: str="andromeda-test") -> dict:
        """ Create provider config object """
        # auth_mode = "AWS_AUTHMODE_ASSUME_ROLE_WITH_CREDENTIALS"
        iam_provider = {
            "accountsConfig": {
                "accounts": [
                    {
                        "accountId": account_id,
                        "isManagementAccount": False
                    }
                ],
            },
            "cloudtrailConfig": {
                "trails": [],
            },
            "authConfig": {
                "authMode": auth_mode
            }
        }
        if auth_mode == "AWS_AUTHMODE_ASSUME_ROLE_WITH_CREDENTIALS":
            assumeRoleWithCredentials = {
                "accessKeyId": acc_key_id,
                "secretAccessKey": sec_acc_key,
                "roleName": role_name,
                "roleAccountId": "*",
            }
            iam_provider['authConfig'][
                'assumeRoleWithCredentials'] = assumeRoleWithCredentials
        elif auth_mode == "AWS_AUTHMODE_ASSUME_ROLE":
            assumeRole = {
                "roleName": role_name,
                "roleAccountID": "*",
                "externalId": external_id
            }
            iam_provider['authConfig']['assumeRole'] = assumeRole

        for trail in trails:
            trail_obj = {
                "trailArn": trail['arn'],
            }
            if trail.get('s3_bucket_account_id', ""):
                trail_obj['s3BucketAccountId'] = trail['s3_bucket_account_id']
            iam_provider['cloudtrailConfig']['trails'].append(trail_obj)

        return iam_provider

    def create_eligibility(
            self, api_session: requests.Session,
            provider_id: str,
            eligibility_mapping: dict) -> (int, dict):
        try:
            url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/eligibility")
            response = api_session.post(url, json=eligibility_mapping, verify=False)
            status_code, obj = response.status_code, response.json()
            return status_code, obj
        except:
            raise APISessionException("Failed to create eligibility")

    def accept_delete_identity_risk_inside_account(
        self,
        api_session: requests.Session,
        account_id: str,
        identity_id: str,
        request_type: str,
    ):
        """
        This function creates a post/delete request to update accepted_risk for an identity inside an account
        """
        url = f"{self.api_endpoint}/identities/{identity_id}/accounts/{account_id}/accepted-risk"

        logger.debug(
            "accept_delete_identity_risk_inside_account: RequestType: %s | URL: %s",
            request_type,
            url,
        )

        response = None
        if request_type == "POST":
            response = api_session.post(url)
        elif request_type == "DELETE":
            response = api_session.delete(url)
        else:
            logger.error("Invalid request_type: %s. Must be 'POST' or 'DELETE'", request_type)
            return

        logger.debug(
            "accept_delete_identity_risk_inside_account: ResponseStatus: %s",
            response.status_code,
        )

    def get_provider_gcp_config_object(
            self, auth_mode: str, organization_id: str, service_account_key: str, audit_logs_config: dict = None) -> dict:
        """ Create gcp provider config object """
        gcp_provider = {
            "organizationId": organization_id,
            "authConfig": {
                "authMode": auth_mode,
                "serviceAccount": {
                    "keyJson": service_account_key
                }
            },
            "auditLogsConfig": audit_logs_config
        }
        return gcp_provider

    def create_or_update_gcp_provider_config(
            self, api_session: requests.Session, provider_id: str, gcp_provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        #logger.info("creating gcp config for provider %s", provider_id)
        # check if the aws config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/gcp/config")
        return self.create_or_update_provider(
            api_session=api_session, provider_id=provider_id, provider_config=gcp_provider_obj,
            provider_url=url)

    def create_or_update_sfdc_provider_config(
            self, api_session: requests.Session, provider_id: str, sfdc_provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        #logger.info("creating gcp config for provider %s", provider_id)
        # check if the aws config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/salesforce/config")
        return self.create_or_update_provider(
            api_session=api_session, provider_id=provider_id, provider_config=sfdc_provider_obj,
            provider_url=url)

    def create_or_update_mongodb_provider_config(
            self, api_session: requests.Session, provider_id: str, provider_config: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        #logger.info("creating gcp config for provider %s", provider_id)
        # check if the aws config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/atlas/config")
        return self.create_or_update_provider(
            api_session=api_session, provider_id=provider_id, provider_config=provider_config,
            provider_url=url)

    def get_provider_google_workspace_config_object(
            self, auth_mode: str, domain: str, admin_email: str, service_account_key: str, audit_logs_config: dict = None) -> dict:
        """ Create gcp provider config object """
        gw_provider = {
            "domain": domain,
            "adminEmail": admin_email,
            "authConfig": {
                "authMode": auth_mode,
                "serviceAccount": {
                    "keyJson": service_account_key
                }
            },
            "auditLogsConfig": audit_logs_config
        }

        return gw_provider

    def create_or_update_google_workspace_provider_config(
            self, api_session: requests.Session, provider_id: str, workspace_provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        logger.info("creating google workspace config for provider %s", provider_id)
        # check if the aws config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/googleworkspace/config")
        return self.create_or_update_provider(
            api_session=api_session, provider_id=provider_id, provider_config=workspace_provider_obj,
            provider_url=url)

    def get_provider_ad_config_object(self, ad_configuration: dict, broker_id: str) -> dict:
        """ Create ad provider config object """
        ad_provider = {
            "authConfig": {
                "authMode": ad_configuration["authConfig"]["authMode"],
                "staticCredentials": {
                    "password": ad_configuration["authConfig"]["staticCredentials"]["password"],
                }
            },
            "activeDirectoryEndpoint": ad_configuration["activeDirectoryEndpoint"],
            "bindDn": ad_configuration["bindDn"],
            "baseDn": ad_configuration["baseDn"],
            "brokers": [broker_id],
            "ldapFilters": {
                "userFilter": ad_configuration["ldapFilters"]["userFilter"],
                "groupFilter": ad_configuration["ldapFilters"]["groupFilter"],
            }
        }
        return ad_provider

    def create_or_update_ad_provider_config(
            self, api_session: requests.Session, provider_id: str, ad_provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        #logger.info("creating ad config for provider %s", provider_id)
        # check if the aws config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/activedirectory/config")
        return self.create_or_update_provider(
            api_session=api_session, provider_id=provider_id, provider_config=ad_provider_obj,
            provider_url=url)

    def create_default_broker(self, api_session: requests.Session) -> tuple[int, dict]:
        """
        This function creates a default broker
        """
        logger.info("creating default broker")
        url = self.get_resource_url(resoure_type=f"brokers")
        response = api_session.get(url)
        broker_data = {
            "broker": {
                "name": "test-default-broker"
            }
        }
        response_json = response.json()
        if response.status_code == 200 and response_json and response_json['count'] > 0:
            logger.debug("default broker already exists with id %s", response_json['results'][0]['id'])
            return response.status_code, response_json['results'][0]
        else:
            logger.debug("default broker does not exist, creating new one")
            response = getattr(api_session, "post")(url, json=broker_data, verify=False)
            return response.status_code, response.json()

    def create_broker_secret(self, api_session: requests.Session, broker_id: str) -> tuple[int, dict]:
        """
        This function creates or updates the broker secret
        """
        logger.info("creating broker secret for broker %s", broker_id)
        url = self.get_resource_url(resoure_type=f"brokers/{broker_id}/auth-config")
        response = getattr(api_session, "post")(url)
        return response.status_code, response.json()

    def get_provider_pingone_config_object(
            self, environment_id: str, region: str, client_id: str, client_secret: str) -> dict:
        """ Create PingOne provider config object """
        pingone_provider = {
            "environmentId": environment_id,
            "region": region,
            "authConfig": {
                "authMode": "PINGONE_AUTHMODE_STATIC_CREDENTIALS",
                "staticCredentials": {
                    "clientId": client_id,
                    "clientSecret": client_secret
                }
            }
        }
        return pingone_provider

    def create_or_update_pingone_provider_config(
            self, api_session: requests.Session, provider_id: str, pingone_provider_obj: dict) -> tuple[int, dict]:
        """
        This function creates or updates the cloud specific settings for a provider
        """
        #logger.info("creating pingone config for provider %s", provider_id)
        # check if the pingone config is already present
        url = self.get_resource_url(
                resoure_type=f"providers/{provider_id}/pingone/config")
        return self.create_or_update_provider(
            api_session=api_session, provider_id=provider_id, provider_config=pingone_provider_obj,
            provider_url=url)
