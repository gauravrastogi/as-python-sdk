# Copyright 2025 Andromeda Security, Inc.
#
import argparse
import os
import logging
from typing import Generator, Optional
import functools
import json
import csv
import time
import traceback
from collections import namedtuple
import requests
from gql import Client, gql
from gql.dsl import (DSLQuery, dsl_gql, DSLSchema, DSLInlineFragment, DSLMetaField)
from gql.transport.requests import RequestsHTTPTransport
from api.graphql import graphql_query_snippets as gql_snippets
from sdk.api_utils import APIUtils

logger = logging.getLogger(__name__)
logging.getLogger("urllib3").setLevel(logging.WARNING)

DEFAULT_PAGE_SIZE = 100

class AndromedaProvider(dict):
    def __init__(self):
        super().__init__()
        self['activeBindings'] = {
            'configured': [],
            'resolved': []
        }
        self['humans'] = {}
        self['nhis'] = {}
        self['groups'] = {}
        self['roles'] = {}
        self['accounts'] = {}
        self['assignableGroups'] = {}
        self['assignableUsers'] = {}
        self['assignablePolicies'] = {}
        self['applicationAssignments'] = []
        self['eligibilities'] = {}


class AndromedaInventory(dict):
    """
    AndromedaInventory is a class that fetches the inventory from the Andromeda API.
    It is a subclass of dict and can be used as a dictionary.
    """
    def __init__(self, gql_client: Client, api_session: requests.Session, output_dir: str = ".",
                 pacer_duration_s: int = 2, default_page_size: int = DEFAULT_PAGE_SIZE, as_endpoint: str= "http://localhost:8080",
                 gql_endpoint: str = "http://localhost:8088/graphql"):
        super().__init__()
        self.gql_client = gql_client
        self.api_session = api_session
        # check and create the output directory
        response = api_session.get(f"{as_endpoint}/tenantsettings")
        response.raise_for_status()
        self.tenant_id = response.json()["tenantId"]
        self.output_dir = f"{output_dir}/{self.tenant_id}"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.pacer_duration_s = pacer_duration_s
        self['provider_map'] = {}
        self.default_page_size = default_page_size
        self.as_endpoint = as_endpoint
        if not self.gql_client:
            self.gql_client = self.get_gql_client(api_session, gql_endpoint)

    @property
    def provider_map(self):
        return self['provider_map']


    def get_gql_client(self, api_session: requests.Session, graphql_url: str):
        """ Create GraphQL client and schema from the API session """
        logger.debug("Creating GraphQL client %s", graphql_url)
        transport = RequestsHTTPTransport(url=graphql_url,
                                    headers=api_session.headers,
                                    cookies=api_session.cookies,
                                    timeout=240)
        client = Client(transport=transport, fetch_schema_from_transport=True)
        introspection = "{__schema{queryType{name}}}"
        client.execute(gql(introspection))
        return client

    def as_gql_generic_itr(self, base_fn: functools.partial, *args, **kwargs) -> Generator[dict, None, None]:
        """"
        expects the base function to be a partial function with the following signature:
        base_fn(batch_size: int, skip: int, *args, **kwargs) -> Generator[dict, None, None]

        Usage:
        1. Create a function that can take batch_size and skip as arguments and return a generator.
        2. Create a partial function with the function and any additional arguments.
            def get_provider_privilege_users(provider_id: str, as_test_run_id: str, privilege_user_suffix: str,
                gql_client: Client, page_size: int = 100, skip: int = 0):
        3. Use the as_gql_generic_itr to iterate over the generator.
            partial_fn_itr = functools.partial(
                get_provider_privilege_users, e2e_provider['id'], as_test_run_id, privilege_user_suffix, gql_client)
            as_identities = []
            for identity in self.as_gql_generic_itr(partial_fn_itr):
                as_identities.append(identity)
        """
        page_size = kwargs.get('page_size', 100)
        max_items = kwargs.get('max_count', 10000)
        skip = 0
        rate_limit = kwargs.get('rate_limit', 1)
        for pop_arg in ['page_size', 'skip']:
            kwargs.pop(pop_arg, None)
        for skip in range(0, max_items, page_size):
            try:
                #logger.debug("Fetching items: page_size %s skip %s", page_size, skip)
                items = base_fn(page_size, skip, *args, **kwargs)
            except AssertionError:
                raise
            except Exception as e:
                logger.error("base_fn %s Skipping iteration as failed to get the items: page_size %s skip %s with error %s",
                            base_fn.func.__func__, page_size, skip, e)
                logger.error(traceback.format_exc())
                raise
            if not items:
                # breaking the loop as we are guessing the make number of entries in the iteration
                # instead of knowing exactly how many entries are there. If result is empty, we can break.
                break
            for item in items:
                yield item
            if len(items) < page_size:
                # Fewer items returned than the page_size indicates this is the last batch
                break
            if rate_limit:
                time.sleep(rate_limit)


    def as_provider_accounts_base_fn(
            self, provider_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:

        logger.debug("Fetching accounts for provider %s filters %s page_size %s skip %s",
                    provider_id, filters, page_size, skip)

        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.accounts(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.AccountsConnection.edges.select(
                        ds.AccountEdge.node.select(
                            *gql_snippets.list_trivial_fields_Account(ds),
                            ds.Account.identities.select(
                                ds.AccountIdentitiesConnection.pageInfo.select(
                                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                                ),
                            ),
                            ds.Account.serviceIdentities.select(
                                ds.AccountServiceIdentitiesConnection.pageInfo.select(
                                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                                ),
                            ),
                            ds.Account.accountIdentitiesSummary.select(
                                *gql_snippets.list_trivial_fields_AccountIdentitiesSummary(ds),
                                ds.AccountIdentitiesSummary.groupedBySignificance.select(
                                    *gql_snippets.list_trivial_fields_AccountIdentitiesGroupedBySignificance(ds),
                                ),
                                ds.AccountIdentitiesSummary.groupedByBlastRiskLevel.select(
                                    *gql_snippets.list_trivial_fields_AccountIdentitiesGroupedByBlastRiskLevel(ds),
                                ),
                                ds.AccountIdentitiesSummary.groupedByState.select(
                                    ds.IdentityGroupedByState.state,
                                    ds.IdentityGroupedByState.count,
                                ),
                                ds.AccountIdentitiesSummary.groupedByRiskCategory.select(
                                    *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategorySummary(ds),
                                    ds.IdentityGroupedByRiskCategorySummary.categories.select(
                                        *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategory(ds),
                                        ds.IdentityGroupedByRiskCategory.factors.select(
                                            *gql_snippets.list_trivial_fields_IdentityGroupedByRiskFactor(ds),
                                        )
                                    )
                                ),
                            ),
                            ds.Account.accountServiceIdentitiesSummary.select(
                                ds.AccountServiceIdentitiesSummary.groupedBySignificance.select(
                                    *gql_snippets.list_trivial_fields_AccountServiceIdentitiesGroupedBySignificance(ds),
                                ),
                                ds.AccountServiceIdentitiesSummary.groupedByBlastRiskLevel.select(
                                    *gql_snippets.list_trivial_fields_AccountIdentitiesGroupedByBlastRiskLevel(ds),
                                ),
                                ds.AccountServiceIdentitiesSummary.groupedByRiskCategory.select(
                                    *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategorySummary(ds),
                                    ds.IdentityGroupedByRiskCategorySummary.categories.select(
                                        *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategory(ds),
                                        ds.IdentityGroupedByRiskCategory.factors.select(
                                            *gql_snippets.list_trivial_fields_IdentityGroupedByRiskFactor(ds),
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    ds.AccountsConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        accountNodes = response["data"]['Provider']['accounts']['edges']
        accounts = [node['node'] for node in accountNodes]
        logger.debug("num accounts returned %s", len(accounts))
        return accounts

    def provider_accounts_itr(self, provider_id: str, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_provider_accounts_base_fn, provider_id, filters)
        for account in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield account

    def provider_resource_groups_base_fn(self, provider_id: str, account_id: str, filters: dict,
                                        page_size: int, skip: int) -> Generator[list, None, None]:
        """
        Fetch the resource groups for a given account
        """
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Account(
                id=account_id,
                providerId=provider_id
            ).select(
                ds.Account.resourceGroups(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters
                ).select(
                    ds.ResourceGroupConnection.edges.select(
                        ds.ResourceGroupEdge.node.select(
                            ds.ResourceGroup.id(),
                            ds.ResourceGroup.name(),
                            ds.ResourceGroup.externalId(),
                        )
                    ),
                    ds.ResourceGroupConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        rg_nodes = response["data"]['Account']['resourceGroups']['edges']
        rgs = [node['node'] for node in rg_nodes]
        logger.debug("num resource groups returned %s", len(rgs))
        return rgs

    def provider_resource_groups_itr(self, provider_id: str, account_id: str, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        """
        Fetch the resource groups for a given account
        """
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.provider_resource_groups_base_fn, provider_id, account_id, filters)
        for resource_group in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield resource_group

    def _fetch_accounts(self, provider_id: str, provider_data: dict) -> dict:
        for account in self.provider_accounts_itr(provider_id):
            provider_data["accounts"][account["id"]] = account
        logger.debug("provider %s accounts  %d", provider_id, len(self.provider_map[provider_id]["accounts"]))

    def as_provider_accounts_policies_data_base_fn(
            self, provider_id: str, account_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching policies for provider %s account %s filters %s page_size %s skip %s",
                    provider_id, account_id, filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Account(
                id=account_id,
                providerId=provider_id
            ).select(
                ds.Account.id(),
                ds.Account.name(),
                ds.Account.policiesData(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters
                    ).select(
                        ds.AccountPoliciesDataConnection.edges.select(
                            ds.AccountPolicyDataEdge.node.select(
                                ds.AccountPolicyData.policyId(),
                                ds.AccountPolicyData.policyName(),
                                ds.AccountPolicyData.policyType(),
                                ds.AccountPolicyData.blastRisk(),
                                ds.AccountPolicyData.blastRiskLevel(),
                                ds.AccountPolicyData.policyLastUsedAt(),
                                ds.AccountPolicyData.opsInsights.select(
                                    *gql_snippets.list_trivial_fields_PolicyOpsInsightData(ds),
                                ),
                                ds.AccountPolicyData.policyDetails.select(
                                    ds.AccountPolicyDetailsConnection.pageInfo.select(
                                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                                    )
                                ),
                                ds.AccountPolicyData.permissionsSummary.select(
                                    *gql_snippets.list_trivial_fields_PermissionsSummary(ds),
                                    ds.PermissionsSummary.permissionsAccessLevelSummary.select(
                                        *gql_snippets.list_trivial_fields_PermissionsAccessLevelSummary(ds),
                                    ),
                                ),
                                ds.AccountPolicyData.activities(
                                    pageArgs={"pageSize": 10,
                                              "sort": "-timestamp"},
                                ).select(
                                    ds.ActivitiesConnection.edges.select(
                                        ds.ActivityEdge.node.select(
                                            *gql_snippets.list_trivial_fields_Activity(ds),
                                        ),
                                    ),
                                    ds.ActivitiesConnection.pageInfo.select(
                                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                                    ),
                                ),
                            )
                        ),
                        ds.AccountPoliciesDataConnection.pageInfo.select(
                            *gql_snippets.list_trivial_fields_PageInfo(ds),
                        )
                    )
                )
            )
        )
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        policyNodes = response["data"]['Account']['policiesData']['edges']
        policies = [node['node'] for node in policyNodes]
        logger.debug("num policies returned %s", len(policies))
        return policies

    def provider_account_policies_itr(self, provider_id: str, account_id: str,
                                filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_provider_accounts_policies_data_base_fn, provider_id, account_id, filters)
        for as_policy in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield as_policy

    def as_provider_policies_data_base_fn(
            self, provider_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching policies for provider %s filters %s page_size %s skip %s",
                    provider_id, filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.id(),
                ds.Provider.name(),
                ds.Provider.policies(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters
                    ).select(
                        ds.PoliciesConnection.edges.select(
                            ds.PolicyEdge.node.select(
                                ds.Policy.id(),
                                ds.Policy.name(),
                                ds.Policy.policyType(),
                                ds.Policy.accountName(),
                                ds.Policy.accountId(),
                                ds.Policy.externalId(),
                                ds.Policy.policyOpsInsights.select(
                                    *gql_snippets.list_trivial_fields_PolicyOpsInsightData(ds),
                                ),
                            )
                        ),
                        ds.PoliciesConnection.pageInfo.select(
                            *gql_snippets.list_trivial_fields_PageInfo(ds),
                        )
                    )
                )
            )
        )
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        policyNodes = response["data"]['Provider']['policies']['edges']
        policies = [node['node'] for node in policyNodes]
        logger.debug("num policies returned %s", len(policies))
        return policies

    def provider_policies_itr(self, provider_id: str, filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_provider_policies_data_base_fn, provider_id, filters)
        for as_policy in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield as_policy

    def as_provider_active_bindings_base_fn(self, provider_id: str,
                                            provider_data: dict, resolved_view: bool, filters: dict,
                                            page_size: int, skip: int) -> Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        scope_rg_fragment = DSLInlineFragment()
        scope_rg_fragment.on(ds.ResourceGroupScopeData)
        scope_account_fragment = DSLInlineFragment()
        scope_account_fragment.on(ds.AccountScopeData)
        scope_folder_fragment = DSLInlineFragment()
        scope_folder_fragment.on(ds.FolderScopeData)
        filters = filters or {}
        filters['isResolved'] = resolved_view
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.activeBindings(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters
                    ).select(
                    ds.AccountPolicyIdentityBindingsConnection.edges.select(
                        ds.AccountPolicyIdentityBindingEdge.node.select(
                            *gql_snippets.list_trivial_fields_AccountPolicyIdentityBinding(ds),
                            ds.AccountPolicyIdentityBinding.policyData.select(
                                ds.AccountPolicyData.policyId(),
                                ds.AccountPolicyData.policyName(),
                                ds.AccountPolicyData.policyType(),
                                ds.AccountPolicyData.policyLastUsedAt(),
                            ),
                            ds.AccountPolicyIdentityBinding.scope.select(
                                scope_rg_fragment.select(
                                    ds.ResourceGroupScopeData.name(),
                                    ds.ResourceGroupScopeData.id(),
                                    ds.ResourceGroupScopeData.isInherited(),
                                    DSLMetaField("__typename")
                                ),
                                scope_account_fragment.select(
                                    ds.AccountScopeData.name(),
                                    ds.AccountScopeData.id(),
                                    ds.AccountScopeData.isInherited(),
                                    DSLMetaField("__typename")
                                ),
                                scope_folder_fragment.select(
                                    ds.FolderScopeData.name(),
                                    ds.FolderScopeData.id(),
                                    ds.FolderScopeData.isInherited(),
                                    DSLMetaField("__typename")
                                )
                            ),
                            ds.AccountPolicyIdentityBinding.principalData.select(
                                *gql_snippets.list_trivial_fields_PrincipalData(ds),
                            ),
                            ds.AccountPolicyIdentityBinding.trustEdges.select(
                                ds.IncomingTrustsConnection.edges.select(
                                    ds.IncomingTrustEdge.node.select(
                                        *gql_snippets.list_trivial_fields_TrustEdges(ds),
                                        ds.TrustEdges.trustedPrincipalData.select(
                                            *gql_snippets.list_trivial_fields_PrincipalData(ds),
                                        )
                                    )
                                ),
                                ds.IncomingTrustsConnection.pageInfo.select(
                                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                                )
                            )
                        )
                    ),
                    ds.AccountPolicyIdentityBindingsConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        bindings = response["data"]['Provider']['activeBindings']['edges']
        page_info = response["data"]['Provider']['activeBindings']['pageInfo']
        logger.debug("bindings %s page_info %s batch_size %s skip %s filters=%s", len(bindings), page_info, page_size, skip, filters)
        fbindings = [binding['node'] for binding in bindings]
        return fbindings

    def provider_active_bindings_itr(self, provider_id: str, provider_data: dict, resolved_view: bool,
                                     filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_provider_active_bindings_base_fn, provider_id, provider_data, resolved_view, filters)
        for binding in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield binding

    def as_provider_user_resolved_assignments_base_fn(
            self, provider_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        scope_rg_fragment = DSLInlineFragment()
        scope_rg_fragment.on(ds.ResourceGroupScopeData)
        scope_account_fragment = DSLInlineFragment()
        scope_account_fragment.on(ds.AccountScopeData)
        scope_folder_fragment = DSLInlineFragment()
        scope_folder_fragment.on(ds.FolderScopeData)

        principal_identity_origin_fragment = DSLInlineFragment()
        principal_identity_origin_fragment.on(ds.IdentityOriginData)
        principal_service_identity_fragment = DSLInlineFragment()
        principal_service_identity_fragment.on(ds.ServiceIdentity)
        principal_group_fragment = DSLInlineFragment()
        principal_group_fragment.on(ds.Group)
        principal_role_fragment = DSLInlineFragment()
        principal_role_fragment.on(ds.AccountPolicyData)

        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.id(),
                ds.Provider.name(),
                ds.Provider.type(),
                ds.Provider.userResolvedAssignments(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters
                    ).select(
                    ds.AccountPolicyUserResolvedAssignmentsConnection.edges.select(
                        ds.AccountPolicyUserResolvedAssignmentEdge.node.select(
                            #*gql_snippets.list_trivial_fields_AccountPolicyUserResolvedAssignment(ds),
                            ds.AccountPolicyUserResolvedAssignment.providerName(),
                            ds.AccountPolicyUserResolvedAssignment.accountName(),
                            ds.AccountPolicyUserResolvedAssignment.roleName(),
                            #ds.AccountPolicyUserResolvedAssignment.policyBindingLastUsedAt(),
                            ds.AccountPolicyUserResolvedAssignment.principalUsername(),
                            ds.AccountPolicyUserResolvedAssignment.roleData.select(
                                ds.AccountPolicyData.policyId(),
                                ds.AccountPolicyData.policyName(),
                                ds.AccountPolicyData.policyType(),
                                #ds.AccountPolicyData.policyLastUsedAt(),
                            ),
                            ds.AccountPolicyUserResolvedAssignment.scope.select(
                                scope_rg_fragment.select(
                                    ds.ResourceGroupScopeData.name(),
                                    ds.ResourceGroupScopeData.id(),
                                    ds.ResourceGroupScopeData.isInherited(),
                                    DSLMetaField("__typename")
                                ),
                                scope_account_fragment.select(
                                    ds.AccountScopeData.name(),
                                    ds.AccountScopeData.id(),
                                    ds.AccountScopeData.isInherited(),
                                    DSLMetaField("__typename")
                                ),
                                scope_folder_fragment.select(
                                    ds.FolderScopeData.name(),
                                    ds.FolderScopeData.id(),
                                    ds.FolderScopeData.isInherited(),
                                    DSLMetaField("__typename")
                                )
                            ),
                            ds.AccountPolicyUserResolvedAssignment.principal.select(
                                principal_identity_origin_fragment.select(
                                    ds.IdentityOriginData.originUserId(),
                                    ds.IdentityOriginData.originUserName(),
                                    ds.IdentityOriginData.originUserUsername(),
                                    ds.IdentityOriginData.identity.select(
                                        *gql_snippets.list_trivial_fields_Identity(ds),
                                        DSLMetaField("__typename")
                                    ),
                                    DSLMetaField("__typename")
                                ),
                                principal_service_identity_fragment.select(
                                    *gql_snippets.list_trivial_fields_ServiceIdentity(ds),
                                    DSLMetaField("__typename")
                                )
                            ),
                            ds.AccountPolicyUserResolvedAssignment.identityRoleData.select(
                                ds.IdentityPolicyData.policyId(),
                                ds.IdentityPolicyData.policyName(),
                                ds.IdentityPolicyData.policyType(),
                                #*gql_snippets.list_trivial_fields_IdentityPolicyData(ds),
                            ),
                            ds.AccountPolicyUserResolvedAssignment.serviceIdentityRoleData.select(
                                ds.ServiceIdentityPolicyData.policyId(),
                                ds.ServiceIdentityPolicyData.policyName(),
                                ds.ServiceIdentityPolicyData.policyType(),
                                #*gql_snippets.list_trivial_fields_ServiceIdentityPolicyData(ds),
                            ),
                            ds.AccountPolicyUserResolvedAssignment.opsInsights.select(
                                *gql_snippets.list_trivial_fields_PolicyBindingOpsInsightsData(ds),
                            ),
                            ds.AccountPolicyUserResolvedAssignment.configuredAssignments.select(
                                ds.ProviderAssignmentDataConnection.edges.select(
                                    ds.ProviderAssignmentDataEdge.node.select(
                                        ds.ProviderAssignmentData.assignmentType(),
                                        ds.ProviderAssignmentData.accessRequestId(),
                                        ds.ProviderAssignmentData.isAndromedaManaged(),
                                        ds.ProviderAssignmentData.isDirectBinding(),
                                        #*gql_snippets.list_trivial_fields_ProviderAssignmentData(ds),
                                        ds.ProviderAssignmentData.principal.select(
                                            principal_identity_origin_fragment.select(
                                                ds.IdentityOriginData.originUserId(),
                                                ds.IdentityOriginData.originUserName(),
                                                ds.IdentityOriginData.originUserUsername(),
                                                ds.IdentityOriginData.identity.select(
                                                    *gql_snippets.list_trivial_fields_Identity(ds),
                                                    DSLMetaField("__typename")
                                                ),
                                                DSLMetaField("__typename")
                                            ),
                                            principal_service_identity_fragment.select(
                                                ds.ServiceIdentity.username(),
                                                ds.ServiceIdentity.id(),
                                                ds.ServiceIdentity.serviceIdentityType(),
                                                DSLMetaField("__typename")
                                            ),
                                            principal_group_fragment.select(
                                                ds.Group.name(),
                                                ds.Group.id(),
                                                DSLMetaField("__typename")
                                            ),
                                            principal_role_fragment.select(
                                                ds.AccountPolicyData.policyId(),
                                                ds.AccountPolicyData.policyName(),
                                                ds.AccountPolicyData.policyType(),
                                                DSLMetaField("__typename")
                                            ),
                                        ),
                                        ds.ProviderAssignmentData.scope.select(
                                            scope_rg_fragment.select(
                                                ds.ResourceGroupScopeData.name(),
                                                ds.ResourceGroupScopeData.id(),
                                                ds.ResourceGroupScopeData.isInherited(),
                                                DSLMetaField("__typename")
                                            ),
                                            scope_account_fragment.select(
                                                ds.AccountScopeData.name(),
                                                ds.AccountScopeData.id(),
                                                ds.AccountScopeData.isInherited(),
                                                DSLMetaField("__typename")
                                            ),
                                            scope_folder_fragment.select(
                                                ds.FolderScopeData.name(),
                                                ds.FolderScopeData.id(),
                                                ds.FolderScopeData.isInherited(),
                                                DSLMetaField("__typename")
                                            )
                                        ),
                                    ),
                                ),
                                ds.ProviderAssignmentDataConnection.pageInfo.select(
                                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                                ),
                            ),
                        )
                    ),
                    ds.AccountPolicyUserResolvedAssignmentsConnection.pageInfo.select(
                       *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        assignments = response["data"]['Provider']['userResolvedAssignments']['edges']
        #page_info = response["data"]['Provider']['userResolvedAssignments']['pageInfo']
        logger.debug("assignments %s batch_size %s skip %s filters=%s", len(assignments), page_size, skip, filters)
        assignments = [binding['node'] for binding in assignments]
        return assignments

    def as_provider_user_resolved_assignments_itr(self, provider_id: str,
            filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_provider_user_resolved_assignments_base_fn, provider_id, filters)
        for assignment in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield assignment

    def provider_humans_base_fn(self, provider_id: str, provider_data: dict, filters: dict,
                                page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.identities(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.ProviderIdentitiesConnection.edges.select(
                        ds.ProviderIdentityEdge.node.select(
                            *gql_snippets.list_trivial_fields_Identity(ds),
                            ds.Identity.origins(
                                pageArgs={"pageSize": 100},
                            ).select(
                                ds.IdentityOriginDataConnection.edges.select(
                                    ds.IdentityOriginDataEdge.node.select(
                                        *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                                        ds.IdentityOriginData.identity.select(
                                            *gql_snippets.list_trivial_fields_Identity(ds),
                                        )
                                    ),
                                ),
                            ),
                            ds.Identity.orgInfo.select(
                                *gql_snippets.list_trivial_fields_HrIdentityInfo(ds),
                            ),
                            ds.Identity.opsInsights.select(
                                *gql_snippets.list_trivial_fields_IdentityOpsInsightData(ds),
                            ),
                            ds.Identity.riskFactorsData.select(
                                *gql_snippets.list_trivial_fields_RiskFactorData(ds),
                            ),
                        ),
                        ds.ProviderIdentityEdge.identityProviderData.select(
                            *gql_snippets.list_trivial_fields_IdentityProviderData(ds),
                            ds.IdentityProviderData.eligiblePolicies.select(
                                ds.IdentityPolicyEligibilityDataConnection.edges.select(
                                    ds.IdentityPolicyEligibilityDataEdge.node.select(
                                        *gql_snippets.list_trivial_fields_IdentityPolicyEligibilityData(ds),
                                        ds.IdentityPolicyEligibilityData.eligibleUsers(
                                            pageArgs={"pageSize": 100},
                                        ).select(
                                            ds.EligibleUserIncarnationsConnection.edges.select(
                                                ds.EligibleUserIncarnationEdge.node.select(
                                                    *gql_snippets.list_trivial_fields_EligibleUserIncarnation(ds),
                                                ),
                                            ),
                                            ds.EligibleUserIncarnationsConnection.pageInfo.select(
                                                *gql_snippets.list_trivial_fields_PageInfo(ds),
                                            ),
                                        ),
                                    )
                                ),
                            ),
                        ),
                    ),
                    ds.ProviderIdentitiesConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        identityNodes = response["data"]['Provider']['identities']['edges']
        humans = []
        for item in identityNodes:
            human = item['node']
            human['identityProviderData'] = item['identityProviderData']
            humans.append(human)
        for human in humans:
            human['origins'] = [origin['node'] for origin in human['origins']['edges']]
        logger.debug("num identities returned %s", len(identityNodes))
        return humans

    def provider_humans_itr(self, provider_id: str, provider_data: dict,
                            filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.provider_humans_base_fn, provider_id, provider_data, filters)
        for human in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield human

    def as_humans_base_fn(self, filters: dict,
                                page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Identities(
                pageArgs={"pageSize": page_size, "skip": skip},
                filters=filters
            ).select(
                ds.IdentitiesConnection.edges.select(
                    ds.IdentityEdge.node.select(
                        *gql_snippets.list_trivial_fields_Identity(ds),
                        ds.Identity.origins(
                            pageArgs={"pageSize": 100},
                            filters={"isReference": False}
                        ).select(
                            ds.IdentityOriginDataConnection.edges.select(
                                ds.IdentityOriginDataEdge.node.select(
                                    *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                                    ds.IdentityOriginData.awsIamData.select(
                                        ds.IdentityAwsIamData.arn(),
                                        ds.IdentityAwsIamData.id(),
                                        ds.IdentityAwsIamData.path(),
                                        ds.IdentityAwsIamData.username(),
                                    )
                                ),
                            ),
                        ),
                        ds.Identity.orgInfo.select(
                            *gql_snippets.list_trivial_fields_HrIdentityInfo(ds),
                        ),
                        ds.Identity.opsInsights.select(
                            *gql_snippets.list_trivial_fields_IdentityOpsInsightData(ds),
                        ),
                        ds.Identity.riskFactorsData.select(
                            *gql_snippets.list_trivial_fields_RiskFactorData(ds),
                        ),
                    ),
                ),
                ds.IdentitiesConnection.pageInfo.select(
                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                )
            )
        ))

        response = self.gql_client.execute(query, get_execution_result=True).formatted
        identity_nodes = response["data"]['Identities']['edges']
        humans = []
        for item in identity_nodes:
            human = item['node']
            humans.append(human)
        # for human in humans:
        #     human['origins'] = [origin['node'] for origin in human['origins']['edges']]
        logger.debug("num identities returned %s", len(identity_nodes))
        return humans

    def as_humans_itr(self, filters=None, page_size: int = None, *args, **kwargs) -> Generator[dict, None, None]:
        """
        Get all humans from the inventory
        :param filters: filters to apply to the query
        :param page_size: page size to use for the query
        :param args: additional arguments to pass to the query
        :param kwargs: additional keyword arguments to pass to the query
        :return: generator of human dictionaries
        """
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_humans_base_fn, filters)
        yield from self.as_gql_generic_itr(partial_fn_itr, page_size=page_size)

    def as_non_humans_identities_base_fn(
            self, filters: dict, page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        """
        Get all non humans from the inventory
        :param filters: filters to apply to the query
        :param page_size: page size to use for the query
        :param args: additional arguments to pass to the query
        :param kwargs: additional keyword arguments to pass to the query
        :return: generator of non human dictionaries
        """
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.ServiceIdentities(
                pageArgs={"pageSize": page_size, "skip": skip},
                filters=filters
            ).select(
                ds.ServiceIdentitiesConnection.edges.select(
                    ds.ServiceIdentityEdge.node.select(
                        *gql_snippets.list_trivial_fields_ServiceIdentity(ds),

                        ds.ServiceIdentity.opsInsights.select(
                            *gql_snippets.list_trivial_fields_ServiceIdentityOpsInsightData(ds),
                        ),
                        ds.ServiceIdentity.riskFactorsData.select(
                            *gql_snippets.list_trivial_fields_ServiceIdentityRiskFactorData(ds),
                        ),
                        ds.ServiceIdentity.knownDevices.select(
                            ds.KnownDevicesConnection.edges.select(
                                ds.KnownDeviceEdge.node.select(
                                    *gql_snippets.list_trivial_fields_KnownDevice(ds),
                                ),
                            ),
                        ),
                        ds.ServiceIdentity.lastActivity.select(
                            *gql_snippets.list_trivial_fields_Activity(ds),
                        ),
                    ),
                ),
                ds.ServiceIdentitiesConnection.pageInfo.select(
                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                )
            )
        ))

        response = self.gql_client.execute(query, get_execution_result=True).formatted
        identity_nodes = response["data"]['ServiceIdentities']['edges']
        non_humans = []
        for item in identity_nodes:
            non_human = item['node']
            non_humans.append(non_human)
        logger.debug("num identities returned %s", len(identity_nodes))
        return non_humans

    def as_non_humans_identities_itr(self, filters=None, page_size: int = None, *args, **kwargs) -> Generator[dict, None, None]:
        """
        Get all non humans from the inventory
        :param filters: filters to apply to the query
        :param page_size: page size to use for the query
        :param args: additional arguments to pass to the query
        :param kwargs: additional keyword arguments to pass to the query
        :return: generator of human dictionaries
        """
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_non_humans_identities_base_fn, filters)
        yield from self.as_gql_generic_itr(partial_fn_itr, page_size=page_size)



    def provider_groups_base_fn(self, provider_id: str, provider_data: dict, filters: dict,
                                page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.groups(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.ProviderGroupsConnection.edges.select(
                        ds.ProviderGroupDataEdge.node.select(
                            *gql_snippets.list_trivial_fields_Group(ds),
                            ds.Group.members.select(
                                *gql_snippets.list_trivial_fields_GroupMembers(ds),
                                ds.GroupMembers.humanUsers(
                                    pageArgs={"pageSize": 100},
                                ).select(
                                    ds.GroupHumanMembersDataConnection.edges.select(
                                        ds.GroupHumanMembersDataEdge.node.select(
                                            *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                                        ),
                                    ),
                                    ds.GroupHumanMembersDataConnection.pageInfo.select(
                                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                                    ),
                                ),
                                ds.GroupMembers.serviceIdentities.select(
                                    ds.GroupNonHumanMembersDataConnection.edges.select(
                                        ds.GroupNonHumanMembersDataEdge.node.select(
                                            *gql_snippets.list_trivial_fields_ServiceIdentity(ds),
                                        ),
                                    ),
                                    ds.GroupNonHumanMembersDataConnection.pageInfo.select(
                                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                                    ),
                                ),
                                ds.GroupMembers.groups.select(
                                    ds.GroupsConnection.pageInfo.select(
                                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                                    ),
                                ),
                            ),
                        ),
                        ds.ProviderGroupDataEdge.providerGroupsData.select(
                            *gql_snippets.list_trivial_fields_ProviderGroupsData(ds),
                            ds.ProviderGroupsData.members.select(
                                *gql_snippets.list_trivial_fields_ProviderGroupMembers(ds),
                                ds.GroupMembers.humanUsers.select(
                                    ds.GroupHumanMembersDataConnection.edges.select(
                                        ds.GroupHumanMembersDataEdge.node.select(
                                            *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                                        ),
                                    ),
                                    # ds.IdentityOriginDataConnection.pageInfo.select(
                                    #     *gql_snippets.list_trivial_fields_PageInfo(ds),
                                    # ),
                                ),
                                ds.GroupMembers.serviceIdentities.select(
                                    ds.GroupNonHumanMembersDataConnection.edges.select(
                                        ds.GroupNonHumanMembersDataEdge.node.select(
                                            *gql_snippets.list_trivial_fields_ServiceIdentity(ds),
                                        ),
                                    ),
                                    ds.GroupNonHumanMembersDataConnection.pageInfo.select(
                                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                                    ),
                                ),
                            ),
                        ),
                    ),
                    ds.ProviderGroupsConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        nodes = response["data"]['Provider']['groups']['edges']
        items = [node['node'] for node in nodes]
        logger.debug("provider %s num groups returned %s", provider_id, len(nodes))
        return items

    def as_provider_groups_itr(self, provider_id: str, provider_data: dict,
                            filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        logger.debug("Fetching groups for provider %s filters %s", provider_id, filters)
        partial_fn_itr = functools.partial(
            self.provider_groups_base_fn, provider_id, provider_data, filters)
        for item in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield item


    def as_groups_base_fn(self, filters: dict,
            page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Groups(
                pageArgs={"pageSize": page_size, "skip": skip},
                filters=filters
            ).select(
                ds.GroupsConnection.edges.select(
                    ds.GroupDataEdge.node.select(
                        *gql_snippets.list_trivial_fields_Group(ds),
                        ds.Group.members.select(
                            *gql_snippets.list_trivial_fields_GroupMembers(ds),
                            ds.GroupMembers.humanUsers(
                                pageArgs={"pageSize": 100},
                            ).select(
                                ds.GroupHumanMembersDataConnection.edges.select(
                                    ds.GroupHumanMembersDataEdge.node.select(
                                        *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                                    ),
                                ),
                                ds.GroupHumanMembersDataConnection.pageInfo.select(
                                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                                ),
                            ),
                            ds.GroupMembers.serviceIdentities.select(
                                ds.GroupNonHumanMembersDataConnection.edges.select(
                                    ds.GroupNonHumanMembersDataEdge.node.select(
                                        *gql_snippets.list_trivial_fields_ServiceIdentity(ds),
                                    ),
                                ),
                                ds.GroupNonHumanMembersDataConnection.pageInfo.select(
                                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                                ),
                            ),
                            ds.GroupMembers.groups.select(
                                ds.GroupsConnection.pageInfo.select(
                                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                                ),
                            ),
                        ),
                    ),
                ),
                ds.GroupsConnection.pageInfo.select(
                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        nodes = response["data"]['Groups']['edges']
        items = [node['node'] for node in nodes]
        logger.debug("num groups returned %s", len(nodes))
        return items

    def as_groups_itr(self, filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        logger.debug("Fetching groups for filters %s", filters)
        partial_fn_itr = functools.partial(
            self.as_groups_base_fn, filters)
        for item in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield item

    def get_provider_group_human_users_base_fn(self, provider_id: str, group_name: str, filters: dict, page_size: int, skip: int) -> Generator[dict, None, None]:
        logger.debug("Getting human members of group %s", group_name)

        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.groups(
                    filters={"name": {"equals": group_name}}
                    ).select(
                    ds.ProviderGroupsConnection.edges.select(
                        ds.ProviderGroupDataEdge.providerGroupsData.select(
                            *gql_snippets.list_trivial_fields_ProviderGroupsData(ds),
                            ds.ProviderGroupsData.members.select(
                                *gql_snippets.list_trivial_fields_ProviderGroupMembers(ds),
                                ds.GroupMembers.humanUsers(
                                    pageArgs={"pageSize": page_size, "skip": skip},
                                    filters=filters
                                ).select(
                                    ds.GroupHumanMembersDataConnection.edges.select(
                                        ds.GroupHumanMembersDataEdge.node.select(
                                            *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                                        ),
                                    ),
                                    ds.GroupHumanMembersDataConnection.pageInfo.select(
                                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                                    ),
                                ),
                            ),
                        ),
                    ),
                    ds.ProviderGroupsConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        group_data = next(iter(response["data"]['Provider']['groups']['edges']))
        human_members_nodes = group_data['providerGroupsData']['members']['humanUsers']['edges']
        human_members = [h['node'] for h in human_members_nodes]
        logger.debug("group %s members: %s page_size %s skip %s",
                     group_name, len(human_members), page_size, skip)
        return human_members

    def as_provider_group_humans_itr(self, provider_id:str, group_name: str, filters: str=None) -> Generator[dict, None, None]:
        partial_fn_itr = functools.partial(
            self.get_provider_group_human_users_base_fn, provider_id, group_name, filters)
        for identity_origin_data in self.as_gql_generic_itr(partial_fn_itr):
            yield identity_origin_data

    def provider_assignable_users_base_fn(self, provider_id: str, provider_data: dict, filters: dict,
                                page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.id(),
                ds.Provider.name(),
                ds.Provider.assignableUsers(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.AssignableUserDataConnection.edges.select(
                        ds.AssignableUserDataEdge.node.select(
                            *gql_snippets.list_trivial_fields_AssignableUserData(ds),
                            ds.AssignableUserData.userDetails.select(
                                *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                            ),
                        ),
                    ),
                    ds.AssignableUserDataConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        nodes = response["data"]['Provider']['assignableUsers']['edges']
        items = [node['node'] for node in nodes]
        logger.debug("provider %s num assignable users returned %s",
                     response["data"]['Provider']['name'], len(nodes))
        return items

    def provider_assignable_users_itr(self, provider_id: str, provider_data: dict,
                                        filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.provider_assignable_users_base_fn, provider_id, provider_data, filters)
        for item in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield item

    def provider_assignable_policies_base_fn(self, provider_id: str, provider_data: dict, filters: dict,
                                page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.id(),
                ds.Provider.name(),
                ds.Provider.assignablePolicies(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.AccountPoliciesDataConnection.edges.select(
                        ds.AccountPolicyDataEdge.node.select(
                            *gql_snippets.list_trivial_fields_AccountPolicyData(ds),
                        ),
                    ),
                    ds.AccountPoliciesDataConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        nodes = response["data"]['Provider']['assignablePolicies']['edges']
        items = [node['node'] for node in nodes]
        logger.debug("provider %s num assignable policies returned %s",
                     response["data"]['Provider']['name'], len(nodes))
        return items

    def provider_assignable_policies_itr(self, provider_id: str, provider_data: dict,
                                        filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.provider_assignable_policies_base_fn, provider_id, provider_data, filters)
        for item in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield item

    def provider_assignable_groups_base_fn(self, provider_id: str, provider_data: dict, filters: dict,
                                page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.id(),
                ds.Provider.name(),
                ds.Provider.assignableGroups(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.AssignableGroupsConnection.edges.select(
                        ds.AssignableGroupDataEdge.node.select(
                            *gql_snippets.list_trivial_fields_AssignableGroup(ds),
                            ds.AssignableGroup.groupDetails.select(
                                *gql_snippets.list_trivial_fields_Group(ds),
                                ds.Group.members.select(
                                    *gql_snippets.list_trivial_fields_GroupMembers(ds),
                                    ds.GroupMembers.humanUsers.select(
                                        ds.GroupHumanMembersDataConnection.pageInfo.select(
                                            *gql_snippets.list_trivial_fields_PageInfo(ds),
                                        )
                                    ),
                                    ds.GroupMembers.serviceIdentities.select(
                                        ds.GroupNonHumanMembersDataConnection.pageInfo.select(
                                            *gql_snippets.list_trivial_fields_PageInfo(ds),
                                        )
                                    ),
                                    ds.GroupMembers.groups.select(
                                        ds.GroupsConnection.pageInfo.select(
                                            *gql_snippets.list_trivial_fields_PageInfo(ds),
                                        )
                                    )
                                ),
                            ),
                        ),
                    ),
                    ds.AssignableGroupsConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        nodes = response["data"]['Provider']['assignableGroups']['edges']
        items = [node['node'] for node in nodes]
        logger.debug("provider %s num assignable groups returned %s",
                     response["data"]['Provider']['name'],len(nodes))
        return items

    def provider_assignable_groups_itr(self, provider_id: str, provider_data: dict,
                                        filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.provider_assignable_groups_base_fn, provider_id, provider_data, filters)
        for item in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield item


    def account_humans_base_fn(self, provider_id: str, account_id: str, account_data: dict, filters: dict,
                                page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Account(
                providerId=provider_id,
                id=account_id
            ).select(
                ds.Account.identities(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.AccountIdentitiesConnection.edges.select(
                        ds.AccountIdentityEdge.node.select(
                            *gql_snippets.list_trivial_fields_Identity(ds),
                        ),
                        ds.AccountIdentityEdge.identityAccountData.select(
                            *gql_snippets.list_trivial_fields_IdentityAccountData(ds),

                            ds.IdentityAccountData.opsInsights.select(
                                *gql_snippets.list_trivial_fields_IdentityOpsInsightData(ds),
                            ),
                            ds.IdentityAccountData.riskFactorsData.select(
                                *gql_snippets.list_trivial_fields_RiskFactorData(ds),
                            ),
                        ),
                    ),
                    ds.AccountIdentitiesConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        identityNodes = response["data"]['Account']['identities']['edges']
        humans = [node['node'] for node in identityNodes]
        logger.debug("num identities returned %s", len(identityNodes))
        return humans

    def account_humans_itr(self, provider_id: str, account_id: str, account_data: dict,
                            filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.account_humans_base_fn, provider_id, account_id, account_data, filters)
        try:
            for human in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
                yield human
        except Exception as e:
            logger.error("Error fetching account humans for provider %s account %s with error %s",
                         provider_id, account_data['name'], e)

    def account_nhis_base_fn(self, provider_id: str, account_id: str, account_data: dict, filters: dict,
                                page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Account(
                providerId=provider_id,
                id=account_id
            ).select(
                ds.Account.serviceIdentities(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.AccountServiceIdentitiesConnection.edges.select(
                        ds.AccountServiceIdentityEdge.node.select(
                            *gql_snippets.list_trivial_fields_ServiceIdentity(ds),
                        ),
                        ds.AccountServiceIdentityEdge.serviceIdentityAccountData.select(
                            *gql_snippets.list_trivial_fields_ServiceIdentityAccountData(ds),

                            ds.ServiceIdentityAccountData.opsInsights.select(
                                *gql_snippets.list_trivial_fields_ServiceIdentityOpsInsightData(ds),
                            ),
                            ds.ServiceIdentityAccountData.riskFactorsData.select(
                                *gql_snippets.list_trivial_fields_ServiceIdentityRiskFactorData(ds),
                            ),
                        ),
                    ),
                    ds.AccountServiceIdentitiesConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        identityNodes = response["data"]['Account']['serviceIdentities']['edges']
        nhis = [node['node'] for node in identityNodes]
        logger.debug("num identities returned %s", len(identityNodes))
        return nhis

    def account_nhis_itr(self, provider_id: str, account_id: str, account_data: dict,
                            filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.account_nhis_base_fn, provider_id, account_id, account_data, filters)
        try:
            for nhi in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
                yield nhi
        except Exception as e:
            logger.error("Error fetching account humans for provider %s account %s with error %s",
                         provider_id, account_data['name'], e)

    def provider_nhis_base_fn(self, provider_id: str, provider_data: dict, filters: dict,
                                page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        azure_metadata_fragment = DSLInlineFragment()
        azure_metadata_fragment.on(ds.AzureServiceIdentity)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.id(),
                ds.Provider.name(),
                ds.Provider.serviceIdentities(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.ProviderServiceIdentitiesConnection.edges.select(
                        ds.ProviderServiceIdentityEdge.node.select(
                            *gql_snippets.list_trivial_fields_ServiceIdentity(ds),
                            ds.ServiceIdentity.opsInsights.select(
                                *gql_snippets.list_trivial_fields_ServiceIdentityOpsInsightData(ds),
                            ),
                            ds.ServiceIdentity.riskFactorsData.select(
                                *gql_snippets.list_trivial_fields_ServiceIdentityRiskFactorData(ds),
                            ),
                            ds.ServiceIdentity.metadata.select(
                                azure_metadata_fragment.select(
                                    ds.AzureServiceIdentity.subType,
                                    DSLMetaField("__typename")
                                ),
                            ),
                            ds.ServiceIdentity.accessData.select(
                                ds.AccessData.accessKeyData.select(
                                    ds.AccessKeyDataConnection.edges.select(
                                        ds.AccessKeysDataEdge.node.select(
                                            *gql_snippets.list_trivial_fields_AccessKeyData(ds),
                                        )
                                    ),
                                    ds.AccessKeyDataConnection.pageInfo.select(
                                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                                    ),
                                )
                            )
                        ),
                    ),
                    ds.ProviderServiceIdentitiesConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        identityNodes = response["data"]['Provider']['serviceIdentities']['edges']
        nhis = [node['node'] for node in identityNodes]
        logger.debug("num identities returned %s", len(identityNodes))
        return nhis

    def provider_nhis_itr(
            self, provider_id: str, provider_data: dict, filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size

        partial_fn_itr = functools.partial(
            self.provider_nhis_base_fn, provider_id, provider_data, filters)
        for item in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield item


    def provider_application_assignments_base_fn(self, provider_id: str, provider_data: dict, filters: dict,
            page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        principal_identity_fragment = DSLInlineFragment()
        principal_identity_fragment.on(ds.IdentityOriginData)
        principal_nhi_fragment = DSLInlineFragment()
        principal_nhi_fragment.on(ds.ServiceIdentity)
        principal_group_fragment = DSLInlineFragment()
        principal_group_fragment.on(ds.Group)

        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.id(),
                ds.Provider.name(),
                ds.Provider.applicationAssignments(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.ProviderAssignmentsConnection.edges.select(
                        ds.ProviderAssignmentsEdge.node.select(
                            *gql_snippets.list_trivial_fields_ProviderAssignmentsData(ds),
                            ds.ProviderAssignmentsData.assignmentData.select(
                                *gql_snippets.list_trivial_fields_ProviderAssignmentData(ds),
                            ),
                            ds.ProviderAssignmentsData.policy.select(
                                *gql_snippets.list_trivial_fields_Policy(ds),
                            ),
                            ds.ProviderAssignmentsData.principal.select(
                                principal_identity_fragment.select(
                                    *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                                ),
                                principal_group_fragment.select(
                                    *gql_snippets.list_trivial_fields_Group(ds),
                                ),
                                principal_nhi_fragment.select(
                                    ds.ServiceIdentity.id(),
                                    ds.ServiceIdentity.username(),
                                    ds.ServiceIdentity.serviceIdentityType(),
                                    ds.ServiceIdentity.originAccountName(),
                                ),
                            ),
                        ),
                    ),
                    ds.ProviderAssignmentsConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        assignments = response["data"]['Provider']['applicationAssignments']['edges']
        assignments = [node['node'] for node in assignments]
        logger.debug("num assignments returned %s", len(assignments))
        return assignments

    def provider_application_assignments_itr(
            self, provider_id: str, provider_data: dict, filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.provider_application_assignments_base_fn, provider_id, provider_data, filters)
        for item in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield item

    def provider_eligibilities_base_fn(self, provider_id: str, provider_data: dict, filters: dict,
                                page_size: int = 100, skip: int = 0) ->Generator[list, None, None]:
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id
            ).select(
                ds.Provider.eligibilityMappings(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.PolicyEligibilityMappingsConnection.edges.select(
                        ds.PolicyEligibilityMappingEdge.node.select(
                            *gql_snippets.list_trivial_fields_PolicyEligibilityMapping(ds),
                        ),
                    ),
                    ds.PolicyEligibilityMappingsConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        eligibilityNodes = response["data"]['Provider']['eligibilityMappings']['edges']
        eligibilities = [node['node'] for node in eligibilityNodes]
        logger.debug("num eligibilities returned %s", len(eligibilities))
        return eligibilities

    def provider_eligibilities_itr(self, provider_id: str, provider_data: dict,
                            filters=None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.provider_eligibilities_base_fn, provider_id, provider_data, filters)
        for eligibility in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield eligibility

    def download_inventory(self, provider_id: str = "", use_cached: bool = False) -> str:
        inventory_dir = f"{self.output_dir}"
        if not os.path.exists(inventory_dir):
            os.makedirs(inventory_dir)
        self.inventory_data_file = f"{inventory_dir}/andromeda-inventory.json"
        if not use_cached or not os.path.exists(self.inventory_data_file):
            logger.info("Fetching inventory file %s for provider %s as use_cache %s file_exists %s",
                        self.inventory_data_file, provider_id, use_cached, os.path.exists(self.inventory_data_file))
            self._fetch_ai_inventory(provider_id)
        with open(self.inventory_data_file, "w") as f:
            json.dump(self.provider_map, f, indent=2)
        return self.inventory_data_file


    def as_cloud_provider_base_fn(
            self, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching providers filters %s page_size %s skip %s",
                    filters, page_size, skip)
        updated_filters = filters if filters else {}
        updated_filters['category'] = {'equals': 'CLOUD'}
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Providers(
                filters=updated_filters,
                pageArgs={"pageSize": page_size, "skip": skip}
            ).select(
                ds.ProvidersConnection.edges.select(
                    ds.ProviderEdge.node.select(
                        *gql_snippets.list_trivial_fields_Provider(ds),
                        ds.Provider.providerIdentitiesSummary.select(
                            ds.ProviderIdentitiesSummary.groupedByState.select(
                                *gql_snippets.list_trivial_fields_IdentityGroupedByState(ds),
                            ),
                            ds.ProviderIdentitiesSummary.groupedByRiskLevel.select(
                                *gql_snippets.list_trivial_fields_IdentityGroupedByRiskLevel(ds),
                            ),
                            ds.ProviderIdentitiesSummary.groupedByRiskCategory.select(
                                *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategorySummary(ds),
                                ds.IdentityGroupedByRiskCategorySummary.categories.select(
                                    *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategory(ds),
                                    ds.IdentityGroupedByRiskCategory.factors.select(
                                        *gql_snippets.list_trivial_fields_IdentityGroupedByRiskFactor(ds),
                                    )
                                ),
                            ),
                            ds.ProviderIdentitiesSummary.groupedBySignificance.select(
                                *gql_snippets.list_trivial_fields_ProviderIdentitiesGroupedBySignificance(ds),
                            ),
                            ds.ProviderIdentitiesSummary.accessKeysSummary.select(
                                ds.AccessKeysSummary.rotationPastDueCount(),
                                ds.AccessKeysSummary.accessKeysCount(),
                                ds.AccessKeysSummary.accessKeyInactive_365DaysPlus(),
                                ds.AccessKeysSummary.accessKeyInactive_180_365Days(),
                                ds.AccessKeysSummary.accessKeyInactive_90_180Days(),
                                ds.AccessKeysSummary.accessKeyInactive_30_90Days(),
                            ),
                            ds.ProviderIdentitiesSummary.groupedByHrType.select(
                                *gql_snippets.list_trivial_fields_IdentityGroupedByHrType(ds),
                            ),
                        ),
                        ds.Provider.providerServiceIdentitiesSummary.select(
                            ds.ProviderServiceIdentitiesSummary.groupedByRiskLevel.select(
                                *gql_snippets.list_trivial_fields_IdentityGroupedByRiskLevel(ds),
                            ),
                            ds.ProviderServiceIdentitiesSummary.groupedByRiskCategory.select(
                                *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategorySummary(ds),
                                ds.IdentityGroupedByRiskCategorySummary.categories.select(
                                    *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategory(ds),
                                    ds.IdentityGroupedByRiskCategory.factors.select(
                                        *gql_snippets.list_trivial_fields_IdentityGroupedByRiskFactor(ds),
                                    )
                                ),
                            ),
                            ds.ProviderServiceIdentitiesSummary.groupedBySignificance.select(
                                *gql_snippets.list_trivial_fields_ProviderServiceIdentitiesGroupedBySignificance(ds),
                            ),
                            ds.ProviderServiceIdentitiesSummary.accessKeysSummary.select(
                                ds.AccessKeysSummary.rotationPastDueCount(),
                                ds.AccessKeysSummary.accessKeysCount(),
                                ds.AccessKeysSummary.accessKeyInactive_365DaysPlus(),
                                ds.AccessKeysSummary.accessKeyInactive_180_365Days(),
                                ds.AccessKeysSummary.accessKeyInactive_90_180Days(),
                                ds.AccessKeysSummary.accessKeyInactive_30_90Days(),
                            ),
                            ds.ProviderServiceIdentitiesSummary.groupedByType.select(
                                *gql_snippets.list_trivial_fields_ServiceIdentitiesGroupedByType(ds),
                            ),
                        ),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        data = response["data"]
        #logger.info("response data %s", data)
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        providerNodes = response["data"]['Providers']['edges']
        providers = [node['node'] for node in providerNodes]
        logger.debug("num providers returned %s", len(providers))
        return providers

    def cloud_provider_itr(self, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_cloud_provider_base_fn, filters)
        for provider in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield provider

    def as_app_provider_base_fn(
            self, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching providers filters %s page_size %s skip %s",
                    filters, page_size, skip)
        updated_filters = {
            "category": {"equals": "APPLICATION"},
            #"type": {"equals": "PROVIDER_TYPE_IDP_APPLICATION"},
        }
        if filters:
            updated_filters.update(filters)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Providers(
                filters=updated_filters,
                pageArgs={"pageSize": page_size, "skip": skip}
            ).select(
                ds.ProvidersConnection.edges.select(
                    ds.ProviderEdge.node.select(
                        *gql_snippets.list_trivial_fields_Provider(ds),  # Existing provider fields
                        ds.Provider.idpApplicationData.select(
                            *gql_snippets.list_trivial_fields_IdpApplicationData(ds),
                            # ds.IdpApplicationData.idpProvider.select(
                            #     *gql_snippets.list_trivial_fields_Provider(ds),
                            # ),
                            ds.IdpApplicationData.appOktaData.select(
                                *gql_snippets.list_trivial_fields_AppOktaData(ds),
                                ds.AppOktaData.logo.select(
                                    *gql_snippets.list_trivial_fields_LogoData(ds),
                                )
                            ),
                        ),
                        ds.Provider.providerIdentitiesSummary.select(
                            ds.ProviderIdentitiesSummary.groupedByState.select(
                                *gql_snippets.list_trivial_fields_IdentityGroupedByState(ds),
                            ),
                        ),
                        ds.Provider.providerMembersMetadata.select(
                            *gql_snippets.list_trivial_fields_ProviderMembersMetadata(ds),
                        ),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        data = response["data"]
        #logger.debug("response data %s", data)
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        providerNodes = response["data"]['Providers']['edges']
        providers = [node['node'] for node in providerNodes]
        logger.debug("num providers returned %s", len(providers))
        return providers

    def as_provider_base_fn(
            self, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching providers filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Providers(
                filters=filters,
                pageArgs={"pageSize": page_size, "skip": skip}
            ).select(
                ds.ProvidersConnection.edges.select(
                    ds.ProviderEdge.node.select(
                        *gql_snippets.list_trivial_fields_Provider(ds),  # Existing provider fields
                        ds.Provider.providerIdentitiesSummary.select(
                            ds.ProviderIdentitiesSummary.groupedByState.select(
                                *gql_snippets.list_trivial_fields_IdentityGroupedByState(ds),
                            ),
                        ),
                        ds.Provider.providerMembersMetadata.select(
                            *gql_snippets.list_trivial_fields_ProviderMembersMetadata(ds),
                        ),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        data = response["data"]
        #logger.debug("response data %s", data)
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        provider_nodes = response["data"]['Providers']['edges']
        providers = [node['node'] for node in provider_nodes]
        logger.debug("num providers returned %s", len(providers))
        return providers

    def as_provider_itr(self, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_provider_base_fn, filters)
        for provider in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield provider

    def app_provider_itr(self, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_app_provider_base_fn, filters)
        for provider in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield provider

    def as_provider_access_requests_base_fn(self, provider_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching access requests provider %s page_size %s skip %s",
                    provider_id, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Provider(
                id=provider_id,
            ).select(
                ds.Provider.name(),
                ds.Provider.id(),
                ds.Provider.accessRequests(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.IdentityAccessRequestDataConnection.edges.select(
                        ds.IdentityAccessRequestDataEdge.node.select(
                            *gql_snippets.list_trivial_fields_IdentityAccessRequestData(ds),
                            ds.IdentityAccessRequestData.requester.select(
                                *gql_snippets.list_trivial_fields_IdentityAccessRequestRequesterData(ds),
                            ),
                            ds.IdentityAccessRequestData.requestScope.select(
                                *gql_snippets.list_trivial_fields_AccessRequestScope(ds),
                            ),
                            ds.IdentityAccessRequestData.requesterUser.select(
                                *gql_snippets.list_trivial_fields_IdentityAccessRequestRequesterUserData(ds),
                            ),
                            ds.IdentityAccessRequestData.createdBy.select(
                                *gql_snippets.list_trivial_fields_IdentityAccessRequestRequesterData(ds),
                            ),
                            ds.IdentityAccessRequestData.status.select(
                                *gql_snippets.list_trivial_fields_JitPolicyTransactionStatus(ds),
                            ),
                            ds.IdentityAccessRequestData.requestAnalysis.select(
                                *gql_snippets.list_trivial_fields_JitPolicyRequestAnalysis(ds),
                                ds.JitPolicyRequestAnalysis.checks.select(
                                    *gql_snippets.list_trivial_fields_JitPolicyRequestAnalysisCheck(ds),
                                ),
                            ),
                            ds.IdentityAccessRequestData.sessionAnalysis.select(
                                *gql_snippets.list_trivial_fields_JitSessionAnalysis(ds),
                            ),
                            ds.IdentityAccessRequestData.provisioningDetails.select(
                                *gql_snippets.list_trivial_fields_AccessRequestProvisioningDetails(ds),
                                ds.AccessRequestProvisioningDetails.provisioningGroup.select(
                                    *gql_snippets.list_trivial_fields_AccessRequestProvisioningGroup(ds),
                                ),
                                ds.AccessRequestProvisioningDetails.provisioningConditions.select(
                                    *gql_snippets.list_trivial_fields_PolicyProvisioningConditionsData(ds),
                                    ds.PolicyProvisioningConditionsData.azureConditions.select(
                                        *gql_snippets.list_trivial_fields_AzureConditions(ds),
                                    ),
                                ),
                            ),
                            ds.IdentityAccessRequestData.reviews.select(
                                *gql_snippets.list_trivial_fields_IdentityAccessRequestReviewData(ds),
                            ),

                        ),
                    ),
                    ds.IdentityAccessRequestDataConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        requestNodes = response["data"]['Provider']['accessRequests']['edges']
        requests = [node['node'] for node in requestNodes]
        return requests

    def as_provider_access_requests_itr(self, provider_id: str, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_provider_access_requests_base_fn, provider_id, filters)
        for request in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield request

    def as_campaigns_base_fn(
            self, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching campaign filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Campaigns(
                filters=filters,
                pageArgs={"pageSize": page_size, "skip": skip},
            ).select(
                ds.CampaignsConnection.edges.select(
                    ds.CampaignEdge.node.select(
                        *gql_snippets.list_trivial_fields_Campaign(ds),  # Existing provider fields
                        ds.Campaign.campaignTemplate.select(
                            *gql_snippets.list_trivial_fields_CampaignTemplate(ds),
                        ),
                        ds.Campaign.status.select(
                            *gql_snippets.list_trivial_fields_CampaignTransactionStatus(ds),
                        ),
                        ds.Campaign.summary.select(
                            *gql_snippets.list_trivial_fields_CampaignSummary(ds),
                            ds.CampaignSummary.groupedReviewsByAiRecommendation.select(
                                *gql_snippets.list_trivial_fields_AccessReviewsGroupedByAiRecommendation(ds),
                            ),
                            ds.CampaignSummary.groupedReviewByStatus.select(
                                *gql_snippets.list_trivial_fields_AccessReviewsGroupedByStatus(ds),
                            ),
                            ds.CampaignSummary.groupedReviewByStatusNRecommendation.select(
                                *gql_snippets.list_trivial_fields_AccessReviewsGroupedByStatusAndAiRecommendation(ds),
                            ),
                            ds.CampaignSummary.groupedReviewsByScope.select(
                                *gql_snippets.list_trivial_fields_AccessReviewsGroupedByScope(ds),
                            ),
                            ds.CampaignSummary.groupedReviewsByRevocationStatus.select(
                                *gql_snippets.list_trivial_fields_AccessReviewsGroupedByRevocationStatus(ds),
                            )
                        )
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        nodes = response["data"]['Campaigns']['edges']
        campaigns = [node['node'] for node in nodes]
        logger.debug("num campaigns returned %s", len(campaigns))
        return campaigns

    def as_campaigns_itr(self, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_campaigns_base_fn, filters)
        for campaign in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield campaign

    def as_campaign_templates_base_fn(
            self, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching campaign filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.CampaignTemplates(
                filters=filters,
                pageArgs={"pageSize": page_size, "skip": skip},
            ).select(
                ds.CampaignTemplatesConnection.edges.select(
                    ds.CampaignTemplateEdge.node.select(
                        *gql_snippets.list_trivial_fields_CampaignTemplate(ds),
                        ds.CampaignTemplate.owners(
                            pageArgs={"pageSize": 100},
                        ).select(
                            # add edges for the owers connection using IdentitiesConnection
                            ds.IdentitiesConnection.edges.select(
                                ds.IdentityEdge.node.select(
                                    *gql_snippets.list_trivial_fields_Identity(ds),
                                )
                            )
                        )  # Existing provider fields
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        nodes = response["data"]['CampaignTemplates']['edges']
        campaignsTemplates = [node['node'] for node in nodes]
        logger.debug("num campaigns templates returned %s", len(campaignsTemplates))
        return campaignsTemplates

    def as_campaign_templates_itr(self, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_campaign_templates_base_fn, filters)
        for campaign in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield campaign


    def as_campaign_reviewers_base_fn(
            self, campaign_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching campaign reviewers with filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Campaign(
                id=campaign_id
            ).select(
                *gql_snippets.list_trivial_fields_Campaign(ds),  # Existing provider fields
                ds.Campaign.status.select(
                    *gql_snippets.list_trivial_fields_CampaignTransactionStatus(ds),
                ),
                ds.Campaign.reviewers(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.CampaignReviewersConnection.edges.select(
                        ds.CampaignReviewerEdge.node.select(
                            *gql_snippets.list_trivial_fields_Identity(ds),
                        ),
                        ds.CampaignReviewerEdge.reviewerCampaignData.select(
                            *gql_snippets.list_trivial_fields_AccessReviewerCampaignData(ds),
                            ds.AccessReviewerCampaignData.status.select(
                                *gql_snippets.list_trivial_fields_CampaignSnapshotReviewReviewerStatus(ds),
                            ),
                            ds.AccessReviewerCampaignData.assignedReviewer.select(
                                *gql_snippets.list_trivial_fields_Identity(ds),
                            ),
                            # ds.AccessReviewerCampaignData.originalReviewer.select(
                            #     *gql_snippets.list_trivial_fields_Identity(ds),
                            # ),
                            ds.AccessReviewerCampaignData.reviewerSummary.select(
                                *gql_snippets.list_trivial_fields_AccessReviewerCampaignSummary(ds),
                                ds.AccessReviewerCampaignSummary.reviewsGroupedByStatus.select(
                                    *gql_snippets.list_trivial_fields_AccessReviewsGroupedByStatus(ds),
                                ),
                                ds.AccessReviewerCampaignSummary.reviewsGroupedByStatusNRecommendation.select(
                                    *gql_snippets.list_trivial_fields_AccessReviewsGroupedByStatusAndAiRecommendation(ds),
                                ),
                            ),
                        ),
                    ),
                    ds.CampaignReviewersConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )

            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        nodes = response["data"]
        reviewers = nodes['Campaign']['reviewers']['edges']
        logger.debug("num reviewers returned %s", len(reviewers))
        return reviewers

    def as_campaign_reviewers_itr(self, campaign_id: str, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_campaign_reviewers_base_fn, campaign_id, filters)
        for reviewer in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield reviewer

    def as_campaign_access_reviews_base_fn(
            self, campaign_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching campaign reviewers with filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        scope_rg_fragment = DSLInlineFragment()
        scope_rg_fragment.on(ds.ResourceGroupScopeData)
        scope_account_fragment = DSLInlineFragment()
        scope_account_fragment.on(ds.AccountScopeData)
        scope_folder_fragment = DSLInlineFragment()
        scope_folder_fragment.on(ds.FolderScopeData)
        query = dsl_gql(DSLQuery(
            ds.Query.Campaign(
                id=campaign_id
            ).select(
                *gql_snippets.list_trivial_fields_Campaign(ds),  # Existing provider fields
                ds.Campaign.status.select(
                    *gql_snippets.list_trivial_fields_CampaignTransactionStatus(ds),
                ),
                ds.Campaign.accessReviews(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.AccessReviewsConnection.edges.select(
                        ds.AccessReviewEdge.node.select(
                            *gql_snippets.list_trivial_fields_AccessReview(ds),
                            ds.AccessReview.accessAnalysis.select(
                                *gql_snippets.list_trivial_fields_AccessReviewAiAnalysis(ds),
                            ),
                            ds.AccessReview.accessData.select(
                                *gql_snippets.list_trivial_fields_AccessAssignmentData(ds),
                                ds.AccessAssignmentData.scope.select(
                                    scope_rg_fragment.select(
                                        ds.ResourceGroupScopeData.name(),
                                        ds.ResourceGroupScopeData.id(),
                                        ds.ResourceGroupScopeData.isInherited(),
                                        DSLMetaField("__typename")
                                    ),
                                    scope_account_fragment.select(
                                        ds.AccountScopeData.name(),
                                        ds.AccountScopeData.id(),
                                        ds.AccountScopeData.isInherited(),
                                        DSLMetaField("__typename")
                                    ),
                                    scope_folder_fragment.select(
                                        ds.FolderScopeData.name(),
                                        ds.FolderScopeData.id(),
                                        ds.FolderScopeData.isInherited(),
                                        DSLMetaField("__typename")
                                    )
                                ),
                                ds.AccessAssignmentData.account.select(
                                    *gql_snippets.list_trivial_fields_Account(ds),
                                ),
                                ds.AccessAssignmentData.provider.select(
                                    *gql_snippets.list_trivial_fields_Provider(ds),
                                ),
                            ),
                            ds.AccessReview.reviewStatus.select(
                                *gql_snippets.list_trivial_fields_AccessReviewReviewStatus(ds),
                            ),
                            ds.AccessReview.revocationStatus.select(
                                *gql_snippets.list_trivial_fields_RevocationStatus(ds),
                            ),
                            # ds.AccessReview.originalReviewer.select(
                            #     *gql_snippets.list_trivial_fields_Identity(ds),
                            # ),
                            # ds.AccessReview.assignedReviewer.select(
                            #     *gql_snippets.list_trivial_fields_Identity(ds),
                            # ),
                        ),
                    ),
                    ds.AccessReviewsConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )

            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        nodes = response["data"]
        reviews = nodes['Campaign']['accessReviews']['edges']
        reviews = [node['node'] for node in reviews]
        logger.debug("campaign id %s num reviews returned %s", campaign_id, len(reviews))
        return reviews

    def as_campaign_access_reviews_itr(self, campaign_id: str, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_campaign_access_reviews_base_fn, campaign_id, filters)
        for review in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield review

    def as_access_reviewer_reviews_base_fn(
            self, identity_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching campaign reviewers with filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Identity(
                id=identity_id
            ).select(
                ds.Identity.accessReviewsData.select(
                    *gql_snippets.list_trivial_fields_AccessReviewerData(ds),
                    ds.AccessReviewerData.accessReviews(
                        pageArgs={"pageSize": page_size, "skip": skip},
                        filters=filters).select(
                    ).select(
                        ds.AccessReviewsConnection.edges.select(
                            ds.AccessReviewEdge.node.select(
                                *gql_snippets.list_trivial_fields_AccessReview(ds),
                                ds.AccessReview.accessAnalysis.select(
                                    *gql_snippets.list_trivial_fields_AccessReviewAiAnalysis(ds),
                                ),
                                ds.AccessReview.accessData.select(
                                    *gql_snippets.list_trivial_fields_AccessAssignmentData(ds),
                                ),
                                ds.AccessReview.reviewStatus.select(
                                    *gql_snippets.list_trivial_fields_AccessReviewReviewStatus(ds),
                                ),
                                ds.AccessReview.revocationStatus.select(
                                    *gql_snippets.list_trivial_fields_RevocationStatus(ds),
                                ),
                            ),
                        ),
                        ds.AccessReviewsConnection.pageInfo.select(
                            *gql_snippets.list_trivial_fields_PageInfo(ds),
                        )
                    ),

                ),
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        reviews = response['data']['Identity']['accessReviewsData']['accessReviews']['edges']
        reviews = [node['node'] for node in reviews]
        logger.debug("num reviewers returned %s", len(reviews))
        return reviews

    def as_access_reviewer_reviews_itr(self, identity_id: str, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_access_reviewer_reviews_base_fn, identity_id, filters)
        for review in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield review

    def as_provider_access_keys_fn(
            self, provider_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching access keys filters %s page_size %s skip %s",
                    filters, page_size, skip)

        if provider_id:
            filters = filters if filters else {}
            filters['providerId'] = {'equals': provider_id}

        ds = DSLSchema(self.gql_client.schema)
        human_user_fragment = DSLInlineFragment()
        human_user_fragment.on(ds.IdentityOriginData)
        service_identity_fragment = DSLInlineFragment()
        service_identity_fragment.on(ds.ServiceIdentity)
        query = dsl_gql(DSLQuery(
            ds.Query.AccessKeys(
                filters=filters
            ).select(
                ds.ProviderAccessKeysConnection.edges.select(
                    ds.ProviderAccessKeyEdge.node.select(
                        *gql_snippets.list_trivial_fields_ProviderAccessKeyData(ds),  # Existing provider fields
                        ds.ProviderAccessKeyData.keyOpsInsight.select(
                            *gql_snippets.list_trivial_fields_KeyOpsInsightData(ds),
                        ),
                        ds.ProviderAccessKeyData.keyRiskData.select(
                            *gql_snippets.list_trivial_fields_KeyRiskData(ds),
                        ),
                        ds.ProviderAccessKeyData.user.select(
                            human_user_fragment.select(
                            *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                            ds.IdentityOriginData.identity.select(
                                    *gql_snippets.list_trivial_fields_Identity(ds),
                                ),
                            ),
                            service_identity_fragment.select(
                                ds.ServiceIdentity.username(),
                                ds.ServiceIdentity.id(),
                                ds.ServiceIdentity.serviceIdentityType(),
                                ds.ServiceIdentity.state().alias("serviceIdentityState"),
                                ds.ServiceIdentity.opsInsights.select(
                                    *gql_snippets.list_trivial_fields_ServiceIdentityOpsInsightData(ds),
                                ),
                                ds.ServiceIdentity.riskFactorsData.select(
                                    *gql_snippets.list_trivial_fields_ServiceIdentityRiskFactorData(ds),
                                ),
                            ),
                            DSLMetaField("__typename")
                        ),
                        ds.ProviderAccessKeyData.activities.select(
                            *gql_snippets.list_trivial_fields_ActivitiesConnection(ds),
                            ds.ActivitiesConnection.edges.select(
                                ds.ActivityEdge.node.select(
                                    *gql_snippets.list_trivial_fields_Activity(ds),
                                ),
                            ),
                            ds.ActivitiesConnection.pageInfo.select(
                                *gql_snippets.list_trivial_fields_PageInfo(ds),
                            ),
                        ),
                    ),
                ),
                ds.ProviderAccessKeysConnection.pageInfo.select(
                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        keys = [node['node'] for node in response["data"]['AccessKeys']['edges']]
        logger.debug("provider %s, num keys returned %s", provider_id, len(keys))
        return keys

    def as_access_keys_itr(
            self, provider_id: str, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_provider_access_keys_fn, provider_id, filters)
        for key in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield key

    def as_identity_active_assignments_base_fn(
            self, identity_id: str, provider_id: str, account_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching identity active assignments filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        scope_rg_fragment = DSLInlineFragment()
        scope_rg_fragment.on(ds.ResourceGroupScopeData)
        scope_account_fragment = DSLInlineFragment()
        scope_account_fragment.on(ds.AccountScopeData)
        scope_folder_fragment = DSLInlineFragment()
        scope_folder_fragment.on(ds.FolderScopeData)

        query = dsl_gql(DSLQuery(
            ds.Query.Identity(
                id=identity_id
            ).select(
                ds.Identity.id(),
                ds.Identity.name(),
                ds.Identity.providersData(
                    filters={'providerId': {'equals': provider_id}}
                ).select(
                    ds.IdentityProvidersDataConnection.edges.select(
                        ds.IdentityProviderDataEdge.node.select(
                            *gql_snippets.list_trivial_fields_IdentityProviderData(ds),
                            ds.IdentityProviderData.accountsData(
                                filters={'id': {'equals': account_id}}
                            ).select(
                                ds.IdentityAccountsDataConnection.edges.select(
                                    ds.IdentityAccountDataEdge.node.select(
                                        *gql_snippets.list_trivial_fields_IdentityAccountData(ds),
                                        ds.IdentityAccountData.policiesData(
                                            pageArgs={"pageSize": page_size, "skip": skip},
                                            filters=filters
                                        ).select(
                                            ds.IdentityPoliciesDataConnection.edges.select(
                                                ds.IdentityPolicyDataEdge.node.select(
                                                    *gql_snippets.list_trivial_fields_IdentityPolicyData(ds),
                                                    ds.IdentityPolicyData.scope.select(
                                                        scope_rg_fragment.select(
                                                            ds.ResourceGroupScopeData.name(),
                                                            ds.ResourceGroupScopeData.id(),
                                                            ds.ResourceGroupScopeData.isInherited(),
                                                            DSLMetaField("__typename")
                                                        ),
                                                        scope_account_fragment.select(
                                                            ds.AccountScopeData.name(),
                                                            ds.AccountScopeData.id(),
                                                            ds.AccountScopeData.isInherited(),
                                                            DSLMetaField("__typename")
                                                        ),
                                                        scope_folder_fragment.select(
                                                            ds.FolderScopeData.name(),
                                                            ds.FolderScopeData.id(),
                                                            ds.FolderScopeData.isInherited(),
                                                            DSLMetaField("__typename")
                                                        )
                                                    ),
                                                ),
                                            ),
                                            ds.IdentityPoliciesDataConnection.pageInfo.select(
                                                *gql_snippets.list_trivial_fields_PageInfo(ds),
                                            ),
                                        ),
                                    ),
                                ),
                            )
                        ),
                    ),
                ),
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        try:
            assignments = response["data"]['Identity']['providersData']['edges'][0]['node']['accountsData']['edges'][0]['node']['policiesData']['edges']
        except IndexError:
            # If there are no assignments, return an empty list
            assignments = []
        assignments = [node['node'] for node in assignments]
        logger.debug("num assignments returned provider %s account %s %s", provider_id, account_id, len(assignments))
        return assignments

    def as_identity_active_assignments_itr(
            self, identity_id: str, provider_id: str, account_id: str, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_identity_active_assignments_base_fn, identity_id, provider_id, account_id, filters)
        for assignment in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield assignment

    def as_user_provider_resolved_assignments_base_fn(
            self, user_id: str, provider_id: str, assignment_filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        """
        Fetch the resolved assignments for a user in a provider
        """
        logger.debug("Fetching identity active assignments filters %s page_size %s skip %s",
                    assignment_filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        scope_rg_fragment = DSLInlineFragment()
        scope_rg_fragment.on(ds.ResourceGroupScopeData)
        scope_account_fragment = DSLInlineFragment()
        scope_account_fragment.on(ds.AccountScopeData)
        scope_folder_fragment = DSLInlineFragment()
        scope_folder_fragment.on(ds.FolderScopeData)
        scope_provider_fragment = DSLInlineFragment()
        scope_provider_fragment.on(ds.ProviderScopeData)

        user_filters = {}
        if user_id:
            user_filters['id'] = {'equals': user_id}

        query = dsl_gql(DSLQuery(
            ds.Query.Users(
                filters=user_filters
            ).select(
                ds.UserConnection.edges.select(
                    ds.UserEdge.node.select(
                        *gql_snippets.list_trivial_fields_User(ds),
                        ds.User.userData.select(
                            *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                        ),
                        ds.User.userProviderData(
                            pageArgs={"pageSize": 100},
                            filters={'providerId': {'equals': provider_id}}
                        ).select(
                            ds.UserProviderDataConnection.edges.select(
                                ds.UserProviderDataEdge.node.select(
                                    *gql_snippets.list_trivial_fields_Provider(ds),
                                ),
                                ds.UserProviderDataEdge.userProviderData.select(
                                    *gql_snippets.list_trivial_fields_UserProviderData(ds),
                                    ds.UserProviderData.userResolvedAssignments(
                                        pageArgs={"pageSize": page_size, "skip": skip},
                                        filters=assignment_filters
                                    ).select(
                                        ds.AccountPolicyUserResolvedAssignmentsConnection.edges.select(
                                            ds.AccountPolicyUserResolvedAssignmentEdge.node.select(
                                                *gql_snippets.list_trivial_fields_AccountPolicyUserResolvedAssignment(ds),
                                            ),
                                        ),
                                    )
                                )
                            ),
                            ds.UserProviderDataConnection.pageInfo.select(
                                *gql_snippets.list_trivial_fields_PageInfo(ds),
                            ),
                        )
                    ),
                ),
                ds.UserConnection.pageInfo.select(
                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                ),
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        try:
            assignments = response["data"]['Users']['edges'][0]['node']['userProviderData']['edges'][0]['userProviderData']['userResolvedAssignments']['edges']
        except IndexError:
            # If there are no assignments, return an empty list
            assignments = []
        assignments = [node['node'] for node in assignments]
        logger.debug("num assignments returned user %s provider %s num %s",
                     user_id, provider_id, len(assignments))
        return assignments

    def as_user_provider_resolved_assignments_itr(
            self, user_id: str, provider_id: str, assignment_filters: dict = None,
            page_size: int = None) -> Generator[dict, None, None]:
        """
        Iterate over the resolved assignments for a user in a provider
        """
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_user_provider_resolved_assignments_base_fn,
            user_id, provider_id, assignment_filters)
        for assignment in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield assignment

    def as_user_providers_with_assignments_base_fn(
            self, user_id: str, username: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        """
        Fetch the resolved assignments for a user in a provider
        """
        logger.debug("Fetching identity active assignments filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        user_filters = {}
        assert user_id or username, "user_id or username is required"
        if user_id:
            user_filters['id'] = {'equals': user_id}
        if username:
            user_filters['username'] = {'equals': username}

        query = dsl_gql(DSLQuery(
            ds.Query.Users(
                filters=user_filters
            ).select(
                ds.UserConnection.edges.select(
                    ds.UserEdge.node.select(
                        *gql_snippets.list_trivial_fields_User(ds),
                        ds.User.userData.select(
                            *gql_snippets.list_trivial_fields_IdentityOriginData(ds),
                        ),
                        ds.User.userProviderData(
                            pageArgs={"pageSize": page_size, "skip": skip},
                            filters=filters,
                        ).select(
                            ds.UserProviderDataConnection.edges.select(
                                ds.UserProviderDataEdge.node.select(
                                    *gql_snippets.list_trivial_fields_Provider(ds)
                                ),
                            ),
                            ds.UserProviderDataConnection.pageInfo.select(
                                *gql_snippets.list_trivial_fields_PageInfo(ds),
                            ),
                        )
                    ),
                ),
                ds.UserConnection.pageInfo.select(
                    *gql_snippets.list_trivial_fields_PageInfo(ds),
                ),
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        try:
            providers = response["data"]['Users']['edges'][0]['node']['userProviderData']['edges']
        except IndexError:
            # If there are no assignments, return an empty list
            providers = []
        providers = [node['node'] for node in providers]
        logger.debug("num assignments returned user %s num %s",
                     user_id, len(providers))
        return providers

    def as_user_providers_with_assignments_itr(
            self, user_id: str, username: str = "", filters: dict = None,
            page_size: int = None) -> Generator[dict, None, None]:
        """
        Iterate over the resolved assignments for a user in a provider
        """
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_user_providers_with_assignments_base_fn,
            user_id, username, filters)
        for provider in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield provider

    def _fetch_account_policies(self, provider_id: str, account_id: str, account_data: dict) -> dict:
        if 'policies' not in account_data:
            account_data['policies'] = {}
        policy_map = account_data['policies']
        logger.debug("Fetching account policies for provider %s account %s", provider_id, account_id)
        try:
            for policy in self.provider_account_policies_itr(provider_id, account_id):
                policy_map[policy['policyId']] = policy
        except Exception as e:
            logger.error("Error fetching account policies for provider %s account %s with error %s",
                         provider_id, account_id, e)
        return policy_map

    def _fetch_provider_policies(self, provider_id: str, provider_data: dict) -> dict:
        if 'policies' not in provider_data:
            provider_data['policies'] = {}
        policy_map = provider_data['policies']
        for policy in self.provider_policies_itr(provider_id):
            policy_map[policy['id']] = policy
        logger.debug("provider: %s policies: %d", provider_id, len(policy_map))
        return policy_map

    def fetch_humans_summary(self) -> dict:
        """
        Summary of all the identities in the tenant
        """

        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.IdentitiesSummary(
            ).select(
                ds.IdentitiesSummary.groupedByRiskLevel.select(
                    *gql_snippets.list_trivial_fields_IdentityGroupedByRiskLevel(ds),
                ),
                ds.IdentitiesSummary.groupedByRiskCategory.select(
                    *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategorySummary(ds),
                    ds.IdentityGroupedByRiskCategorySummary.categories.select(
                        *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategory(ds),
                        ds.IdentityGroupedByRiskCategory.factors.select(
                            *gql_snippets.list_trivial_fields_IdentityGroupedByRiskFactor(ds),
                        )
                    ),
                ),
                ds.IdentitiesSummary.groupedBySignificance.select(
                    *gql_snippets.list_trivial_fields_IdentityGroupedBySignificance(ds),
                ),
                ds.IdentitiesSummary.accessKeysSummary.select(
                    ds.AccessKeysSummary.rotationPastDueCount(),
                    ds.AccessKeysSummary.accessKeysCount(),
                    ds.AccessKeysSummary.accessKeyInactive_365DaysPlus(),
                    ds.AccessKeysSummary.accessKeyInactive_180_365Days(),
                    ds.AccessKeysSummary.accessKeyInactive_90_180Days(),
                    ds.AccessKeysSummary.accessKeyInactive_30_90Days(),
                ),
                ds.IdentitiesSummary.groupedByState.select(
                    *gql_snippets.list_trivial_fields_IdentityGroupedByState(ds),
                ),
                ds.IdentitiesSummary.groupedByHrType.select(
                    *gql_snippets.list_trivial_fields_IdentityGroupedByHrType(ds),
                ),
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        data = response["data"]["IdentitiesSummary"]
        logger.debug("Humans Summary %s", data)
        return data

    def fetch_nhis_summary(self) -> dict:
        """
        Summary of all the nhis in the tenant
        """
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.ServiceIdentitiesSummary(
            ).select(
                ds.ServiceIdentitiesSummary.groupedByRiskLevel.select(
                    *gql_snippets.list_trivial_fields_IdentityGroupedByRiskLevel(ds),
                ),
                ds.ServiceIdentitiesSummary.groupedByRiskCategory.select(
                    *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategorySummary(ds),
                    ds.IdentityGroupedByRiskCategorySummary.categories.select(
                        *gql_snippets.list_trivial_fields_IdentityGroupedByRiskCategory(ds),
                        ds.IdentityGroupedByRiskCategory.factors.select(
                            *gql_snippets.list_trivial_fields_IdentityGroupedByRiskFactor(ds),
                        )
                    ),
                ),
                ds.ServiceIdentitiesSummary.groupedBySignificance.select(
                    *gql_snippets.list_trivial_fields_ServiceIdentityGroupedBySignificance(ds),
                ),
                ds.ServiceIdentitiesSummary.accessKeysSummary.select(
                    ds.AccessKeysSummary.rotationPastDueCount(),
                    ds.AccessKeysSummary.accessKeysCount(),
                    ds.AccessKeysSummary.accessKeyInactive_365DaysPlus(),
                    ds.AccessKeysSummary.accessKeyInactive_180_365Days(),
                    ds.AccessKeysSummary.accessKeyInactive_90_180Days(),
                    ds.AccessKeysSummary.accessKeyInactive_30_90Days(),
                ),
                ds.ServiceIdentitiesSummary.groupedByType.select(
                    *gql_snippets.list_trivial_fields_ServiceIdentitiesGroupedByType(ds),
                ),
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        data = response["data"]["ServiceIdentitiesSummary"]
        logger.debug("service identities summary response data %s", data)
        return data

    def fetch_providers_summary(self) -> dict:
        """
        Summary of all the providers in the tenant
        """
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.ProvidersSummary(
            ).select(
                ds.ProvidersSummary.groupedByTier.select(
                    *gql_snippets.list_trivial_fields_ProvidersGroupedByTier(ds),
                ),
                ds.ProvidersSummary.providersByConfiguredUsers.select(
                    *gql_snippets.list_trivial_fields_Distribution(ds),
                    ds.Distribution.bucketOptions.select(
                        *gql_snippets.list_trivial_fields_BucketOptions(ds),
                        ds.BucketOptions.exponentialBuckets.select(
                            *gql_snippets.list_trivial_fields_Exponential(ds),
                        )
                    )
                ),
                ds.ProvidersSummary.providersByConfiguredIdentities.select(
                    *gql_snippets.list_trivial_fields_Distribution(ds),
                    ds.Distribution.bucketOptions.select(
                        *gql_snippets.list_trivial_fields_BucketOptions(ds),
                        ds.BucketOptions.exponentialBuckets.select(
                            *gql_snippets.list_trivial_fields_Exponential(ds),
                        )
                    )
                ),
                ds.ProvidersSummary.providersByConfiguredServiceIdentities.select(
                    *gql_snippets.list_trivial_fields_Distribution(ds),
                    ds.Distribution.bucketOptions.select(
                        *gql_snippets.list_trivial_fields_BucketOptions(ds),
                        ds.BucketOptions.exponentialBuckets.select(
                            *gql_snippets.list_trivial_fields_Exponential(ds),
                        )
                    )
                ),
                ds.ProvidersSummary.providersByActiveUsers.select(
                    *gql_snippets.list_trivial_fields_Distribution(ds),
                    ds.Distribution.bucketOptions.select(
                        *gql_snippets.list_trivial_fields_BucketOptions(ds),
                        ds.BucketOptions.exponentialBuckets.select(
                            *gql_snippets.list_trivial_fields_Exponential(ds),
                        )
                    )
                ),
                ds.ProvidersSummary.providersByActiveIdentities.select(
                    *gql_snippets.list_trivial_fields_Distribution(ds),
                    ds.Distribution.bucketOptions.select(
                        *gql_snippets.list_trivial_fields_BucketOptions(ds),
                        ds.BucketOptions.exponentialBuckets.select(
                            *gql_snippets.list_trivial_fields_Exponential(ds),
                        )
                    )
                ),
                ds.ProvidersSummary.providersByActiveServiceIdentities.select(
                    *gql_snippets.list_trivial_fields_Distribution(ds),
                    ds.Distribution.bucketOptions.select(
                        *gql_snippets.list_trivial_fields_BucketOptions(ds),
                        ds.BucketOptions.exponentialBuckets.select(
                            *gql_snippets.list_trivial_fields_Exponential(ds),
                        )
                    )
                ),
                ds.ProvidersSummary.providersByLogins.select(
                    *gql_snippets.list_trivial_fields_Distribution(ds),
                    ds.Distribution.bucketOptions.select(
                        *gql_snippets.list_trivial_fields_BucketOptions(ds),
                        ds.BucketOptions.exponentialBuckets.select(
                            *gql_snippets.list_trivial_fields_Exponential(ds),
                        )
                    )
                ),
                ds.ProvidersSummary.providersByInactiveUsers.select(
                    *gql_snippets.list_trivial_fields_Distribution(ds),
                    ds.Distribution.bucketOptions.select(
                        *gql_snippets.list_trivial_fields_BucketOptions(ds),
                        ds.BucketOptions.exponentialBuckets.select(
                            *gql_snippets.list_trivial_fields_Exponential(ds),
                        )
                    )
                ),
                ds.ProvidersSummary.providersByInactiveIdentities.select(
                    *gql_snippets.list_trivial_fields_Distribution(ds),
                    ds.Distribution.bucketOptions.select(
                        *gql_snippets.list_trivial_fields_BucketOptions(ds),
                        ds.BucketOptions.exponentialBuckets.select(
                            *gql_snippets.list_trivial_fields_Exponential(ds),
                        )
                    )
                ),
                ds.ProvidersSummary.providersByInactiveServiceIdentities.select(
                    *gql_snippets.list_trivial_fields_Distribution(ds),
                    ds.Distribution.bucketOptions.select(
                        *gql_snippets.list_trivial_fields_BucketOptions(ds),
                        ds.BucketOptions.exponentialBuckets.select(
                            *gql_snippets.list_trivial_fields_Exponential(ds),
                        )
                    )
                ),
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        data = response["data"]["ProvidersSummary"]
        logger.debug("response data %s", data)
        return data

    def as_identity_eligibility_details_base_fn(self, identity_id: str, filters: Optional[dict]=None, page_size: Optional[int]=None, skip: Optional[int]=None) -> Generator[dict, None, None]:
        """Base function to iterate through identity eligibility."""
        filters = filters if filters else {}
        assert self.gql_client.schema is not None, "GQL client schema is not set"
        ds = DSLSchema(self.gql_client.schema)

        role_eligibility_fragment = DSLInlineFragment()
        role_eligibility_fragment.on(ds.IdentityProviderEligibilityPolicyData)
        resource_set_eligibility_fragment = DSLInlineFragment()
        resource_set_eligibility_fragment.on(ds.ResourceSetEligibilityData)
        resource_eligibility_fragment = DSLInlineFragment()
        resource_eligibility_fragment.on(ds.IdentityResourceEligibilityData)

        query = dsl_gql(DSLQuery(
            ds.Query.Identity(
                id=identity_id
            ).select(
                ds.Identity.id(),
                ds.Identity.name(),
                ds.Identity.username(),
                ds.Identity.email(),
                ds.Identity.state(),
                ds.Identity.type(),
                ds.Identity.eligibilityDetails.select(
                    ds.IdentityProviderEligibilityDataConnection.edges.select(
                        ds.IdentityProviderEligibilityDataEdge.node.select(
                            *gql_snippets.list_trivial_fields_IdentityProviderEligibilityData(ds),
                            ds.IdentityProviderEligibilityData.eligibleUser.select(
                                ds.IdentityOriginData.originUserId(),
                                ds.IdentityOriginData.originUserName(),
                                ds.IdentityOriginData.originUserUsername(),
                            ),
                            ds.IdentityProviderEligibilityData.accountData.select(
                                *gql_snippets.list_trivial_fields_IdentityProviderEligibilityAccountData(ds)
                            ),
                            ds.IdentityProviderEligibilityData.eligibilityData.select(
                                role_eligibility_fragment.select(
                                    *gql_snippets.list_trivial_fields_IdentityProviderEligibilityPolicyData(ds),
                                ),
                                resource_set_eligibility_fragment.select(
                                    *gql_snippets.list_trivial_fields_ResourceSetEligibilityData(ds),
                                ),
                                # resource_eligibility_fragment.select(
                                #     *gql_snippets.list_trivial_fields_IdentityResourceEligibilityData(ds),
                                # ),
                            )
                        )
                    ),
                    ds.IdentityProviderEligibilityDataConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds)
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        eligibilityDataNodes = response["data"]["Identity"]["eligibilityDetails"]["edges"]
        eligibility = [node["node"] for node in eligibilityDataNodes]
        logger.debug("num providers returned %s", len(eligibility))
        return eligibility

    def as_identity_eligibility_details_itr(self, identity_id: str, filters: Optional[dict]=None, page_size: Optional[int]=None, skip: Optional[int]=None) -> Generator[dict, None, None]:
        """Iterate through identity eligibility."""
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_identity_eligibility_details_base_fn,
            identity_id, filters)
        for eligibility in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield eligibility

    def as_identity_eligible_providers_base_fn(self, identity_id: str, filters: Optional[dict]=None, page_size: Optional[int]=None, skip: Optional[int]=None) -> Generator[dict, None, None]:
        """Base function to iterate through identity eligible providers."""
        filters = filters if filters else {}
        assert self.gql_client.schema is not None, "GQL client schema is not set"
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Identity(
                id=identity_id
            ).select(
                ds.Identity.id(),
                ds.Identity.name(),
                ds.Identity.email(),
                ds.Identity.state(),
                ds.Identity.type(),
                ds.Identity.eligibleProviders.select(
                    ds.IdentityEligibleProvidersConnection.edges.select(
                        ds.IdentityEligibleProvidersEdge.node.select(
                            *gql_snippets.list_trivial_fields_Provider(ds),
                        )
                    ),
                    ds.IdentityEligibleProvidersConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds)
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        providerNodes = response["data"]["Identity"]["eligibleProviders"]["edges"]
        providers = [node["node"] for node in providerNodes]
        logger.debug("num providers returned %s", len(providers))
        return providers


    def as_identity_eligible_providers_itr(
            self, identity_id: str, page_size: Optional[int] = None,
            filters: Optional[dict] = None) -> Generator[dict, None, None]:
        """Iterate through identity eligible providers."""
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_identity_eligible_providers_base_fn,
            identity_id, filters)
        for provider in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield provider

    def as_identity_access_requests_base_fn(self, identity_id: str, filters: dict,
            page_size: int, skip: int) -> Generator[list, None, None]:
        logger.debug("Fetching access requests identity %s page_size %s skip %s",
                    identity_id, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Identity(
                id=identity_id
            ).select(
                ds.Identity.id(),
                ds.Identity.name(),
                ds.Identity.email(),
                ds.Identity.username(),
                ds.Identity.requests(
                    pageArgs={"pageSize": page_size, "skip": skip},
                    filters=filters).select(
                    ds.IdentityAccessRequestDataConnection.edges.select(
                        ds.IdentityAccessRequestDataEdge.node.select(
                            *gql_snippets.list_trivial_fields_IdentityAccessRequestData(ds),
                            ds.IdentityAccessRequestData.requestScope.select(
                                *gql_snippets.list_trivial_fields_AccessRequestScope(ds),
                            ),
                            ds.IdentityAccessRequestData.providerDetailsData.select(
                                *gql_snippets.list_trivial_fields_ProviderDetailsData(ds),
                            ),
                            ds.IdentityAccessRequestData.requester.select(
                                *gql_snippets.list_trivial_fields_IdentityAccessRequestRequesterData(ds),
                            ),
                            ds.IdentityAccessRequestData.createdBy.select(
                                *gql_snippets.list_trivial_fields_IdentityAccessRequestRequesterData(ds),
                            ),
                            ds.IdentityAccessRequestData.requesterUser.select(
                                *gql_snippets.list_trivial_fields_IdentityAccessRequestRequesterUserData(ds),
                            ),
                            ds.IdentityAccessRequestData.status.select(
                                *gql_snippets.list_trivial_fields_JitPolicyTransactionStatus(ds),
                            ),
                            ds.IdentityAccessRequestData.sessionAnalysis.select(
                                *gql_snippets.list_trivial_fields_JitSessionAnalysis(ds),
                            ),
                            ds.IdentityAccessRequestData.provisioningDetails.select(
                                *gql_snippets.list_trivial_fields_AccessRequestProvisioningDetails(ds),
                                ds.AccessRequestProvisioningDetails.provisioningGroup.select(
                                    *gql_snippets.list_trivial_fields_AccessRequestProvisioningGroup(ds),
                                ),
                            ),
                            ds.IdentityAccessRequestData.itsmData.select(
                                *gql_snippets.list_trivial_fields_AccessRequestItsmData(ds),
                            ),
                            ds.IdentityAccessRequestData.reviews.select(
                                *gql_snippets.list_trivial_fields_IdentityAccessRequestReviewData(ds),
                            ),
                            ds.IdentityAccessRequestData.requestAnalysis.select(
                                *gql_snippets.list_trivial_fields_JitPolicyRequestAnalysis(ds),
                                ds.JitPolicyRequestAnalysis.checks.select(
                                    *gql_snippets.list_trivial_fields_JitPolicyRequestAnalysisCheck(ds),
                                ),
                            ),
                            ds.IdentityAccessRequestData.sessionAnalysis.select(
                                *gql_snippets.list_trivial_fields_JitSessionAnalysis(ds),
                            ),
                        ),
                    ),
                    ds.IdentityAccessRequestDataConnection.pageInfo.select(
                        *gql_snippets.list_trivial_fields_PageInfo(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        nodes = response["data"]['Identity']['requests']['edges']
        requests = [node['node'] for node in nodes]
        logger.debug("num requests returned %s", len(requests))
        return requests

    def as_identity_access_requests_itr(self, identity_id: str, filters: Optional[dict]=None,
                                        page_size: Optional[int]=None) -> Generator[dict, None, None]:
        """Iterate through access requests."""
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_identity_access_requests_base_fn, identity_id, filters)
        for request in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield request

    def _fetch_application_assignments(self, provider_id: str, provider_data: dict) -> dict:
        for assignment in self.provider_application_assignments_itr(provider_id, provider_data):
            provider_data['applicationAssignments'].append(assignment)
        logger.debug("provider: %s assignments %s", provider_id, len(provider_data['applicationAssignments']))
        return provider_data.get('applicationAssignments', [])

    def _fetch_assignable_users(self, provider_id: str, provider_data: dict) -> dict:
        for user in self.provider_assignable_users_itr(provider_id, provider_data):
            provider_data['assignableUsers'][user['userDetails']['originUserUsername']] = user
        logger.debug("provider: %s", provider_id)
        return provider_data.get('assignableUsers', {})

    def _fetch_assignable_groups(self, provider_id: str, provider_data: dict) -> dict:
        for group in self.provider_assignable_groups_itr(provider_id, provider_data):
            provider_data['assignableGroups'][group['groupDetails']['id']] = group
        logger.debug("provider: %s", provider_id)
        return provider_data.get('assignableGroups', {})

    def _fetch_assignable_policies(self, provider_id: str, provider_data: dict) -> dict:
        for policy in self.provider_assignable_policies_itr(provider_id, provider_data):
            provider_data['assignablePolicies'][policy['policyId']] = policy
        logger.debug("provider: %s", provider_id)
        return provider_data.get('assignablePolicies', {})

    def _fetch_provider_eligibilities(self, provider_id: str, provider_data: dict) -> dict:
        for eligibility in self.provider_eligibilities_itr(provider_id, provider_data):
            e_tuple = "|".join((provider_id, eligibility['accountId'], eligibility['principalId'], eligibility['policyId']))
            provider_data['eligibilities'][e_tuple] = eligibility
        logger.debug("provider: %s", provider_id)
        return provider_data.get('eligibilities', {})

    def _fetch_idp_application_details(self, provider_id: str, provider_data: dict) -> dict:
        if provider_id not in self.provider_map:
            self.provider_map[provider_id] = AndromedaProvider()
        self.provider_map[provider_id].update(provider_data)
        provider_data = self.provider_map[provider_id]
        self._fetch_humans(provider_id, provider_data)
        self._fetch_nhis(provider_id, provider_data)
        self._fetch_groups(provider_id, provider_data)
        self._fetch_provider_policies(provider_id, provider_data)
        self._fetch_assignable_users(provider_id, provider_data)
        self._fetch_assignable_groups(provider_id, provider_data)
        self._fetch_assignable_policies(provider_id, provider_data)
        self._fetch_application_assignments(provider_id, provider_data)
        self._fetch_provider_eligibilities(provider_id, provider_data)

        logger.info("provider %s humans:%s nhis%s",
                    provider_id, len(provider_data['humans']), len(provider_data['nhis']))
        return

    def _fetch_cloud_provider_details(self, provider_id: str, provider_data: dict) -> dict:
        if provider_id not in self.provider_map:
            self.provider_map[provider_id] = AndromedaProvider()
        self.provider_map[provider_id].update(provider_data)
        provider_data = self.provider_map[provider_id]
        self._fetch_accounts(provider_id, provider_data)
        self._fetch_humans(provider_id, provider_data)
        self._fetch_nhis(provider_id, provider_data)
        self._fetch_groups(provider_id, provider_data)
        self._fetch_provider_policies(provider_id, provider_data)
        self._fetch_ai_provider_active_bindings(provider_id, provider_data, False)
        self._fetch_ai_provider_active_bindings(provider_id, provider_data, True)
        self._fetch_assignable_users(provider_id, provider_data)
        self._fetch_assignable_groups(provider_id, provider_data)
        self._fetch_assignable_policies(provider_id, provider_data)
        self._fetch_provider_eligibilities(provider_id, provider_data)

        for account_id, account_data in provider_data['accounts'].items():
            self._fetch_account_policies(provider_id, account_id, account_data)
            self._fetch_account_humans(provider_id, account_id, account_data)
            self._fetch_account_nhis(provider_id, account_id, account_data)

        logger.info("provider %s humans:%s nhis%s accounts %s active bindings%s",
                    provider_id, len(provider_data['humans']), len(provider_data['nhis']),
                    len(provider_data['accounts']),
                    len(provider_data['activeBindings']))
        return

    def _fetch_ai_inventory(self, provider_id: str = '') -> dict:
        providers_summary = self.fetch_providers_summary()
        self['providers_summary'] = providers_summary
        filters = {}
        if provider_id:
            filters['id'] = {'equals': provider_id}
        for provider_data in self.cloud_provider_itr(filters=filters):
            self._fetch_cloud_provider_details(provider_data["id"], provider_data)

        filters = {}
        if provider_id:
            filters['id'] = {'equals': provider_id}
        for provider_data in self.app_provider_itr(filters=filters):
            self._fetch_idp_application_details(provider_data["id"], provider_data)
        return self.provider_map

    def _fetch_ai_provider_active_bindings(self, provider_name: str, provider_data: dict, resolved_view: bool = False) -> dict:
        if 'activeBindings' not in provider_data:
            provider_data['activeBindings'] = {
                'configured': [],
                'resolved': []
            }
        view_type = 'resolved' if resolved_view else 'configured'
        for binding in self.provider_active_bindings_itr(provider_data["id"], provider_data, resolved_view):
            provider_data['activeBindings'][view_type].append(binding)
        logger.info("num active bindings view_type %s: %s", view_type, len(provider_data['activeBindings'][view_type]))
        return provider_data['activeBindings']

    def _fetch_humans(self, provider_id: str, provider_data: dict) -> dict:
        for human in self.provider_humans_itr(provider_id, provider_data):
            self.provider_map[provider_id]["humans"][human["username"]] = human
        logger.info("humans %d", len(self.provider_map[provider_id]["humans"]))

    def _fetch_groups(self, provider_id: str, provider_data: dict) -> dict:
        for group in self.as_provider_groups_itr(provider_id, provider_data):
            self.provider_map[provider_id]["groups"][group["name"]] = group
        logger.info("groups %d", len(self.provider_map[provider_id]["groups"]))

    def _fetch_account_humans(self, provider_id: str, account_id: str, account_data: dict) -> dict:
        acc_inventory_data = self.provider_map[provider_id]["accounts"][account_id]
        if 'humans' not in acc_inventory_data:
            acc_inventory_data['humans'] = {}
        for human in self.account_humans_itr(provider_id, account_id, account_data):
            acc_inventory_data[human["username"]] = human
        logger.info("humans %d", len(acc_inventory_data.get("humans", {})))

    def _fetch_account_nhis(self, provider_id: str, account_id: str, account_data: dict) -> dict:
        acc_inventory_data = self.provider_map[provider_id]["accounts"][account_id]
        if 'nhis' not in acc_inventory_data:
            acc_inventory_data['nhis'] = {}
        for nhi in self.account_nhis_itr(provider_id, account_id, account_data):
            acc_inventory_data[nhi["username"]] = nhi
        logger.info("nhis %d", len(acc_inventory_data.get("nhis", {})))

    def _fetch_nhis(self, provider_id: str, provider_data: dict) -> dict:
        for nhi in self.provider_nhis_itr(provider_id, provider_data):
            self.provider_map[provider_id]["nhis"][nhi["username"]] = nhi
        logger.info("nhis %d", len(self.provider_map[provider_id]["nhis"]))

    def as_identities_base_fn(self, filters: dict, page_size: int, skip: int) -> Generator[list, None, None]:
        """Fetch identities with username, id, and name."""
        logger.debug("Fetching identities with filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Identities(
                pageArgs={"pageSize": page_size, "skip": skip},
                filters=filters
            ).select(
                ds.IdentitiesConnection.edges.select(
                    ds.IdentityEdge.node.select(
                        ds.Identity.id(),
                        ds.Identity.name(),
                        ds.Identity.username(),
                        ds.Identity.email(),
                        ds.Identity.state(),
                        ds.Identity.type()
                    )
                ),
                ds.IdentitiesConnection.pageInfo.select(
                    *gql_snippets.list_trivial_fields_PageInfo(ds)
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        identityNodes = response["data"]["Identities"]["edges"]
        identities = [node["node"] for node in identityNodes]
        logger.debug("num identities returned %s", len(identities))
        return identities

    def identities_itr(self, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        """Iterate through identities."""
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_identities_base_fn, filters)
        for identity in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield identity

    def as_events_base_fn(self, filters: dict, page_size: int, skip: int) -> Generator[list, None, None]:
        """Fetch events with username, id, and name."""
        logger.debug("Fetching events with filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.AndromedaEvents(
                pageArgs={"pageSize": page_size, "skip": skip},
                filters=filters
            ).select(
                ds.AndromedaEventsConnection.edges.select(
                    ds.AndromedaEventsEdge.node.select(
                        *gql_snippets.list_trivial_fields_AndromedaEventsNode(ds),
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        if response.get("errors"):
            logger.error("errors in the response %s", response["errors"])
        eventNodes = response["data"]["AndromedaEvents"]["edges"]
        events = []
        for node in eventNodes:
            try:
                event = node["node"]
                # unpack the data from the event
                event['data'] = json.loads(event['data'])
                if 'value' in event['data']:
                    event['data'] = json.loads(event['data']['value'])
                if 'payload' in event['data']:
                    event['data'] = json.loads(event['data']['payload'])
                events.append(event)
            except KeyError as e:
                logger.error("error unpacking event %s", e)
                continue
        logger.debug("num events returned %s", len(events))
        return events

    def as_events_itr(self, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        """Iterate through events."""
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_events_base_fn, filters)
        for event in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield event

    def as_recommendations_base_fn(self, filters: dict, page_size: int, skip: int) -> Generator[list, None, None]:
        """Fetch events with username, id, and name."""
        logger.debug("Fetching events with filters %s page_size %s skip %s",
                    filters, page_size, skip)
        ds = DSLSchema(self.gql_client.schema)
        query = dsl_gql(DSLQuery(
            ds.Query.Recommendations(
                filters=filters,
                pageArgs={"pageSize": page_size, "skip": skip},
            ).select(
                ds.RecommendationConnection.edges.select(
                    ds.RecommendationEdge.node.select(
                        *gql_snippets.list_trivial_fields_RecommendationNode(ds),
                        ds.RecommendationNode.origin.select(
                            *gql_snippets.list_trivial_fields_RecommendationOrigin(ds),
                        ) # Existing provider fields
                    )
                )
            )
        ))
        response = self.gql_client.execute(query, get_execution_result=True).formatted
        if response.get("errors"):
            logger.error("errors in the response %s", response["errors"])
        recommendationNodes = response["data"]["Recommendations"]["edges"]
        recommendations = [r['node'] for r in recommendationNodes]
        logger.debug("num events returned %s", len(recommendations))
        return recommendations

    def as_recommendations_itr(self, filters: dict = None, page_size: int = None) -> Generator[dict, None, None]:
        """ Iterate through recommendations"""
        page_size = page_size if page_size else self.default_page_size
        partial_fn_itr = functools.partial(
            self.as_recommendations_base_fn, filters)
        for recommendation in self.as_gql_generic_itr(partial_fn_itr, page_size=page_size):
            yield recommendation

def dev_download_resolved_resolved_bindings(ai: AndromedaInventory) -> None:
    """ Download the resolved active bindings for all providers """
    logger.info("Downloading resolved active bindings for all providers")

    for provider in ai.cloud_provider_itr():
        active_bindings = []
        for assignment in  ai.as_provider_user_resolved_assignments_itr(provider['id'], provider, page_size=10):
            active_bindings.append(assignment)
            logger.debug("provider %s assignment %s added to the list", provider['id'], assignment)
        with open(os.path.join(ai.output_dir, f"{provider['id']}-resolved_active_bindings.json"), 'w') as f:
            json.dump(active_bindings, f, indent=2)

def dev_download_application_summary(ai: AndromedaInventory) -> None:
    """ Download the application summary for all providers """
    logger.info("Downloading application summary for all providers")
    app_data = namedtuple('app_data', ['name', 'id', 'configuredUsersCount', 'inactiveUsersCount', 'inactiveUsersPercentage'])

    with open(os.path.join(ai.output_dir, 'application_summary.csv'), 'w') as f:
        csv_writer = csv.DictWriter(f, fieldnames=app_data._fields)
        csv_writer.writeheader()
        for app in ai.app_provider_itr():
            app_stats = app['providerMembersMetadata']
            inactive_users = round(100*app_stats['inactiveUsersCount']/app_stats['configuredUsersCount'] if app_stats['configuredUsersCount'] else 0, 1)
            app_record = app_data(app['name'], app['id'], app_stats['configuredUsersCount'],
                        app_stats['inactiveUsersCount'], inactive_users)
            csv_writer.writerow(app_record._asdict())
            logger.debug("app summary %s", app_record)


def main():
    HELP_STR = """
    This script creates or updates an Andromeda Provider. It takes the parameters from the andromeda_settings.yaml file.

    The output is created at <output_dir>/<tenant_id>/andromeda-inventory.json eg.
    /tmp/andromeda-inventory/9c719c8f-bf6c-40cd-80bd-e18f671411f3/andromeda-inventory.json

    Example with API Token:
        python3 lib/python/sdk/samples/andromeda-inventory.py  --api-token <api_token> --gql-endpoint <gql endpoint> --http-endpoint <http endpoint>

    Example with Session cookie for local with page_size as 50:
        python3 lib/python/sdk/samples/andromeda-inventory.py  --session_cookie='<session_cookie> --page_size=50'
    """

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=(HELP_STR)
    )

    parser.add_argument('--api_token', '-t',
                        help='API token for Andromeda',
                        default="")

    parser.add_argument('--session_cookie', '-c',
                        help='Session Cookie for Andromeda',
                        default="")

    parser.add_argument('--gql_endpoint',
                        default="http://localhost:8088/graphql",
                        help='GQL Endpoint')

    parser.add_argument('--http_endpoint',
                        default="http://localhost:8080",
                        help='HTTP endpoint')

    parser.add_argument('--output_dir', '-o',
                        default="/tmp/andromeda-inventory",
                        help='HTTP endpoint')

    parser.add_argument('--provider_id', '-p',
                        default="",
                        help='ID of the provider to filter on')

    parser.add_argument('--logLevel',
                        default="DEBUG",
                        help='log level for the module when run as a script')

    parser.add_argument('--page_size',
                        default=DEFAULT_PAGE_SIZE, type=int,
                        help='Page size for fetching data. Default is 100')

    parser.add_argument('--development',
                        action='store_true',
                        help='for use during development')

    args = parser.parse_args()

    au = APIUtils(api_endpoint=args.http_endpoint)
    logger.setLevel(getattr(logging, args.logLevel))
    ch = logging.StreamHandler()
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(lineno)s: %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    api_session = None
    if args.session_cookie:
        logger.debug("Using cookie for session")
        api_session = au.get_api_session_w_cookie(args.session_cookie)
    elif args.api_token:
        logger.debug("Using api token for session")
        api_session = au.get_api_session_w_api_token(
            args.api_token)
    else:
         raise Exception("No API token or session cookie provided")

    if not api_session:
        raise Exception("No API session created")
    ai = AndromedaInventory(None, api_session, output_dir=args.output_dir, default_page_size=int(args.page_size),
                            as_endpoint=args.http_endpoint, gql_endpoint=args.gql_endpoint)

    if not args.development:
        ai.download_inventory(provider_id=args.provider_id)
    else:
        logger.info(json.dumps(ai.fetch_providers_summary(), indent=2))
        #dev_download_resolved_resolved_bindings(ai)
        dev_download_application_summary(ai)

if __name__ == '__main__':
    main()
