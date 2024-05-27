# Copyright 2021 99cloud
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from pathlib import PurePath
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from keystoneauth1.identity.v3 import Password, Token
from keystoneauth1.session import Session
from keystoneclient.client import Client as KeystoneClient

from skyline_apiserver import schemas, version
from skyline_apiserver.api import deps
from skyline_apiserver.client import utils
from skyline_apiserver.client.openstack.keystone import get_token_data, get_user, revoke_token
from skyline_apiserver.client.openstack.system import (
    get_endpoints,
    get_project_scope_token,
    get_projects,
)
from skyline_apiserver.client.utils import generate_session, get_system_session
from skyline_apiserver.config import CONF
from skyline_apiserver.core.security import (
    generate_profile,
    generate_profile_by_token,
    parse_access_token,
)
from skyline_apiserver.db import api as db_api
from skyline_apiserver.log import LOG
from skyline_apiserver.types import constants

from keystoneauth1.session import Session
from keystoneclient.v3 import client
from skyline_apiserver import schemas

router = APIRouter()


async def _get_default_project_id(
    session: Session, region: str, user_id: Optional[str] = None
) -> Union[str, None]:
    system_session =session
    if not user_id:
        token = session.get_token()
        token_data = await get_token_data(token, region, system_session)
        _user_id = token_data["token"]["user"]["id"]
    else:
        _user_id = user_id
    user = await get_user(_user_id, region, system_session)
    return getattr(user, "default_project_id", None)


async def _get_projects_and_unscope_token(
    region: str,
    domain: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    token: Optional[str] = None,
    project_enabled: bool = False,
) -> Tuple[List[Any], str, Union[str, None]]:
    unscope_auth = None
    if token:
        unscope_auth = Token(
            auth_url="https://cloud10.cloudportal.app:5000/v3/",
            token=token,
            reauthenticate=False,
        )
    else:
        unscope_auth = Password(
            auth_url="https://cloud10.cloudportal.app:5000/v3/",
            user_domain_name=domain,
            username=username,
            password=password,
            reauthenticate=False
        )

    session = Session(
        auth=unscope_auth, verify=CONF.default.cafile, timeout=constants.DEFAULT_TIMEOUT
    )

    unscope_client = KeystoneClient(
        session=session,
        endpoint="https://cloud10.cloudportal.app:5000/v3/",
        interface=CONF.openstack.interface_type,
        # project_name="service",
        project_domain_id="Default",
        user_domain_id="Default"
    )

    project_scope = unscope_client.auth.projects()
    unscope_token = token if token else session.get_token()

    if project_enabled:
        project_scope = [scope for scope in project_scope if scope.enabled]

    if not project_scope:
        raise Exception("You are not authorized for any projects or domains.")
    service_object = next((obj for obj in project_scope if obj.name == 'service'), None)

    # default_project_id = await _get_default_project_id(session, region)

    return project_scope, unscope_token, service_object.id


async def _patch_profile(profile: schemas.Profile, global_request_id: str, session: Session) -> schemas.Profile:
    try:
        profile.endpoints = await get_endpoints(region=profile.region, session=session)

        projects = await get_projects(
            global_request_id=global_request_id,
            region=profile.region,
            user=profile.user.id,
            session=session
        )

        if not projects:
            projects, _, default_project_id = await _get_projects_and_unscope_token(
                region=profile.region, token=profile.keystone_token
            )
        else:
            default_project_id = await _get_default_project_id(
                session, profile.region, user_id=profile.user.id
            )

        profile.projects = {
            i.id: {
                "name": i.name,
                "enabled": i.enabled,
                "domain_id": i.domain_id,
                "description": i.description,
            }
            for i in projects
        }

        profile.default_project_id = default_project_id

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    return profile


@router.post(
    "/login",
    description="Login & get user profile.",
    responses={
        200: {"model": schemas.Profile},
        401: {"model": schemas.UnauthorizedMessage},
    },
    response_model=schemas.Profile,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def login(
    request: Request,
    response: Response,
    credential: schemas.Credential,
    x_openstack_request_id: str = Header(
        "",
        alias=constants.INBOUND_HEADER,
        regex=constants.INBOUND_HEADER_REGEX,
    ),
) -> schemas.Profile:
    try:
        project_scope, unscope_token, default_project_id = await _get_projects_and_unscope_token(
            region=credential.region,
            domain="Default",
            username=credential.username,
            password=credential.password,
            project_enabled=True,
        )

        if default_project_id not in [i.id for i in project_scope]:
            default_project_id = None
        project_scope_token = await get_project_scope_token(
            keystone_token=unscope_token,
            region=credential.region,
            project_id=default_project_id or project_scope[0].id,
        )



        new_auth = Password(
                    auth_url="https://cloud10.cloudportal.app:5000/v3/",
                    username=credential.username, 
                    password=credential.password,
                    user_domain_name="default",
                    project_name="admin",
                    project_domain_name="default",
                )
        new_session = Session(auth=new_auth)
        new_client = KeystoneClient(session=new_session)
        # new_client = KeystoneClient(session=new_session,project_name="service",)

        new_project_scope = new_client.auth.projects()
        new_token = new_session.get_token()
        new_project_scope = [scope for scope in new_project_scope if scope.enabled]
        if not new_project_scope:
            raise Exception("You are not authorized for any projects or domains.")
        
        new_token_data = new_client.tokens.get_token_data(token=new_token)

        # token_data = unscope_client.tokens.get_token_data(token=project_scope_token)
        profile = schemas.Profile(
            keystone_token=project_scope_token,
            region=credential.region,
            project=new_token_data["token"]["project"],
            user=new_token_data["token"]["user"],
            roles=new_token_data["token"]["roles"],
            keystone_token_exp=new_token_data["token"]["expires_at"],
            base_domains=CONF.openstack.base_domains,
            exp=int(time.time()) + CONF.default.access_token_expire,
            uuid=uuid.uuid4().hex,
            version=version.version_string(),
        )
        # profile = await generate_profile(
        #     keystone_token=project_scope_token,
        #     region=credential.region,
        #     session=session,
        #     unscope_client=unscope_client,
        # )
        profile = await _patch_profile(profile, x_openstack_request_id, new_session)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    else:
        response.set_cookie(CONF.default.session_name, profile.toJWTPayload())
        response.set_cookie(constants.TIME_EXPIRED_KEY, str(profile.exp))
        return profile


@router.get(
    "/sso",
    description="SSO configuration.",
    responses={
        200: {"model": schemas.SSO},
    },
    response_model=schemas.SSO,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def get_sso(request: Request) -> schemas.SSO:
    sso: Dict = {
        "enable_sso": False,
        "protocols": [],
    }
    if CONF.openstack.sso_enabled:
        protocols: List = []

        ks_url = CONF.openstack.keystone_url.rstrip("/")
        url_scheme = "https" if CONF.default.ssl_enabled else "http"
        port = f":{request.url.port}" if request.url.port else ""
        base_url = f"{url_scheme}://{request.url.hostname}{port}"
        base_path = str(PurePath("/").joinpath(CONF.openstack.nginx_prefix, "skyline"))

        for protocol in CONF.openstack.sso_protocols:

            url = (
                f"{ks_url}/auth/OS-FEDERATION/websso/{protocol}"
                f"?origin={base_url}{base_path}{constants.API_PREFIX}/websso"
            )

            protocols.append(
                {
                    "protocol": protocol,
                    "url": url,
                }
            )

        sso = {
            "enable_sso": CONF.openstack.sso_enabled,
            "protocols": protocols,
        }

    return schemas.SSO(**sso)


@router.post(
    "/websso",
    description="Websso",
    responses={
        302: {"class": RedirectResponse},
        401: {"model": schemas.common.UnauthorizedMessage},
    },
    response_class=RedirectResponse,
    status_code=status.HTTP_302_FOUND,
    response_description="Redirect",
)
async def websso(
    token: str = Form(...),
    x_openstack_request_id: str = Header(
        "",
        alias=constants.INBOUND_HEADER,
        regex=constants.INBOUND_HEADER_REGEX,
    ),
) -> RedirectResponse:
    try:
        project_scope, _, default_project_id = await _get_projects_and_unscope_token(
            region=CONF.openstack.sso_region,
            token=token,
            project_enabled=True,
        )

        if default_project_id not in [i.id for i in project_scope]:
            default_project_id = None
        project_scope_token = await get_project_scope_token(
            keystone_token=token,
            region=CONF.openstack.sso_region,
            project_id=default_project_id or project_scope[0].id,
        )

        profile = await generate_profile(
            keystone_token=project_scope_token,
            region=CONF.openstack.sso_region,
        )

        profile = await _patch_profile(profile, x_openstack_request_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    else:
        response = RedirectResponse(url="/base/overview", status_code=status.HTTP_302_FOUND)
        response.set_cookie(CONF.default.session_name, profile.toJWTPayload())
        response.set_cookie(constants.TIME_EXPIRED_KEY, str(profile.exp))
        return response


@router.get(
    "/profile",
    description="Get user profile.",
    responses={
        200: {"model": schemas.Profile},
        401: {"model": schemas.UnauthorizedMessage},
    },
    response_model=schemas.Profile,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def get_profile(
    profile: schemas.Profile = Depends(deps.get_profile_update_jwt),
    x_openstack_request_id: str = Header(
        "",
        alias=constants.INBOUND_HEADER,
        regex=constants.INBOUND_HEADER_REGEX,
    ),
) -> schemas.Profile:
    session = get_system_session()

    return await _patch_profile(profile, x_openstack_request_id,session)


@router.post(
    "/logout",
    description="Log out.",
    responses={
        200: {"model": schemas.Message},
    },
    response_model=schemas.Message,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def logout(
    response: Response,
    request: Request,
    payload: str = Depends(deps.getJWTPayload),
    x_openstack_request_id: str = Header(
        "",
        alias=constants.INBOUND_HEADER,
        regex=constants.INBOUND_HEADER_REGEX,
    ),
) -> schemas.Message:
    if payload:
        try:
            token = parse_access_token(payload)
            profile = await generate_profile_by_token(token)
            session = await generate_session(profile)
            await revoke_token(profile, session, x_openstack_request_id, token.keystone_token)
            await db_api.revoke_token(profile.uuid, profile.exp)
        except Exception as e:
            LOG.debug(str(e))
    response.delete_cookie(CONF.default.session_name)
    return schemas.Message(message="Logout OK")


@router.post(
    "/switch_project/{project_id}",
    description="Switch project.",
    responses={
        200: {"model": schemas.Profile},
        401: {"model": schemas.UnauthorizedMessage},
    },
    response_model=schemas.Profile,
    status_code=status.HTTP_200_OK,
    response_description="OK",
)
async def switch_project(
    project_id: str,
    response: Response,
    profile: schemas.Profile = Depends(deps.get_profile),
    x_openstack_request_id: str = Header(
        "",
        alias=constants.INBOUND_HEADER,
        regex=constants.INBOUND_HEADER_REGEX,
    ),
) -> schemas.Profile:
    try:
        project_scope_token = await get_project_scope_token(
            keystone_token=profile.keystone_token,
            region=profile.region,
            project_id=project_id,
        )

        profile = await generate_profile(
            keystone_token=project_scope_token,
            region=profile.region,
            uuid_value=profile.uuid,
        )
        profile = await _patch_profile(profile, x_openstack_request_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    else:
        response.set_cookie(CONF.default.session_name, profile.toJWTPayload())
        response.set_cookie(constants.TIME_EXPIRED_KEY, str(profile.exp))
        return profile
