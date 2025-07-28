

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class HostConfig(BaseSettings):
    """
    Configuration settings for Elasticsearch
    """

    DIFY_WEB_HOST: Optional[str] = Field(
        description="dify web host",
        default="localhost",
    )
    OIDC_REDIRECT_URI: Optional[str] = Field(
        description="oidc",
        default="localhost",
    )

    OIDC_CLIENT_ID: Optional[str] = Field(
        description="oidc",
        default="localhost",
    )
    OIDC_CLIENT_SECRET: Optional[str] = Field(
        description="oidc",
        default="localhost",
    )


