from configs.extra.host_config import HostConfig
from configs.extra.notion_config import NotionConfig
from configs.extra.sentry_config import SentryConfig


class ExtraServiceConfig(
    # place the configs in alphabet order
    NotionConfig,
    SentryConfig,
    HostConfig,
):
    pass
