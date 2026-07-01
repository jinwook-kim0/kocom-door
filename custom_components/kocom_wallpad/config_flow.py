"""Config flow for Kocom Wallpad."""

from __future__ import annotations

from typing import Any
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_HOST, CONF_PORT

from .const import (
    CONF_RECOVERY_FAILURES,
    CONF_RECOVERY_SERVICE,
    DEFAULT_RECOVERY_FAILURES,
    DEFAULT_RECOVERY_SERVICE,
    DEFAULT_TCP_PORT,
    DOMAIN,
)


class KocomConfigFlow(ConfigFlow, domain=DOMAIN):
    """Config flow for Kocom Wallpad."""

    VERSION = 1

    @staticmethod
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Create the options flow."""
        return KocomOptionsFlow(config_entry)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a flow initialized by the user."""
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = user_input[CONF_HOST]
            port: int = user_input[CONF_PORT]

            # 시리얼의 경우 host가 "/"로 시작하면 장치 경로로 간주하고 port 무시
            if host.startswith("/"):
                port = None

            await self.async_set_unique_id(host)
            self._abort_if_unique_id_configured()

            return self.async_create_entry(
                title=host,
                data={CONF_HOST: host, CONF_PORT: port}
            )

        schema = vol.Schema({
            vol.Required(CONF_HOST): str,
            vol.Required(CONF_PORT, default=DEFAULT_TCP_PORT): int,
        })
        return self.async_show_form(
            step_id="user", data_schema=schema, errors=errors
        )


class KocomOptionsFlow(OptionsFlow):
    """Options flow for Kocom Door."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage Kocom Door options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        schema = vol.Schema({
            vol.Optional(
                CONF_RECOVERY_SERVICE,
                default=self.config_entry.options.get(
                    CONF_RECOVERY_SERVICE,
                    self.config_entry.data.get(
                        CONF_RECOVERY_SERVICE, DEFAULT_RECOVERY_SERVICE
                    ),
                ),
            ): str,
            vol.Optional(
                CONF_RECOVERY_FAILURES,
                default=self.config_entry.options.get(
                    CONF_RECOVERY_FAILURES,
                    self.config_entry.data.get(
                        CONF_RECOVERY_FAILURES, DEFAULT_RECOVERY_FAILURES
                    ),
                ),
            ): int,
        })
        return self.async_show_form(step_id="init", data_schema=schema)
