"""Component setup for Kocom Wallpad."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_HOST, CONF_PORT, EVENT_HOMEASSISTANT_STOP
from homeassistant.helpers import device_registry as dr

from .const import (
    CONF_RECOVERY_FAILURES,
    CONF_RECOVERY_SERVICE,
    DEFAULT_RECOVERY_FAILURES,
    DEFAULT_RECOVERY_SERVICE,
    DOMAIN,
    PLATFORMS,
)
from .gateway import KocomGateway


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Kocom Wallpad from a config entry."""
    host: str = entry.data[CONF_HOST]
    port: int | None = entry.data[CONF_PORT]
    recovery_service = entry.options.get(
        CONF_RECOVERY_SERVICE,
        entry.data.get(CONF_RECOVERY_SERVICE, DEFAULT_RECOVERY_SERVICE),
    )
    recovery_failures = entry.options.get(
        CONF_RECOVERY_FAILURES,
        entry.data.get(CONF_RECOVERY_FAILURES, DEFAULT_RECOVERY_FAILURES),
    )

    device_registry = dr.async_get(hass)
    device_registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, str(host))},
        manufacturer="KOCOM Co., Ltd",
        model="EW11 Door Gateway",
        name=f"Kocom Door {host}",
    )

    gateway = KocomGateway(
        hass,
        entry,
        host=host,
        port=port,
        recovery_service=recovery_service,
        recovery_failures=recovery_failures,
    )
    try:
        await gateway.async_get_entity_registry()
        await gateway.async_start()

        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = gateway

        entry.async_on_unload(
            hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, gateway.async_stop)
        )
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except Exception:
        hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
        await gateway.async_stop()
        raise

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        gateway: KocomGateway = hass.data[DOMAIN].pop(entry.entry_id)
        await gateway.async_stop()
    return unload_ok
