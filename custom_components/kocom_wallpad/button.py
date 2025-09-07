"""Switch platform for Kocom Wallpad."""

from __future__ import annotations

from typing import Any, List

from homeassistant.components.button import ButtonEntity, ButtonDeviceClass

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from .gateway import KocomGateway
from .models import DeviceState
from .entity_base import KocomBaseEntity
from .const import DOMAIN, LOGGER


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Kocom switch platform."""
    gateway: KocomGateway = hass.data[DOMAIN][entry.entry_id]

    @callback
    def async_add_button(devices=None):
        """Add switch entities."""
        if devices is None:
            devices = gateway.get_devices_from_platform(Platform.BUTTON)

        entities: List[KocomDoorLock] = []
        for dev in devices:
            entity = KocomDoorLock(gateway, dev)
            entities.append(entity)
        if entities:
            async_add_entities(entities)

    entry.async_on_unload(
        async_dispatcher_connect(
            hass, gateway.async_signal_new_device(Platform.BUTTON), async_add_button
        )
    )
    async_add_button()

class KocomDoorLock(KocomBaseEntity, ButtonEntity):
    _attr_icon = "mdi:door-open"
    
    def __init__(self, gateway: KocomGateway, device: DeviceState) -> None:
        super().__init__(gateway, device)
        
    @property
    def device_class(self) -> ButtonDeviceClass:
        return self._device.attribute.get("device_class", None)
    
    async def async_press(self) -> None:
        await self.gateway.async_send_action(self._device.key, "turn_on")


