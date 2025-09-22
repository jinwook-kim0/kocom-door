"""Binary Sensor platform for Kocom Wallpad."""

from __future__ import annotations

from typing import Any, List

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorDeviceClass
)

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.event import async_call_later

from .gateway import KocomGateway
from .models import DeviceState
from .entity_base import KocomBaseEntity
from .const import DOMAIN, LOGGER, SubType


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Kocom binary sensor platform."""
    gateway: KocomGateway = hass.data[DOMAIN][entry.entry_id]

    @callback
    def async_add_binary_sensor(devices=None):
        """Add binary sensor entities."""
        if devices is None:
            devices = gateway.get_devices_from_platform(Platform.BINARY_SENSOR)

        entities: List[KocomBinarySensor] = []
        for dev in devices:
            if dev.key.sub_type in (SubType.BELL, SubType.PRESENCE):
                entity = KocomDoorBell(gateway, dev)
            else:
                entity = KocomBinarySensor(gateway, dev)
            entities.append(entity)
        if entities:
            async_add_entities(entities)

    entry.async_on_unload(
        async_dispatcher_connect(
            hass, gateway.async_signal_new_device(Platform.BINARY_SENSOR), async_add_binary_sensor
        )
    )
    async_add_binary_sensor()
    

class KocomBinarySensor(KocomBaseEntity, BinarySensorEntity):
    """Representation of a Kocom binary sensor."""

    def __init__(self, gateway: KocomGateway, device: DeviceState) -> None:
        """Initialize the binary sensor."""
        super().__init__(gateway, device)

    @property
    def is_on(self) -> bool:
        return self._device.state
    
    @property
    def device_class(self) -> BinarySensorDeviceClass | None:
        return self._device.attribute.get("device_class", None)
    
    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        return self._device.attribute.get("extra_state", None)
    
class KocomDoorBell(KocomBinarySensor):
    def __init__(self, gateway: KocomGateway, device: DeviceState) -> None:
        """Initialize the binary sensor."""
        super().__init__(gateway, device)
        self._reset_timer = None

    async def async_added_to_hass(self):
        LOGGER.debug(f"DoorBell {self._device.key.device_type.name} async_added_to_hass")
        sig = self.gateway.async_signal_device_updated(self._device.key.unique_id)
        self._reset_timer = async_call_later(self.hass, 2, self._auto_reset_callback)
        LOGGER.debug(self._reset_timer)
        @callback
        def _handle_update(dev):
            self._device = dev
            self.update_from_state()
        self._unsubs.append(async_dispatcher_connect(self.hass, sig, _handle_update))

    @callback
    def update_from_state(self) -> None:
        LOGGER.debug(f"BinarySensor:: update_from_state (state: {self._device.state})")
        self.async_write_ha_state()
        if self.is_on:
            if self._reset_timer:
                self._reset_timer()
            LOGGER.debug("Auto reset scheduled")
            self._reset_timer = async_call_later(self.hass, 10, self._auto_reset_callback)
        
    async def _auto_reset_callback(self, now):
        LOGGER.debug("Async Auto Reset")
        self._device.state = False
        self.async_write_ha_state()
        self._reset_timer = None
