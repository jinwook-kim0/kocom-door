"""Controller for Kocom Wallpad."""

from __future__ import annotations

from typing import List, Callable, Any, Tuple
from dataclasses import dataclass, replace

from homeassistant.const import Platform, UnitOfTemperature
from homeassistant.components.sensor import SensorDeviceClass
from homeassistant.components.binary_sensor import BinarySensorDeviceClass
from homeassistant.components.switch import SwitchDeviceClass
from homeassistant.components.climate.const import (
    PRESET_NONE,
    PRESET_AWAY,
    FAN_LOW,
    HVACMode,
)

from .const import (
    LOGGER,
    PACKET_PREFIX,
    PACKET_SUFFIX,
    PACKET_LEN,
    CMD_CONFIRM_TIMEOUT,
    DeviceType,
    SubType,
)
from .models import (
    DEVICE_TYPE_MAP,
    AIRCONDITIONER_HVAC_MAP,
    AIRCONDITIONER_FAN_MAP,
    VENTILATION_PRESET_MAP,
    ELEVATOR_DIRECTION_MAP,
    DeviceKey,
    DeviceState
)

Predicate = Callable[[DeviceState], bool]

REV_DT_MAP = {v: k for k, v in DEVICE_TYPE_MAP.items()}
REV_AC_HVAC_MAP = {v: k for k, v in AIRCONDITIONER_HVAC_MAP.items()}
REV_AC_FAN_MAP = {v: k for k, v in AIRCONDITIONER_FAN_MAP.items()}
REV_VENT_PRESET_MAP = {v: k for k, v in VENTILATION_PRESET_MAP.items()}
"""
Internal Door Bell
AA 55 
7B
9C 
02 
02 00 
FF FF 
FF 
FF 31 FF FF FF 02 01 24 
9B 0D 0D

AA55
7B
9C
02
0200
FFFF
FF
FF 31 FF FF FF 01 01 71
C80D0D

Common Door Bell
AA55
7B
9C
02
0800
FFFF
FF
FFFFFFFFFF010152
190D0D"""


"""Internal Call
AA55
79
BC
02
0200
31FF
FF
FF61FFFFFF030008
D30D0D

Open
AA55
79
BC
02
0200
31FF
FF
FF61FFFFFF240097
A20D0D

Drop
AA55
79
BC
02
0200
31FF
FF
FF61FFFFFF040091
440D0D
"""
"""
Common Door Call
AA55
79
BC
08
0200
FFFF
FF
FF61FFFFFF030026950D0D

AA55
79BC
08
0200
FFFF
FF
FF61FFFFFF2400B9
E40D0D

0xAA55
[2] = 7B
type [3] = 9C
[4] = 02
dest [5, 6] = 0200
src [7, 8] = FFFF
[9] = FF
[10:18] = FF 31 FF FF FF 01 01 71
[18] = C8

[2] 7B 
[3] 9C 
[4] 02 
dest [5, 6] 02 00 
src [7, 8] FF FF 
[9] FF 
[10: 18] FF 31 FF FF FF 02 01 24 
[18] 9B 0D 0D
"""
"""
AA55
7B9C
02
0800
FFFF
FF
FFFFFFFFFF010152
190D0D
"""
"""
Call AA55
[2] = 79
type [3] BC
[4] 02
dest [5, 6] 0200
src [7, 8] 31FF
[9] FF
[10: 18] = FF 61 FF FF FF 03 00 08
[18] D30D0D

Open AA55
[2] = 79
type [3] BC
[4] 02
dest [5, 6] 0200
src [7, 8] 31FF
[9] FF
[10: 18] FF 61 FF FF FF 24 00 97
[18] A20D0D

Drop AA55
[2] 79
type [3] BC
[4] 02
dest [5, 6] 0200
src [7, 8] 31FF
[9] FF
[10:18] FF 61 FF FF FF 04 00 91
[18] 44 0D 0D

"""
@dataclass(slots=True, frozen=True)
class PacketFrame:
    """Packet frame."""
    raw: bytes

    @property
    def packet_type(self) -> int:
        return (self.raw[3] >> 4) & 0x0F

    @property
    def dest(self) -> bytes:
        return self.raw[5:7]

    @property
    def src(self) -> bytes:
        return self.raw[7:9]

    @property
    def command(self) -> int:
        return self.raw[9]

    @property
    def payload(self) -> bytes:
        return self.raw[10:18]

    @property
    def checksum(self) -> int:
        return self.raw[18]

    @property
    def peer(self) -> tuple[int, int]:
        if (self.raw[2] >> 4) & 0x0F == 0x07:
            if self.dest[0] == 0x08:
                return (0x08, 0x00)
            else:
                return (self.dest[0], self.dest[1])
        else:
            LOGGER.warning("Peer resolution failed: dest=%s, src=%s", self.dest.hex(), self.src.hex())
            return (0, 0)

    @property
    def dev_type(self) -> DeviceType:
        dev_type = DEVICE_TYPE_MAP.get(self.peer[0], None)
        if dev_type is None:
            LOGGER.debug(f"Unknown device type code={hex(self.peer[0])}, raw={self.raw.hex()}, packet_type={hex(self.packet_type)}, src={self.src.hex()}, dest={self.dest.hex()}, command={hex(self.command)}, payload={self.payload.hex()}")
            #LOGGER.debug("Unknown device type code=%s, raw=%s", hex(self.peer[0]), self.raw.hex())
            dev_type = DeviceType.UNKNOWN
        return dev_type

    @property
    def dev_room(self) -> int:
        return self.peer[1]


class KocomController:
    """Controller for Kocom Wallpad."""

    def __init__(self, gateway) -> None:
        """Initialize the controller."""
        self.gateway = gateway
        self._rx_buf = bytearray()
        self._device_storage: dict[str, Any] = {}

    @staticmethod
    def _checksum(buf: bytes) -> int:
        return sum(buf) % 256

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self._rx_buf.extend(chunk)
        for pkt in self._split_buf():
            LOGGER.debug("Packet received: raw=%s", pkt.hex())
            self._dispatch_packet(pkt)

    def _split_buf(self) -> List[bytes]:
        packets: List[bytes] = []

        while len(self._rx_buf) >= PACKET_LEN:
            start = self._rx_buf.find(PACKET_PREFIX)
            if start < 0:
                break

            self._rx_buf = self._rx_buf[start:]
            if len(self._rx_buf) < PACKET_LEN:
                break

            # 고정 길이 확인 후 서픽스 검사
            candidate = bytes(self._rx_buf[:PACKET_LEN])
            if not candidate.endswith(PACKET_SUFFIX):
                # 한 바이트 밀어서 재탐색 (프레이밍 어긋남 복구)
                self._rx_buf = self._rx_buf[1:]
                continue
            else: 
                packets.append(candidate)
                self._rx_buf = self._rx_buf[PACKET_LEN:]
        return packets

    def _dispatch_packet(self, packet: bytes) -> None:
        frame = PacketFrame(packet)
        if self._checksum(packet[2:18]) != frame.checksum and frame.dev_type not in (DeviceType.INTERNAL_DOOR, DeviceType.COMMON_DOOR):
            LOGGER.debug("Packet checksum is invalid. raw=%s", frame.raw.hex())
            return

        dev_state = None
        if frame.dev_type == DeviceType.INTERNAL_DOOR:
            LOGGER.debug("Internal DOOR type: %s (raw=%s)", frame.dev_type.name, frame.raw.hex())
            dev_state = self._handle_internal_doorbell(frame)
        elif frame.dev_type == DeviceType.COMMON_DOOR:
            LOGGER.debug("Common DOOR type: %s (raw=%s)", frame.dev_type.name, frame.raw.hex())
            dev_state = self._handle_common_doorbell(frame)
           
        else:
            LOGGER.debug("Unhandled device type: %s (raw=%s)", frame.dev_type.name, frame.raw.hex())
            return

        if not dev_state:
            return

        if isinstance(dev_state, list):
            for state in dev_state:
                state._packet = packet
                self.gateway.on_device_state(state)
        else:
            dev_state._packet = packet
            self.gateway.on_device_state(dev_state)

    def _handle_internal_doorbell(self, frame: PacketFrame) -> List[DeviceState]:
        states: List[DeviceState] = []

        key = DeviceKey(
            device_type=frame.dev_type,
            room_index=frame.dev_room,
            device_index = 0,
            sub_type=SubType.BELL,
        )
        platform = Platform.BINARY_SENSOR
        attribute = {"device_class": BinarySensorDeviceClass.SOUND}
        state = frame.payload[5] in (0x01, 0x02)
        dev = DeviceState(key=key, platform=platform, attribute=attribute, state=state)
        states.append(dev)
     
        key = DeviceKey(
            device_type=frame.dev_type,
            room_index=frame.dev_room,
            device_index = 1,
            sub_type = SubType.CALL
        )
        platform = Platform.SWITCH
        attribute = {}

        if frame.payload[5] in (0x03, 0x04):
            state = frame.payload[5] == 0x03
        else:
            state = None
        dev = DeviceState(key=key, platform=platform, attribute=attribute, state=state)
        states.append(dev)

        key = DeviceKey(
            device_type=frame.dev_type,
            room_index=frame.dev_room,
            device_index=2,
            sub_type = SubType.DOOR_LOCK
        )
        platform = Platform.BUTTON
        attribute = {"device_class": None}
        state = frame.payload[5] == 0x24
        dev = DeviceState(key=key, platform=platform, attribute=attribute, state=state)
        states.append(dev)
        return states
       

    def _handle_common_doorbell(self, frame: PacketFrame) -> List[DeviceState]:
        states: List[DeviceState] = []

        key = DeviceKey(
            device_type=frame.dev_type,
            room_index=frame.dev_room,
            device_index = 0,
            sub_type=SubType.BELL,
        )
        platform = Platform.BINARY_SENSOR
        attribute = {"device_class": BinarySensorDeviceClass.SOUND}
        state = frame.payload[5] in (0x01, 0x02)
        dev = DeviceState(key=key, platform=platform, attribute=attribute, state=state)
        states.append(dev)
     
        key = DeviceKey(
            device_type=frame.dev_type,
            room_index=frame.dev_room,
            device_index = 1,
            sub_type = SubType.CALL
        )
        platform = Platform.SWITCH
        attribute = {}

        if frame.payload[5] in (0x03, 0x04):
            state = frame.payload[5] == 0x03
        else:
            state = None
        dev = DeviceState(key=key, platform=platform, attribute=attribute, state=state)
        states.append(dev)

        key = DeviceKey(
            device_type=frame.dev_type,
            room_index=frame.dev_room,
            device_index=2,
            sub_type = SubType.DOOR_LOCK
        )
        platform = Platform.BUTTON
        attribute = {"device_class": None}
        state = frame.payload[5] == 0x24
        dev = DeviceState(key=key, platform=platform, attribute=attribute, state=state)
        states.append(dev)
        return states
          
   
    # TODO: 명령 상태 비교 로직 통합 (gateway.py)
    def _match_key_and(self, key: DeviceKey, cond: Predicate) -> Predicate:
        def _inner(dev: DeviceState) -> bool:
            if dev.key.key != key.key:
                return False
            return cond(dev)
        return _inner

    def _expect_for_switch_like(self, key: DeviceKey, action: str, **kwargs: Any) -> Tuple[Predicate, float]:
        def _on(dev: DeviceState) -> bool:  return bool(dev.state) is True
        def _off(dev: DeviceState) -> bool: return bool(dev.state) is False

        if action == "turn_on":
            return self._match_key_and(key, _on), CMD_CONFIRM_TIMEOUT
        if action == "turn_off":
            return self._match_key_and(key, _off), CMD_CONFIRM_TIMEOUT
        return self._match_key_and(key, lambda _d: False), CMD_CONFIRM_TIMEOUT

    def build_expectation(self, key: DeviceKey, action: str, **kwargs: Any) -> Tuple[Predicate, float]:
        dt = key.device_type
        if dt in (DeviceType.LIGHT, DeviceType.LIGHTCUTOFF, DeviceType.OUTLET, DeviceType.ELEVATOR):
            return self._expect_for_switch_like(key, action, **kwargs)
        if dt == DeviceType.VENTILATION:
            return self._expect_for_ventilation(key, action, **kwargs)
        if dt == DeviceType.GASVALVE:
            return self._expect_for_gasvalve(key, action, **kwargs)
        if dt == DeviceType.THERMOSTAT:
            return self._expect_for_thermostat(key, action, **kwargs)
        if dt == DeviceType.AIRCONDITIONER:
            return self._expect_for_airconditioner(key, action, **kwargs)            
        if dt == DeviceType.INTERNAL_DOOR:
            return self._match_key_and(key, lambda _d: True), CMD_CONFIRM_TIMEOUT
        if dt == DeviceType.COMMON_DOOR:
            return self._match_key_and(key, lambda _d: True), CMD_CONFIRM_TIMEOUT
        return self._match_key_and(key, lambda _d: False), CMD_CONFIRM_TIMEOUT

    def generate_command(self, key: DeviceKey, action: str, **kwargs) -> Tuple[bytes, Predicate, float]:
        device_type = key.device_type
        room_index = key.room_index
        device_index = key.device_index
        sub_type = key.sub_type

        if device_type not in REV_DT_MAP:
            raise ValueError(f"Invalid device type: {device_type}")

        type_bytes = bytes([0x79, 0xBC])
        padding = bytes([0x00])
        dest_dev = bytes([REV_DT_MAP[device_type]])
        dest_room = bytes([room_index & 0xFF])
        src_dev = bytes([0x01])
        src_room = bytes([0x00])
        command = bytes([0xff])
        data = bytearray(8)

        if device_type == DeviceType.INTERNAL_DOOR:
            if sub_type == SubType.DOOR_LOCK and action == "turn_on":
                padding = bytes([0x02])
                dest_dev = bytes([0x02])
                dest_room = bytes([0x00])
                src_dev = bytes([0x31])
                src_room = bytes([0xff])
                data = bytes([0xff, 0x61, 0xff, 0xff, 0xff, 0x24, 0x00, 0x97])
        elif sub_type == SubType.CALL:
                padding = bytes([0x02])
                dest_dev = bytes([0x02])
                dest_room = bytes([0x00])
                src_dev = bytes([0x31])
                src_room = bytes([0xff])
                if action == "turn_on":
                    data = bytes([0xff, 0x61, 0xff, 0xff, 0xff, 0x03, 0x00, 0x08])
                elif action == "turn_off":
                    data = bytes([0xff, 0x61, 0xff, 0xff, 0xff, 0x04, 0x00, 0x91])
        elif device_type == DeviceType.COMMON_DOOR:
            if sub_type == SubType.DOOR_LOCK and action == "turn_on":
                padding = bytes([0x08])
                dest_dev = bytes([0x02])
                dest_room = bytes([0x00])
                src_dev = bytes([0xff])
                src_room = bytes([0xff])
                data = bytes([0xff, 0x61, 0xff, 0xff, 0xff, 0x24, 0x00, 0xb9])
            elif sub_type == SubType.CALL:
                padding = bytes([0x08])
                dest_dev = bytes([0x02])
                dest_room = bytes([0x00])
                src_dev = bytes([0xff])
                src_room = bytes([0xff])
                if action == "turn_on":
                    data = bytes([0xff, 0x61, 0xff, 0xff, 0xff, 0x03, 0x00, 0x26])
                elif action == "turn_off":
                    padding = bytes([0x00])
                    dest_dev = bytes([0x00])
                    src_dev = bytes([0x00])
                    data = bytes([0xff, 0x00, 0xff, 0xff, 0xff, 0x04, 0x00, 0xc5])
        else:
            raise ValueError(f"Invalid device generator: {device_type}")

        body = b"".join([type_bytes, padding, dest_dev, dest_room, src_dev, src_room, command, bytes(data)])
        checksum = bytes([self._checksum(body)])
        packet = bytes([0xAA, 0x55]) + body + checksum + bytes([0x0D, 0x0D])

        expect, timeout = self.build_expectation(key, action, **kwargs)
        return packet, expect, timeout

   