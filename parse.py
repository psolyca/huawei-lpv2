
import builtins
import sys
import argparse
import logging
import base64
from os import path
from typing import Optional, List, Dict

from pyshark import FileCapture

from huawei.protocol import (
    Command,
    AUTH_VERSION,
    Packet,
    encode_int,
    decode_int,
    hexlify,
    decrypt_packet,
    decrypt_bonding_key,
    create_secret_key,
    # for testing purpose
    create_bonding_key,
    generate_nonce,
)
from huawei.services.helper import get_service, get_command, add_method
from huawei.services.device_config import (
    Activities,
    DeviceConfig,
    LinkParams,
    process_link_params,
    process_authentication,
    process_battery_level,
    process_bond_params,
)
from huawei.services.notification import (
    Notification,
)
from huawei.services import CryptoTags

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class Parse:
    def __init__(self):
        self._received: int = None
        # self.state: BandState = BandState.Disconnected

        # self.client: BleakClient = client
        # self.loop = loop
        # In Sharedpreferences mac (server) = 88:11:96:5E:12:0A
        # In Wireshark server = 88:11:96:5E:12:0A
        # In Wireshark client = C4:F0:81:B9:4F:1A
        # In Packet client = 67:CD:3B:FF:4F:1A
        # In config hLPv2 client = C4:B3:01:XX:XX:XX
        # In config hLPv2 device = 6C:B7:49:XX:XX:XX
        self.server_mac: str = None #Band
        self.client_mac: str = None #Phone
        self.device_mac: str = None
        self.client_serial: str = None

        self._key: bytes = None
        self._server_nonce: Optional[bytes] = None
        self._client_nonce: bytes = None
        # self._encryption_counter: int = 0
        self._iv: bytes = None

        self.link_params: Optional[LinkParams] = None

        self.bond_status: Optional[int] = None
        self.bond_status_info: Optional[int] = None
        self.bt_version: Optional[int] = None
        self._bonding_key: bytes = None
        self._services: List = []
        self._commandsPerService: Dict = {}

        self._packet: Optional[Packet] = None
        # self._event = asyncio.Event()
        self.__message_id: int = -1

    def parse_log(self, input_file, verbose=False):
        cap = FileCapture(input_file, custom_parameters=["-2"])
        if verbose:
            cap.set_debug()

        for frame, pkt in enumerate(cap):
            if "BTATT" in pkt:
                if self.server_mac is None:
                    self.server_mac = pkt.bluetooth.addr.upper()
                if self.device_mac is None:
                    self.device_mac = pkt.bluetooth.src.upper()
                self._received = int(pkt.hci_h4.direction, 16)
                try:
                    pkt_value = pkt.btatt.value.replace(":", "")
                except AttributeError:
                    # No value
                    pass
                else:
                    logger.info(f"########## frame : {frame + 1} ##########")
                    self._packet = Packet.from_bytes(
                        bytes.fromhex(pkt_value), self._packet
                    )
                    if self._packet.complete:
                        self._manage_pkt()

    def _manage_pkt(self):
        service = get_service(self._packet.service_id)
        command = get_command(service, self._packet.command_id)
        crypted: bool = False
        if CryptoTags.Encryption in self._packet.command:
            self._packet = self._packet.decrypt(**self._credentials)
            crypted = True
        logger.info(
            f"{'Received' if self._received else 'Send'} "
            f"{'Crypted ' if crypted else ''} "
            f"Packet : {self._packet}"
        )
        try:
            command.process(self)
        except Exception as e:
            logger.debug(e)
        self._packet = None

    @property
    def _credentials(self):
        iv = self._packet.command[CryptoTags.InitVector].value
        return {"key": self._key, "iv": iv}

    @add_method(DeviceConfig.LinkParams)
    def _link_params(self):
        if self._received:
            self.link_params, self._server_nonce = process_link_params(
                self._packet.command
            )
        else:
            logger.info("Request parameters")

    @add_method(DeviceConfig.Auth)
    def _authentication(self):
        if self._received:
            process_authentication(
                self._packet.command, self._client_nonce, self._server_nonce
            )
        else:
            self._client_nonce = self._packet.command[
                DeviceConfig.Auth.Tags.Nonce
            ].value[2:]
            logger.info(
                "Request authentication:\n"
                f"\tClient nonce: {hexlify(self._client_nonce)}"
            )

    @add_method(DeviceConfig.BondParams)
    def _bondparams(self):
        if self._received:
            process_bond_params(self._packet.command)
        else:
            self.client_serial = self._packet.command[
                DeviceConfig.BondParams.Tags.ClientSerial
            ].value.decode()
            self.client_mac = self._packet.command[
                DeviceConfig.BondParams.Tags.ClientMacAddress
            ].value.decode()
            logger.info(
                "Request bond parameters:\n"
                f"\tClient serial: {self.client_serial}\n"
                f"\tClient mac: {self.client_mac}"
            )

    @add_method(DeviceConfig.Bond)
    def _bond(self):
        if self._received:
            status = self._packet.command[DeviceConfig.Bond.Tags.Status].value
            logger.info(f"Process bond:\n\tStatus: {int(status.hex(), 16)}")
        else:
            request_code = self._packet.command[
                DeviceConfig.Bond.Tags.RequestCode
            ].value
            self._bonding_key = self._packet.command[
                DeviceConfig.Bond.Tags.BondingKey
            ].value
            self._iv = self._packet.command[DeviceConfig.Bond.Tags.InitVector].value
            doNotKnow = self._packet.command[DeviceConfig.Bond.Tags.DoNotKnow].value
            if self._key is None:
                self._key = decrypt_bonding_key(
                    self.server_mac, self._bonding_key, self._iv
                )
            logger.info(
                "Request bond:\n"
                f"\tRequest code: {int(request_code.hex(), 16)}\n"
                f"\tBonding key: {hexlify(self._bonding_key)}\n"
                f"\tInitial vector: {hexlify(self._iv)}\n"
                f"\tKey: {hexlify(self._key)}\n"
                f"\tDo Not Know: {hexlify(doNotKnow)}"
            )

    # All following request and process have to be decoded...
    @add_method(DeviceConfig.ProductInfo)
    def _productinfo(self):
        if self._received:
            tags = DeviceConfig.ProductInfo.Tags
            model = (
                self._packet.command[tags.ProductModel]
                .value.rstrip(b'\x00')
                .decode()
            )
            logger.info(
                "Process product information\n"
                f"\tBTVersion: {self._packet.command[tags.BTVersion].value.decode()}\n"
                f"\tProductType: {decode_int(self._packet.command[tags.ProductType].value)}\n"
                f"\tSoftwareVersion: {self._packet.command[tags.SoftwareVersion].value.decode()}\n"
                f"\tSerialNumber: {self._packet.command[tags.SerialNumber].value.decode()}\n"
                f"\tProductModel: {model}\n"
                f"\tForceSN: {decode_int(self._packet.command[tags.ForceSN].value)}"
            )
        else:
            logger.info(str(self._packet))
            logger.info("Request product information")

    @add_method(DeviceConfig.SetTime)
    def _set_time(self):
        if self._received:
            logger.info("Process set time")
        else:
            logger.info("Request set time")

    @add_method(DeviceConfig.BatteryLevel)
    def _battery_level(self):
        if self._received:
            battery_level = process_battery_level(self._packet.command)
            logger.info(f"Battery level:\n\t{battery_level}")
        else:
            logger.info(f"Battery level requested")

    @add_method(DeviceConfig.SupportedServices)
    def _supported_services(self):
        if self._received:
            services = self._packet.command[
                DeviceConfig.SupportedServices.Tags.ActiveServices
            ].value

            active = [s for i, s in enumerate(self._services) if services[i]]
            logger.info(
                "Process supported services:\n"
                f"\t{active}"
            )
            self._services = active
        else:
            self._services = self._packet.command[
                DeviceConfig.SupportedServices.Tags.Services
            ].value
            logger.info("Request supported services")

    @add_method(DeviceConfig.SupportedCommands)
    def _supported_commands(self):
        if self._received:
            tags = DeviceConfig.SupportedCommands.Tags
            active = {}
            serviceId = None
            commands = self._packet.command[
                tags.SupportedCommands
            ].command
            for key in self._commandsPerService:
                for service in commands.tlvs:
                    if (
                        service.value == key
                        and service.tag == tags.ServiceId
                    ):
                        serviceId = decode_int(key)
                    elif serviceId is not None:
                        active[serviceId] = [
                            c
                            for i, c in enumerate(self._commandsPerService[key])
                            if service.value[i]
                        ]
                        serviceId = None
                        break
            logger.info("Received support commands:")
            for key in active:
                logger.info(f"\t{key}: {active[key]}")
            self._commandsPerService = active
        else:
            commands = self._packet.command[
                DeviceConfig.SupportedCommands.Tags.SupportedCommands
            ].command
            serviceId = None
            for tlv in commands.tlvs:
                if tlv.tag == DeviceConfig.SupportedCommands.Tags.ServiceId:
                    serviceId = tlv.value
                elif serviceId is not None:
                    self._commandsPerService[serviceId] = tlv.value
                    serviceId = None
            logger.info("Request support commands")

    @add_method(DeviceConfig.SupportedActivity)
    def _supported_activity(self):
        if self._received:
            activities = {}
            activity = None
            for tlv in self._packet.command[
                DeviceConfig.SupportedActivity.Tags.SupportedActivity
            ].command.tlvs:
                if tlv.tag == DeviceConfig.SupportedActivity.Tags.Activity:
                    activity = decode_int(tlv.value)
                elif activity is not None:
                    activities[activity] = 1 == ((decode_int(tlv.value) >> 5) & 1)
                    activity = None
            logger.info("Process supported activity with HeartRate:")
            for key in activities:
                logger.info(f"\t{Activities(key).name}: {activities[key]}")
        else:
            logger.info("Request  supported activity")

    @add_method(Notification.Type)
    def _notification_type(self):
        if self._received:
            logger.info(
                "Process notification type:\n"
                f"Promt Push = {hexlify(self._packet.command[Notification.Type.Tags.PromptPush].value)}"
            )

        else:
            logger.info("Request notification type")

def main():
    parser = argparse.ArgumentParser(description=
        'Parse Wireshark log file to decode Huawei LP protocol')
    parser.add_argument("-i", "--input",
                        action="store",
                        help="Path of log file.")
    parser.add_argument("-o", "--output",
                        action="store",
                        help="Path to save parsed log.")
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Path to save parsed log.")
    args = parser.parse_args()

    if args.input is not None:
        if not path.exists(args.input):
            print("Input path does not exists")
            exit()

    if args.output is not None:
        fh = logging.FileHandler(args.output, mode='w')
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
    else:
        sh = logging.StreamHandler()
        sh.setLevel(logging.DEBUG)
        logger.addHandler(sh)

    parser = Parse()
    parser.parse_log(args.input, args.verbose)

    ### Workaround for pyShark to hide an ignored exception when ProactorEventLoop
    ### is used on Windows.
    ### Exception ignored in: <function _ProactorBasePipeTransport.__del__ at
    ### ValueError: I/O operation on closed pipe
    ### From https://github.com/aio-libs/aiohttp/issues/4324#issuecomment-733884349
    from functools import wraps
    from asyncio.proactor_events import _ProactorBasePipeTransport

    def silence_event_loop_closed(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except ValueError as e:
                if str(e) != 'I/O operation on closed pipe':
                    raise
        return wrapper

    _ProactorBasePipeTransport.__del__ = silence_event_loop_closed(
        _ProactorBasePipeTransport.__del__
    )
    ###


if __name__ == "__main__":
    main()