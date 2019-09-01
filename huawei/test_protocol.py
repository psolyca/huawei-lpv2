import unittest

from .protocol import HUAWEI_LPV2_MAGIC, VarInt, TLV, Command, Packet, encode_int, decode_int, hexlify, \
    create_secret_key, create_bonding_key, generate_nonce, decrypt, AES_BLOCK_SIZE, NONCE_LENGTH, encrypt, \
    compute_digest


class TestUtils(unittest.TestCase):
    def test_hexlify(self):
        self.assertEqual("", hexlify(b""))
        self.assertEqual("31 32 33 34 35", hexlify(b"12345"))

    def test_int_encoding(self):
        self.assertEqual(list(range(1000)), [decode_int(encode_int(i)) for i in range(1000)])


class TestVarInt(unittest.TestCase):
    INTS = [0, 1, 127, 128, 8193, 16383, 16384]
    BYTES = [b"\x00", b"\x01", b"\x7F", b"\x81\x00", b"\xC0\x01", b"\xFF\x7F", b"\x81\x80\x00"]

    def test_serialization(self):
        self.assertEqual(self.BYTES, [bytes(VarInt(i)) for i in self.INTS])

    def test_deserialization(self):
        self.assertEqual(self.INTS, [int(VarInt.from_bytes(i)) for i in self.BYTES])

    def test_roundtrip(self):
        numbers = list(range(1000))
        self.assertEqual(numbers, [int(VarInt.from_bytes(bytes(VarInt(i)))) for i in numbers])

    def test_equality(self):
        self.assertEqual(VarInt(1), VarInt(1))
        self.assertNotEqual(VarInt(1), VarInt(2))

    def test_length(self):
        self.assertEqual([len(x) for x in self.BYTES], [len(VarInt(i)) for i in self.INTS])


class TestTLV(unittest.TestCase):
    def test_serialization(self):
        tlv = TLV(tag=1, value=b"abc")
        self.assertEqual(b"\x01\x03abc", bytes(tlv))

    def test_deserialization(self):
        pass  # TODO

    def test_equality(self):
        tlv1, tlv2, tlv3 = TLV(tag=1, value=b"abc"), TLV(tag=1, value=b"abc"), TLV(tag=1, value=b"cde")
        self.assertEqual(tlv1, tlv2)
        self.assertNotEqual(tlv1, tlv3)


class TestCommand(unittest.TestCase):
    DATA = "01 00 02 00 03 00 04 00"

    def test_serialization(self):
        cmd1, cmd2 = Command(), Command(tlvs=[TLV(tag=1, value=b"abc"), TLV(tag=2, value=b"cde")])
        self.assertEqual(b"", bytes(cmd1))
        self.assertEqual(b"\x01\x03abc\x02\x03cde", bytes(cmd2))

        self.assertEqual(cmd2[2], TLV(tag=2, value=b"cde"))

    def test_deserialization(self):
        cmd = Command.from_bytes(bytes.fromhex(self.DATA))

        self.assertEqual(4, len(cmd.tlvs))
        self.assertEqual([1, 2, 3, 4], [tlv.tag for tlv in cmd.tlvs])
        self.assertEqual([b""] * 4, [tlv.value for tlv in cmd.tlvs])

        self.assertEqual(cmd[3], TLV(tag=3, value=b""))

    def test_contains(self):
        cmd = Command.from_bytes(bytes.fromhex(self.DATA))
        self.assertTrue(all(tag in cmd for tag in [1, 2, 3, 4]))
        self.assertFalse(5 in cmd)


class TestPacket(unittest.TestCase):
    DATA = "5A 00 08 00 01 02 03 03 61 62 63 E1 D3"
    PACKET = Packet(service_id=1, command_id=2, command=Command(tlvs=[TLV(tag=3, value=b"abc")]))

    def test_deserialization(self):
        self.assertRaisesRegex(ValueError, r"packet too short", Packet.from_bytes, b"")
        self.assertRaisesRegex(ValueError, r"magic mismatch", Packet.from_bytes, b"123456")
        self.assertRaisesRegex(ValueError, r"checksum mismatch", Packet.from_bytes, HUAWEI_LPV2_MAGIC + b"123456")

        self.assertEqual(self.PACKET, Packet.from_bytes(bytes.fromhex(self.DATA)))

    def test_serialization(self):
        self.assertEqual(bytes.fromhex(self.DATA), bytes(self.PACKET))


class TestCrypto(unittest.TestCase):
    MAC_ADDRESS = "FF:FF:FF:FF:FF:CC"
    SECRET_KEY = bytes.fromhex("EE FF 25 87 2A BB 19 1A 15 37 85 24 AF C0 89 E6")
    DIGEST = "BD 37 66 40 CD 62 73 FB AE A3 25 1B F3 4F 51 3D E3 B5 F3 4A 95 DC 9B 6F FD DB 93 AD 59 67 03 B0"

    def test_generate_nonce(self):
        self.assertEqual(AES_BLOCK_SIZE, NONCE_LENGTH)
        self.assertEqual(AES_BLOCK_SIZE, len(generate_nonce()))

    def test_digest(self):
        self.assertEqual(bytes.fromhex(self.DIGEST), compute_digest("", b"", b""))

    def test_secret_key(self):
        self.assertEqual(self.SECRET_KEY, create_secret_key(self.MAC_ADDRESS))

    def test_roundtrip(self):
        data, key, iv = generate_nonce() + b'abc', generate_nonce(), generate_nonce()
        self.assertEqual(data, decrypt(encrypt(data, key, iv), key, iv))

    def test_bonding_key(self):
        key, iv = generate_nonce(), generate_nonce()
        bonding_key = create_bonding_key(self.MAC_ADDRESS, key, iv)
        self.assertEqual(key, decrypt(bonding_key, self.SECRET_KEY, iv))
