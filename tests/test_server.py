import socket
import threading
import unittest
from unittest.mock import patch

import server


class ReceiverProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receiver = server.LinkScopeReceiverServer(
            ("127.0.0.1", 0), server.LinkScopeReceiverHandler
        )
        cls.thread = threading.Thread(target=cls.receiver.serve_forever, daemon=True)
        cls.thread.start()
        cls.address = cls.receiver.server_address

    @classmethod
    def tearDownClass(cls):
        cls.receiver.shutdown()
        cls.receiver.server_close()
        cls.thread.join(timeout=2)

    def connect(self):
        sock = socket.create_connection(self.address, timeout=2)
        sock.settimeout(2)
        return sock, sock.makefile("rb")

    def test_probe_handshake(self):
        sock, stream = self.connect()
        with sock, stream:
            self.assertEqual(stream.readline(), b"LINKSCOPE-READY\n")
            sock.sendall(b"PROBE\n")
            self.assertEqual(stream.readline(), b"OK\n")

    def test_receives_data_and_acknowledges_byte_count(self):
        payload = b"LinkScope test payload"
        sock, stream = self.connect()
        with sock, stream:
            self.assertEqual(stream.readline(), b"LINKSCOPE-READY\n")
            sock.sendall(b"START\n")
            self.assertEqual(stream.readline(), b"GO\n")
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(stream.readline(), f"OK {len(payload)}\n".encode("ascii"))


class DiscoveryValidationTests(unittest.TestCase):
    def setUp(self):
        self.local_ip = patch.object(server, "primary_ipv4", return_value="192.168.1.10")
        self.local_ip.start()
        self.addCleanup(self.local_ip.stop)

    def test_rejects_invalid_cidr(self):
        with self.assertRaises(ValueError):
            server.discover_devices("not-a-subnet")

    def test_rejects_ipv6(self):
        with self.assertRaisesRegex(ValueError, "IPv4"):
            server.discover_devices("2001:db8::/64")

    def test_subnet_must_contain_local_address(self):
        with self.assertRaisesRegex(ValueError, "должна включать"):
            server.discover_devices("192.168.2.0/24")

    def test_rejects_subnet_larger_than_1024_addresses(self):
        with self.assertRaisesRegex(ValueError, "1024"):
            server.discover_devices("192.168.0.0/21")


if __name__ == "__main__":
    unittest.main()
