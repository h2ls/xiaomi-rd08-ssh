"""Optional real SSH protocol tests against a loopback-only in-process server.

Install paramiko to run these tests; it is not a runtime dependency of the tool.
The server returns fixture data and never executes received commands.
"""
import socket
import threading
import time
import unittest
from unittest.mock import patch

import rd08_ssh_enable as tool

try:
    import paramiko
except ImportError:
    paramiko = None


@unittest.skipIf(paramiko is None, 'optional local SSH tests require paramiko')
class LocalSSHTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = paramiko.RSAKey.generate(2048)

    def setUp(self):
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.address = self.listener.getsockname()
        self.transport = None
        self.workers = []
        self.server_errors = []
        outer = self

        class Server(paramiko.ServerInterface):
            def check_auth_password(self, user, password):
                return (paramiko.AUTH_SUCCESSFUL if (user, password) == ('root', 'fixture')
                        else paramiko.AUTH_FAILED)

            def get_allowed_auths(self, user):
                return 'password'

            def check_channel_request(self, kind, channel_id):
                return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                worker = threading.Thread(target=outer.respond, args=(channel, command), daemon=True)
                outer.workers.append(worker)
                worker.start()
                return True

        def serve():
            try:
                conn, _ = self.listener.accept()
                self.transport = paramiko.Transport(conn)
                self.transport.add_server_key(self.key)
                self.transport.start_server(server=Server())
                self.stop.wait(10)
            except Exception as exc:
                if not self.stop.is_set():
                    self.server_errors.append(exc)

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()
        original_connect = socket.create_connection

        def connect(address, timeout):
            self.assertEqual(address, ('fixture-only', 22))
            return original_connect(self.address, timeout)

        self.connection_patch = patch.object(tool.socket, 'create_connection', side_effect=connect)
        self.connection_patch.start()

    def respond(self, channel, command):
        try:
            # Ensure the client also exercises EAGAIN before receiving output.
            if self.stop.wait(0.05):
                return
            if command == b'slow':
                self.stop.wait(5)
                return
            if command == b'large-stderr':
                channel.sendall_stderr(b'E' * (3 * 1024 * 1024))
                channel.send_exit_status(2)
            elif command == b'fail':
                channel.sendall(b'partial output\n')
                channel.sendall_stderr(b'fixture failure\n')
                channel.send_exit_status(7)
            else:
                channel.sendall(b'first\n')
                self.stop.wait(0.02)
                channel.sendall(b'second\n')
                channel.send_exit_status(0)
            channel.shutdown_write()
            channel.close()
        except Exception as exc:
            if not self.stop.is_set():
                self.server_errors.append(exc)

    def tearDown(self):
        self.connection_patch.stop()
        self.stop.set()
        if self.transport:
            self.transport.close()
        self.listener.close()
        self.thread.join(5)
        for worker in self.workers:
            worker.join(5)
        self.assertFalse(self.server_errors, self.server_errors)

    def test_delayed_output_and_repeated_commands(self):
        sh = tool.SSH('fixture-only', 'root', 'fixture')
        try:
            for _ in range(2):
                self.assertEqual(sh.run('ok', timeout=3), 'first\nsecond\n')
        finally:
            sh.close()

    def test_remote_failure_keeps_channel_results(self):
        sh = tool.SSH('fixture-only', 'root', 'fixture')
        try:
            with self.assertRaises(tool.RemoteCommandError) as caught:
                sh.run('fail', timeout=3)
            self.assertEqual(caught.exception.status, 7)
            self.assertEqual(caught.exception.stdout, 'partial output\n')
            self.assertEqual(caught.exception.stderr, 'fixture failure\n')
            self.assertEqual(sh.run('ok', timeout=3), 'first\nsecond\n')
        finally:
            sh.close()

    def test_large_stderr_does_not_block_stdout_read(self):
        sh = tool.SSH('fixture-only', 'root', 'fixture')
        try:
            with self.assertRaises(tool.RemoteCommandError) as caught:
                sh.run('large-stderr', timeout=5)
            self.assertEqual(len(caught.exception.stderr), 3 * 1024 * 1024)
        finally:
            sh.close()

    def test_real_timeout_closes_connection(self):
        sh = tool.SSH('fixture-only', 'root', 'fixture')
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            sh.run('slow', timeout=0.2)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(sh.sock.fileno(), -1)


if __name__ == '__main__':
    unittest.main()
