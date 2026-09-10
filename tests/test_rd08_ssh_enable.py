"""Offline regression tests. No router connections or flash writes are performed."""
import base64
import contextlib
import io
import re
import unittest
from collections import deque
from types import SimpleNamespace
from unittest.mock import Mock, patch

import rd08_ssh_enable as tool
from ssh2.error_codes import LIBSSH2_ERROR_EAGAIN


BOOT_ID = '00000000-0000-0000-0000-000000000001'
NEXT_BOOT_ID = '00000000-0000-0000-0000-000000000002'
TOKEN = SimpleNamespace(hex='regression')


class FakeSocket:
    def __init__(self, chunks=()):
        self.chunks = deque(chunks)
        self.sent = []
        self.closed = False

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        item = self.chunks.popleft() if self.chunks else b''
        if isinstance(item, Exception):
            raise item
        return item

    def settimeout(self, value):
        self.timeout = value

    def close(self):
        self.closed = True


def telnet_with(chunks):
    sh = tool.Telnet.__new__(tool.Telnet)
    sh.s = FakeSocket(chunks)
    sh._pending = b''
    sh._iac = bytearray()
    return sh


def frame(output=b'', status=0):
    return (b'\r\n__BEGIN_regression__\r\n' + output +
            b'\r\n__END_regression__:' + str(status).encode() + b'\r\nroot# ')


class SSHTests(unittest.TestCase):
    def shell(self, stdout=((0, b''),), stderr=((0, b''),), status=0):
        sh = tool.SSH.__new__(tool.SSH)
        sh.sock = Mock()
        channel = Mock()
        channel.read.side_effect = stdout
        channel.read_stderr.side_effect = stderr
        channel.eof.return_value = True
        channel.get_exit_status.return_value = status
        for name in ('execute', 'send_eof', 'wait_eof', 'close', 'wait_closed'):
            getattr(channel, name).return_value = 0
        sh.s = Mock()
        sh.s.open_session.return_value = channel
        return sh, channel

    def test_nonzero_exit_reports_stderr(self):
        sh, channel = self.shell(stderr=((13, b'write failed\n'), (0, b'')),
                                 stdout=((0, b''), (0, b'')), status=1)
        with self.assertRaises(tool.RemoteCommandError) as caught:
            sh.run('mock command')
        self.assertEqual(caught.exception.status, 1)
        self.assertEqual(caught.exception.stderr, 'write failed\n')
        channel.wait_closed.assert_called_once()

    def test_drains_both_streams_after_eof(self):
        sh, _ = self.shell(stdout=((3, b'one'), (3, b'two'), (0, b'')),
                           stderr=((4, b'warn'), (0, b''), (0, b'')))
        self.assertEqual(sh.run('mock command'), 'onetwo')

    def test_eagain_does_not_end_read(self):
        sh, channel = self.shell(stdout=((LIBSSH2_ERROR_EAGAIN, b''), (2, b'ok'), (0, b'')),
                                 stderr=((LIBSSH2_ERROR_EAGAIN, b''), (0, b''), (0, b'')))
        channel.eof.side_effect = [False, True]
        with patch.object(sh, '_wait') as wait:
            self.assertEqual(sh.run('mock command'), 'ok')
        wait.assert_called_once()

    def test_read_exception_is_not_success(self):
        sh, channel = self.shell()
        channel.read.side_effect = OSError('disconnected')
        with self.assertRaises(ConnectionError):
            sh.run('mock command')
        sh.sock.close.assert_called_once()

    def test_timeout_prevents_execution(self):
        sh, channel = self.shell()
        with self.assertRaises(TimeoutError):
            sh.run('mock command', timeout=0)
        channel.execute.assert_not_called()
        sh.sock.close.assert_called_once()

    def test_wait_timeout_closes_socket(self):
        sh, channel = self.shell(stdout=((LIBSSH2_ERROR_EAGAIN, b''),))
        channel.eof.return_value = False
        sh.s.block_directions.return_value = 1
        with patch.object(tool.select, 'select', return_value=([], [], [])):
            with self.assertRaises(TimeoutError):
                sh.run('mock command')
        sh.sock.close.assert_called_once()

    def test_open_session_eagain_retries(self):
        sh, channel = self.shell()
        sh.s.open_session.side_effect = [LIBSSH2_ERROR_EAGAIN, channel]
        with patch.object(sh, '_wait'):
            self.assertEqual(sh.run('mock command'), '')

    def test_auth_failure_closes_socket(self):
        sock = Mock()
        session = Mock()
        session.userauth_password.side_effect = RuntimeError('bad password')
        with patch.object(tool.socket, 'create_connection', return_value=sock), \
                patch('ssh2.session.Session', return_value=session):
            with self.assertRaises(RuntimeError):
                tool.SSH('unused', 'root', 'unused')
        sock.close.assert_called_once()


class PasswordInputTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def test_windows_console_reads_standard_input_without_echo(self):
        kernel = Mock()
        kernel.SetConsoleMode.return_value = True
        with patch.object(tool, '_windows_console', return_value=(kernel, 123, 7)), \
                patch('builtins.input', return_value=' password ') as read:
            self.assertEqual(tool._hidden_input('password: '), ' password ')
        read.assert_called_once_with('password: ')
        self.assertEqual([call.args for call in kernel.SetConsoleMode.call_args_list],
                         [(123, 3), (123, 7)])
        self.assertIn('不显示字符或星号', self.output.getvalue())

    def test_console_mode_restored_on_cancel_and_eof(self):
        for error in (KeyboardInterrupt, EOFError):
            with self.subTest(error=error):
                kernel = Mock()
                kernel.SetConsoleMode.return_value = True
                with patch.object(tool, '_windows_console', return_value=(kernel, 123, 7)), \
                        patch('builtins.input', side_effect=error):
                    with self.assertRaises(error):
                        tool._hidden_input('password: ')
                self.assertEqual(kernel.SetConsoleMode.call_args_list[-1].args, (123, 7))

    def test_pseudo_terminal_falls_back_to_stdin_with_notice(self):
        with patch.object(tool, '_windows_console', return_value=None), \
                patch('builtins.input', return_value='fixture') as read:
            self.assertEqual(tool._hidden_input('password: '), 'fixture')
        read.assert_called_once()
        self.assertIn('无法隐藏密码', self.output.getvalue())

    def test_failed_echo_control_falls_back_to_stdin(self):
        kernel = Mock()
        kernel.SetConsoleMode.return_value = False
        with patch.object(tool, '_windows_console', return_value=(kernel, 123, 7)), \
                patch('builtins.input', return_value='fixture'):
            self.assertEqual(tool._hidden_input('password: '), 'fixture')
        self.assertIn('无法隐藏密码', self.output.getvalue())

    def test_nonterminal_input_does_not_use_console_reader(self):
        with patch.object(tool.sys.stdin, 'isatty', return_value=False), \
                patch.object(tool, '_hidden_input') as hidden, \
                patch('builtins.input', return_value=' fixture '):
            self.assertEqual(tool.ask('password', secret=True), ' fixture ')
        hidden.assert_not_called()
        self.assertIn('无法隐藏密码', self.output.getvalue())

    @unittest.skipUnless(tool.sys.platform == 'win32', 'Windows IDLE regression')
    def test_idle_tty_without_file_descriptor_uses_input(self):
        # Use IDLE's real stream implementation; only its UI proxy is a fixture.
        from idlelib.run import StdInputFile
        shell = Mock()
        shell.readline.return_value = ' idle password \n'
        idle_input = StdInputFile(shell, 'stdin')
        self.assertTrue(idle_input.isatty())
        with self.assertRaises(io.UnsupportedOperation):
            idle_input.fileno()
        with patch.object(tool.sys, 'stdin', idle_input), \
                patch('msvcrt.getwch') as console_read:
            self.assertEqual(tool.ask('password', secret=True), ' idle password ')
        shell.readline.assert_called_once()
        console_read.assert_not_called()
        self.assertIn('无法隐藏密码', self.output.getvalue())


class TelnetTests(unittest.TestCase):
    def setUp(self):
        token = patch.object(tool.uuid, 'uuid4', return_value=TOKEN)
        token.start()
        self.addCleanup(token.stop)

    def test_echo_is_not_completion_and_output_is_clean(self):
        echo = (b"root# printf '\\n%s\\n' '__BEGIN_regression__'; "
                b"sh -c 'sleep 5'; printf '\\n%s:%s\\n' '__END_regression__' 0\r\n")
        sh = telnet_with([echo, frame(b'actual result\r\n')])
        self.assertEqual(sh.run('sleep 5'), 'actual result\n')
        self.assertEqual(len(sh.s.chunks), 0)

    def test_marker_split_across_packets(self):
        sh = telnet_with([bytes([byte]) for byte in frame(b'ok')])
        self.assertEqual(sh.run('mock command'), 'ok')

    def test_nonzero_exit_raises(self):
        sh = telnet_with([frame(b'write failed', 7)])
        with self.assertRaises(tool.RemoteCommandError) as caught:
            sh.run('mock command')
        self.assertEqual(caught.exception.status, 7)
        self.assertEqual(caught.exception.stdout, 'write failed')

    def test_disconnect_is_not_empty_success(self):
        sh = telnet_with([])
        with self.assertRaises(ConnectionError):
            sh.run('mock command')
        self.assertTrue(sh.s.closed)

    def test_timeout_closes_desynchronized_connection(self):
        sh = telnet_with([])
        with patch.object(sh, '_read', side_effect=TimeoutError('slow command')):
            with self.assertRaises(TimeoutError):
                sh.run('mock command')
        self.assertTrue(sh.s.closed)

    def test_login_requires_prompts_and_root_identity(self):
        sock = FakeSocket([b'router login: ', b'Password: ', b'root@router:~# ', frame(b'0\r\n')])
        with patch.object(tool.socket, 'create_connection', return_value=sock):
            sh = tool.Telnet('unused', 'root', 'test password')
        self.assertIs(sh.s, sock)
        self.assertEqual(sock.sent[:2], [b'root\n', b'test password\n'])

    def test_empty_login_response_rejected_and_closed(self):
        sock = FakeSocket([])
        with patch.object(tool.socket, 'create_connection', return_value=sock):
            with self.assertRaises(ConnectionError):
                tool.Telnet('unused', 'root', 'wrong')
        self.assertTrue(sock.closed)

    def test_wrong_password_rejected(self):
        sock = FakeSocket([b'login: ', b'Password: ', b'Login incorrect\r\nlogin: '])
        with patch.object(tool.socket, 'create_connection', return_value=sock):
            with self.assertRaisesRegex(RuntimeError, '登录失败'):
                tool.Telnet('unused', 'root', 'wrong')
        self.assertTrue(sock.closed)

    def test_nonroot_prompt_rejected(self):
        sock = FakeSocket([b'login: ', b'Password: ', b'user$ ', frame(b'1000\r\n')])
        with patch.object(tool.socket, 'create_connection', return_value=sock):
            with self.assertRaisesRegex(RuntimeError, 'root shell'):
                tool.Telnet('unused', 'root', 'wrong')
        self.assertTrue(sock.closed)

    def test_telnet_negotiation_across_packets(self):
        sh = telnet_with([b'\xff', b'\xfb\x01', b'login: '])
        self.assertEqual(sh._read(), b'login: ')
        self.assertEqual(sh.s.sent, [b'\xff\xfd\x01'])


class EnableTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        sleep = patch.object(tool.time, 'sleep')
        sleep.start()
        self.addCleanup(sleep.stop)
        self.web = Mock(ip='unused')
        self.web.rce.return_value = True

    def test_password_round_trip_and_no_plaintext_log(self):
        password = '  a$VAR;"\'`echo hi`\\n密码!  '
        with patch.object(tool, 'verify_ssh', return_value=True) as verify:
            self.assertTrue(tool.enable_ssh(self.web, password))
        command = self.web.rce.call_args_list[-1].args[1]
        encoded = re.search(r"printf '%s' '([A-Za-z0-9+/=]+)'", command).group(1)
        self.assertEqual(base64.b64decode(encoded).decode(), password + '\n' + password + '\n')
        self.assertNotIn(';', command)
        self.assertNotIn(password, self.output.getvalue())
        verify.assert_called_once_with('unused', password)

    def test_invalid_password_rejected_before_mutation(self):
        for password in (None, '', 'a\nb', 'a\rb', 'a\0b', 'a\x7fb'):
            with self.subTest(password=repr(password)), self.assertRaises(ValueError):
                tool.enable_ssh(self.web, password)
        self.web.rce.assert_not_called()
        self.web.macfilter_del.assert_not_called()

    def test_cleanup_failure_does_not_override_success(self):
        self.web.macfilter_del.side_effect = [RuntimeError('cleanup'), None, None]
        with patch.object(tool, 'verify_ssh', return_value=True):
            self.assertTrue(tool.enable_ssh(self.web, 'password'))
        self.assertEqual(self.web.macfilter_del.call_count, 3)
        self.assertIn('清理失败', self.output.getvalue())

    def test_cleanup_preserves_primary_error_and_attempts_only_used_rules(self):
        self.web.rce.side_effect = [True, ValueError('primary failure')]
        self.web.macfilter_del.side_effect = RuntimeError('cleanup failure')
        with self.assertRaisesRegex(ValueError, 'primary failure'):
            tool.enable_ssh(self.web, 'password')
        self.assertEqual(self.web.macfilter_del.call_count, 2)

    def test_open_port_cannot_replace_authentication(self):
        with patch.object(tool, 'tcp_open', return_value=True), \
                patch.object(tool, 'SSH', side_effect=RuntimeError('wrong password')):
            with self.assertRaisesRegex(RuntimeError, 'SSH 登录验证失败'):
                tool.enable_ssh(self.web, 'password')

    def test_secret_input_preserves_spaces(self):
        with patch.object(tool.sys.stdin, 'isatty', return_value=False), \
                patch('builtins.input', return_value=' password '):
            self.assertEqual(tool.ask('password', secret=True), ' password ')

    def test_delete_api_error_is_detected(self):
        web = tool.RouterWeb('unused', 'unused')
        response = Mock()
        response.json.return_value = {'code': 1}
        web.s = Mock()
        web.s.post.return_value = response
        with self.assertRaises(RuntimeError):
            web.macfilter_del('mock-mac')

    def test_rce_separator_validation_is_not_an_assert(self):
        web = tool.RouterWeb('unused', 'unused')
        web.s = Mock()
        with self.assertRaises(ValueError):
            web.rce('mock-mac', 'one; two')
        web.s.post.assert_not_called()


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        redirect = contextlib.redirect_stdout(io.StringIO())
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def test_soft_persist_stops_on_install_failure(self):
        sh = Mock()
        sh.run.side_effect = tool.RemoteCommandError(1, stderr='read-only filesystem')
        with patch.object(tool, 'get_shell', return_value=sh):
            with self.assertRaises(tool.RemoteCommandError):
                tool.soft_persist('unused', 'unused')
        self.assertEqual(sh.run.call_count, 1)
        sh.close.assert_called_once()

    def test_soft_persist_checks_file_before_accepting_config(self):
        sh = Mock()
        def run(command):
            if command.startswith('test -x'):
                raise tool.RemoteCommandError(1)
            return '/data/auto_ssh/auto_ssh.sh\n'
        sh.run.side_effect = run
        with patch.object(tool, 'get_shell', return_value=sh):
            with self.assertRaises(tool.RemoteCommandError):
                tool.soft_persist('unused', 'unused')
        self.assertFalse(any(c.args[0].startswith('uci get') for c in sh.run.call_args_list))

    def test_soft_persist_requires_exact_configuration(self):
        sh = Mock()
        sh.run.return_value = 'wrong auto_ssh.sh path'
        with patch.object(tool, 'get_shell', return_value=sh):
            with self.assertRaisesRegex(RuntimeError, '配置校验失败'):
                tool.soft_persist('unused', 'unused')

    def test_soft_persist_success(self):
        sh = Mock()
        values = {'auto_ssh': 'include', 'auto_ssh.type': 'script',
                  'auto_ssh.path': '/data/auto_ssh/auto_ssh.sh', 'auto_ssh.enabled': '1'}
        sh.run.side_effect = lambda cmd: values.get(cmd.removeprefix('uci get firewall.'), '')
        with patch.object(tool, 'get_shell', return_value=sh):
            self.assertTrue(tool.soft_persist('unused', 'unused'))
        sh.close.assert_called_once()

    def test_reboot_not_observed_stops_reconnect(self):
        sh = Mock()
        sh.run.return_value = BOOT_ID
        with patch.object(tool, 'wait_router_down', return_value=False), \
                patch.object(tool, 'wait_router_up') as up:
            with self.assertRaisesRegex(RuntimeError, '未观察到'):
                tool.reboot_and_reconnect(sh, 'unused', 'unused')
        up.assert_not_called()
        sh.close.assert_called_once()

    def test_reboot_nonzero_exit_is_not_treated_as_disconnect(self):
        sh = Mock()
        sh.run.side_effect = [BOOT_ID, tool.RemoteCommandError(1)]
        with patch.object(tool, 'wait_router_down') as down:
            with self.assertRaises(tool.RemoteCommandError):
                tool.reboot_and_reconnect(sh, 'unused', 'unused')
        down.assert_not_called()
        sh.close.assert_called_once()

    def test_expected_reboot_disconnect_still_requires_new_boot(self):
        sh = Mock()
        sh.run.side_effect = [BOOT_ID, ConnectionError('reboot disconnected')]
        with patch.object(tool, 'wait_router_down', return_value=True), \
                patch.object(tool, 'wait_router_up') as up:
            tool.reboot_and_reconnect(sh, 'unused', 'unused')
        up.assert_called_once_with('unused', 'unused', previous_boot_id=BOOT_ID)

    def test_same_boot_is_rejected_before_new_boot_is_accepted(self):
        old, new = Mock(), Mock()
        old.run.return_value, new.run.return_value = BOOT_ID, NEXT_BOOT_ID
        with patch.object(tool, 'get_shell', side_effect=[old, new]), \
                patch.object(tool.time, 'sleep'):
            self.assertIs(tool.wait_router_up('unused', 'unused', previous_boot_id=BOOT_ID), new)
        old.close.assert_called_once()
        new.close.assert_not_called()

    def test_invalid_boot_id_stops_before_flash_write(self):
        sh = Mock()
        sh.run.return_value = 'not a boot id'
        with patch.object(tool, 'get_shell', return_value=sh), patch.object(tool, 'confirm', return_value=True):
            with self.assertRaisesRegex(RuntimeError, '启动编号'):
                tool.deep_persist('unused', 'unused')
        self.assertEqual(sh.run.call_count, 1)
        sh.close.assert_called_once()

    def test_deep_persist_does_not_continue_after_missing_reboot(self):
        sh = Mock()
        sh.run.return_value = BOOT_ID
        with patch.object(tool, 'get_shell', return_value=sh), \
                patch.object(tool, 'confirm', return_value=True), \
                patch.object(tool, 'wait_router_down', return_value=False):
            with self.assertRaisesRegex(RuntimeError, '第 1 次重启'):
                tool.deep_persist('unused', 'unused')
        commands = [call.args[0] for call in sh.run.call_args_list]
        self.assertFalse(any(cmd.startswith('bdata ') for cmd in commands))
        self.assertNotIn('mtd erase crash', commands)

    def test_deep_persist_stops_on_flash_failure(self):
        sh = Mock()
        sh.run.side_effect = [BOOT_ID, tool.RemoteCommandError(1, stderr='mtd failed')]
        with patch.object(tool, 'get_shell', return_value=sh), \
                patch.object(tool, 'confirm', return_value=True), \
                patch.object(tool, 'reboot_and_reconnect') as reboot:
            with self.assertRaisesRegex(RuntimeError, '写入 crash'):
                tool.deep_persist('unused', 'unused')
        reboot.assert_not_called()
        sh.close.assert_called_once()

    def test_second_reboot_failure_prevents_crash_erase(self):
        first, second = Mock(), Mock()
        first.run.return_value = BOOT_ID
        second.run.side_effect = lambda cmd: 'on' if cmd.endswith('get boot_wait') else '1'
        with patch.object(tool, 'get_shell', return_value=first), \
                patch.object(tool, 'confirm', return_value=True), \
                patch.object(tool, 'reboot_and_reconnect', side_effect=[second, RuntimeError('no reboot')]):
            with self.assertRaisesRegex(RuntimeError, '第 2 次重启'):
                tool.deep_persist('unused', 'unused')
        commands = [call.args[0] for call in second.run.call_args_list]
        self.assertNotIn('mtd erase crash', commands)
        second.close.assert_called_once()

    def test_deep_success_requires_final_ssh_authentication(self):
        sh = Mock()
        def run(cmd):
            if 'boot_id' in cmd:
                return BOOT_ID
            return 'on' if cmd.endswith('get boot_wait') else '1'
        sh.run.side_effect = run
        with patch.object(tool, 'get_shell', return_value=sh), \
                patch.object(tool, 'confirm', return_value=True), \
                patch.object(tool, 'reboot_and_reconnect', return_value=sh) as reboot, \
                patch.object(tool, '_install_auto_ssh') as install, \
                patch.object(tool, 'verify_ssh', side_effect=RuntimeError('authentication failed')):
            with self.assertRaisesRegex(RuntimeError, '恢复自启配置'):
                tool.deep_persist('unused', 'unused')
        self.assertEqual(reboot.call_count, 3)
        install.assert_called_once_with(sh)
        sh.close.assert_called_once()

    def test_deep_persist_checks_all_three_reboots(self):
        sh = Mock()
        def run(cmd):
            if 'boot_id' in cmd:
                return BOOT_ID
            return 'on' if cmd.endswith('get boot_wait') else '1'
        sh.run.side_effect = run
        with patch.object(tool, 'get_shell', return_value=sh), \
                patch.object(tool, 'confirm', return_value=True), \
                patch.object(tool, 'reboot_and_reconnect', return_value=sh) as reboot, \
                patch.object(tool, '_install_auto_ssh') as install, \
                patch.object(tool, 'verify_ssh', return_value=True) as verify:
            self.assertTrue(tool.deep_persist('unused', 'unused'))
        self.assertEqual(reboot.call_count, 3)
        install.assert_called_once_with(sh)
        verify.assert_called_once_with('unused', 'unused')
        sh.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
