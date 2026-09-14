import contextlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'orange-proxy'))

import extract_livebox_sip as extractor
import proxy


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'credentials.env'
        self.line = {
            'name': '+1000',
            'uri': '+1000@sip.example',
            'authUserName': 'test@sip.example',
            'authPassword': 'test$#=password\'"',
        }
        self.sip = {
            'userAgentDomain': 'sip.example',
            'proxyServer': 'proxy.example',
            'proxyServerPort': 5090,
        }
        self.values = extractor.build_env_map(self.line, self.sip)

    def test_extractor_file_is_accepted_by_bridge_cli(self):
        extractor.write_env_file(self.path, self.values)
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(sys, 'argv', ['proxy.py', '--env-file', str(self.path)]), \
                patch.object(proxy, 'OrangeSIPBridge') as bridge:
            self.assertEqual(proxy.main(), 0)
        config = bridge.call_args.args[0]
        self.assertEqual(config.auth_username, self.line['authUserName'])
        self.assertEqual(config.password, self.line['authPassword'])
        self.assertEqual(config.from_number, '+1000')
        self.assertEqual(config.domain, 'sip.example')
        self.assertEqual((config.proxy_host, config.proxy_port), ('proxy.example', 5090))
        bridge.return_value.run.assert_called_once_with()

    def test_environment_overrides_file(self):
        self.values['ORANGE_PROXY_LOG_LEVEL'] = 'DEBUG'
        extractor.write_env_file(self.path, self.values)
        with patch.dict(os.environ, {'ORANGE_SIP_PASSWORD': 'override'}, clear=True), \
                patch.object(sys, 'argv', ['proxy.py', '--env-file', str(self.path)]), \
                patch.object(proxy.logging, 'basicConfig') as logging_config, \
                patch.object(proxy, 'OrangeSIPBridge') as bridge:
            self.assertEqual(proxy.main(), 0)
        self.assertEqual(bridge.call_args.args[0].password, 'override')
        self.assertEqual(logging_config.call_args.kwargs['level'], 'DEBUG')

    def test_canonical_names_override_legacy_names(self):
        legacy = {
            'ORANGE_AUTH_USERNAME': 'old-user', 'ORANGE_PASSWORD': 'old-password',
            'ORANGE_FROM_NUMBER': '+2000', 'ORANGE_DOMAIN': 'old.example',
            'ORANGE_PROXY_HOST': 'old-proxy.example', 'ORANGE_PROXY_PORT': '5061',
            'ORANGE_REGISTER_EXPIRES': '60',
        }
        with patch.dict(os.environ, {**legacy, **self.values}, clear=True):
            config = proxy.BridgeConfig.from_env()
        self.assertEqual(config.auth_username, self.line['authUserName'])
        self.assertEqual(config.password, self.line['authPassword'])
        self.assertEqual(config.from_number, '+1000')
        self.assertEqual(config.domain, 'sip.example')
        self.assertEqual((config.proxy_host, config.proxy_port), ('proxy.example', 5090))
        self.assertEqual(config.register_expires, 3600)

    def test_password_is_hidden_by_default(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            extractor.print_summary(self.line, self.sip, self.values)
        self.assertNotIn(self.line['authPassword'], output.getvalue())
        self.assertIn('ORANGE_SIP_PASSWORD=<redacted>', output.getvalue())

    def test_password_can_be_shown_explicitly(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            extractor.print_summary(self.line, self.sip, self.values, show_secrets=True)
        self.assertIn(self.line['authPassword'], output.getvalue())

    @unittest.skipUnless(os.name == 'posix', 'POSIX file permissions')
    def test_new_credential_file_is_private_with_permissive_umask(self):
        previous = os.umask(0)
        try:
            extractor.write_env_file(self.path, self.values)
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertIn(self.line['authPassword'], self.path.read_text())

    @unittest.skipUnless(os.name == 'posix', 'POSIX file permissions')
    def test_existing_credential_file_becomes_private(self):
        self.path.write_text('old contents')
        self.path.chmod(0o644)
        extractor.write_env_file(self.path, self.values)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == 'posix', 'POSIX file permissions')
    def test_raw_dump_with_credentials_is_private(self):
        extractor.dump_json(self.path.parent, 'line', self.line)
        self.assertEqual(stat.S_IMODE((self.path.parent / 'line.json').stat().st_mode), 0o600)


if __name__ == '__main__':
    unittest.main()
