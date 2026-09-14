import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import proxy


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        with patch.dict(proxy.os.environ, {'ORANGE_AUTH_USERNAME': 'test', 'ORANGE_PASSWORD': 'secret', 'ORANGE_FROM_NUMBER': '+1000'}):
            config = proxy.BridgeConfig.from_env()
        self.bridge = proxy.OrangeSIPBridge.__new__(proxy.OrangeSIPBridge)
        self.bridge.config = config
        self.bridge.sock = Mock()
        self.bridge.downstream_sock = Mock()
        self.bridge.sock.getsockname.return_value = ('127.0.0.1', 5064)
        self.bridge.downstream_sock.getsockname.return_value = ('127.0.0.1', 5070)
        self.bridge.advertised_host = '127.0.0.1'
        self.bridge.register_state = proxy.RegisterState(valid_until=124)
        self.bridge.register_transaction = None
        self.bridge.register_retry_at = 0.0
        self.bridge.client_transactions = {}
        self.bridge.server_transactions = {}
        self.bridge.sessions = {}
        self.clock = 0.0
        for name in ('time', 'monotonic'):
            p = patch.object(proxy.time, name, lambda: self.clock)
            p.start()
            self.addCleanup(p.stop)

    def response(self, code=200, cseq=None):
        tx = self.bridge.register_transaction
        headers = [('Call-ID', tx.call_id), ('CSeq', f'{cseq or tx.cseq} REGISTER'), ('Expires', '3600')]
        if code == 401:
            headers.append(('WWW-Authenticate', 'Digest realm="test", nonce="nonce", algorithm=MD5'))
        return proxy.SIPMessage(f'SIP/2.0 {code} Test', headers, b'')

    def test_refresh_and_auth_do_not_read_or_wait_on_socket(self):
        self.bridge.ensure_registered()
        self.bridge.downstream_sock.send.assert_not_called()
        self.clock = 4
        self.bridge.ensure_registered()
        self.assertEqual(self.bridge.register_transaction.cseq, 1)
        self.bridge.handle_registration_response(self.response(401))
        self.assertEqual(self.bridge.register_transaction.cseq, 2)
        payload = self.bridge.downstream_sock.send.call_args.args[0]
        self.assertIn(b'Authorization:', payload)
        self.assertNotIn('nonce="nonce"', proxy.format_sip_message(proxy.parse_sip_message(payload)))
        self.bridge.handle_registration_response(self.response())
        self.assertEqual(self.bridge.register_state.valid_until, 3604)
        self.assertIsNone(self.bridge.register_transaction)
        self.bridge.downstream_sock.recv.assert_not_called()
        self.bridge.downstream_sock.recvfrom.assert_not_called()

    def test_retransmission_preserves_transaction_and_stale_response_is_ignored(self):
        self.clock = 4
        self.bridge.ensure_registered()
        first = self.bridge.downstream_sock.send.call_args.args[0]
        self.clock = 4.5
        self.bridge.ensure_registered()
        self.assertEqual(self.bridge.downstream_sock.send.call_args.args[0], first)
        self.bridge.handle_registration_response(self.response(401))
        self.bridge.handle_registration_response(self.response(200, cseq=1))
        self.assertIsNotNone(self.bridge.register_transaction)
        self.assertEqual(self.bridge.register_state.valid_until, 124)

    def test_timeout_keeps_call_packets_available_and_retries(self):
        self.clock = 4
        self.bridge.ensure_registered()
        bye = proxy.SIPMessage('BYE sip:test SIP/2.0', [('Call-ID', 'call'), ('CSeq', '2 BYE')], b'')
        self.assertFalse(self.bridge.handle_registration_response(bye))
        self.clock = 65
        self.bridge.ensure_registered()
        self.assertIsNone(self.bridge.register_transaction)
        self.bridge.downstream_sock.recv.assert_not_called()
        self.clock = 70
        self.bridge.ensure_registered()
        self.assertIsNotNone(self.bridge.register_transaction)

    def test_two_active_calls_keep_processing_during_registration_refresh(self):
        b = self.bridge
        requests = [proxy.SIPMessage('INVITE sip:+1000@example SIP/2.0', [
            ('Via', f'SIP/2.0/UDP orange.example;branch=z9hG4bK{index}'),
            ('Call-ID', f'orange-{index}'), ('CSeq', '1 INVITE'),
            ('To', '<sip:+1000@example>'), ('From', '<sip:caller@example>;tag=t'),
        ], b'') for index in range(2)]
        for request in requests:
            b.handle_packet(b.downstream_sock, request, ('127.0.0.1', 5060))
        self.assertEqual(len(b.sessions), 2)
        self.clock = 4
        b.ensure_registered()
        b.handle_packet(b.downstream_sock, self.response(401), ('127.0.0.1', 5060))
        # A CANCEL interleaves with the authenticated REGISTER response.
        cancel = proxy.SIPMessage('CANCEL sip:+1000@example SIP/2.0', [
            (k, '1 CANCEL' if k == 'CSeq' else v) for k, v in requests[0].headers
        ], b'')
        b.handle_packet(b.downstream_sock, cancel, ('127.0.0.1', 5060))
        self.assertEqual(len(b.sessions), 1)
        self.clock = 5
        b.handle_packet(b.downstream_sock, self.response(), ('127.0.0.1', 5060))
        self.assertEqual(b.register_state.valid_until, 3605)
        self.assertIsNone(b.register_transaction)
        self.assertEqual(next(iter(b.sessions.values())).downstream_call_id, 'orange-1')
        b.downstream_sock.recvfrom.assert_not_called()
        b.sock.recvfrom.assert_not_called()


if __name__ == '__main__':
    unittest.main()
