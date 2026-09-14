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

    def test_active_inbound_call_renews_before_old_expiry_and_still_handles_bye(self):
        b = self.bridge
        request = proxy.SIPMessage('INVITE sip:+1000@example SIP/2.0', [('Call-ID', 'orange-call'), ('CSeq', '1 INVITE'), ('To', '<sip:+1000@example>'), ('From', '<sip:caller@example>;tag=t')], b'')
        bye = proxy.SIPMessage('BYE sip:+1000@example SIP/2.0', [('Call-ID', 'orange-call'), ('CSeq', '12 BYE')], b'')
        b.handle_downstream_request_inbound = Mock(return_value=True)
        renewed_at = []
        call_packets = 0
        def ready(*_):
            nonlocal call_packets
            if call_packets == 0:
                invite = proxy.parse_sip_message(b.sock.sendto.call_args.args[0])
                answer = proxy.build_response(invite, 200, "OK", proxy.with_tag(invite.get("To"), "agent-tag"))
                b.sock.recvfrom.return_value = (answer, ("127.0.0.1", 5060))
                call_packets += 1
                return ([b.sock], [], [])
            if call_packets == 1:
                answer = proxy.parse_sip_message(b.downstream_sock.send.call_args.args[0])
                ack = proxy.SIPMessage("ACK sip:+1000@example SIP/2.0", [("Call-ID", "orange-call"), ("CSeq", "1 ACK"), ("From", request.get("From")), ("To", answer.get("To"))], b"")
                b.downstream_sock.recvfrom.return_value = (ack.to_bytes(), ("127.0.0.1", 5060))
                call_packets += 1
                return ([b.downstream_sock], [], [])
            self.clock += 0.5
            if b.register_transaction:
                code = 401 if b.register_transaction.cseq == 1 else 200
                b.downstream_sock.recvfrom.return_value = (self.response(code).to_bytes(), ('127.0.0.1', 5060))
                if code == 200:
                    renewed_at.append(self.clock)
                return ([b.downstream_sock], [], [])
            if self.clock >= 125:
                b.downstream_sock.recvfrom.return_value = (bye.to_bytes(), ('127.0.0.1', 5060))
                return ([b.downstream_sock], [], [])
            return ([], [], [])
        with patch.object(proxy.select, 'select', ready):
            b.handle_inbound_invite(request, ('127.0.0.1', 5060))
        self.assertTrue(renewed_at)
        self.assertLess(renewed_at[0], 124)
        self.assertGreater(b.register_state.valid_until, self.clock)
        self.assertEqual(b.handle_downstream_request_inbound.call_args.args[1].method, 'BYE')


if __name__ == '__main__':
    unittest.main()
