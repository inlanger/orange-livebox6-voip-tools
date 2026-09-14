import dataclasses
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import proxy


class CallLifecycleTests(unittest.TestCase):
    def setUp(self):
        with patch.dict(proxy.os.environ, {'ORANGE_AUTH_USERNAME': 'test', 'ORANGE_PASSWORD': 'secret', 'ORANGE_FROM_NUMBER': '+1000'}):
            config = dataclasses.replace(proxy.BridgeConfig.from_env(), bind_host='127.0.0.1', bind_port=0, downstream_port=0, proxy_host='127.0.0.1', proxy_port=9)
        self.b = proxy.OrangeSIPBridge(config)
        self.b.sock.close()
        self.b.downstream_sock.close()
        self.b.sock = Mock()
        self.b.downstream_sock = Mock()
        self.b.sock.getsockname.return_value = ('127.0.0.1', 5064)
        self.b.downstream_sock.getsockname.return_value = ('127.0.0.1', 5070)
        self.b.register_state.valid_until = 10000
        self.clock = 0.0
        for name in ('time', 'monotonic'):
            p = patch.object(proxy.time, name, lambda: self.clock)
            p.start()
            self.addCleanup(p.stop)

    def request(self, method='INVITE', call_id='caller', seq=1, branch='z9hG4bKcaller', to_tag=''):
        return proxy.SIPMessage(f'{method} sip:+2000@example SIP/2.0', [
            ('Via', f'SIP/2.0/UDP 127.0.0.1:6000;branch={branch};rport'),
            ('From', '<sip:+1000@example>;tag=from'), ('To', '<sip:+2000@example>' + to_tag),
            ('Call-ID', call_id), ('CSeq', f'{seq} {method}'), ('Contact', '<sip:caller@127.0.0.1:6000>'),
            ('Content-Length', '0'),
        ], b'')

    def outbound(self):
        request = self.request()
        session = proxy.CallSession(request, ('127.0.0.1', 6000), 'bridge', 'sip:caller@127.0.0.1:6000', 2, '+2000', 'orange', 'bridge-from', downstream_route_headers=['<sip:route.example;lr>'])
        self.b.send_downstream_invite(session)
        return session, self.downstream()[-1]

    def downstream(self):
        return [proxy.parse_sip_message(c.args[0]) for c in self.b.downstream_sock.send.call_args_list]

    def upstream(self):
        return [proxy.parse_sip_message(c.args[0]) for c in self.b.sock.sendto.call_args_list]

    def response(self, request, code, extra=()):
        return proxy.parse_sip_message(proxy.build_response(request, code, 'Test', proxy.with_tag(request.get('To'), 'remote'), extra_headers=list(extra)))

    def receive(self, sock, msg):
        return self.b.handle_transaction_packet(sock, msg, ('127.0.0.1', 6000))

    def test_failed_invite_is_acked_with_original_branch_and_repeated_after_call(self):
        session, invite = self.outbound()
        response = self.response(invite, 488, [('Reason', 'Q.850;cause=111'), ('Warning', '305 test "Incompatible media format"')])
        self.receive(self.b.downstream_sock, response)
        ack = self.downstream()[-1]
        self.assertEqual(ack.method, 'ACK')
        self.assertEqual(ack.get('Via'), invite.get('Via'))
        self.assertEqual(ack.request_uri, invite.request_uri)
        self.assertEqual(ack.get_all('Route'), invite.get_all('Route'))
        self.assertEqual(ack.get('To'), response.get('To'))
        self.assertTrue(session.finished)
        self.assertEqual(self.upstream()[-1].get('Warning'), response.get('Warning'))
        before = len(self.upstream())
        self.receive(self.b.downstream_sock, response)
        self.assertEqual(self.downstream()[-1].to_bytes(), ack.to_bytes())
        self.assertEqual(len(self.upstream()), before)

    def test_auth_retry_acks_old_transaction_and_ignores_duplicate_challenge(self):
        session, invite = self.outbound()
        challenge = self.response(invite, 401, [('WWW-Authenticate', 'Digest realm="example", nonce="nonce"')])
        self.receive(self.b.downstream_sock, challenge)
        packets = self.downstream()
        self.assertEqual([p.method for p in packets], ['INVITE', 'ACK', 'INVITE'])
        self.assertEqual(packets[-1].get('CSeq'), '2 INVITE')
        self.receive(self.b.downstream_sock, challenge)
        self.assertEqual(self.downstream()[-1].method, 'ACK')
        self.assertEqual(sum(p.method == 'INVITE' for p in self.downstream()), 2)

    def test_bye_retries_after_call_returns_and_stops_on_matching_response(self):
        session, invite = self.outbound()
        self.receive(self.b.downstream_sock, self.response(invite, 200, [('Contact', '<sip:remote@example>')]))
        bye = self.request('BYE', seq=2, branch='z9hG4bKbye', to_tag=';tag=bridge')
        self.assertTrue(self.b.handle_upstream_request(session, bye, session.upstream_addr))
        sent = self.downstream()[-1]
        self.assertEqual(sent.method, 'BYE')
        self.clock = 0.5
        self.b.tick_transactions()
        self.assertEqual(self.downstream()[-1].to_bytes(), sent.to_bytes())
        wrong = self.response(sent, 200)
        wrong.headers = [(k, v.replace('branch=z9hG4bK', 'branch=z9hG4bKwrong')) if k == 'Via' else (k, v) for k, v in wrong.headers]
        self.receive(self.b.downstream_sock, wrong)
        self.clock = 1.5
        self.b.tick_transactions()
        self.assertEqual(self.downstream()[-1].method, 'BYE')
        self.receive(self.b.downstream_sock, self.response(sent, 200))
        count = len(self.downstream())
        self.clock = 5
        self.b.tick_transactions()
        self.assertEqual(len(self.downstream()), count)

    def test_cancel_before_provisional_then_late_answer_is_acked_and_hung_up(self):
        session, invite = self.outbound()
        cancel = self.request('CANCEL')
        self.b.handle_upstream_request(session, cancel, session.upstream_addr)
        self.assertNotIn('CANCEL', [p.method for p in self.downstream()])
        self.receive(self.b.downstream_sock, self.response(invite, 100))
        self.assertEqual(self.downstream()[-1].method, 'CANCEL')
        answered = self.response(invite, 200, [('Contact', '<sip:remote@example>')])
        self.receive(self.b.downstream_sock, answered)
        self.assertEqual([p.method for p in self.downstream()][-2:], ['ACK', 'BYE'])
        self.assertFalse(any(p.status_code == 200 and p.get('CSeq') == '1 INVITE' for p in self.upstream()))
        self.receive(self.b.downstream_sock, answered)
        self.assertEqual(self.downstream()[-1].method, 'ACK')
        self.assertEqual(sum(p.method == 'BYE' for p in self.downstream()), 1)

    def test_accepted_inbound_survives_five_minutes_without_sip_then_handles_bye(self):
        b = self.b
        request = self.request(call_id='incoming')
        calls = 0
        def ready(*_):
            nonlocal calls
            calls += 1
            if calls == 1:
                invite = self.upstream()[-1]
                b.sock.recvfrom.return_value = (self.response(invite, 200, [('Contact', '<sip:agent@example>')]).to_bytes(), ('127.0.0.1', 5060))
                return ([b.sock], [], [])
            if calls == 2:
                answer = next(p for p in self.downstream() if p.is_response and p.status_code == 200)
                ack = self.request('ACK', call_id='incoming', branch='z9hG4bKack', to_tag=';tag=' + proxy.extract_tag(answer.get('To')))
                b.downstream_sock.recvfrom.return_value = (ack.to_bytes(), ('127.0.0.1', 5060))
                return ([b.downstream_sock], [], [])
            if calls == 3:
                self.clock = 301
                return ([], [], [])
            self.clock = 302
            bye = self.request('BYE', call_id='incoming', seq=2, branch='z9hG4bKbye')
            b.downstream_sock.recvfrom.return_value = (bye.to_bytes(), ('127.0.0.1', 5060))
            return ([b.downstream_sock], [], [])
        with patch.object(proxy.select, 'select', ready):
            b.handle_inbound_invite(request, ('127.0.0.1', 5060))
        self.assertEqual(self.clock, 302)
        self.assertEqual(self.upstream()[-1].method, 'BYE')

    def test_accepted_outbound_survives_five_minutes_without_sip_then_handles_bye(self):
        calls = 0
        def ready(*_):
            nonlocal calls
            calls += 1
            if calls == 1:
                invite = self.downstream()[-1]
                self.b.downstream_sock.recvfrom.return_value = (self.response(invite, 200).to_bytes(), ('127.0.0.1', 5060))
                return ([self.b.downstream_sock], [], [])
            if calls == 2:
                answer = next(p for p in self.upstream() if p.is_response and p.status_code == 200)
                ack = self.request('ACK', branch='z9hG4bKack', to_tag=';tag=' + proxy.extract_tag(answer.get('To')))
                self.b.sock.recvfrom.return_value = (ack.to_bytes(), ('127.0.0.1', 6000))
                return ([self.b.sock], [], [])
            if calls == 3:
                self.clock = 301
                return ([], [], [])
            self.clock = 302
            bye = self.request('BYE', seq=2, branch='z9hG4bKbye')
            self.b.sock.recvfrom.return_value = (bye.to_bytes(), ('127.0.0.1', 6000))
            return ([self.b.sock], [], [])
        with patch.object(proxy.select, 'select', ready):
            self.b.handle_invite(self.request(), ('127.0.0.1', 6000))
        self.assertEqual(self.clock, 302)
        self.assertEqual(self.downstream()[-1].method, 'BYE')

    def test_final_response_retries_until_ack_and_duplicate_invite_replays_it(self):
        session, invite = self.outbound()
        self.receive(self.b.downstream_sock, self.response(invite, 200))
        answer = self.upstream()[-1]
        self.clock = 0.5
        self.b.tick_transactions()
        self.assertEqual(self.upstream()[-1].to_bytes(), answer.to_bytes())
        self.receive(self.b.sock, self.request('ACK', branch='z9hG4bKack', to_tag=';tag=bridge'))
        count = len(self.upstream())
        self.clock = 10
        self.b.tick_transactions()
        self.assertEqual(len(self.upstream()), count)
        self.receive(self.b.sock, session.upstream_request)
        self.assertEqual(self.upstream()[-1].to_bytes(), answer.to_bytes())
        self.assertEqual(sum(p.method == 'INVITE' for p in self.downstream()), 1)

    def test_missing_ack_ends_both_legs_after_bounded_wait(self):
        session, invite = self.outbound()
        self.receive(self.b.downstream_sock, self.response(invite, 200))
        self.clock = proxy.SIP_TRANSACTION_TIMEOUT
        self.b.tick_transactions()
        self.assertTrue(session.finished)
        self.assertEqual(self.downstream()[-1].method, 'BYE')
        self.assertEqual(self.upstream()[-1].method, 'BYE')

    def test_ack_matches_dialog_tags_when_address_headers_are_reformatted(self):
        for sock in (self.b.sock, self.b.downstream_sock):
            with self.subTest(sock=sock):
                self.b.server_transactions.clear()
                expired = Mock()
                invite = self.request()
                answer = self.response(invite, 200)
                self.b.send_sip(sock, answer.to_bytes(), None, on_ack_timeout=expired)
                ack = self.request('ACK', branch='z9hG4bKnewack', to_tag=';tag=remote')
                ack.headers = [(k, v.replace('@example>', '@EXAMPLE>') + ' ')
                               if k in {'From', 'To'} else (k, v) for k, v in ack.headers]
                self.receive(sock, ack)
                tx = next(iter(self.b.server_transactions.values()))
                self.assertIsNone(tx.retry_at)
                self.clock += proxy.SIP_TRANSACTION_TIMEOUT + 1
                self.b.tick_transactions()
                expired.assert_not_called()

    def test_ack_with_wrong_dialog_or_sequence_does_not_confirm_call(self):
        answer = self.response(self.request(), 200)
        self.b.send_sip(self.b.sock, answer.to_bytes(), None, on_ack_timeout=Mock())
        tx = next(iter(self.b.server_transactions.values()))
        for header, value in [('Call-ID', 'different'), ('CSeq', '2 ACK'),
                              ('From', '<sip:+1000@example>;tag=wrong'),
                              ('To', '<sip:+2000@example>;tag=wrong')]:
            with self.subTest(header=header):
                ack = self.request('ACK', branch='z9hG4bKnewack', to_tag=';tag=remote')
                ack.headers = [(k, value if k == header else v) for k, v in ack.headers]
                self.receive(self.b.sock, ack)
                self.assertIsNotNone(tx.on_ack_timeout)
                self.assertIsNotNone(tx.retry_at)

    def test_non_2xx_ack_still_requires_original_transaction_branch(self):
        answer = self.response(self.request(), 488)
        self.b.send_sip(self.b.sock, answer.to_bytes(), None)
        tx = next(iter(self.b.server_transactions.values()))
        self.receive(self.b.sock, self.request('ACK', branch='z9hG4bKwrong', to_tag=';tag=remote'))
        self.assertIsNotNone(tx.retry_at)
        self.receive(self.b.sock, self.request('ACK', to_tag=';tag=remote'))
        self.assertIsNone(tx.retry_at)

    def test_invite_timeout_returns_failure_and_cleans_up_late_answer(self):
        session, invite = self.outbound()
        self.clock = 0.5
        self.b.tick_transactions()
        self.assertEqual(self.downstream()[-1].to_bytes(), invite.to_bytes())
        self.clock = proxy.SIP_TRANSACTION_TIMEOUT
        self.b.tick_transactions()
        self.assertTrue(session.finished)
        self.assertEqual(self.upstream()[-1].status_code, 408)
        self.receive(self.b.downstream_sock, self.response(invite, 200))
        self.assertEqual([p.method for p in self.downstream()][-2:], ['ACK', 'BYE'])
        self.assertEqual(self.upstream()[-1].status_code, 408)

    def test_auth_retries_are_bounded_and_every_challenge_is_acked(self):
        session, invite = self.outbound()
        for _ in range(4):
            challenge = self.response(invite, 407, [('Proxy-Authenticate', 'Digest realm="example", nonce="nonce"')])
            self.receive(self.b.downstream_sock, challenge)
            invite = next(p for p in reversed(self.downstream()) if p.method == 'INVITE')
        self.assertTrue(session.finished)
        self.assertEqual(sum(p.method == 'INVITE' for p in self.downstream()), 4)
        self.assertEqual(sum(p.method == 'ACK' for p in self.downstream()), 4)
        self.assertEqual(self.upstream()[-1].status_code, 407)

    def test_transaction_caches_expire(self):
        session, invite = self.outbound()
        self.receive(self.b.downstream_sock, self.response(invite, 488))
        self.clock = proxy.SIP_TRANSACTION_TIMEOUT + 1
        self.b.tick_transactions()
        self.assertFalse(self.b.client_transactions)
        self.assertFalse(self.b.server_transactions)
        before = len(self.upstream())
        self.receive(self.b.sock, self.request('ACK', to_tag=';tag=bridge'))
        self.assertEqual(len(self.upstream()), before)


if __name__ == '__main__':
    unittest.main()
