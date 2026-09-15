"""Real UDP peers exercise the bridge loops without an operator or telephone."""
import dataclasses
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import proxy


class StopBridge(Exception):
    pass


class UDPCallTests(unittest.TestCase):
    def setUp(self):
        self.orange = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.livekit = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for sock in (self.orange, self.livekit):
            sock.bind(('127.0.0.1', 0))
            sock.settimeout(2)
            self.addCleanup(sock.close)
        with patch.dict(proxy.os.environ, {'ORANGE_AUTH_USERNAME': 'test', 'ORANGE_PASSWORD': 'secret', 'ORANGE_FROM_NUMBER': '+1000'}):
            config = dataclasses.replace(proxy.BridgeConfig.from_env(), bind_host='127.0.0.1', bind_port=0, downstream_port=0, proxy_host='127.0.0.1', proxy_port=self.orange.getsockname()[1], upstream_host='127.0.0.1', upstream_port=self.livekit.getsockname()[1])
        self.b = proxy.OrangeSIPBridge(config)
        config.bind_port = self.b.sock.getsockname()[1]
        config.downstream_port = self.b.downstream_sock.getsockname()[1]
        self.upstream = self.b.sock.getsockname()
        self.downstream = self.b.downstream_sock.getsockname()
        self.stop = threading.Event()
        self.errors = []
        real_select = proxy.select.select
        def select(*args):
            if self.stop.is_set():
                raise StopBridge()
            return real_select(*args)
        self.select_patch = patch.object(proxy.select, 'select', select)
        self.select_patch.start()
        def run():
            try:
                self.b.run()
            except StopBridge:
                pass
            except Exception as exc:
                self.errors.append(exc)
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_bridge)
        register = self.recv(self.orange, method='REGISTER')
        self.reply(self.orange, self.downstream, register, 200, [('Expires', '3600')])

    def stop_bridge(self):
        self.stop.set()
        self.thread.join(2)
        self.select_patch.stop()
        self.b.sock.close()
        self.b.downstream_sock.close()
        self.assertFalse(self.thread.is_alive())
        self.assertFalse(self.errors, self.errors)

    def recv(self, sock, method=None, code=None, cseq_method=None, call_id=None):
        for _ in range(20):
            msg = proxy.parse_sip_message(sock.recvfrom(65535)[0])
            if method and (msg.is_response or msg.method != method):
                continue
            if code and (not msg.is_response or msg.status_code != code):
                continue
            if cseq_method and proxy.parse_cseq(msg.get('CSeq'))[1] != cseq_method:
                continue
            if call_id and msg.get('Call-ID') != call_id:
                continue
            return msg
        self.fail('Expected packet was not received')

    def request(self, sock, method='INVITE', *, call_id='test', seq=1, branch=None, to=None):
        return proxy.SIPMessage(f'{method} sip:+2000@example SIP/2.0', [
            ('Via', f'SIP/2.0/UDP 127.0.0.1:{sock.getsockname()[1]};branch={branch or "z9hG4bK" + call_id};rport'),
            ('From', '<sip:+1000@example>;tag=caller'), ('To', to or '<sip:+2000@example>'),
            ('Call-ID', call_id), ('CSeq', f'{seq} {method}'),
            ('Contact', f'<sip:peer@127.0.0.1:{sock.getsockname()[1]}>'), ('Content-Length', '0'),
        ], b'')

    def reply(self, sock, addr, req, code, extra=(), body=b''):
        payload = proxy.build_response(req, code, 'Test', proxy.with_tag(req.get('To'), 'peer'), extra_headers=list(extra), body=body)
        sock.sendto(payload, addr)
        return proxy.parse_sip_message(payload)

    def start_call(self, caller, call_id):
        addr = self.downstream if caller is self.orange else self.upstream
        callee = self.livekit if caller is self.orange else self.orange
        request = self.request(caller, call_id=call_id)
        caller.sendto(request.to_bytes(), addr)
        return request, self.recv(callee, method='INVITE')

    def answer_call(self, caller, request, invite):
        callee = self.livekit if caller is self.orange else self.orange
        callee_addr = self.upstream if caller is self.orange else self.downstream
        caller_addr = self.downstream if caller is self.orange else self.upstream
        self.reply(callee, callee_addr, invite, 200)
        self.recv(callee, method='ACK', call_id=invite.get('Call-ID'))
        answer = self.recv(caller, code=200, cseq_method='INVITE', call_id=request.get('Call-ID'))
        caller.sendto(self.request(caller, 'ACK', call_id=request.get('Call-ID'),
                                  branch='z9hG4bKack' + request.get('Call-ID'),
                                  to=answer.get('To')).to_bytes(), caller_addr)
        return answer

    def end_call(self, caller, request, invite, answer):
        callee = self.livekit if caller is self.orange else self.orange
        caller_addr = self.downstream if caller is self.orange else self.upstream
        callee_addr = self.upstream if caller is self.orange else self.downstream
        bye = self.request(caller, 'BYE', call_id=request.get('Call-ID'), seq=2,
                           branch='z9hG4bKbye' + request.get('Call-ID'), to=answer.get('To'))
        caller.sendto(bye.to_bytes(), caller_addr)
        self.recv(caller, code=200, cseq_method='BYE', call_id=request.get('Call-ID'))
        forwarded = self.recv(callee, method='BYE', call_id=invite.get('Call-ID'))
        self.reply(callee, callee_addr, forwarded, 200)

    def test_forwarded_identity_survives_bridge_without_changing_destination(self):
        request = self.request(self.orange, call_id='forwarded', to='<sip:+3000@example>')
        diversion = '<sip:+3000@example>;reason=unconditional'
        history = ['<sip:+3000@example>;index=1', '<sip:+2000@example>;index=1.1']
        request.headers.extend([('Diversion', diversion), *[('History-Info', h) for h in history]])
        self.orange.sendto(request.to_bytes(), self.downstream)
        forwarded = self.recv(self.livekit, method='INVITE')
        self.assertEqual(forwarded.get('Diversion'), diversion)
        self.assertEqual(forwarded.get('History-Info'), ', '.join(history))
        self.assertIn('sip:+2000@', forwarded.request_uri)
        self.assertEqual(forwarded.get('To'), '<sip:+3000@example>')

    def test_two_inbound_calls_answer_and_end_independently(self):
        first, first_invite = self.start_call(self.orange, 'first')
        first_answer = self.answer_call(self.orange, first, first_invite)
        second, second_invite = self.start_call(self.orange, 'second')
        self.assertNotEqual(first_invite.get('Call-ID'), second_invite.get('Call-ID'))
        second_answer = self.answer_call(self.orange, second, second_invite)
        self.end_call(self.orange, first, first_invite, first_answer)
        self.end_call(self.orange, second, second_invite, second_answer)

    def test_inbound_and_outbound_overlap_even_with_same_original_call_id(self):
        incoming, incoming_invite = self.start_call(self.orange, 'shared')
        incoming_answer = self.answer_call(self.orange, incoming, incoming_invite)
        outgoing, outgoing_invite = self.start_call(self.livekit, 'shared')
        outgoing_answer = self.answer_call(self.livekit, outgoing, outgoing_invite)
        self.end_call(self.livekit, outgoing, outgoing_invite, outgoing_answer)
        self.end_call(self.orange, incoming, incoming_invite, incoming_answer)

    def test_two_ringing_calls_keep_their_sdp_and_can_answer_in_reverse_order(self):
        calls = []
        for call_id, port in [('first', 30000), ('second', 30002)]:
            request = self.request(self.orange, call_id=call_id)
            request.body = f'v=0\r\nm=audio {port} RTP/AVP 8\r\n'.encode()
            request.headers = [(k, str(len(request.body)) if k == 'Content-Length' else v) for k, v in request.headers]
            self.orange.sendto(request.to_bytes(), self.downstream)
            invite = self.recv(self.livekit, method='INVITE')
            self.assertEqual(invite.body, request.body)
            self.reply(self.livekit, self.upstream, invite, 183, body=request.body)
            progress = self.recv(self.orange, code=183, call_id=call_id)
            self.assertEqual(progress.body, request.body)
            calls.append((request, invite))
        answered = [(req, inv, self.answer_call(self.orange, req, inv)) for req, inv in reversed(calls)]
        for request, invite, answer in answered:
            self.end_call(self.orange, request, invite, answer)

    def test_cancel_and_late_answer_of_second_call_leave_first_active(self):
        first, first_invite = self.start_call(self.orange, 'first')
        first_answer = self.answer_call(self.orange, first, first_invite)
        second, second_invite = self.start_call(self.orange, 'second')
        self.reply(self.livekit, self.upstream, second_invite, 180)
        self.recv(self.orange, code=180, call_id='second')
        cancel = self.request(self.orange, 'CANCEL', call_id='second')
        self.orange.sendto(cancel.to_bytes(), self.downstream)
        self.recv(self.orange, code=200, cseq_method='CANCEL', call_id='second')
        self.recv(self.orange, code=487, call_id='second')
        forwarded = self.recv(self.livekit, method='CANCEL', call_id=second_invite.get('Call-ID'))
        self.reply(self.livekit, self.upstream, forwarded, 200)
        late_answer = self.reply(self.livekit, self.upstream, second_invite, 200)
        ack = self.recv(self.livekit, method='ACK', call_id=second_invite.get('Call-ID'))
        bye = self.recv(self.livekit, method='BYE', call_id=second_invite.get('Call-ID'))
        self.reply(self.livekit, self.upstream, bye, 200)
        self.livekit.sendto(late_answer.to_bytes(), self.upstream)
        self.assertEqual(self.recv(self.livekit, method='ACK').to_bytes(), ack.to_bytes())
        self.end_call(self.orange, first, first_invite, first_answer)

    def test_shared_capacity_rejects_third_call_and_reuses_released_slot(self):
        self.b.config.max_calls = 2
        first, first_invite = self.start_call(self.orange, 'first')
        first_answer = self.answer_call(self.orange, first, first_invite)
        second, second_invite = self.start_call(self.livekit, 'second')
        third = self.request(self.orange, call_id='third')
        self.orange.sendto(third.to_bytes(), self.downstream)
        busy = self.recv(self.orange, code=486, call_id='third')
        self.orange.sendto(third.to_bytes(), self.downstream)
        self.assertEqual(self.recv(self.orange, code=486, call_id='third').to_bytes(), busy.to_bytes())
        self.orange.sendto(self.request(self.orange, 'ACK', call_id='third', to=busy.get('To')).to_bytes(), self.downstream)
        second_answer = self.answer_call(self.livekit, second, second_invite)
        self.end_call(self.orange, first, first_invite, first_answer)
        fourth, fourth_invite = self.start_call(self.orange, 'fourth')
        fourth_answer = self.answer_call(self.orange, fourth, fourth_invite)
        self.end_call(self.livekit, second, second_invite, second_answer)
        self.end_call(self.orange, fourth, fourth_invite, fourth_answer)

    def test_wrong_dialog_and_reinvite_do_not_create_or_end_another_call(self):
        first, first_invite = self.start_call(self.orange, 'first')
        first_answer = self.answer_call(self.orange, first, first_invite)
        second, second_invite = self.start_call(self.orange, 'second')
        second_answer = self.answer_call(self.orange, second, second_invite)
        wrong_bye = self.request(self.orange, 'BYE', call_id='first', seq=2,
                                 branch='z9hG4bKwrongbye', to=second_answer.get('To'))
        self.orange.sendto(wrong_bye.to_bytes(), self.downstream)
        self.recv(self.orange, code=481, call_id='first')
        reinvite = self.request(self.orange, call_id='first', seq=3,
                                branch='z9hG4bKreinvite', to=first_answer.get('To'))
        self.orange.sendto(reinvite.to_bytes(), self.downstream)
        self.recv(self.orange, code=501, call_id='first')
        unknown = self.request(self.orange, call_id='unknown', to=first_answer.get('To'))
        self.orange.sendto(unknown.to_bytes(), self.downstream)
        self.recv(self.orange, code=481, call_id='unknown')
        self.end_call(self.orange, first, first_invite, first_answer)
        self.end_call(self.orange, second, second_invite, second_answer)

    def test_callee_hangup_routes_both_directions_while_another_call_is_active(self):
        for caller in [self.orange, self.livekit]:
            with self.subTest(inbound=caller is self.orange):
                prefix = 'in' if caller is self.orange else 'out'
                first, first_invite = self.start_call(caller, prefix + '-first')
                self.answer_call(caller, first, first_invite)
                second, second_invite = self.start_call(caller, prefix + '-second')
                second_answer = self.answer_call(caller, second, second_invite)
                callee = self.livekit if caller is self.orange else self.orange
                callee_addr = self.upstream if caller is self.orange else self.downstream
                caller_addr = self.downstream if caller is self.orange else self.upstream
                bye = self.request(callee, 'BYE', call_id=first_invite.get('Call-ID'), seq=7,
                                   branch='z9hG4bKcallee' + prefix, to=first_invite.get('From'))
                bye.headers = [(k, proxy.with_tag(first_invite.get('To'), 'peer') if k == 'From' else v)
                               for k, v in bye.headers]
                callee.sendto(bye.to_bytes(), callee_addr)
                self.recv(callee, code=200, cseq_method='BYE', call_id=first_invite.get('Call-ID'))
                forwarded = self.recv(caller, method='BYE', call_id=first.get('Call-ID'))
                self.reply(caller, caller_addr, forwarded, 200)
                self.end_call(caller, second, second_invite, second_answer)

    def test_outbound_lost_invite_and_bye_and_duplicate_200(self):
        req = self.request(self.livekit)
        self.livekit.sendto(req.to_bytes(), self.upstream)
        invite = self.recv(self.orange, method='INVITE')
        repeated = self.recv(self.orange, method='INVITE')
        self.assertEqual(invite.to_bytes(), repeated.to_bytes())
        response = self.reply(self.orange, self.downstream, invite, 200)
        ack = self.recv(self.orange, method='ACK')
        answer = self.recv(self.livekit, code=200)
        self.livekit.sendto(self.request(self.livekit, 'ACK', branch='z9hG4bKack', to=answer.get('To')).to_bytes(), self.upstream)
        self.orange.sendto(response.to_bytes(), self.downstream)
        self.assertEqual(self.recv(self.orange, method='ACK').to_bytes(), ack.to_bytes())
        self.livekit.sendto(self.request(self.livekit, 'BYE', seq=2, branch='z9hG4bKbye', to=answer.get('To')).to_bytes(), self.upstream)
        self.recv(self.livekit, code=200, cseq_method='BYE')
        bye = self.recv(self.orange, method='BYE')
        self.assertEqual(self.recv(self.orange, method='BYE').to_bytes(), bye.to_bytes())
        self.reply(self.orange, self.downstream, bye, 200)

    def test_inbound_failure_ack_and_old_response_while_new_call_is_active(self):
        req = self.request(self.orange)
        self.orange.sendto(req.to_bytes(), self.downstream)
        invite = self.recv(self.livekit, method='INVITE')
        failure = self.reply(self.livekit, self.upstream, invite, 488)
        ack = self.recv(self.livekit, method='ACK')
        self.assertEqual(ack.get('Via'), invite.get('Via'))
        rejected = self.recv(self.orange, code=488)
        self.orange.sendto(self.request(self.orange, 'ACK', to=rejected.get('To')).to_bytes(), self.downstream)
        self.orange.sendto(req.to_bytes(), self.downstream)
        self.assertEqual(self.recv(self.orange, code=488).to_bytes(), rejected.to_bytes())
        new_req = self.request(self.orange, call_id='new')
        self.orange.sendto(new_req.to_bytes(), self.downstream)
        new_invite = self.recv(self.livekit, method='INVITE')
        self.livekit.sendto(failure.to_bytes(), self.upstream)
        self.assertEqual(self.recv(self.livekit, method='ACK').to_bytes(), ack.to_bytes())
        self.reply(self.livekit, self.upstream, new_invite, 486)
        self.recv(self.orange, code=486)

    def test_inbound_cancel_races_with_answer(self):
        req = self.request(self.orange)
        self.orange.sendto(req.to_bytes(), self.downstream)
        invite = self.recv(self.livekit, method='INVITE')
        self.reply(self.livekit, self.upstream, invite, 180)
        self.recv(self.orange, code=180)
        self.orange.sendto(self.request(self.orange, 'CANCEL').to_bytes(), self.downstream)
        self.recv(self.livekit, method='CANCEL')
        self.recv(self.orange, code=200, cseq_method='CANCEL')
        self.recv(self.orange, code=487)
        self.reply(self.livekit, self.upstream, invite, 200)
        self.recv(self.livekit, method='ACK')
        bye = self.recv(self.livekit, method='BYE')
        self.reply(self.livekit, self.upstream, bye, 200)

    def test_inbound_reformatted_ack_keeps_call_open_past_ack_deadline(self):
        req = self.request(self.orange)
        self.orange.sendto(req.to_bytes(), self.downstream)
        invite = self.recv(self.livekit, method='INVITE')
        self.reply(self.livekit, self.upstream, invite, 200)
        self.recv(self.livekit, method='ACK')
        answer = self.recv(self.orange, code=200)
        ack = self.request(self.orange, 'ACK', branch='z9hG4bKack', to=answer.get('To'))
        ack.headers = [(k, v.replace('@example>', '@EXAMPLE>')) if k in {'From', 'To'} else (k, v)
                       for k, v in ack.headers]
        self.orange.sendto(ack.to_bytes(), self.downstream)
        self.orange.settimeout(proxy.SIP_TRANSACTION_TIMEOUT + 1)
        with self.assertRaises(socket.timeout):
            self.orange.recvfrom(65535)  # No repeated 200 or automatic BYE after a valid ACK.
        self.orange.settimeout(2)
        self.orange.sendto(self.request(self.orange, 'BYE', seq=2, branch='z9hG4bKbye', to=answer.get('To')).to_bytes(), self.downstream)
        self.recv(self.orange, code=200, cseq_method='BYE')
        bye = self.recv(self.livekit, method='BYE')
        self.reply(self.livekit, self.upstream, bye, 200)


if __name__ == '__main__':
    unittest.main()
