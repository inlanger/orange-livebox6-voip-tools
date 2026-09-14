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

    def recv(self, sock, method=None, code=None, cseq_method=None):
        for _ in range(20):
            msg = proxy.parse_sip_message(sock.recvfrom(65535)[0])
            if method and (msg.is_response or msg.method != method):
                continue
            if code and (not msg.is_response or msg.status_code != code):
                continue
            if cseq_method and proxy.parse_cseq(msg.get('CSeq'))[1] != cseq_method:
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

    def reply(self, sock, addr, req, code, extra=()):
        payload = proxy.build_response(req, code, 'Test', proxy.with_tag(req.get('To'), 'peer'), extra_headers=list(extra))
        sock.sendto(payload, addr)
        return proxy.parse_sip_message(payload)

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
