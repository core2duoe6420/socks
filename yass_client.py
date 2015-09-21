# -*- coding: utf-8 -*-

import tcp_event
import logger
import yass_base


_log = logger.Logger("yass_client")


class YASSClient(yass_base.YASSBase):
    """yet another shadowsocks"""

    def __init__(self, config):
        yass_base.YASSBase.__init__(self, config, "client")


    def _on_read(self, sock, istream, ostream):
        if sock not in self._pairs:
            return

        pair = self._pairs[sock]
        if pair["status"] == self.ST_BEGIN:
            try:
                auth = istream.read_all()
                reply = self._socks5_auth(auth)
            except (tcp_event.StreamClosed, ValueError):
                ostream.close()
                return

            if reply is None:
                ostream.close()
                return
            ostream.write(reply)
            pair["status"] = self.ST_AUTH

        elif pair["status"] == self.ST_AUTH:
            try:
                request = istream.read_all()
            except tcp_event.StreamClosed:
                ostream.close()
                return
            try:
                addr_type, addr, port = self._socks5_request(request)
            except ValueError:
                ostream.write(self._gen_reply(7))
                ostream.close()
                return
            ostream.write(self._gen_reply(0, addr_type, addr, port))

            socks_address = self._pack_socks_address(addr_type, addr, port)

            server = pair["server"]
            server_ostream = self._io.get_otream(server)
            self._send_frame(socks_address, server_ostream)

            pair_info = self._get_pair_info(pair)
            pair_info["domain"] = addr
            pair["status"] = self.ST_DATA

        elif pair["status"] == self.ST_DATA:
            if sock == pair["server"]:
                # 服务器的响应，应该是加密的
                peer = pair["client"]
                try:
                    while True:
                        peer_ostream = self._io.get_otream(peer)
                        try:
                            frame = self._recv_frame(istream)
                        except ValueError:
                            ostream.close()
                            peer_ostream.close()
                            return
                        if frame is not None:
                            peer_ostream.write(frame)
                        else:
                            break
                except tcp_event.StreamClosed:
                    pass
            else:
                # 接收到浏览器发来的请求
                peer = pair["server"]
                try:
                    frame = istream.read_all()
                    if len(frame) != 0:
                        peer_ostream = self._io.get_otream(peer)
                        self._send_frame(frame, peer_ostream)
                except tcp_event.StreamClosed:
                    pass

            if istream.eof():
                ostream.close()
                peer_ostream = self._io.get_otream(peer)
                peer_ostream.close()


if __name__ == "__main__":
    yass_client = YASSClient({
        "server": "127.0.0.1",
        "server_port": 10001,
        "listen_port": 10000,
        "password": "demasiya"
    })
    yass_client.run()
