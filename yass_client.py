# -*- coding: utf-8 -*-

import tcp_event
import yass_base


class YASSClient(yass_base.YASSOneToOneBase):
    """yet another shadowsocks"""

    def __init__(self, config):
        yass_base.YASSOneToOneBase.__init__(self, config, "client")

    def _on_read(self, sock, istream, ostream):
        if sock not in self._set:
            return

        status = self._set.get_sock_attr(sock, "status")
        if status == self.ST_BEGIN:
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
            self._set.set_sock_attr(sock, status=self.ST_AUTH)

        elif status == self.ST_AUTH:
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

            server = self._set.get_tunnel_sock(sock)
            server_ostream = self._io.get_otream(server)
            self._send_frame(socks_address, server_ostream)

            self._set.set_sock_attr(sock, status=self.ST_DATA)
            self._set.set_sock_attr(sock, domain=addr)

        elif status == self.ST_DATA:
            peer = self._set.get_tunnel_sock(sock)
            if self._set.sock_type(sock) == self._set.SOCK_SERVER:
                # 服务器的响应，应该是加密的
                try:
                    while True:
                        peer_ostream = self._io.get_otream(peer)
                        try:
                            data = self._recv_frame(istream)
                        except ValueError:
                            ostream.close()
                            peer_ostream.close()
                            return
                        if data is not None:
                            peer_ostream.write(data)
                        else:
                            break
                except tcp_event.StreamClosed:
                    pass
            else:
                try:
                    data = istream.read_all()
                    if len(data) != 0:
                        peer_ostream = self._io.get_otream(peer)
                        self._send_frame(data, peer_ostream)
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
