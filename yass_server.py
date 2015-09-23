# -*- coding: utf-8 -*-

import tcp_event
import socket
import yass_base


class YASSServer(yass_base.YASSOneToOneBase):
    """yet another shadowsocks"""

    def __init__(self, config):
        yass_base.YASSOneToOneBase.__init__(self, config, "server")

    def _on_read(self, sock, istream, ostream):
        if sock not in self._set:
            return

        status = self._set.get_sock_attr(sock, "status")
        if status == self.ST_BEGIN:
            try:
                data = self._recv_frame(istream)
            except (ValueError, tcp_event.StreamClosed):
                ostream.close()
                return

            if data is None:
                return

            _, addr, port = self._unpack_socks_address(data)
            server = self._set.get_tunnel_sock(sock)
            try:
                self._connect_server(server, addr, port)
            except socket.error:
                ostream.close()
                return
            self._set.set_sock_attr(sock, status=self.ST_CONNECTED)
            self._set.set_sock_attr(sock, domain=addr)

        peer = self._set.get_tunnel_sock(sock)
        if self._set.sock_type(sock) == self._set.SOCK_SERVER:
            try:
                data = istream.read_all()
                if len(data) != 0:
                    peer_ostream = self._io.get_otream(peer)
                    self._send_frame(data, peer_ostream)
            except tcp_event.StreamClosed:
                pass
        else:
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

        if istream.eof():
            ostream.close()
            peer_output_stream = self._io.get_otream(peer)
            peer_output_stream.close()


if __name__ == "__main__":
    yass_server = YASSServer({
        "server": "127.0.0.1",
        "server_port": 10001,
        "password": "demasiya"
    })
    yass_server.run()
