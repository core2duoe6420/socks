# -*- coding: utf-8 -*-

import tcp_event
import socket
import logger
import yass_base


_log = logger.Logger("yass_server")


class YASSServer(yass_base.YASSPairBase):
    """yet another shadowsocks"""

    def __init__(self, config):
        yass_base.YASSPairBase.__init__(self, config, "server")

    def _on_read(self, sock, istream, ostream):
        if sock not in self._pairs:
            return

        pair = self._pairs[sock]
        if pair["status"] == self.ST_BEGIN:
            try:
                frame = self._recv_frame(istream)
            except (ValueError, tcp_event.StreamClosed):
                ostream.close()
                return

            if frame is None:
                return

            _, addr, port = self._unpack_socks_address(frame)
            server = pair["server"]
            try:
                self._connect_server(server, addr, port)
            except socket.error:
                ostream.close()
                return

            pair_info = self._get_pair_info(pair)
            pair_info["domain"] = addr
            pair["status"] = self.ST_CONNECTED

        if sock == pair["server"]:
            peer = pair["client"]
            try:
                frame = istream.read_all()
                if len(frame) != 0:
                    peer_ostream = self._io.get_otream(peer)
                    self._send_frame(frame, peer_ostream)
            except tcp_event.StreamClosed:
                pass
        else:
            peer = pair["server"]
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
