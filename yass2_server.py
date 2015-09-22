# -*- coding: utf-8 -*-

import tcp_event
import socket
import logger
import yass_base

_log = logger.Logger("socks_base")


class YASS2Server(yass_base.YASSBase):
    def __init__(self, config):
        super(YASS2Server, self).__init__(config, "server")

    def _on_accept(self, server_sock, new_sock):
        _log.info("connect success, addr=" + str(new_sock.getpeername()))
        new_sock.setblocking(False)
        self._peers.append(new_sock)
        self._io.add_sock(new_sock,
                          on_receive=self._on_read,
                          on_close=self._on_close,
                          on_error=self._on_error)

    def _on_read(self, sock, istream, ostream):
        if sock in self._peers:
            try:
                while True:
                    try:
                        frame_tuple = self._recv_frame(istream)
                    except ValueError:
                        # data corrupted, should not happen
                        _log.error("Fatal error, data corrupted")
                        exit(11)

                    if frame_tuple is not None:
                        frame_type, conn_id, data = frame_tuple
                        if frame_type != self.FRAME_NEWCONN:
                            conn_sock = self._get_conn(conn_id)
                            if conn_sock is None:
                                return
                            conn_ostream = self._io.get_otream(conn_sock)

                        if frame_type == self.FRAME_DATA:
                            conn_ostream.write(data)
                        elif frame_type == self.FRAME_DELCONN:
                            self._del_conn(conn_id)
                            conn_ostream.close()
                        elif frame_type == self.FRAME_NEWCONN:
                            _, addr, port = self._unpack_socks_address(data)
                            conn_sock = socket.socket()
                            conn_sock.setblocking(False)
                            try:
                                self._connect_server(conn_sock, addr, port)
                            except socket.error:
                                self._send_frame(self.FRAME_DELCONN, conn_id, None, ostream)
                                return
                            self._new_conn(conn_sock, conn_id)
                    else:
                        break
            except tcp_event.StreamClosed:
                pass

        elif sock in self._socks:
            sock_info = self._socks[sock]
            conn_id = sock_info["id"]
            try:
                data = istream.read_all()
                if len(data) != 0:
                    self._send_data_frame(conn_id, data)
            except tcp_event.StreamClosed:
                pass

            if istream.eof():
                ostream.close()


if __name__ == "__main__":
    yass_client = YASS2Server({
        "server": "127.0.0.1",
        "server_port": 10001,
        "listen_port": 10000,
        "password": "demasiya"
    })
    yass_client.run()