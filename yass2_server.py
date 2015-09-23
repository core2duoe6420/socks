# -*- coding: utf-8 -*-

import tcp_event
import socket
import yass_base


class YASS2Server(yass_base.YASSMultiToOneBase):
    def __init__(self, config):
        super(YASS2Server, self).__init__(config, "server")

    def _on_accept(self, server_sock, new_sock):
        self._log.info("accept yass2 client success")
        new_sock.setblocking(False)
        self._set.add_sock(self._set.SOCK_END, new_sock)
        self._set.print_sock_stat(new_sock)
        self._io.add_sock(new_sock,
                          on_receive=self._on_read,
                          on_close=self._on_close,
                          on_error=self._on_error)

    def _on_read(self, sock, istream, ostream):
        sock_type = self._set.sock_type(sock)
        if sock_type == self._set.SOCK_END:
            while True:
                try:
                    frame_tuple = self._recv_frame(istream, True)
                except ValueError:
                    # data corrupted, should not happen
                    self._log.error("Fatal error, data corrupted")
                    exit(11)
                except tcp_event.StreamClosed:
                    break
                if frame_tuple is None:
                    break

                frame_type, conn_id, data = frame_tuple
                conn_sock = self._set.get_conn_sock(conn_id)
                if conn_sock is not None and frame_type == self.FRAME_NEWCONN or \
                        conn_sock is None and frame_type != self.FRAME_NEWCONN:
                    continue
                if frame_type != self.FRAME_NEWCONN:
                    conn_ostream = self._io.get_otream(conn_sock)

                if frame_type == self.FRAME_DATA:
                    # try:
                    conn_ostream.write(data)
                    # except tcp_event.StreamClosed:
                    #    pass
                elif frame_type == self.FRAME_DELCONN:
                    self._set.del_sock(conn_sock)
                    conn_ostream.close()
                elif frame_type == self.FRAME_NEWCONN:
                    _, addr, port = self._unpack_socks_address(data)
                    conn_sock = socket.socket()
                    conn_sock.setblocking(False)
                    try:
                        self._connect_server(conn_sock, addr, port)
                    except socket.error:
                        self._send_frame("", ostream, self.FRAME_DELCONN, conn_id)
                        continue
                    self._set.add_sock(self._set.SOCK_CONN, conn_sock, conn_id)
                    self._set.set_sock_attr(conn_sock, domain=addr)

        elif sock_type == self._set.SOCK_CONN:
            try:
                data = istream.read_all()
                if len(data) != 0:
                    self._send_data_frame(sock, data)
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