# -*- coding: utf-8 -*-

import tcp_event
import socket
import yass_base


class YASS2Client(yass_base.YASSMultiToOneBase):
    def __init__(self, config):
        super(YASS2Client, self).__init__(config, "client")

        end_sock = socket.socket()
        end_sock.setblocking(False)
        self._connect_server(end_sock, self._config["server"], self._config["server_port"])

        self._set.add_sock(self._set.SOCK_END, end_sock)

    def _on_connect(self, sock, istream, ostream):
        self._log.info("connect yass2 server success")
        self._set.set_sock_attr(sock, make_stat="end")
        self._set.print_sock_stat(sock)

    def _on_accept(self, server_sock, new_sock):
        new_sock.setblocking(False)
        self._io.add_sock(new_sock,
                          on_receive=self._on_read,
                          on_close=self._on_close,
                          on_error=self._on_error)

        self._set.add_sock(self._set.SOCK_CONN, new_sock)
        self._set.set_sock_attr(new_sock, status=self.ST_BEGIN)

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
                if conn_sock is None:
                    continue
                conn_ostream = self._io.get_otream(conn_sock)
                if frame_type == self.FRAME_DATA:
                    # try:
                    conn_ostream.write(data)
                    # except tcp_event.StreamClosed:
                    #    pass
                elif frame_type == self.FRAME_DELCONN:
                    self._set.del_sock(conn_sock)
                    conn_ostream.close()

        elif sock_type == self._set.SOCK_CONN:
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
                self._send_newconn_frame(sock, socks_address)

                self._set.set_sock_attr(sock, domain=addr)
                self._set.print_sock_stat(sock)
                self._set.set_sock_attr(sock, status=self.ST_DATA)

            elif status == self.ST_DATA:
                try:
                    data = istream.read_all()
                    if len(data) != 0:
                        self._send_data_frame(sock, data)
                except tcp_event.StreamClosed:
                    pass

            if istream.eof():
                ostream.close()


if __name__ == "__main__":
    yass_client = YASS2Client({
        "server": "127.0.0.1",
        "server_port": 10001,
        "listen_port": 10000,
        "password": "demasiya"
    })
    yass_client.run()