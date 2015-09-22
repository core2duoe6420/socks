# -*- coding: utf-8 -*-

import tcp_event
import socket
import logger
import yass_base

_log = logger.Logger("socks_base")


class YASS2Client(yass_base.YASSBase):
    def __init__(self, config):
        super(YASS2Client, self).__init__(config, "client")

        server_sock = socket.socket()
        server_sock.setblocking(False)
        self._connect_server(server_sock, self._config["server"], self._config["server_port"])
        self._peers.append(server_sock)
        self._id = 1

    def _on_connect(self, sock, istream, ostream):
        _log.info("connect success, addr=" + str(sock.getpeername()))

    def _on_accept(self, server_sock, new_sock):
        new_sock.setblocking(False)
        self._io.add_sock(new_sock,
                          on_receive=self._on_read,
                          on_close=self._on_close,
                          on_error=self._on_error)

        self._new_conn(new_sock, self._id)
        self._id += 1

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
                        conn_sock = self._get_conn(conn_id)
                        if conn_sock is None:
                            return
                        conn_ostream = self._io.get_otream(conn_sock)
                        if frame_type == self.FRAME_DATA:
                            conn_ostream.write(data)
                        elif frame_type == self.FRAME_DELCONN:
                            self._del_conn(conn_id)
                            conn_ostream.close()
                    else:
                        break
            except tcp_event.StreamClosed:
                pass
        elif sock in self._socks:
            sock_info = self._socks[sock]
            conn_id = sock_info["id"]
            if sock_info["status"] == self.ST_BEGIN:
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
                sock_info["status"] = self.ST_AUTH

            elif sock_info["status"] == self.ST_AUTH:
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
                self._send_newconn_frame(conn_id, socks_address)
                sock_info["status"] = self.ST_DATA

            elif sock_info["status"] == self.ST_DATA:
                try:
                    data = istream.read_all()
                    if len(data) != 0:
                        self._send_data_frame(conn_id, data)
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