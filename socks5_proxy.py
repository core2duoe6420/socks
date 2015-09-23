# -*- coding: utf-8 -*-

import tcp_event
import socket
import socks_base


class Socks5Proxy(socks_base.SocksBase):

    def __init__(self, listen_port):
        super(Socks5Proxy, self).__init__(listen_port)
        self._set = socks_base.OneToOneSockSet(self._log)

    def _on_accept(self, server_sock, new_sock):
        new_sock.setblocking(False)
        self._set.add_sock(socks_base.OneToOneSockSet.SOCK_CLIENT, new_sock)
        self._set.set_sock_attr(new_sock, status=self.ST_BEGIN)
        self._io.add_sock(new_sock,
                          on_receive=self._on_read,
                          on_close=self._on_close,
                          on_error=self._on_error)

    def _on_close(self, sock):
        # sock可能在peer被删除时一起删除了
        if sock not in self._set:
            return

        self._set.set_sock_attr(sock, end_time=self._log.datetime())
        self._log.debug("closing pair")
        self._set.print_sock_stat(sock)

        peer = self._set.get_tunnel_sock(sock)

        if self._set.sock_type(sock) == self._set.SOCK_SERVER:
            if self._set.get_sock_attr(sock, "status") == self.ST_AUTH:
                # 连接服务器时发生了错误
                client_ostream = self._io.get_otream(peer)
                client_ostream.write(self._gen_reply(4))
                client_ostream.close()

        self._set.del_sock(sock)
        try:
            peer_ostream = self._io.get_otream(peer)
            peer_ostream.close()
        except tcp_event.StreamNotExist:
            pass

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
                _, addr, port = self._socks5_request(request)
            except ValueError:
                ostream.write(self._gen_reply(7))
                ostream.close()
                return

            server = self._set.get_tunnel_sock(sock)
            try:
                self._connect(server, addr, port)
            except socket.error:
                ostream.close()
                return
            self._io.add_sock(server,
                              on_receive=self._on_read,
                              on_connect=self._on_connect,
                              on_close=self._on_close,
                              on_error=self._on_error)
            self._set.set_sock_attr(sock, domain=addr)

        elif status == self.ST_DATA:
            peer = self._set.get_tunnel_sock(sock)

            peer_ostream = self._io.get_otream(peer)
            try:
                buf = istream.read_all()
                peer_ostream.write(buf)
            except tcp_event.StreamClosed:
                pass

            if istream.eof():
                ostream.close()
                peer_ostream.close()

    def _on_connect(self, sock, istream, ostream):
        # 连接成功时conn_pair有可能已经被删除，应该是因为客户端已经终止了连接
        if sock not in self._set:
            return

        if self._set.sock_type(sock) != self._set.SOCK_SERVER:
            raise ValueError("server does not match")
        # 我们连接成功了
        addr, port = sock.getsockname()
        client = self._set.get_tunnel_sock(sock)
        client_ostream = self._io.get_otream(client)
        client_ostream.write(self._gen_reply(0, 1, addr, port))
        self._set.set_sock_attr(sock, status=self.ST_DATA)
        self._set.set_sock_attr(sock, make_stat="server")
        self._set.print_sock_stat(sock)


if __name__ == "__main__":
    sock_server = Socks5Proxy(10000)
    sock_server.run()
