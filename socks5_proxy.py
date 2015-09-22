# -*- coding: utf-8 -*-

import tcp_event
import socket
import logger
import socks_base


_log = logger.Logger("socks5")


class Socks5Proxy(socks_base.SocksPairBase):

    def __init__(self, listen_port):
        super(Socks5Proxy, self).__init__(listen_port)

    def _on_accept(self, server_sock, new_sock):
        new_sock.setblocking(False)
        # 有可能在根本没有连接server的情况下客户端就断开连接了，这种情况下，我们仰仗python的垃圾回收来回收socket资源
        server_sock = socket.socket()
        server_sock.setblocking(False)
        pair = {
            "client": new_sock,
            "server": server_sock,
            "status": self.ST_BEGIN,
            "info_index": len(self._stat["pairs"])
        }
        self._pairs[new_sock] = self._pairs[server_sock] = pair
        self._io.add_sock(new_sock,
                          on_receive=self._on_read,
                          on_close=self._on_close,
                          on_error=self._on_error)

        self._stat["pairs"].append({"client": self._make_sock_info(new_sock),
                                    "server": {"fd": server_sock.fileno()},
                                    "domain": "not connected"})

    def _on_close(self, sock):
        # sock可能在peer被删除时一起删除了
        if sock not in self._pairs:
            return

        pair = self._pairs[sock]
        pair_info = self._get_pair_info(pair)
        pair_info["server"]["end"] = pair_info["client"]["end"] = _log.datetime()
        _log.debug("closing pair")
        self._print_pair_info(pair_info)

        if sock == pair["server"]:
            peer = pair["client"]
        else:
            peer = pair["server"]

        if sock == pair["server"]:
            if pair["status"] == self.ST_AUTH:
                # 连接服务器时发生了错误
                client_ostream = self._io.get_otream(peer)
                client_ostream.write(self._gen_reply(4))
                client_ostream.close()

        del self._pairs[sock]
        del self._pairs[peer]
        try:
            peer_ostream = self._io.get_otream(peer)
            peer_ostream.close()
        except tcp_event.StreamNotExist:
            pass

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
                _, addr, port = self._socks5_request(request)
            except ValueError:
                ostream.write(self._gen_reply(7))
                ostream.close()
                return

            server = pair["server"]
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
            pair_info = self._get_pair_info(pair)
            pair_info["domain"] = addr

        elif pair["status"] == self.ST_DATA:
            if sock == pair["server"]:
                peer = pair["client"]
            else:
                peer = pair["server"]

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
        if sock not in self._pairs:
            return

        pair = self._pairs[sock]
        if sock != pair["server"]:
            raise ValueError("server does not match")
        # 我们连接成功了
        addr, port = sock.getsockname()
        client = pair["client"]
        client_ostream = self._io.get_otream(client)
        client_ostream.write(self._gen_reply(0, 1, addr, port))
        pair["status"] = self.ST_DATA

        pair_info = self._get_pair_info(pair)
        pair_info["server"] = self._make_sock_info(sock)
        self._print_pair_info(pair_info)


if __name__ == "__main__":
    sock_server = Socks5Proxy(10000)
    sock_server.run()
