# -*- coding: utf-8 -*-

import tcp_event
import logger
import socks_base
import cipher
import socket

_log = logger.Logger("yass_base")


class YASSBase(socks_base.SocksBase):
    """yet another shadowsocks"""

    def __init__(self, config, actor):
        config["actor"] = actor
        if actor == "client":
            listen_port = config["listen_port"]
        elif actor == "server":
            listen_port = config["server_port"]
        socks_base.SocksBase.__init__(self, listen_port)
        self._config = config
        self._config["key"] = cipher.gen_key(self._config["password"])

    def _on_accept(self, server_sock, new_sock):
        new_sock.setblocking(False)
        remote_sock = socket.socket()
        remote_sock.setblocking(False)
        if self._config["actor"] == "client":
            try:
                self._connect_server(remote_sock, self._config["server"],
                                     self._config["server_port"])
            except socket.error:
                self._io.get_otream(new_sock).close()
                return

        pair = {
            "client": new_sock,
            "server": remote_sock,
            "status": self.ST_BEGIN,
            "info_index": len(self._stat["pairs"])
        }

        self._pairs[new_sock] = self._pairs[remote_sock] = pair
        self._io.add_sock(new_sock,
                          on_receive=self._on_read,
                          on_close=self._on_close,
                          on_error=self._on_error)

        self._stat["pairs"].append({"client": self._make_sock_info(new_sock),
                                    "server": {"fd": remote_sock.fileno()},
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

        del self._pairs[sock]
        del self._pairs[peer]
        try:
            peer_stream = self._io.get_otream(peer)
            peer_stream.close()
        except tcp_event.StreamNotExist:
            pass

    def _on_read(self, sock, istream, ostream):
        pass

    def _on_connect(self, sock, istream, ostream):
        # 连接成功时conn_pair有可能已经被删除，应该是因为客户端已经终止了连接
        if sock not in self._pairs:
            return

        pair = self._pairs[sock]
        if sock != pair["server"]:
            raise ValueError("server does not match")

        pair_info = self._get_pair_info(pair)
        pair_info["server"] = self._make_sock_info(sock)
        self._print_pair_info(pair_info)

    def _send_frame(self, frame, ostream):
        ciphertext = cipher.encrypt(self._config["key"], frame)
        ostream.write(len(ciphertext))
        ostream.write(ciphertext)

    def _recv_frame(self, istream):
        try:
            ciphertext_len = istream.read_bin_int(keep_in_stream=True)
            ciphertext = istream.read_bin(4 + ciphertext_len)
        except tcp_event.ResourceError:
            return None
        ciphertext = ciphertext[4:]

        plaintext = cipher.decrypt(self._config["key"], ciphertext)
        if plaintext is None:
            raise ValueError("MAC fail, data corrupted")
        return plaintext

    def _connect_server(self, sock, addr, port):
        socks_base.SocksBase._connect(sock, addr, port)
        self._io.add_sock(sock,
                          on_receive=self._on_read,
                          on_connect=self._on_connect,
                          on_close=self._on_close,
                          on_error=self._on_error)