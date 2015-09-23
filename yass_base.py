# -*- coding: utf-8 -*-

import tcp_event
import socks_base
import cipher
import struct
import socket


class YASSBase(socks_base.SocksBase):
    def __init__(self, config, actor):
        if actor == "client":
            listen_port = config["listen_port"]
        elif actor == "server":
            listen_port = config["server_port"]
        super(YASSBase, self).__init__(listen_port)
        self._config = config
        self._config["key"] = cipher.gen_key(self._config["password"])
        self._config["actor"] = actor

    def _connect_server(self, sock, addr, port):
        socks_base.SocksBase._connect(sock, addr, port)
        self._io.add_sock(sock,
                          on_receive=self._on_read,
                          on_connect=self._on_connect,
                          on_close=self._on_close,
                          on_error=self._on_error)

    def _send_frame(self, data, ostream, frame_type=None, conn_id=None):
        if frame_type is not None:
            plaintext = struct.pack("!BI", frame_type, conn_id) + data
            self._log.debug("send frame, type=%d, id=%d" % (frame_type, conn_id))
        else:
            plaintext = data
        ciphertext = cipher.encrypt(self._config["key"], plaintext)
        ostream.write(len(ciphertext))
        ostream.write(ciphertext)

    def _recv_frame(self, istream, frame=False):
        try:
            ciphertext_len = istream.read_bin_int(keep_in_stream=True)
            ciphertext = istream.read_bin(4 + ciphertext_len)
        except tcp_event.ResourceError:
            return None

        ciphertext = ciphertext[4:]
        plaintext = cipher.decrypt(self._config["key"], ciphertext)
        if plaintext is None:
            raise ValueError("MAC fail, data corrupted")

        if frame:
            frame_type, conn_id = struct.unpack("!BI", plaintext[:5])
            data = plaintext[5:]
            self._log.debug("recv frame, type=%d, id=%d" % (frame_type, conn_id))
            return frame_type, conn_id, data
        else:
            return plaintext


class YASSMultiToOneBase(YASSBase):
    FRAME_NEWCONN = 1
    FRAME_DATA = 2
    FRAME_DELCONN = 3

    def __init__(self, config, actor):
        super(YASSMultiToOneBase, self).__init__(config, actor)
        self._set = socks_base.MultiToOneSockSet(self._log)

    def _do_send_frame(self, frame_type, sock, data):
        conn_id = self._set.get_sock_attr(sock, "id")
        end_ostream = self._io.get_otream(self._set.get_end_sock())
        self._send_frame(data, end_ostream, frame_type, conn_id)

    def _send_delconn_frame(self, sock):
        self._do_send_frame(self.FRAME_DELCONN, sock, "")

    def _send_newconn_frame(self, sock, socks_address):
        self._do_send_frame(self.FRAME_NEWCONN, sock, socks_address)

    def _send_data_frame(self, sock, data):
        self._do_send_frame(self.FRAME_DATA, sock, data)

    def _on_close(self, sock):
        if self._set.sock_type(sock) == self._set.SOCK_END:
            # 暂时只有一个连接
            self._log.error("Fatal error, server connection closed")
            exit(10)

        elif sock in self._set:
            self._send_delconn_frame(sock)
            self._set.del_sock(sock)


class YASSOneToOneBase(YASSBase):
    def __init__(self, config, actor):
        super(YASSOneToOneBase, self).__init__(config, actor)
        self._set = socks_base.OneToOneSockSet(self._log)

    def _on_accept(self, server_sock, new_sock):
        new_sock.setblocking(False)
        self._set.add_sock(socks_base.OneToOneSockSet.SOCK_CLIENT, new_sock)
        self._set.set_sock_attr(new_sock, status=self.ST_BEGIN)
        self._io.add_sock(new_sock,
                          on_receive=self._on_read,
                          on_close=self._on_close,
                          on_error=self._on_error)

        if self._config["actor"] == "client":
            remote_sock = self._set.get_tunnel_sock(new_sock)
            try:
                self._connect_server(remote_sock,
                                     self._config["server"],
                                     self._config["server_port"])
            except socket.error:
                self._io.get_otream(new_sock).close()
                return

    def _on_close(self, sock):
        # sock可能在peer被删除时一起删除了
        if sock not in self._set:
            return

        self._set.set_sock_attr(sock, end_time=self._log.datetime())
        self._log.debug("closing pair")
        self._set.print_sock_stat(sock)

        peer = self._set.get_tunnel_sock(sock)
        self._set.del_sock(sock)
        try:
            peer_ostream = self._io.get_otream(peer)
            peer_ostream.close()
        except tcp_event.StreamNotExist:
            pass

    def _on_connect(self, sock, istream, ostream):
        # 连接成功时conn_pair有可能已经被删除，应该是因为客户端已经终止了连接
        if sock not in self._set:
            return

        if self._set.sock_type(sock) != self._set.SOCK_SERVER:
            raise ValueError("server does not match")

        self._set.set_sock_attr(sock, make_stat="server")
        self._set.print_sock_stat(sock)
