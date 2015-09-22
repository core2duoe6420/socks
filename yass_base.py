# -*- coding: utf-8 -*-

import tcp_event
import logger
import socks_base
import cipher
import struct
import socket

_log = logger.Logger("yass_base")


def _get_listen_port(config, actor):
    if actor == "client":
        listen_port = config["listen_port"]
    elif actor == "server":
        listen_port = config["server_port"]
    return listen_port


def _do_send_frame(key, data, ostream, frame_type=None, conn_id=None):
    if frame_type is not None:
        plaintext = struct.pack("!BI", frame_type, conn_id) + data
        _log.debug("send frame, type=%d, id=%d" % (frame_type, conn_id))
    else:
        plaintext = data
    ciphertext = cipher.encrypt(key, plaintext)
    ostream.write(len(ciphertext))
    ostream.write(ciphertext)


def _do_recv_frame(key, istream, frame=False):
    try:
        ciphertext_len = istream.read_bin_int(keep_in_stream=True)
        ciphertext = istream.read_bin(4 + ciphertext_len)
    except tcp_event.ResourceError:
        return None

    ciphertext = ciphertext[4:]
    plaintext = cipher.decrypt(key, ciphertext)
    if plaintext is None:
        raise ValueError("MAC fail, data corrupted")

    if frame:
        frame_type, conn_id = struct.unpack("!BI", plaintext[:5])
        data = plaintext[5:]
        _log.debug("recv frame, type=%d, id=%d" % (frame_type, conn_id))
        return frame_type, conn_id, data
    else:
        return plaintext


class YASSBase(socks_base.SocksBase):
    FRAME_NEWCONN = 1
    FRAME_DATA = 2
    FRAME_DELCONN = 3

    # 两段重复代码，但是我想不出好的办法解决它们，继承并没有用
    def __init__(self, config, actor):
        super(YASSBase, self).__init__(_get_listen_port(config, actor))
        self._config = config
        self._config["key"] = cipher.gen_key(self._config["password"])
        self._config["actor"] = actor

        self._socks = {}
        # peer指yass的对端，对客户端来说peer是server，对server来说peer是客户端
        self._peers = []

    def _connect_server(self, sock, addr, port):
        socks_base.SocksBase._connect(sock, addr, port)
        self._io.add_sock(sock,
                          on_receive=self._on_read,
                          on_connect=self._on_connect,
                          on_close=self._on_close,
                          on_error=self._on_error)

    def _send_delconn_frame(self, sock):
        conn_id = self._socks[sock]["id"]
        peer_ostream = self._io.get_otream(self._peers[0])
        self._send_frame(self.FRAME_DELCONN, conn_id, "", peer_ostream)

    def _send_newconn_frame(self, conn_id, socks_address):
        peer_ostream = self._io.get_otream(self._peers[0])
        self._send_frame(self.FRAME_NEWCONN, conn_id, socks_address, peer_ostream)

    def _send_data_frame(self, conn_id, data):
        peer_ostream = self._io.get_otream(self._peers[0])
        self._send_frame(self.FRAME_DATA, conn_id, data, peer_ostream)

    def _on_close(self, sock):
        if sock in self._peers:
            # 暂时只有一个连接
            _log.error("Fatal error, server connection closed")
            exit(10)

        elif sock in self._socks:
            self._send_delconn_frame(sock)
            self._del_conn(sock)

    def _new_conn(self, sock, conn_id):
        self._socks[sock] = {
            "status": self.ST_BEGIN,  # server中无用
            "id": conn_id
        }

    def _del_conn(self, sock):
        try:
            del self._socks[sock]
        except KeyError:
            pass

    def _get_conn(self, conn_id):
        try:
            return filter(lambda x: x[1]["id"] == conn_id, self._socks.items())[0][0]
        except IndexError:
            return None

    def _send_frame(self, frame_type, conn_id, data, ostream):
        _do_send_frame(self._config["key"], data, ostream, frame_type, conn_id)

    def _recv_frame(self, istream):
        return _do_recv_frame(self._config["key"], istream, True)


class YASSPairBase(socks_base.SocksPairBase):
    def __init__(self, config, actor):
        super(YASSPairBase, self).__init__(_get_listen_port(config, actor))
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
        _do_send_frame(self._config["key"], frame, ostream)

    def _recv_frame(self, istream):
        return _do_recv_frame(self._config["key"], istream)