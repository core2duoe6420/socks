# -*- coding: utf-8 -*-

import tcp_event
import socket
import errno
import os
import logger


_log = logger.Logger("socks5")


class Socks5Proxy:
    ST_BEGIN = 1
    ST_AUTH = 2
    ST_DATA = 3

    def __init__(self, listen_port):
        self._pairs = {}
        self._stat = {"pairs": []}
        server_sock = socket.socket()
        server_sock.setblocking(False)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", listen_port))
        server_sock.listen(20)

        self._io = tcp_event.TcpEvent()
        self._io.add_sock(server_sock, on_accept=self._on_accept)

    def run(self):
        self._io.run()

    @staticmethod
    def _make_sock_info(sock):
        local_ip, local_port = sock.getsockname()
        remote_ip, remote_port = sock.getpeername()
        return {
            "fd": sock.fileno(),
            "local": local_ip + ":" + str(local_port),
            "remote": remote_ip + ":" + str(remote_port),
            "start": _log.datetime(),
            "end": "0"
        }

    @staticmethod
    def _print_sock_info(sock_info):
        info = ", ".join(["=".join((str(k), str(v))) for k, v in sock_info.items()])
        _log.debug("socket info: %s" % info)

    def _print_pair_info(self, pair_info):
        _log.debug("pair info: server_fd=%d, client_fd=%d, domain=%s"
               % (pair_info["server"]["fd"], pair_info["client"]["fd"], pair_info["domain"]))
        self._print_sock_info(pair_info["server"])
        self._print_sock_info(pair_info["client"])
        _log.blank_line()
        _log.flush()

    def _on_accept(self, server_sock, new_sock):
        new_sock.setblocking(False)
        # 有可能在根本没有连接server的情况下客户端就断开连接了，这种情况下，我们仰仗python的垃圾回收来回收socket资源
        server_sock = socket.socket()
        server_sock.setblocking(False)
        pair = {"client": new_sock, "server": server_sock,
                "status": self.ST_BEGIN, "info_index": len(self._stat["pairs"])}
        self._pairs[new_sock] = self._pairs[server_sock] = pair
        self._io.add_sock(new_sock, on_receive=self._on_read, on_close=self._on_close, on_error=self._on_error)

        self._stat["pairs"].append({"client": self._make_sock_info(new_sock),
                                    "server": {"fd": server_sock.fileno()},
                                    "domain": "not connected"})

    def _get_pair_info(self, pair):
        return self._stat["pairs"][pair["info_index"]]

    def _on_error(self, sock, err_code):
        _log.debug("error: fd=%d, %s" % (sock.fileno(), os.strerror(err_code)))

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
                client_out_stream = self._io.get_output_stream(peer)
                client_out_stream.write("\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                client_out_stream.close()

        del self._pairs[sock]
        del self._pairs[peer]
        try:
            peer_stream = self._io.get_output_stream(peer)
            peer_stream.close()
        except tcp_event.StreamNotExist:
            pass

    def _on_read(self, sock, in_stream, out_stream):
        if sock not in self._pairs:
            return

        pair = self._pairs[sock]
        try:
            if pair["status"] == self.ST_BEGIN:
                version = in_stream.read_bin_int(1)
                if version != 5:
                    out_stream.close()
                    return
                method_num = in_stream.read_bin_int(1)
                if method_num != 1:
                    out_stream.close()
                    return
                methods = in_stream.read_bin_int(1)
                if methods != 0:
                    out_stream.close()
                    return
                out_stream.write("\x05\x00")
                pair["status"] = self.ST_AUTH

            elif pair["status"] == self.ST_AUTH:
                version = in_stream.read_bin_int(1)
                # version
                if version != 5:
                    out_stream.close()
                    return
                cmd = in_stream.read_bin_int(1)
                # 请求类型
                if cmd != 1:
                    out_stream.write("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                    out_stream.close()
                    return
                # 保留字节
                in_stream.read_bin(1)
                # 请求地址
                addr_type = in_stream.read_bin_int(1)
                if addr_type == 1: #IPv4
                    addr = socket.inet_ntoa(in_stream.read_bin(4))
                elif addr_type == 3: #域名
                    addr = in_stream.read_bin(in_stream.read_bin_int(1))
                else:
                    out_stream.write("\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                    out_stream.close()
                    return
                # 请求端口
                port = in_stream.read_bin_int(2)

                server = pair["server"]
                try:
                    server.connect((addr, port))
                except socket.error, e:
                    if e.errno in (errno.EINPROGRESS, errno.EWOULDBLOCK):
                        pass
                    else:
                        out_stream.close()
                        return

                self._io.add_sock(server, on_receive=self._on_read, on_connect=self._on_connect,
                                  on_close=self._on_close, on_error=self._on_error)

                pair_info = self._get_pair_info(pair)
                pair_info["domain"] = addr

            elif pair["status"] == self.ST_DATA:
                if sock == pair["server"]:
                    peer = pair["client"]
                else:
                    peer = pair["server"]

                peer_output_stream = self._io.get_output_stream(peer)
                try:
                    buf = in_stream.read_all()
                    peer_output_stream.write(buf)
                except tcp_event.StreamClosed:
                    pass

                if in_stream.eof():
                    out_stream.close()
                    peer_output_stream.close()

        except tcp_event.StreamClosed:
            out_stream.close()

    def _on_connect(self, sock, in_stream, out_stream):
        # 连接成功时conn_pair有可能已经被删除，应该是因为客户端已经终止了连接
        if sock not in self._pairs:
            return

        pair = self._pairs[sock]
        if sock != pair["server"]:
            raise ValueError("server does not match")
        # 我们连接成功了
        addr, port = sock.getsockname()
        client = pair["client"]
        client_out_stream = self._io.get_output_stream(client)
        client_out_stream.write("\x05\x00\x00\x01" + socket.inet_aton(addr))
        client_out_stream.write(port, 2)
        pair["status"] = self.ST_DATA

        pair_info = self._get_pair_info(pair)
        pair_info["server"] = self._make_sock_info(sock)
        self._print_pair_info(pair_info)


if __name__ == "__main__":
    server = Socks5Proxy(10000)
    server.run()
