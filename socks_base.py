# -*- coding: utf-8 -*-

import tcp_event
import socket
import struct
import os
import logger
import errno


class OneToOneSockSet(object):
    """模型：
    |browser/client|<---->|socks客户端|<------->|socks服务器|<---->|要访问服务器|
                    n条连接              n条连接             n条连接
    """
    SOCK_CLIENT = 1
    SOCK_SERVER = 2

    def __init__(self, log):
        self._pairs = {}
        self._stat = {"pairs": []}
        self._log = log

    def add_sock(self, sock_type, sock):
        if sock_type != self.SOCK_CLIENT:
            raise ValueError("invalid socket type")

        server_sock = socket.socket()
        server_sock.setblocking(False)
        pair = {
            "client": sock,
            "server": server_sock,
            "status": -1,
            "stat_index": len(self._stat["pairs"])
        }
        self._pairs[sock] = self._pairs[server_sock] = pair

        self._stat["pairs"].append({"client": self._make_sock_stat(sock),
                                    "server": {"fd": server_sock.fileno()},
                                    "domain": "not connected"})

    def get_sock_attr(self, sock, attr):
        if attr == "status":
            return self._pairs[sock]["status"]

    def set_sock_attr(self, sock, **kwargs):
        pair = self._pairs[sock]
        pair_stat = self._get_pair_stat(pair)
        for k, v in kwargs.items():
            if k == "status":
                pair["status"] = v
            elif k == "end_time":
                pair_stat["server"]["end"] = v
                pair_stat["client"]["end"] = v
            elif k == "make_stat":
                pair_stat[v] = self._make_sock_stat(sock)
            else:
                pair_stat[k] = v

    def get_tunnel_sock(self, sock):
        """返回与sock关联的sock，在一对一模型中，就是相关连的sock"""
        pair = self._pairs[sock]
        if sock == pair["client"]:
            return pair["server"]
        else:
            return pair["client"]

    def del_sock(self, sock):
        peer_sock = self.get_tunnel_sock(sock)
        del self._pairs[peer_sock]
        del self._pairs[sock]

    def sock_type(self, sock):
        pair = self._pairs[sock]
        if sock == pair["client"]:
            return self.SOCK_CLIENT
        else:
            return self.SOCK_SERVER

    def __contains__(self, sock):
        return sock in self._pairs

    def _make_sock_stat(self, sock):
        local_ip, local_port = sock.getsockname()
        remote_ip, remote_port = sock.getpeername()
        return {
            "fd": sock.fileno(),
            "local": local_ip + ":" + str(local_port),
            "remote": remote_ip + ":" + str(remote_port),
            "start": self._log.datetime(),
            "end": "0"
        }

    def _print_sock_stat(self, sock_stat):
        info = ", ".join(["=".join((str(k), str(v))) for k, v in sock_stat.items()])
        self._log.debug("socket stat: %s" % info)

    def _print_pair_stat(self, pair_stat):
        self._log.debug("pair stat: server_fd=%d, client_fd=%d, domain=%s"
                        % (pair_stat["server"]["fd"], pair_stat["client"]["fd"], pair_stat["domain"]))
        self._print_sock_stat(pair_stat["server"])
        self._print_sock_stat(pair_stat["client"])
        self._log.blank_line()
        self._log.flush()

    def _get_pair_stat(self, pair):
        return self._stat["pairs"][pair["stat_index"]]

    def print_sock_stat(self, sock):
        pair = self._pairs[sock]
        pair_stat = self._get_pair_stat(pair)
        self._print_pair_stat(pair_stat)


class MultiToOneSockSet(object):
    """模型：
    |browser/client|<---->|socks客户端|<------->|socks服务器|<---->|要访问服务器|
                    n条连接           m条连接(m<=5)          n条连接
    """
    SOCK_END = 1
    SOCK_CONN = 2

    def __init__(self, log):
        self._ends = {}
        self._conns = {}
        self._stat = []
        self._id = 1
        self._end_id = -1
        self._log = log

    def add_sock(self, sock_type, sock, conn_id=-1):
        if sock_type == self.SOCK_END:
            self._ends[sock] = {
                "stat_index": len(self._stat),
                "id": self._end_id
            }
            self._end_id -= 1
        elif sock_type == self.SOCK_CONN:
            if conn_id == -1:
                conn_id = self._id
            self._conns[sock] = {
                "id": conn_id,
                "status": -1,
                "stat_index": len(self._stat)
            }
            self._id += 1
        self._stat.append(self._make_sock_stat(sock))

    def get_sock_attr(self, sock, attr):
        return self._conns[sock][attr]

    def set_sock_attr(self, sock, **kwargs):
        sock_info = self._get_sock_info(sock)
        sock_stat = self._stat[sock_info["stat_index"]]
        for k, v in kwargs.items():
            if k == "status":
                sock_info["status"] = v
            elif k == "end_time":
                sock_stat["end"] = v
            elif k == "make_info":
                self._stat[sock_info["stat_index"]] = self._make_sock_stat(sock)
            else:
                sock_stat[k] = v

    def get_conn_sock(self, conn_id):
        try:
            return filter(lambda x: x[1]["id"] == conn_id, self._conns.items())[0][0]
        except IndexError:
            return None

    def get_end_sock(self):
        return self._ends.keys()[0]

    def del_sock(self, sock):
        if sock in self._conns:
            del self._conns[sock]
        elif sock in self._ends:
            del self._ends[sock]

    def sock_type(self, sock):
        if sock in self._conns:
            return self.SOCK_CONN
        elif sock in self._ends:
            return self.SOCK_END

    def __contains__(self, sock):
        return sock in self._conns or sock in self._ends

    def _get_sock_info(self, sock):
        if sock in self._conns:
            return self._conns[sock]
        elif sock in self._ends:
            return self._ends[sock]

    def _make_sock_stat(self, sock):
        local_ip, local_port = sock.getsockname()
        try:
            remote_ip, remote_port = sock.getpeername()
        except socket.error:
            return {
                "fd": sock.fileno(),
                "domain": "not connected"
            }

        return {
            "fd": sock.fileno(),
            "id": self._get_sock_info(sock)["id"],
            "local": local_ip + ":" + str(local_port),
            "remote": remote_ip + ":" + str(remote_port),
            "start": self._log.datetime(),
            "end": "active",
            "domain": "not connected"
        }

    def print_sock_stat(self, sock):
        sock_info = self._get_sock_info(sock)
        sock_stat = self._stat[sock_info["stat_index"]]
        info = ", ".join(["=".join((str(k), str(v))) for k, v in sock_stat.items()])
        self._log.debug("socket stat: %s" % info)


class SocksBase(object):
    ST_BEGIN = 1
    ST_AUTH = 2
    ST_DATA = 3
    ST_CONNECTED = 4

    def __init__(self, listen_port):
        server_sock = socket.socket()
        server_sock.setblocking(False)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", listen_port))
        server_sock.listen(40)

        self._io = tcp_event.TcpEvent()
        self._io.add_sock(server_sock, on_accept=self._on_accept)
        self._log = logger.Logger(self.__class__.__name__)

    def run(self):
        self._io.run()

    @staticmethod
    def _unpack_socks_address(socks_address):
        addr_type = struct.unpack("!B", socks_address[:1])[0]
        socks_address = socks_address[1:]
        if addr_type == 1:
            addr = socket.inet_ntoa(socks_address[:4])
            socks_address = socks_address[4:]
        elif addr_type == 3:
            addr_len = struct.unpack("!B", socks_address[:1])[0]
            addr = socks_address[1:addr_len + 1]
            socks_address = socks_address[addr_len + 1:]
        elif addr_type == 4:
            addr = socket.inet_ntop(socket.AF_INET6, socks_address[:16])
            socks_address = socks_address[16:]

        port = struct.unpack("!H", socks_address)[0]
        if len(socks_address) != 2:
            raise ValueError("invalid socks_address")
        return addr_type, addr, port

    @staticmethod
    def _pack_socks_address(addr_type, addr, port):
        socks_address = struct.pack("!B", addr_type)
        if addr_type == 1:
            socks_address += socket.inet_aton(addr)
        elif addr_type == 3:
            socks_address += struct.pack("!B%ds" % len(addr), len(addr), addr)
        elif addr_type == 4:
            socks_address += socket.inet_pton(socket.AF_INET6, addr)
        socks_address += struct.pack("!H", port)
        return socks_address

    @staticmethod
    def _socks5_auth(auth):
        version, nmethods = struct.unpack("!BB", auth[:2])
        if version != 5:
            return None
        auth = auth[2:]
        if len(auth) != nmethods:
            raise ValueError("invalid method selection message")
        methods = struct.unpack("!%dB" % nmethods, auth)
        if 0 in methods:
            return b"\x05\x00"
        else:
            return None

    @staticmethod
    def _socks5_request(request):
        version, cmd = struct.unpack("!BB", request[:2])
        if version != 5 or cmd != 1:
            raise ValueError("unsupported socks version or command")

        request = request[3:]
        # 请求地址
        return SocksBase._unpack_socks_address(request)

    def _on_accept(self, server_sock, new_sock):
        pass

    def _on_error(self, sock, err_code):
        self._log.error("error: fd=%d, %s" % (sock.fileno(), os.strerror(err_code)))

    def _on_close(self, sock):
        pass

    def _on_read(self, sock, istream, ostream):
        pass

    def _on_connect(self, sock, istream, ostream):
        pass

    @staticmethod
    def _connect(sock, addr, port):
        try:
            sock.connect((addr, port))
        except socket.error, e:
            if e.errno in (errno.EINPROGRESS, errno.EWOULDBLOCK):
                pass
            else:
                raise
        return sock

    @staticmethod
    def _gen_reply(reply, addr_type=1, bind_addr="", bind_port=0):
        if reply == 0:
            return "\x05\x00\x00" + SocksBase._pack_socks_address(addr_type, bind_addr, bind_port)
        else:
            return "\x05" + struct.pack("!B", reply) + "\x00\x01\x00\x00\x00\x00\x00\x00"
