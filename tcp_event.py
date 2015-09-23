# -*- coding: utf-8 -*-

import socket
import errno
import io_event
import struct
import re
import logger


EVT_IN = "on_receive"
EVT_OUT = "on_send"
EVT_ERR = "on_error"
EVT_ACCEPT = "on_accept"
EVT_CONNECT = "on_connect"
EVT_CLOSE = "on_close"


class ResourceError(Exception):
    pass


class StreamClosed(Exception):
    pass


class StreamNotExist(Exception):
    pass


class TcpStream(object):

    def __init__(self):
        self._buf = ""
        self._eof = False

    @staticmethod
    def _get_format(data_type, size, little_endian):
        if data_type is int:
            size_fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}
        if data_type is float:
            size_fmt = {4: "f", 8: "d"}
        fmt = "!"  # network字节序
        if little_endian:
            fmt = "<"
        try:
            fmt += size_fmt[size]
        except KeyError:
            raise ValueError("unsupported size")
        return fmt

    def write(self, data, size=4, little_endian=False, skip_check=False):
        """
        向流中写入数据
        :param data: 要写入的数据，类型可以是str,int或float
        :param size: 仅当类型是int,float时有效，指定流中占的字节数，只能是1,2,4,8中的一个
        :param little_endian: 是否使用小端序
        :param skip_check: 指定为True时会忽略流的eof标志检查，这是为了给TcpEvent发送数据时
                        当遇到EWOULDBLOCK时回写数据用的，防止因为设置了eof而使数据丢
                        失。DO NOT use it if you don't know what you are doing
        :return: 无返回值
        """
        if self._eof and not skip_check:
            raise StreamClosed()
        if type(data) is str:
            self._buf += data
        elif type(data) is int or type(data) is float:
            self._buf += struct.pack(self._get_format(type(data), size, little_endian), data)
        else:
            raise ValueError("unsupported data type")

    def _read_check(self):
        if self.eof():
            raise StreamClosed()

    def read_all(self, keep_in_stream=False):
        self._read_check()
        ret = self._buf
        if not keep_in_stream:
            self._buf = ""
        return ret

    def _do_read_binary(self, data_type, size, little_endian, keep_in_stream):
        self._read_check()
        if len(self._buf) < size:
            raise ResourceError()

        buf = self._buf[:size]
        if not keep_in_stream:
            self._buf = self._buf[size:]
        return struct.unpack(self._get_format(data_type, size, little_endian), buf)[0]

    def read_bin_int(self, size=4, little_endian=False, keep_in_stream=False):
        """keep_in_stream为True时会将读取的数据继续保留在流中，下次读取还会读出"""
        return self._do_read_binary(int, size, little_endian, keep_in_stream)

    def read_bin_float(self, size=4, little_endian=False, keep_in_stream=False):
        return self._do_read_binary(float, size, little_endian, keep_in_stream)

    def read_bin(self, size, keep_in_stream=False):
        """该函数返回的是类型是str，不是数组"""
        self._read_check()
        if len(self._buf) < size:
            raise ResourceError()

        ret = self._buf[:size]
        if not keep_in_stream:
            self._buf = self._buf[size:]
        return ret

    def read_int(self, keep_in_stream=False):
        return int(self.read_word(keep_in_stream))

    def read_line(self, keep_in_stream=False):
        self._read_check()
        index = self._buf.find("\n")
        if index == -1:
            if self._eof:
                return self.read_all(keep_in_stream)
            else:
                raise ResourceError()

        ret = self._buf[:index + 1]
        if not keep_in_stream:
            self._buf = self._buf[index + 1:]
        return ret

    def read_word(self, keep_in_stream=False):
        self._read_check()
        p = re.compile(r"\W\n?")
        match = p.search(self._buf)
        if match:
            ret = self._buf[:match.start(0)]
            if not keep_in_stream:
                self._buf = self._buf[match.end(0):]
            return ret
        else:
            if self._eof:
                return self.read_all(keep_in_stream)
            else:
                raise ResourceError()

    def close(self):
        self._eof = True

    def closed(self):
        """仅返回eof标志"""
        return self._eof

    def eof(self):
        """仅当缓冲已经全部被读取完毕并且设置了eof标志时才返回True"""
        return self._eof and len(self._buf) == 0

    def __len__(self):
        return len(self._buf)


class TcpEvent(object):

    def __init__(self):
        self._io = io_event.get_event_loop()
        self._sock_set = {}
        self._log = logger.Logger(self.__class__.__name__, log_file=None)

    def _setup_write_event(self, sock, handler):
        self._io.modify_sock(sock, io_event.EVT_WRITE, handler)

    def _setup_read_event(self, sock, handler):
        self._io.modify_sock(sock, io_event.EVT_READ, handler)

    def get_istream(self, sock):
        if sock not in self._sock_set:
            raise StreamNotExist()
        return self._sock_set[sock]["in"]

    def get_otream(self, sock):
        if sock not in self._sock_set:
            raise StreamNotExist()
        self._setup_write_event(sock, self._on_write)
        return self._sock_set[sock]["out"]

    def add_sock(self, sock, **kwargs):
        kwargs["in"] = TcpStream()
        kwargs["out"] = TcpStream()
        sock.setblocking(False)
        self._sock_set[sock] = kwargs
        self._io.add_sock(sock, on_read=self._on_read, on_error=self._on_error)
        if EVT_CONNECT in kwargs:
            self._setup_write_event(sock, self._on_write)

    def _del_sock(self, sock):
        try:
            del self._sock_set[sock]
        except KeyError:
            pass
        self._io.del_sock(sock)

    def _close_sock(self, sock, reason=None):
        # 因为on_write中shutdown改为了close，可能会重复删除，所以需要做检测
        if sock not in self._sock_set:
            return

        if reason is not None:
            self._log.info("close socket, %s, fd=%d" % (reason, sock.fileno()))

        sock_info = self._sock_set[sock]
        if EVT_CLOSE in sock_info:
            sock_info[EVT_CLOSE](sock)
        self._del_sock(sock)
        sock.close()

    def _on_read(self, sock):
        sock_info = self._sock_set[sock]
        if EVT_IN in sock_info:
            istream = sock_info["in"]
            ostream = sock_info["out"]
            while True:
                try:
                    buf = sock.recv(10240)
                except socket.error, e:
                    # self._log.warning("socket read error, fd=%d, %s" %
                    #                   (sock.fileno(), os.strerror(e.errno)))
                    if e.errno == errno.EWOULDBLOCK:
                        break
                    else:
                        self._on_error(sock, e.errno)
                        return
                if buf:
                    istream.write(buf)
                else:
                    # 对端正常关闭连接
                    self._setup_read_event(sock, None)
                    istream.close()
                    break

            # 回调程序读取数据时应该负责捕获StreamClosed()异常
            sock_info[EVT_IN](sock, istream, ostream)
            self._send_ostream(sock)

            # 如果对端关闭连接，且out流中的数据已经全部发送，关闭sock
            if istream.closed() and len(ostream) == 0:
                self._close_sock(sock, "peer close socket")

        elif EVT_ACCEPT in sock_info:
            while True:
                try:
                    new_sock, addr = sock.accept()
                except socket.error, e:
                    # self._log.warning("socket accept error, fd=%d, %s" %
                    #                   (sock.fileno(), os.strerror(e.errno)))
                    if e.errno == errno.EWOULDBLOCK:
                        break
                    else:
                        self._on_error(sock, e.errno)
                        return

                sock_info[EVT_ACCEPT](sock, new_sock)

        else:
            raise ValueError("no on_read function")

    def _on_write(self, sock):
        sock_info = self._sock_set[sock]
        istream = sock_info["in"]
        ostream = sock_info["out"]
        if EVT_CONNECT in sock_info:
            sock_info[EVT_CONNECT](sock, istream, ostream)
            del sock_info[EVT_CONNECT]

        if EVT_OUT in sock_info:
            sock_info[EVT_OUT](sock, istream, ostream)

        self._send_ostream(sock)

    def _on_error(self, sock, err_code=-1):
        sock_info = self._sock_set[sock]
        if EVT_ERR in sock_info:
            if err_code == -1:
                err_code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            sock_info[EVT_ERR](sock, err_code)
        self._close_sock(sock, "error occurs")

    def _send_ostream(self, sock):
        sock_info = self._sock_set[sock]
        ostream = sock_info["out"]
        try:
            buf = ostream.read_all()
            while len(buf) > 0:
                try:
                    write_len = sock.send(buf)
                    buf = buf[write_len:]
                except socket.error, e:
                    # self._log.warning("socket write error, fd=%d, %s" %
                    #                   (sock.fileno(), os.strerror(e.errno)))
                    if e.errno == errno.EWOULDBLOCK:
                        self._setup_write_event(sock, self._on_write)
                        ostream.write(buf, skip_check=True)
                        return
                    else:
                        self._on_error(sock, e.errno)
                        return
            # 执行到这说明buf已经全部发送完毕，取消之前可能由get_output_stream设置的on_write事件
            self._setup_write_event(sock, None)

        except StreamClosed:
            pass

        if ostream.eof():
            # 如果用户结束了输出流，且流中数据已经全部发送，shutdown连接
            self._close_sock(sock, "user close output stream")
            # shutdown在linux下会使socket清理不干净，改用close
            # try:
            #     sock.shutdown(socket.SHUT_WR)
            # except socket.error:
            #     pass

    def run(self):
        self._io.run()
