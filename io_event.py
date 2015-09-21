# -*- coding: utf-8 -*-

import select
import logger


EVT_READ = "on_read"
EVT_WRITE = "on_write"
EVT_ERROR = "on_error"

_events = (EVT_READ, EVT_WRITE, EVT_ERROR)


def get_event_loop():
    if hasattr(select, "epoll"):
        return Epoll()
    elif hasattr(select, "select"):
        return Select()
    else:
        raise RuntimeError("can not find any available functions in 'select' package")

_log = logger.Logger("io_event")


class Select:
    def __init__(self):
        self._sock_set = {}
        self._sock_lists = {}
        for event in _events:
            self._sock_lists[event] = []

    def add_sock(self, sock, **kwargs):
        self._sock_set[sock] = kwargs
        for event in _events:
            if event in kwargs and kwargs[event] is not None:
                self._sock_lists[event].append(sock)
            else:
                kwargs[event] = None

        if kwargs[EVT_READ] is None or kwargs[EVT_ERROR] is None:
            raise ValueError("Select needs on_read() and on_error() callback")

        _log.info("add socket, fd=%d" % (sock.fileno()))

    def del_sock(self, sock):
        if sock in self._sock_set:
            _log.info("del socket, fd=%d" % (sock.fileno()))
            del self._sock_set[sock]
        for event in _events:
            if sock in self._sock_lists[event]:
                self._sock_lists[event].remove(sock)

    def modify_sock(self, sock, event, handler):
        if sock not in self._sock_set:
            _log.warning("sock %s does not exist in Select._sock_set" % (str(sock)))
            return

        sock_info = self._sock_set[sock]
        sock_list = self._sock_lists[event]

        if sock_info[event] == handler:
            return

        sock_info[event] = handler

        exist_in_list = sock in sock_list
        if handler is not None and not exist_in_list:
            sock_list.append(sock)
        elif handler is None and exist_in_list:
            sock_list.remove(sock)

        _log.info("modify socket, fd=%d, event=%s, handler=%s" % (sock.fileno(), event, str(handler)))

    def _print_list(self, name, event_list):
        _log.debug("%s: " % name + ",".join([str(x.fileno()) for x in event_list]))

    def _print_lists(self, r, w, e):
        _log.blank_line()
        self._print_list("RD_INT", self._sock_lists[EVT_READ])
        self._print_list("WR_INT", self._sock_lists[EVT_WRITE])
        self._print_list("ER_INT", self._sock_lists[EVT_ERROR])
        self._print_list("RD_EVT", r)
        self._print_list("WR_EVT", w)
        self._print_list("ER_EVT", e)

    def run(self):
        while True:
            try:
                r, w, e = select.select(self._sock_lists[EVT_READ],
                                        self._sock_lists[EVT_WRITE],
                                        self._sock_lists[EVT_ERROR])

                self._print_lists(r, w, e)
                for sock in r:
                    _log.event("%s, fd=%d" % (EVT_READ, sock.fileno()))
                    self._sock_set[sock][EVT_READ](sock)

                for sock in e:
                    # on_read事件处理程序可能会删除sock，需要第二次检测
                    if sock in self._sock_lists[EVT_ERROR]:
                        _log.event("%s, fd=%d" % (EVT_ERROR, sock.fileno()))
                        self._sock_set[sock][EVT_ERROR](sock)
                for sock in w:
                    if sock in self._sock_lists[EVT_WRITE]:
                        _log.event("%s, fd=%d" % (EVT_WRITE, sock.fileno()))
                        handler = self._sock_set[sock][EVT_WRITE]
                        self.modify_sock(sock, EVT_WRITE, None)
                        handler(sock)

            except ValueError:
                # select队列中的sock超过一定数量会报错，我们取最后的四分之一调用on_error
                _log.warning("Too many sockets in select, error on last 1/4 sockets")
                err_list = self._sock_lists[EVT_ERROR]
                sock_num = len(err_list)
                for i in xrange(sock_num - 1, sock_num * 3 / 4, -1):
                    sock = err_list[i]
                    _log.event("%s, fd=%d" % ("on_clean", sock.fileno()))
                    self._sock_set[sock][EVT_ERROR](sock)
            except:
                raise


class Epoll:
    def __init__(self):
        self._sock_set = {}
        self._epoll = select.epoll()

    def add_sock(self, sock, **kwargs):
        kwargs["sock"] = sock
        if EVT_READ not in kwargs:
            raise ValueError("Epoll needs on_read() callback")
        if EVT_WRITE not in kwargs:
            kwargs[EVT_WRITE] = None
        if EVT_ERROR not in kwargs:
            kwargs[EVT_ERROR ] = None
        self._sock_set[sock.fileno()] = kwargs

        event_mask = select.EPOLLIN
        if kwargs[EVT_WRITE] is not None:
            event_mask |= select.EPOLLOUT
        self._epoll.register(sock.fileno(), event_mask)
        _log.info("add socket, fd=%d" % (sock.fileno()))

    def del_sock(self, sock):
        fd = sock.fileno()

        self._epoll.unregister(fd)
        del self._sock_set[fd]
        _log.info("del socket, fd=%d" % fd)

    def modify_sock(self, sock, event, handler):
        sock_info = self._sock_set[sock.fileno()]

        if sock_info[event] == handler:
            return

        sock_info[event] = handler

        event_mask = select.EPOLLIN
        if event == EVT_WRITE and handler is not None:
            event_mask |= select.EPOLLOUT

        self._epoll.modify(sock.fileno(), event_mask)
        _log.info("modify socket, fd=%d, event=%s, handler=%s" % (sock.fileno(), event, str(handler)))

    def _print_list(self, name, event_list):
        _log.debug("%s: " % name + ",".join(map(str, event_list)))

    def _print_lists(self, events):
        _log.blank_line()
        self._print_list("INT", self._sock_set.keys())
        self._print_list("EVT", [x[0] for x in events])

    def run(self):
        while True:
            events = self._epoll.poll()
            self._print_lists(events)
            for fd, event in events:
                sock_info = self._sock_set[fd]
                sock = sock_info["sock"]
                if event & select.EPOLLIN:
                    _log.event("%s, fd=%d" % (EVT_READ, fd))
                    if sock_info[EVT_READ] is not None:
                        sock_info[EVT_READ](sock)
                    else:
                        _log.warning("socket %d on_read callback is None" % fd)

                if fd in self._sock_set:
                    if event & select.EPOLLOUT:
                        _log.event("%s, fd=%d" % (EVT_WRITE, fd))
                        handler = sock_info[EVT_WRITE]
                        if handler is not None:
                            self.modify_sock(sock, EVT_WRITE, None)
                            handler(sock)

                if fd in self._sock_set:
                    if event & select.EPOLLERR or event & select.EPOLLHUP:
                        _log.event("%s, fd=%d" % (EVT_ERROR, fd))
                        if sock_info[EVT_ERROR] is not None:
                            sock_info[EVT_ERROR](sock)
                        else:
                            # 如果没有安装错误处理程序，那么由我们清除sock并且关闭它
                            self.del_sock(sock)
                            sock.close()
