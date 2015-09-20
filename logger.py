from __future__ import print_function
import sys
import time
from functools import partial


class Logger:

    _categories = ["INFO", "DEBUG", "ERROR", "WARNING", "EVENT"]

    def __init__(self, module, log_file=sys.stdout):
        self._module = module
        if type(log_file) is str:
            self._file = open(log_file, "w")
        elif type(log_file) is file:
            self._file = log_file
        else:
            raise ValueError("unsupported log_file")

        for category in self._categories:
            self.__dict__[category.lower()] = partial(self._log, category)

    def _log(self, category, msg, new_line=True):
        end = None
        if not new_line:
            end = ""
        print("[%s][%s][%s] %s" % (self.time(), self._module, category, msg), end=end, file=self._file)

    def blank_line(self):
        print("", file=self._file)

    def flush(self):
        self._file.flush()

    @staticmethod
    def _format_time(fmt):
        return time.strftime(fmt, time.localtime())

    @staticmethod
    def datetime():
        return Logger._format_time("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def data():
        return Logger._format_time("%Y-%m-%d")

    @staticmethod
    def time():
        return Logger._format_time("%H:%M:%S")


if __name__ == "__main__":
    l = Logger("test")
    l.event("test event")
    l.info("test info")

