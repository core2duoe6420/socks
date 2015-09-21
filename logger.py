from __future__ import print_function
import sys
import time
from functools import partial


class Logger:

    _categories = {
        "INFO": True,
        "DEBUG": True,
        "ERROR": True,
        "WARNING": True,
        "EVENT": True
    }

    def __init__(self, module, log_file=sys.stdout, categories=_categories):
        self._module = module
        if type(log_file) is str:
            self._file = open(log_file, "w")
        elif type(log_file) is file or log_file is None:
            self._file = log_file
        else:
            raise ValueError("unsupported log_file")

        for category, on in categories.items():
            self.__dict__[category.lower()] = partial(self._log, category) if on else self._placeholder

    def _placeholder(self, msg, new_line=True):
        pass

    def _log(self, category, msg, new_line=True):
        if self._file is None:
            return
        end = None
        if not new_line:
            end = ""
        print("[%s][%s][%s] %s" % (self.time(), self._module, category, msg), end=end, file=self._file)

    def blank_line(self):
        if self._file is None:
            return
        print("", file=self._file)

    def flush(self):
        if self._file is None:
            return
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

