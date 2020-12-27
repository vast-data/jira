import sys
import string
from traceback import format_exception

from easypy.units import DataSize, KiB, MiB
from easypy.humanize import compact


MAX_COMMENT_LENGTH = MiB // 2
MAX_TEXT_LENGTH = KiB * 30


class SafeTextTranslator():
    PRINTABLES = set(ord(c) for c in string.printable)

    def __getitem__(self, c):
        if c > 256 or c in self.PRINTABLES:
            return c


def clean(text, _T=SafeTextTranslator()):
    return text.translate(_T)


def trim(text, max_size, clean_text=True):
    if not text:
        return text
    if clean_text:
        text = clean(text)
    size = DataSize(len(text))
    if size >= max_size:
        chunk = max_size // 2 - 500
        text = f"{text[:chunk]}....\n...\n...(tl;dr...)\n...\n...\n....{text[-chunk:]}\n" \
               f"Text was chomped because it was too long ({size})"
    return text


def squeeze_summary(string):
    # TODO - squeeze summary in a smarter way (i.e remove numbers)
    string = string.splitlines()[0]  # take only first line of exception
    return compact(string, 255, suffix_length=10)


def noformatted(text, max_size=MAX_TEXT_LENGTH, clean_text=True):
    text = trim(text, max_size, clean_text=clean_text) if text else ""
    return f"{{noformat}}\n{text}\n{{noformat}}"


def noformatted_exc(exc_info=None):
    if not exc_info:
        exc_info = sys.exc_info()
    if not any(exc_info):
        return "(No exception)"
    return noformatted("".join(format_exception(*exc_info)))
