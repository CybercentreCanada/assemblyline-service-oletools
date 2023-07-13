#pylint: disable=E0401,C0114,C0115,C0116,C0414,W0611,W0613
# flake8: noqa
from __future__ import annotations

import logging
from collections.abc import Generator
from typing import Literal

from _typeshed import Incomplete
from oletools import ftguess as ftguess
from oletools import oleobj as oleobj
from oletools.common import clsid as clsid
from oletools.thirdparty.tablestream import tablestream as tablestream
from oletools.thirdparty.xglob import xglob as xglob

class NullHandler(logging.Handler):
    def emit(self, record) -> None: ...

def get_logger(name, level=...): ...

log: Incomplete
HEX_DIGIT: bytes
SINGLE_RTF_TAG: bytes
NESTED_RTF_TAG: Incomplete
ASCII_NAME: bytes
SIGNED_INTEGER: bytes
CONTROL_WORD: Incomplete
re_control_word: Incomplete
CONTROL_SYMBOL: bytes
re_control_symbol: Incomplete
TEXT: bytes
re_text: Incomplete
IGNORED: Incomplete
PATTERN: Incomplete
re_hexblock: Incomplete
re_embedded_tags: Incomplete
re_decimal: Incomplete
re_delimiter: Incomplete
DELIMITER: bytes
DELIMITERS_ZeroOrMore: bytes
BACKSLASH_BIN: bytes
DECIMAL_GROUP: bytes
re_delims_bin_decimal: Incomplete
re_delim_hexblock: Incomplete
re_executable_extensions: Incomplete
DESTINATION_CONTROL_WORDS: Incomplete
BACKSLASH: Incomplete
BRACE_OPEN: Incomplete
BRACE_CLOSE: Incomplete
UNICODE_TYPE = str
RTF_MAGIC: bytes

def duration_str(duration): ...

class Destination:
    cword: Incomplete
    data: bytes
    start: Incomplete
    end: Incomplete
    group_level: int
    def __init__(self, cword: Incomplete | None = ...) -> None: ...

class RtfParser:
    data: Incomplete
    index: int
    size: Incomplete
    group_level: int
    destinations: Incomplete
    current_destination: Incomplete
    def __init__(self, data) -> None: ...
    def parse(self) -> None: ...
    def open_group(self) -> None: ...
    def close_group(self) -> None: ...
    def open_destination(self, destination) -> None: ...
    def close_destination(self, destination) -> None: ...
    def control_word(self, matchobject, cword, param) -> None: ...
    def control_symbol(self, matchobject) -> None: ...
    def text(self, matchobject, text) -> None: ...
    def bin(self, bindata) -> None: ...
    def end_of_file(self) -> None: ...

class RtfObject:
    start: Incomplete
    end: Incomplete
    hexdata: Incomplete
    rawdata: Incomplete
    is_ole: bool
    oledata: bytes | None
    format_id: int | None
    class_name: Literal[''] | bytes | None
    oledata_size: int | None
    is_package: bool
    olepkgdata: Incomplete
    filename: Incomplete
    src_path: Incomplete
    temp_path: Incomplete
    ftg: Incomplete
    clsid: Incomplete
    clsid_desc: Incomplete
    def __init__(self) -> None: ...

class RtfObjParser(RtfParser):
    objects: list[RtfObject]
    def __init__(self, data) -> None: ...
    def open_destination(self, destination) -> None: ...
    def close_destination(self, destination) -> None: ...
    def bin(self, bindata) -> None: ...
    def control_word(self, matchobject, cword, param) -> None: ...
    def control_symbol(self, matchobject) -> None: ...

def rtf_iter_objects(filename, min_size: int = ...) -> Generator[Incomplete, None, None]: ...
def is_rtf(arg, treat_str_as_data: bool = ...): ...
def sanitize_filename(filename, replacement: str = ..., max_length: int = ...): ...
def process_file(container, filename, data, output_dir: Incomplete | None = ..., save_object: bool = ...) -> None: ...
def main() -> None: ...
