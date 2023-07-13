#pylint: disable=E0401,C0114,C0115,C0116,C0414,W0611,W0613
# flake8: noqa
from __future__ import annotations

import io
import logging
from collections.abc import Generator
from typing import IO, Literal, overload

from _typeshed import Incomplete
from oletools.common.io_encoding import ensure_stdout_handles_unicode as ensure_stdout_handles_unicode
from oletools.ooxml import XmlParser as XmlParser
from oletools.ppt_record_parser import PptFile as PptFile
from oletools.ppt_record_parser import PptRecordExOleVbaActiveXAtom as PptRecordExOleVbaActiveXAtom
from oletools.ppt_record_parser import is_ppt as is_ppt
from oletools.thirdparty import xglob as xglob

DEFAULT_LOG_LEVEL: str
LOG_LEVELS: Incomplete

class NullHandler(logging.Handler):
    def emit(self, record) -> None: ...

def get_logger(name, level=...): ...

log: Incomplete

def enable_logging() -> None: ...

NULL_CHAR: int
xrange = range
OOXML_RELATIONSHIP_TAG: str
TAG_CUSTOMUI_2007: str
TAG_CUSTOMUI_2010: str
STRUCT_UINT32: Incomplete
STRUCT_UINT16: Incomplete
STR_MAX_LEN: int
DUMP_CHUNK_SIZE: int
RETURN_NO_DUMP: int
RETURN_DID_DUMP: int
RETURN_ERR_ARGS: int
RETURN_ERR_STREAM: int
RETURN_ERR_DUMP: int
BLACKLISTED_RELATIONSHIP_TYPES: Incomplete
MAX_FILENAME_LENGTH: int
MAX_FILENAME_ATTEMPTS: int

@overload
def read_uint32(data: bytes, index: int) -> tuple[int, int]: ...
@overload
def read_uint32(data: IO[bytes], index: None) -> tuple[int, None]: ...
@overload
def read_uint16(data: bytes, index: int) -> tuple[int, int]: ...
@overload
def read_uint16(data: IO[bytes], index: None) -> tuple[int, None]: ...
@overload
def read_length_prefixed_string(data: bytes, index: int) -> tuple[Literal[''] | bytes, int]: ...
@overload
def read_length_prefixed_string(data: IO[bytes], index: None) -> tuple[Literal[''] | bytes, None]: ...

def guess_encoding(data): ...
def read_zero_terminated_string(data, index): ...

class OleNativeStream:
    TYPE_LINKED: int
    TYPE_EMBEDDED: int
    filename: Incomplete
    src_path: Incomplete
    unknown_short: Incomplete
    unknown_long_1: Incomplete
    unknown_long_2: Incomplete
    temp_path: Incomplete
    actual_size: Incomplete
    data: Incomplete
    package: Incomplete
    is_link: Incomplete
    data_is_stream: Incomplete
    def __init__(self, bindata: Incomplete | None = ..., package: bool = ...) -> None: ...
    def parse(self, data) -> None: ...

class OleObject:
    TYPE_LINKED: int
    TYPE_EMBEDDED: int
    ole_version: int | None
    format_id: int | None
    class_name: Literal[''] | bytes | None
    topic_name: Literal[''] | bytes | None
    item_name: Literal[''] | bytes | None
    data: bytes
    data_size: int | None
    def __init__(self, bindata: bytes | None = ...) -> None: ...
    extra_data: Incomplete
    def parse(self, data: bytes) -> None: ...

def shorten_filename(fname, max_len): ...
def sanitize_filename(filename, replacement: str = ..., max_len=...): ...
def get_sane_embedded_filenames(filename, src_path, tmp_path, max_len, noname_index) -> Generator[Incomplete, None, None]: ...
def find_ole_in_ppt(filename) -> Generator[Incomplete, None, None]: ...

class FakeFile(io.RawIOBase):
    data: Incomplete
    pos: int
    size: Incomplete
    def __init__(self, data) -> None: ...
    def readable(self): ...
    def writable(self): ...
    def seekable(self): ...
    def readinto(self, target): ...
    def read(self, n_data: int = ...): ...
    def seek(self, pos, offset=...) -> None: ...
    def tell(self): ...

def find_ole(filename, data, xml_parser: Incomplete | None = ...) -> Generator[Incomplete, None, None]: ...
def find_external_relationships(xml_parser) -> Generator[Incomplete, None, None]: ...
def find_customUI(xml_parser) -> Generator[Incomplete, None, None]: ...
def process_file(filename, data, output_dir: Incomplete | None = ...): ...
def existing_file(filename): ...
def main(cmd_line_args: Incomplete | None = ...): ...
