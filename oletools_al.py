# wrapper service for py-oletools by Philippe Lagadec - http://www.decalage.info
from textwrap import dedent

from assemblyline.common.charset import safe_str
from assemblyline.common.iprange import is_ip_reserved
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TAG_USAGE, TEXT_FORMAT
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

VBA_Parser = None
VBA_Scanner = None
OleID = None
Indicator = None
olefile = None
olefile2 = None
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
    AL_Oletools_001 = Heuristic("AL_Oletools_001", "Attached Document Template", "document/office/ole",
                                dedent("""\
                                       /Attached template specified in xml relationships. This can be used
                                       for malicious purposes.
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

    MAX_STRINGDUMP_CHARS = 500
    MAX_STRING_SCORE = SCORE.VHIGH
    MAX_MACRO_SECTIONS = 3
    MIN_MACRO_SECTION_SCORE = SCORE.MED

    # in addition to those from olevba.py
    ADDITIONAL_SUSPICIOUS_KEYWORDS = ('WinHttp', 'WinHttpRequest', 'WinInet', 'Lib "kernel32" Alias')

    def __init__(self, cfg=None):
        super(Oletools, self).__init__(cfg)
        self.request = None
        self.task = None
        self.ole_result = None
        self.scored_macro_uri = False
        self.ip_re = re.compile(
            r'^((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]).){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))'
        )
        self.domain_re = re.compile('^((?:(?:[a-zA-Z0-9\-]+)\.)+[a-zA-Z]{2,5})')
        self.uri_re = re.compile(r'[a-zA-Z]+:/{1,3}[^/]+/[^\s]+')

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        from oletools.olevba import VBA_Parser, VBA_Scanner
        from oletools.oleid import OleID, Indicator
        from oletools.thirdparty.olefile import olefile, olefile2
        from oletools.rtfobj import rtf_iter_objects
        global VBA_Parser, VBA_Scanner
        global OleID, Indicator, olefile, olefile2, rtf_iter_objects

    def start(self):
        self.log.debug("Service started")

    def get_tool_version(self):
        return self.SERVICE_VERSION

    def execute(self, request):
        self.task = request.task
        request.result = Result()
        self.ole_result = request.result
        self.request = request
        self.scored_macro_uri = False

        path = request.download()
        filename = os.path.basename(path)
        file_contents = request.get()

        try:
            self.check_for_macros(filename=filename, file_contents=file_contents)
            self.check_xml_strings(path)
            self.rip_mhtml(file_contents)
            self.extract_streams(path, file_contents)
        except Exception as e:
            self.log.error("We have encountered a critical error: {}".format(e))

        score_check = 0
        for section in self.ole_result.sections:
            score_check += self.calculate_nested_scores(section)

        if score_check == 0:
            request.result = Result()

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
            return False
        else:
            full_uri = m.group(0)

        proto, uri = full_uri.split('://', 1)
        if proto == 'file':
            return False

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

        return scorable

    def check_xml_strings(self, path):
        xml_string_res = ResultSection(score=SCORE.NULL,
                                       title_text="Attached Template Targets in XML")
        try:
            template_re = re.compile(r'/attachedTemplate"\s+[Tt]arget="((?!file)[^"]+)"\s+[Tt]argetMode="External"')
            uris = []
            zip_uris = []
            if zipfile.is_zipfile(path):
                z = zipfile.ZipFile(path)
                for f in z.namelist():
                    data = z.open(f).read()
                    zip_uris.extend(template_re.findall(data))
                z.close()
                for uri in zip_uris:
                    if self.parse_uri(uri):
                        uris.append(uri)

                uris = list(set(uris))
                # If there are domains or IPs, report them
                if uris:
                    xml_string_res.score = 500
                    xml_string_res.add_lines(uris)
                    xml_string_res.report_heuristics(Oletools.AL_Oletools_001)

        except Exception as e:
            self.log.debug("Failed to analyze XML: {}".format(e))

        if xml_string_res.score > 0:
            self.ole_result.add_section(xml_string_res)

    def check_for_macros(self, filename, file_contents):
        # noinspection PyBroadException
        try:
            vba_parser = VBA_Parser(filename=filename, data=file_contents)

            try:
                if vba_parser.detect_vba_macros():
                    self.ole_result.add_tag(TAG_TYPE.TECHNIQUE_MACROS,
                                            "Contains VBA Macro(s)",
                                            weight=TAG_WEIGHT.LOW,
                                            usage=TAG_USAGE.IDENTIFICATION)
                    allmacros = []
                    all_vba = ''

                    try:
                        for (subfilename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                            all_vba += vba_code + '\n'
                            if vba_code.strip() != '':
                                vba_code = vba_code.strip()
                                vba_code_sha256 = hashlib.sha256(vba_code).hexdigest()
                                macro_section = self.macro_section_builder(vba_code)
                                toplevel_score = self.calculate_nested_scores(macro_section)

                                allmacros.append(Macro(vba_code, vba_code_sha256, macro_section, toplevel_score))
                    except Exception as e:
                        self.log.debug("OleVBA VBA_Parser.extract_macros failed: {}".format(str(e)))
                        section = ResultSection(SCORE.NULL, "OleVBA : Error extracting macros")
                        self.ole_result.add_section(section)

                    filtered_macros = []
                    if len(allmacros) > 0:
                        # noinspection PyBroadException
                        try:
                            # first sort all analyzed macros by their relative score, highest first
                            allmacros.sort(key=attrgetter('macro_score'), reverse=True)

                            # then only keep, theoretically, the most interesting ones
                            filtered_macros = allmacros[0:min(len(allmacros), self.MAX_MACRO_SECTIONS)]
                        except:
                            self.log.debug("Sort and filtering of macro scores failed, "
                                           "reverting to full list of extracted macros")
                            filtered_macros = allmacros
                    else:
                        self.ole_result.add_section(ResultSection(SCORE.NULL, "No interesting macros found."))

                    for macro in filtered_macros:
                        if macro.macro_score >= self.MIN_MACRO_SECTION_SCORE:
                            self.ole_result.add_section(macro.macro_section)

                    # Create extracted file for all VBA script.
                    if len(all_vba) > 0:
                        vba_file_path = ""
                        vba_all_sha256 = hashlib.sha256(all_vba).hexdigest()
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

        analyzed_code = self.deobfuscator(vba_code)
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

                        subsection.add_line("{}: {}".format(keyword, description))
                        desc_ip = self.ip_re.match(description)
                        if self.parse_uri(description) is True:
                            scored_macro_uri = True
                        elif desc_ip:
                            ip_str = desc_ip.group(1)
                            if not is_ip_reserved(ip_str):
                                scored_macro_uri = True
                                subsection.add_tag(TAG_TYPE.NET_IP,
                                                   ip_str,
                                                   TAG_WEIGHT.HIGH,
                                                   usage=TAG_USAGE.CORRELATION)
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
            self.request.add_extracted(ole10_stream_file, "Embedded OLE Stream", stream_name)
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
        streams = []
        for dir_entry in listdir:
            streams.append('/'.join(dir_entry))
        for stream in streams:
            self.log.debug("Extracting stream: {}".format(stream))
            data = ole.openstream(stream).getvalue()
            try:

                if "Ole10Native" in stream:
                    if self.process_ole10native(stream, data, streams_section) is True:
                        continue

                elif "PowerPoint Document" in stream:
                    if self.process_powerpoint_stream(data, streams_section) is True:
                        continue

                streams_section.add_line(safe_str(stream))
                # Only write all streams with deep scan.
                stream_name = '{}.ole_stream'.format(hashlib.sha256(data).hexdigest())
                if self.request.deep_scan:
                    stream_path = os.path.join(self.working_directory, stream_name)
                    with open(stream_path, 'w') as fh:
                        fh.write(data)
                    self.request.add_extracted(stream_path, "Embedded OLE Stream.", stream)

            except Exception as e:
                self.log.error("Error adding extracted stream {}: {}".format(stream, e))
                continue

    # noinspection PyBroadException
    def extract_streams(self, file_name, file_contents):
        try:
            streams_res = ResultSection(score=SCORE.INFO,
                                        title_text="Embedded document stream(s)")
            oles = {}
            ole2s = {}
            ole_filenames = set()

            # Get the OLEs
            if zipfile.is_zipfile(file_name):
                z = zipfile.ZipFile(file_name)
                for f in z.namelist():
                    bin_data = z.open(f).read()
                    bin_fname = os.path.join(self.working_directory,
                                             "{}.tmp".format(hashlib.sha256(bin_data).hexdigest()))
                    with open(bin_fname, 'w') as bin_fh:
                        bin_fh.write(bin_data)
                    if olefile.isOleFile(bin_fname):
                        oles[f] = olefile.OleFileIO(bin_fname)
                        ole_filenames.add(f)
                    if olefile2.isOleFile(bin_fname):
                        ole2s[f] = olefile2.OleFileIO(bin_fname)
                        ole_filenames.add(f)
                z.close()
            else:
                if olefile.isOleFile(file_name):
                    oles[file_name] = olefile.OleFileIO(file_name)
                    ole_filenames.add(file_name)

                if olefile2.isOleFile(file_name):
                    ole2s[file_name] = olefile2.OleFileIO(file_name)
                    ole_filenames.add(file_name)

            for ole_filename in ole_filenames:
                try:
                    self.process_ole_stream(oles[ole_filename], streams_res)
                except Exception:
                    if ole_filename not in ole2s:
                        continue
                    try:
                        self.process_ole_stream(ole2s[ole_filename], streams_res)
                    except:
                        continue

            for _, offset, rtfobject in rtf_iter_objects(file_contents):
                rtfobject_name = hex(offset) + '.rtfobj'
                extracted_obj = os.path.join(self.working_directory, rtfobject_name)
                with open(extracted_obj, 'wb') as fh:
                    fh.write(rtfobject)
                self.request.add_extracted(extracted_obj,
                                           'Embedded RTF Object at offset %s' % hex(offset),
                                           rtfobject_name)

            if len(streams_res.body) > 0:
                self.ole_result.add_section(streams_res)
        except Exception:
            self.log.debug("Error extracting streams: {}".format(traceback.format_exc(limit=2)))
