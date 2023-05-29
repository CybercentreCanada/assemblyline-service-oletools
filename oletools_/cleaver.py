
import json

import hachoir.core.config as hachoir_config
from assemblyline.common.str_utils import safe_str, translate_str
from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection
from hachoir.core.error import getBacktrace
from hachoir.core.log import log as hachoir_log
from hachoir.field import Int8
from hachoir.field.basic_field_set import ParserError
from hachoir.field.field import MissingField
from hachoir.field.seekable_field_set import RootSeekableFieldSet
from hachoir.parser.guess import createParser, guessParser
from hachoir.parser.misc.msoffice import RootEntry
from hachoir.parser.misc.msoffice_summary import (
    CompObj,
    DocSummary,
    PropertyContent,
    PropertyIndex,
    Summary,
    SummarySection,
)
from hachoir.parser.misc.ole2 import HEADER_SIZE
from oletools_.codepages import CODEPAGE_MAP


def build_key(input_string):
    list_string = list(input_string)
    new_list = []
    previous_upper = False
    for idx, i in enumerate(list_string):
        if i.isupper():
            if idx != 0 and not previous_upper:
                new_list.append("_")

            previous_upper = True
            new_list.append(i.lower())
        elif i in [".", "_"]:
            previous_upper = True
            new_list.append(i)
        else:
            previous_upper = False
            new_list.append(i)

    return "".join(new_list)


class DummyObject(Int8):
    # noinspection PyPep8Naming,PyMethodMayBeStatic
    def createValue(self):
        return 66


class OLEDeepParser(object):

    def __init__(self, file_path, parent_res, logger, task):
        self.file_path = file_path
        self.parent_res = parent_res
        self.additional_parsing_fields = {}
        self.ole2parser = None
        self.office_root_entry_parser = None
        self.children = {}
        self.parent = {}
        self.property_dict = {}
        self.current_section = None
        self.current_codepage = None
        hachoir_log.use_buffer = True
        self.invalid_streams = []
        self.invalid_properties_count = 0
        self.log = logger
        self.task = task

    def get_parser(self, field_type):
        # from ol2 parser
        if field_type == 'Property':
            return self.parse_property
        elif field_type == 'CustomFragment':
            return self.parse_custom_fragment

        # from msoffice_summary parser
        elif field_type in ['SummaryFieldSet', 'Summary', 'DocSummary']:
            return self.parse_summary_field_set
        elif field_type == 'SummarySection':
            return self.parse_summary_section
        elif field_type == 'PropertyContent':
            return self.parse_property_content
        elif field_type == 'CompObj':
            return self.parse_comp_obj

        # No parser found
        else:
            self.log.warning(f"Could not find parser for type: {field_type}")
            return None

    PARSING_MODE_CACHE = 0
    PARSING_MODE_DISPLAY = 1

    GUID_DESC = {
        "GUID v0 (0): 00020803-0000-0000-C000-000000000046": "Microsoft Graph Chart",
        "GUID v0 (0): 00020900-0000-0000-C000-000000000046": "Microsoft Word95",
        "GUID v0 (0): 00020901-0000-0000-C000-000000000046": "Microsoft Word 6.0 - 7.0 Picture",
        "GUID v0 (0): 00020906-0000-0000-C000-000000000046": "Microsoft Word97",
        "GUID v0 (0): 00020907-0000-0000-C000-000000000046": "Microsoft Word",

        "GUID v0 (0): 00020C01-0000-0000-C000-000000000046": "Excel",
        "GUID v0 (0): 00020821-0000-0000-C000-000000000046": "Excel",
        "GUID v0 (0): 00020820-0000-0000-C000-000000000046": "Excel97",
        "GUID v0 (0): 00020810-0000-0000-C000-000000000046": "Excel95",

        "GUID v0 (0): 00021a14-0000-0000-C000-000000000046": "Visio",
        "GUID v0 (0): 0002CE02-0000-0000-C000-000000000046": "Microsoft Equation 3.0",

        "GUID v0 (0): 0003000A-0000-0000-C000-000000000046": "Paintbrush Picture",

        "GUID v0 (0): 0003000C-0000-0000-C000-000000000046": "Package",

        "GUID v0 (0): 000C1082-0000-0000-C000-000000000046": "Transform (MST)",
        "GUID v0 (0): 000C1084-0000-0000-C000-000000000046": "Installer Package (MSI)",

        "GUID v0 (0): 00020D0B-0000-0000-C000-000000000046": "MailMessage",

        "GUID v1 (Timestamp & MAC-48): 29130400-2EED-1069-BF5D-00DD011186B7": "Lotus WordPro",
        "GUID v1 (Timestamp & MAC-48): 46E31370-3F7A-11CE-BED6-00AA00611080": "Microsoft Forms 2.0 MultiPage",
        "GUID v1 (Timestamp & MAC-48): 5512D110-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML SUBMIT",
        "GUID v1 (Timestamp & MAC-48): 5512D11A-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML TEXT",
        "GUID v1 (Timestamp & MAC-48): 5512D11C-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML Hidden",
        "GUID v1 (Timestamp & MAC-48): 64818D10-4F9B-11CF-86EA-00AA00B929E8": "Microsoft PowerPoint Presentation",
        "GUID v1 (Timestamp & MAC-48): 64818D11-4F9B-11CF-86EA-00AA00B929E8": "Microsoft PowerPoint Presentation",
        "GUID v1 (Timestamp & MAC-48): 11943940-36DE-11CF-953E-00C0A84029E9": "Microsoft Photo Editor 3.0 Photo",
        "GUID v1 (Timestamp & MAC-48): D27CDB6E-AE6D-11CF-96B8-444553540000": "Shockwave Flash",
        "GUID v1 (Timestamp & MAC-48): 8BD21D40-EC42-11CE-9E0D-00AA006002F3": "Active X Checkbox",
        "GUID v1 (Timestamp & MAC-48): 8BD21D50-EC42-11CE-9E0D-00AA006002F3": "Active X Radio Button",
        "GUID v1 (Timestamp & MAC-48): B801CA65-A1FC-11D0-85AD-444553540000": "Adobe Acrobat Document",
        "GUID v1 (Timestamp & MAC-48): A25250C4-50C1-11D3-8EA3-0090271BECDD": "WordPerfect Office",
        "GUID v1 (Timestamp & MAC-48): C62A69F0-16DC-11CE-9E98-00AA00574A4F": "Microsoft Forms 2.0 Form"
    }

    def parse_summary_field_set(self, field, res, mode, parent_res):
        if mode == self.PARSING_MODE_CACHE:
            # when we get here, we assume it's because we are using the short block,
            # otherwise, this is set somewhere else

            # we first get the offset from the short block but then we
            # need to map it back to the file, which is from root[X].
            # offset = field['start'].value * self.ole2parser.ss_size
            # noinspection PyProtectedMember
            offset = field.absolute_address
            keep_looping = True
            root_index = 0
            address = 0
            while keep_looping:
                current_root = self.ole2parser[f"root[{root_index}]"]

                if offset == 0 or current_root.size > offset:
                    address = current_root.address + offset
                    keep_looping = False
                else:
                    offset -= current_root.size
                    root_index += 1
            self.additional_parsing_fields[address] = field

        elif mode == self.PARSING_MODE_DISPLAY:
            self.parse_field_name('section', field, True, res, mode, parent_res, field['section_count'].value)

    def parse_summary_section(self, field, res, mode, parent_res):
        self.current_codepage = None
        section_index = field.name[field.name.find('[') + 1:field.name.find(']')]
        section_index_field = field[f"../section_index[{section_index}]/name"]

        if section_index_field.value == u"\xe0\x85\x9f\xf2\xf9\x4f\x68\x10\xab\x91\x08\x00\x2b\x27\xb3\xd9":
            self.current_section = PropertyIndex.COMPONENT_PROPERTY
        elif section_index_field.value == u"\x02\xd5\xcd\xd5\x9c\x2e\x1b\x10\x93\x97\x08\x00\x2b\x2c\xf9\xae":
            self.current_section = PropertyIndex.DOCUMENT_PROPERTY
        elif section_index_field.value == u"\x05\xd5\xcd\xd5\x9c\x2e\x1b\x10\x93\x97\x08\x00\x2b\x2c\xf9\xae":
            # FMTID_UserDefinedProperties
            self.current_section = None
        else:
            self.current_section = None
            unknown_guid = ""
            for c in section_index_field.value:
                unknown_guid += f"{hex(ord(c))} "

            self.log.warning(f"Unknown_guid: {unknown_guid} {self.task.sid}/{self.task.sha256}")

        self.parse_field_name('property', field, True, res, mode, parent_res, field['property_count'].value)

    # noinspection PyUnusedLocal
    def parse_property_content(self, field, res, mode, parent_res):
        property_index = field.name[field.name.find('[') + 1:field.name.find(']')]
        property_index_field = field[f"../property_index[{property_index}]/id"]

        if self.current_section is not None and property_index_field.value in self.current_section:
            description = self.current_section[property_index_field.value]
        else:
            description = f"unknown_property_type: {property_index_field.value}"

        if description == "CodePage":
            self.current_codepage = field.display

            if field.display in CODEPAGE_MAP:
                code_page_desc = CODEPAGE_MAP[field.display]
            else:
                code_page_desc = "unknown"
                self.log.info(f"Unknown code page: {field.display} {self.task.sid}/{self.task.sha256}")

            res.body[build_key(description)] = f"{field.display} ({code_page_desc})"
            res.add_tag('file.ole.summary.codepage', field.display)

        elif (description in ("LastPrinted", "CreateTime", "LastSavedTime") and len(field.display) > 0 and
                field.display != "1601-01-01 00:00:00" and field.display != 'None' and field.display != 'False'):
            res.body[build_key(description)] = field.display

            if description == 'LastPrinted':
                res.add_tag('file.ole.summary.last_printed', field.display)
            elif description == 'CreateTime':
                res.add_tag('file.ole.summary.create_time', field.display)
            elif description == 'LastSavedTime':
                res.add_tag('file.ole.summary.last_saved_time', field.display)
        else:
            value = field.display
            if self.current_codepage is not None:
                try:
                    value = value.encode(self.current_codepage)
                except LookupError:
                    value = field.display
                except OverflowError:
                    value = field.display

            # if the value has an end of string, remove it.
            value = value.strip(b'\x00')

            res.body[build_key(description)] = safe_str(value)

            if len(value) > 0 and field.display.count('\0') != len(field.display):
                if description == 'Title':
                    res.add_tag('file.ole.summary.title', value)
                elif description == 'Subject':
                    res.add_tag('file.ole.summary.subject', value)
                elif description == 'Author':
                    res.add_tag('file.ole.summary.author', value)
                elif description == 'Comments':
                    res.add_tag('file.ole.summary.comment', value)
                elif description == 'LastSavedBy':
                    res.add_tag('file.ole.summary.last_saved_by', value)
                elif description == 'Manager':
                    res.add_tag('file.ole.summary.manager', value)
                elif description == 'Company':
                    res.add_tag('file.ole.summary.company', value)
        return True

    def parse_comp_obj(self, field, res):
        try:
            self.cache_fields(field, res)
            user_type = field["user_type"]
            user_type_value = user_type.value.encode(user_type.charset)
            char_enc_guessed = translate_str(user_type_value)

            res.body['user_type'] = char_enc_guessed['converted']
            res.body['user_type_encoding'] = char_enc_guessed['encoding']
        except MissingField:
            pass

        try:
            res.body['prog_id'] = field['prog_id'].value
        except MissingField:
            pass

    def dump_property(self, field, path, index, res, parent_res, is_orphan):
        if field['name'].value != '':
            name = field['name'].display[1:-1]
            p_type = field['type'].value

            if path[-1:] == '\\':
                abs_name = f"{path}{name}"
            else:
                abs_name = f"{path}\\{name}"

            prop_res = ResultSection(f"Property: {abs_name}", body_format=BODY_FORMAT.KEY_VALUE, body={})

            # if type is not: 1- storage, 2- stream an not 5- root, that is weird.
            if p_type != 1 and p_type != 2 and p_type != 5:
                self.invalid_properties_count += 1

            # for properties not storage (which should be seen like a folder)
            if p_type != 1:
                size = field['size'].value
            else:
                size = 0

            address = 0
            if size > 0:
                if field['size'].value < self.ole2parser['header/threshold'].value and index != '0':
                    # we first get the offset from the short block but then we need
                    # to map it back to the file, which is from root[X].
                    offset = field['start'].value * self.ole2parser.ss_size
                    keep_looping = True
                    root_index = 0
                    while keep_looping:
                        try:
                            current_root = self.ole2parser[f"root[{root_index}]"]

                            if offset == 0 or current_root.size > offset:
                                address = current_root.address + offset
                                keep_looping = False
                            else:
                                offset -= current_root.size
                                root_index += 1

                        except MissingField:
                            keep_looping = False
                            address = None
                            if not is_orphan:
                                self.invalid_streams.append(field['name'].display)
                else:
                    address = HEADER_SIZE + field['start'].value * self.ole2parser.sector_size
            else:
                address = 0

            if address >= 0:
                prop_res.body['property_meta'] = \
                    f"offset: {hex(address // 8)} size: {hex(size)} / {field['type'].display} / " \
                    f"{field['decorator'].display} / id={index} left={field['left'].display} " \
                    f"right={field['right'].display} child={field['child'].display}"
            else:
                prop_res.body['property_meta'] = \
                    f"offset: could not map.. size: {hex(size)} / {field['type'].display} / " \
                    f"{field['decorator'].display} / id={index} left={field['left'].display} " \
                    f"right={field['right'].display} child={field['child'].display}"

            # for root or storage
            if p_type == 5 or p_type == 1:
                if field['clsid'].display != "Null GUID: 00000000-0000-0000-0000-000000000000":
                    clsid_desc = self.GUID_DESC.get(field['clsid'].display, "unknown clsid")
                    prop_res.body["clsid"] = f"{field['clsid'].display} ({clsid_desc})"
                    prop_res.add_tag('file.ole.clsid', field['clsid'].display)
                if field['creation'].display != "1601-01-01 00:00:00":
                    prop_res.body["creation_date"] = field['creation'].display
                    prop_res.add_tag('file.date.creation', field['creation'].display)
                if field['lastmod'].display != "1601-01-01 00:00:00":
                    prop_res.body["last_modified_date"] = field['lastmod'].display
                    prop_res.add_tag('file.date.last_modified', field['lastmod'].display)

            # fixes up a bug:
            if name == '\\1CompObj':
                if p_type != 2:
                    res_error = ResultSection(f"\\1CompObj type is '{p_type}' and it should be 2 (stream) "
                                              f"... really suspicious.")
                    res_error.set_heuristic(41)
                    prop_res.add_subsection(res_error)
                    size = field['size'].value

                # Apparently, we can get to this point and have office_root_entry_parser set to None.
                # Not sure what we should do about that but trying to use that member variable seems
                # like a bad idea...
                if self.office_root_entry_parser is not None:
                    temp_field = None
                    for f in self.office_root_entry_parser.createFields():
                        if f.name.startswith('compobj'):
                            temp_field = f

                    # cache all the sub-fields....
                    for _ in temp_field:
                        pass

                    self.parse_field(temp_field, prop_res, self.PARSING_MODE_DISPLAY, parent_res)

            if size > 0 and index != '0':
                field_with_other_parser = self.additional_parsing_fields.get(address, None)

                if field_with_other_parser:
                    # noinspection PyTypeChecker
                    self.parse_field(field_with_other_parser, prop_res, self.PARSING_MODE_DISPLAY, parent_res)

            if len(prop_res.body) > 1:
                prop_res.set_body(json.dumps(prop_res.body))
                res.add_subsection(prop_res)

    def dump_siblings(self, index, path, res, parent_res, is_orphan):
        if (index != 'unused' and index in self.property_dict and
                self.property_dict[index][1] is False):
            field = self.property_dict[index][0]

            if field['type'].display != 'storage':
                self.property_dict[index][1] = True

            self.dump_siblings(field['left'].display, path, res, parent_res, is_orphan)
            if field['type'].display != 'storage':
                self.dump_property(field, path, index, res, parent_res, is_orphan)
            self.dump_siblings(field['right'].display, path, res, parent_res, is_orphan)

    def dump_dir(self, dir_index, path, parent_res, is_orphan):
        # 1. make sure the directory wasn't dumped already
        if dir_index in self.property_dict and self.property_dict[dir_index][1] is False:
            self.property_dict[dir_index][1] = True

            field = self.property_dict[dir_index][0]
            field_name = field['name'].display[1:-1]
            field_full_name = path + field_name

            # 2. create a res with it's name
            res = ResultSection(f"OLE2 STORAGE: {field_full_name}")

            # 3. Dump the dir property
            self.dump_property(self.property_dict[dir_index][0], path, dir_index, res, parent_res, is_orphan)

            # 3. navigate the red-black tree
            self.dump_siblings(field['child'].display, field_full_name, res, parent_res, is_orphan)

            if len(res.subsections) > 0:
                parent_res.add_subsection(res)

            # call recursively our children when there is a children
            if dir_index in self.children:
                for sub_dir in self.children[dir_index][1]:
                    self.dump_dir(sub_dir, field_full_name + '\\', parent_res, is_orphan)

    def dump_properties(self, parent_res):
        # 1. start with id 0 and naviguate the tree from there.
        self.dump_dir('0', '\\', parent_res, False)

        # 2. any missing properties, look for dir first?
        while len(self.parent) > 0:
            cur_dir = list(self.parent.items())[0][0]
            if self.property_dict[cur_dir][1]:
                del self.parent[cur_dir]
            else:
                while cur_dir in self.parent and self.property_dict[self.parent[cur_dir]][1] is False:
                    cur_dir = self.parent[cur_dir]
                self.dump_dir(cur_dir, '\\-ORPHAN-\\', parent_res, True)

        for (p_id, field_struct) in self.property_dict.items():
            if field_struct[1] is False and field_struct[0]['type'].display == 'storage':
                self.dump_dir(p_id, '\\-ORPHAN-\\', parent_res, True)

        if len(self.invalid_streams) > 0:
            res_error = ResultSection("Trying to access stream content from the short block, but root[0] doesn't "
                                      "even exist.  This file is either corrupted, patched or exploiting a "
                                      "vulnerability.", parent=parent_res)
            res_error.add_line(f"Unable to access the following stream(s): {'', ''.join(self.invalid_streams)}")
            res_error.set_heuristic(40)

        # 3. any missing properties, with no parent?
        orphans = {}
        for (p_id, field_struct) in self.property_dict.items():
            if field_struct[1] is False and field_struct[0]['name'].value != '':
                orphans[p_id] = field_struct

        if len(orphans) > 0:
            res = ResultSection("OLE2 STORAGE: \\-ORPHAN-")
            for (p_id, field_struct) in orphans.items():
                self.dump_property(field_struct[0], '\\-ORPHAN-', p_id, res, parent_res, True)

            if len(res.subsections) > 0:
                parent_res.add_subsection(res)

    def find_parent(self, parent_index, children_index, recurse_count=0):
        if children_index != 'unused':
            if recurse_count > 10:
                return
            try:
                children_field = self.ole2parser[f"property[{children_index}]"]
            except MissingField:
                return

            if children_field['type'].display == 'storage':
                self.children[parent_index][1].append(children_index)
                if children_field not in self.parent:
                    self.parent[children_index] = parent_index

            recurse_count += 1
            self.find_parent(parent_index, children_field['left'].display, recurse_count)
            self.find_parent(parent_index, children_field['right'].display, recurse_count)

    # noinspection PyUnusedLocal
    def parse_property(self, field, res, mode, parent_res):
        if mode == self.PARSING_MODE_CACHE:
            property_index = field.name[field.name.find('[') + 1:field.name.find(']')]
            child = field['child'].display

            if child != 'unused':
                self.children[property_index] = [child, []]
                self.find_parent(property_index, child)
            self.property_dict[property_index] = [field, False]

    # noinspection PyProtectedMember
    def parse_custom_fragment(self, field, res, mode, parent_res):
        field_address = field.absolute_address
        stream = field.getSubIStream()
        parser = guessParser(stream)

        # cache all the fields first otherwise I won't be able to access it.
        if isinstance(parser, RootSeekableFieldSet):
            self.cache_fields(parser, parent_res)

        if isinstance(parser, RootEntry):
            self.office_root_entry_parser = parser

            # 1- list all of the summary
            self.parse_field_name('summary', parser, True, res, mode, parent_res)

            # 2- list all doc_summary
            self.parse_field_name('doc_summary', parser, True, res, mode, parent_res)

        elif isinstance(parser, DocSummary):
            self.additional_parsing_fields[field_address] = parser

        elif isinstance(parser, Summary):
            self.additional_parsing_fields[field_address] = parser

        elif isinstance(parser, SummarySection):
            self.additional_parsing_fields[field_address] = parser

        elif isinstance(parser, CompObj):
            self.parse_comp_obj(CompObj(stream), res)

        else:
            self.log.warning(f"Could not parse custom fragment '{field.name}'. "
                             f"[Guessed parser: {parser.__class__.__name__}]")

    def parse_field(self, field, res, mode, parent_res):
        parser_func = self.get_parser(field.getFieldType())
        if parser_func:
            parser_func(field, res, mode, parent_res)

    # noinspection PyProtectedMember
    def parse_field_name(self, field_name, field, is_array, res, mode, parent_res, num_of_loop=0):
        index = 0
        keep_looping = True
        entry_found = False

        self.cache_fields(field, parent_res)
        current_field_name = None
        while keep_looping and field._getCurrentLength() > 0:
            try:
                while keep_looping:
                    if is_array:
                        index_str = f"[{index}]"
                        index += 1
                    else:
                        index_str = ""
                        keep_looping = False

                    if num_of_loop != 0 and index == num_of_loop:
                        keep_looping = False

                    current_field_name = f"{field_name}{index_str}"

                    sub_field = field[current_field_name]
                    entry_found = True
                    self.parse_field(sub_field, res, mode, parent_res)

            except MissingField as e:
                if num_of_loop == 0 or index >= num_of_loop:
                    keep_looping = False
                if e.key == current_field_name:
                    pass
                else:
                    raise

            except ParserError:
                if num_of_loop == 0 or index >= num_of_loop:
                    keep_looping = False

        return entry_found

    # noinspection PyProtectedMember
    def cache_fields(self, field, parent_res):
        num_of_attempt = 15
        keep_trying = True
        previous_parser_error = None
        failed_again = False

        while keep_trying:
            # noinspection PyBroadException
            try:
                if field.is_field_set and field._getCurrentLength() > 0:
                    for _ in field:
                        pass

            except MissingField as e:
                res = ResultSection(f"Hachoir lib COULD NOT get field '{e.key}' from "
                                    f"'{e.field.path}'.  This file is either corrupted, "
                                    f"patched or exploiting a vulnerability.", parent=parent_res)

                res.set_heuristic(42)
            except ParserError as e:
                if previous_parser_error is None and previous_parser_error != str(e):
                    previous_parser_error = str(e)
                    if str(e).startswith("OLE2: Unable to parse property of type "):
                        res = ResultSection(f"Hachoir lib DID NOT successfully "
                                            f"parse one of the property [{str(e)}].  This "
                                            f"file is either corrupted, patched or exploiting a vulnerability.",
                                            parent=parent_res)

                        res.set_heuristic(43)
                    elif str(e).startswith('Unable to add ') and str(e).endswith(" is too large"):
                        res = ResultSection(f"Hachoir lib determined that a field "
                                            f"is overflowing the file [{str(e)}].  This "
                                            f"file is either corrupted, patched or exploiting a vulnerability.",
                                            parent=parent_res)

                        res.set_heuristic(44)
                    elif str(e).endswith(" is too large!"):
                        res = ResultSection(f"Hachoir lib COULD NOT access a field "
                                            f"[{str(e)}].  This file is either corrupted,"
                                            f" patched or exploiting a vulnerability.", parent=parent_res)

                        res.set_heuristic(45)
                    elif str(e).startswith("Seek above field set end"):
                        res = ResultSection(f"Hachoir lib determined that a field is "
                                            f"overflowing the file [{str(e)}].  This "
                                            f"file is either corrupted, patched or exploiting a vulnerability.",
                                            parent=parent_res)

                        res.set_heuristic(44)
                    elif "FAT chain: Found a loop" in str(e):
                        if str(e).startswith('B'):
                            fat = 'BFAT'
                        else:
                            fat = 'SFAT'
                        res = ResultSection(f"Hachoir lib found a loop when navigating "
                                            f"through the {fat} [{str(e)}].  This file "
                                            f"is either corrupted, patched or exploiting a vulnerability.",
                                            parent=parent_res)

                        res.set_heuristic(46)
                    elif "FAT chain: Invalid block index" in str(e):
                        if str(e).startswith('B'):
                            fat = 'BFAT'
                        else:
                            fat = 'SFAT'
                        res = ResultSection(f"Hachoir lib found an invalid block index "
                                            f"in the {fat} [{str(e)}].  This file is "
                                            f"either corrupted, patched or exploiting a vulnerability.",
                                            parent=parent_res)

                        res.set_heuristic(47)
                    elif str(e).startswith("OLE2: Invalid endian value"):
                        res = ResultSection(f"The stream endian field is not valid "
                                            f"[{str(e)}].  This file is either "
                                            f"corrupted, patched or exploiting a vulnerability.", parent=parent_res)

                        res.set_heuristic(48)
                    else:
                        res = ResultSection(f"Hachoir lib DID NOT successfully parse the entire file ... "
                                            f"odd [{str(e)}].", parent=parent_res)

                        res.set_heuristic(49)
                        backtrace = getBacktrace(None)
                        self.log.info(f"{self.task.sid}/{self.task.sha256}\n{backtrace}")

            except Exception:
                if num_of_attempt == 15:
                    res = ResultSection("Hachoir lib DID NOT successfully parse the entire file ... odd.",
                                        parent=parent_res)
                    res.set_heuristic(49)
                    backtrace = getBacktrace(None)
                    self.log.info(f"{self.task.sid}/{self.task.sha256}\n{backtrace}")
                elif failed_again is False:
                    failed_again = True
                    ResultSection("Hachoir failed to parse the entire file after retrying.", parent=parent_res)
                    backtrace = getBacktrace(None)
                    self.log.info(f"{self.task.sid}/{self.task.sha256}\n{backtrace}")

            num_of_attempt -= 1
            keep_trying = num_of_attempt > 0

    def dump_invalid_properties(self, parent_res):
        if self.invalid_properties_count:
            res = ResultSection(f"We've found {self.invalid_properties_count} properties with IDs different than "
                                f"1 (storage), 2 (stream) and 5 (root)", parent=parent_res)
            res.set_heuristic(50)

    def parse_ole2(self, parser, parent_res):
        self.ole2parser = parser
        # 1- cache all the fields first.
        self.cache_fields(parser, parent_res)

        # 2- load up the more detailed ole2 parser and cache the results.
        self.parse_field_name('root[0]', parser, False, None, self.PARSING_MODE_CACHE, parent_res)

        # 3- cache the summary
        self.parse_field_name('summary', parser, True, None, self.PARSING_MODE_CACHE, parent_res)

        # 4- cache the doc_summary
        self.parse_field_name('doc_summary', parser, True, None, self.PARSING_MODE_CACHE, parent_res)

        # 5- cache the properties.
        self.parse_field_name('property', parser, True, None, self.PARSING_MODE_CACHE, parent_res)

        # 6- display all the properties (and all of the summary/doc_summary under the respective property)
        self.dump_properties(parent_res)

        # 7- display invalid properties
        self.dump_invalid_properties(parent_res)

    def run(self):
        hachoir_config.quiet = True
        self.additional_parsing_fields = {}
        self.ole2parser = None
        self.office_root_entry_parser = None
        self.children = {}
        self.parent = {}
        self.property_dict = {}
        self.invalid_streams = []
        self.invalid_properties_count = 0

        parser = createParser(self.file_path)
        if parser is not None:
            with parser:
                tags = parser.getParserTags()
                parser_id = tags.get('id', 'unknown')

                # Do OLE2 deep analysis if requested
                if parser_id == 'ole2':
                    ole2_res = ResultSection(f"Hachoir OLE2 Deep Analysis", parent=self.parent_res)
                    # this is just so that we don't bail on the NULL property type and we keep on going.
                    for (key, value) in PropertyContent.TYPE_INFO.items():
                        if value[1] is None:
                            PropertyContent.TYPE_INFO[key] = (value[0], DummyObject)
                    self.parse_ole2(parser, ole2_res)
