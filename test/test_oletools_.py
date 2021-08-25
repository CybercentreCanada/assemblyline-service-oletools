
from oletools.olevba import __version__ as olevba_version
from oletools.oleid import __version__ as oleid_version
from oletools.rtfobj import __version__ as rtfobj_version
from oletools.msodde import __version__ as msodde_version

from oletools_.oletools_ import Oletools

def test_get_oletools_version():
    ole = Oletools()
    ole.start()
    assert ole.get_tool_version() == f"olevba v{olevba_version}, oleid v{oleid_version}, " \
                                     f"rtfobj v{rtfobj_version}, msodde v{msodde_version}"
