#!/usr/bin/env python

import os


def install(alsi):

    # Add yara rules to deployment
    yara_import_script = os.path.join(alsi.alroot, "pkg", "assemblyline", "al", "run", "yara_importer.py")
    rule_file = os.path.join(alsi.alroot, "pkg", "al_services", "alsvc_oletools",
                             "yara_rules", "oletools_sigs.yar")
    alsi.runcmd("{script} -f -s {rules}".format(script=yara_import_script, rules=rule_file))


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
