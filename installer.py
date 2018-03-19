#!/usr/bin/env python

import os


def install(alsi):
    alsi.milestone('Starting Oletools install..')
    ole_tgz = 'oletools-0.45.tar.gz'
    local_path = os.path.join('/tmp', ole_tgz)
    remote_path = 'oletools/' + ole_tgz
    alsi.fetch_package(remote_path, local_path)
    alsi.runcmd('sudo -H pip install ' + local_path, piped_stdio=False)
    # Add yara rules to deployment
    yara_import_script = os.path.join(alsi.alroot, "pkg", "assemblyline", "al", "run", "yara_importer.py")
    rule_file = os.path.join(alsi.alroot, "pkg", "al_services", "alsvc_oletools",
                             "yara_rules", "oletools_sigs.yar")
    alsi.runcmd("{script} -f -s {rules}".format(script=yara_import_script, rules=rule_file))
    alsi.milestone('Completed Oletools install.')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
