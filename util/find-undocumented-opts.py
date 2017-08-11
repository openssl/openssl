#!/usr/bin/python3
import os
import re
import subprocess

class ManpageOptionChecker(object):
    _HELPPAGE_OPTION_RE = re.compile("^ -(?P<opt>[-0-9A-Za-z_]+)")
    _MANPAGE_OPTION_RE = re.compile("\[B<-(?P<opt>[-0-9A-Za-z_]+)")
    _IGNORED_OPTIONS = set([
        "aes128", "aes192", "aes256",
        "aria128", "aria192", "aria256",
        "camellia128", "camellia192", "camellia256",
        "des", "des3",
        "idea"
    ])

    def __init__(self, openssl_binary = "openssl"):
        self._openssl = openssl_binary

    def _get_supported_cmds(self):
        cmds = subprocess.check_output([ self._openssl, "list", "-commands" ])
        cmds = cmds.decode().replace("\n", " ").split()
        return cmds

    def _get_supported_options(self, command):
        helppage = subprocess.check_output([ self._openssl, command, "-help" ],
                stderr = subprocess.STDOUT)
        helppage = helppage.decode()
        options = set()
        for line in helppage.split("\n"):
            result = self._HELPPAGE_OPTION_RE.match(line)
            if result is None:
                continue
            result = result.groupdict()
            options.add(result["opt"])
        return options

    def _get_documented_options(self, command):
        manpage_filename = "doc/man1/%s.pod" % (command)
        if not os.path.isfile(manpage_filename):
            return None
        with open(manpage_filename, "r") as f:
            manpage = f.read()
        options = set()
        for match in self._MANPAGE_OPTION_RE.finditer(manpage):
            opt = match.groupdict()["opt"]
            options.add(opt)
        return options

    def _check_command_manpage(self, command):
        documented_opts = self._get_documented_options(command)
        if documented_opts is None:
            print("%s: Manpage for command entirely missing" % (command))
            return
        supported_opts = self._get_supported_options(command)

        documented_opts -= self._IGNORED_OPTIONS
        supported_opts -= self._IGNORED_OPTIONS

        undocumented_options = supported_opts - documented_opts
        unsupported_options = documented_opts - supported_opts
        if len(undocumented_options) > 0:
            print("%s: Undocumented options are:\n\t* %s" %
                    (command, "\n\t* ".join(sorted(undocumented_options))))
        if len(unsupported_options) > 0:
            print("%s: Unsupported options are:\n\t* %s" %
                    (command, "\n\t* ".join(sorted(unsupported_options))))

    def run(self):
        for command in sorted(self._get_supported_cmds()):
            self._check_command_manpage(command)

moc = ManpageOptionChecker()
moc.run()

