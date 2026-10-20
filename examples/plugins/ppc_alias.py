"""Example architecture plugin: expose an existing SLEIGH CPU under another name (`--arch ppc32be`)."""
from rdis import plugins, sleigh

RDIS_API = 1

plugins.register_arch("ppc32be", lambda: sleigh.make("ppc"))
