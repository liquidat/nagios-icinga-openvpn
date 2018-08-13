from distutils.core import setup

setup(
  name         = 'nagios-icinga-openvpn',
  version      = '0.0.1',
  author       = 'Roland Wolters (liquidat)',
  author_email = 'liquidat@bayz.de',
  url          = 'https://github.com/liquidat/nagios-icinga-openvpn',
  scripts      = ['bin/check_openvpn'],
  description  = 'Nagios/Icinga check for OpenVPN availability',
  long_description=open('README.md').read(),
  license      = 'COPYING'
)
