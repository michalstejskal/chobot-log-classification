__author__ = 'drathier'

# based off of https://github.com/jordansissel/grok-cpp/blob/master/pygrok/pygrok/patterns.py

whitespace = {
	"ANY": r"(\n|\t|\r| )+"
}

base = {


	'USERNAME': r'''[a-zA-Z0-9_-]+''',
	'USER': r'''%{USERNAME}''',
	'INT': r'''(?:[+-]?(?:[0-9]+))''',
	'NUMBER': r'''(?:[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?)|(?:\.[0-9]+)))''',
	'POSITIVENUM': r'''\b[0-9]+\b''',
	'WORD': r'''\w+''',
	'NOTSPACE': r'''\S+''',
	'DATA': r'''.*?''',
	'GREEDYDATA': r'''.*''',
	'QUOTEDSTRING': r'''(?:(?<!\\)(?:"(?:\\.|[^\\"])*")|(?:'(?:\\.|[^\\'])*')|(?:`(?:\\.|[^\\`])*`))''',
	'MAC': r'''(?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})''',
	'CISCOMAC': r'''(?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})''',
	'WINDOWSMAC': r'''(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})''',
	'COMMONMAC': r'''(?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})''',
	'IP': r'''(?:%{IPv4}|%{IPv6})''',
	'IPv4': r'''(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])''',
	'IPv6': r'''(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))''',
	'HOSTNAME': r'''(?:[0-9A-z][0-9A-z-]{0,62})(?:\.(?:[0-9A-z][0-9A-z-]{0,62}))*\.?''',
	'HOST': r'''%{HOSTNAME}''',
	'IPORHOST': r'''(?:%{HOSTNAME}|%{IP})''',
	'HOSTPORT': r'''(?:%IPORHOST=~\.%:%{POSITIVENUM})''',
	'PATH': r'''(?:%{UNIXPATH}|%{WINPATH})''',
	'UNIXPATH': r'''(?<![\w\\/])(?:/(?:[\w_@:.,-]+|\\.)*)+''',
	'LINUXTTY': r'''(?:/dev/pts/%{POSITIVENUM})''',
	'BSDTTY': r'''(?:/dev/tty[pq][a-z0-9])''',
	'TTY': r'''(?:%{BSDTTY}|%LINUXTTY)''',
	'WINPATH': r'''(?:\\[^\\?*]*)+''',
	'URIPROTO': r'''[A-z]+(\+[A-z+]+)?''',
	'URIHOST': r'''%{IPORHOST}(?:%{PORT})?''',
	'URIPATH': r'''(?:/[A-z0-9$.+!*'(),~#%-]*)+''',
	'URIPARAM': r'''\?(?:[A-z0-9]+(?:=(?:[^&]*))?(?:&(?:[A-z0-9]+(?:=(?:[^&]*))?)?)*)?''',
	'URIPATHPARAM': r'''%{URIPATH}(?:%{URIPARAM})?''',
	'URI': r'''%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATH})?(?:%{URIPARAM})?''',
	'MONTH': r'''\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b''',
	'MONTHNUM': r'''\b(?:0?[0-9]|1[0-2])\b''',
	'MONTHDAY': r'''(?:(?:3[01]|[0-2]?[0-9]))''',
	'DAY': r'''(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)''',
	'YEAR': r'''%{INT}''',
	'TIME': r'''(?!<[0-9])(?:2[0123]|[01][0-9]):(?:[0-5][0-9])(?::(?:[0-5][0-9])(?:\.[0-9]+)?)?(?![0-9])''',
	'DATESTAMP': r'''%{INT}/%{INT}/%{INT}-%{INT}:%{INT}:%{INT}(\.%INT)?''',
	'SYSLOGDATE': r'''%{MONTH} +%{MONTHDAY} %{TIME}''',
	'PROG': r'''(?:[A-z][\w-]+(?:\/[\w-]+)?)''',
	'PID': r'''%{INT}''',
	'SYSLOGPROG': r'''%{PROG}(?:\[%{PID}\])?''',
	'HTTPDATE': r'''%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %INT:ZONE%''',
	'QS': r'''%{QUOTEDSTRING}''',
	'SYSLOGBASE': r'''%{SYSLOGDATE} %{HOSTNAME} %{SYSLOGPROG}:''',
	'COMBINEDAPACHELOG': r'''%{IPORHOST} %USER:IDENT% %USER:AUTH% \[%{HTTPDATE}\] "%{WORD} %{URIPATHPARAM} HTTP/%{NUMBER}" %NUMBER:RESPONSE% (?:%NUMBER:BYTES%|-) "(?:%URI:REFERRER%|-)" %QS:AGENT%''',
	'YESNO': r"(YES|NO)"
}

cisco = {
	"INTERFACE_METHOD": r"(RARP|SLARP|BOOTP|TFTP|manual|NVRAM|IPCP|DHCP|unset|other)",
	"INTERFACE_STATUS": r"(up|down|administratively down|up \(looped\))",
	"IP": r"((?P<ipv4>%{IPv4})|(?P<ipv6>%{IPv4})|unassigned)",
	"INTERFACE": r"(?P<interface_name>\w+(\d+((/|:)\d+)?)?(\.(?P<sub_interface>\d*))?)",
	"IP_INTERFACE_BRIEF_ROW": r"%{cisco.INTERFACE} *%{cisco.IP} *%{YESNO:interface_ok} *%{cisco.INTERFACE_METHOD:method} *%{cisco.INTERFACE_STATUS:status} *%{cisco.INTERFACE_STATUS:protocol_status}",
	"IP_INTERFACE_SUMMARY": r"(?P<interface_up>\*)? *%{cisco.INTERFACE} *(?P<packets_in_input_hold_queue>\d+) *(?P<packets_dropped_from_input_queue>\d+) *(?P<packets_in_output_hold_queue>\d+) *(?P<packets_dropped_from_output_queue>\d+) *(?P<bits_per_second_received>\d+) *(?P<packets_per_second_received>\d+) *(?P<bits_per_second_sent>\d+) *(?P<packets_per_second_sent>\d+) *(?P<throttle_count>\d+)",
	"IP_INTERFACE_MAC": r"(?: address is )(?P<mac>%{MAC})? +%{cisco.INTERFACE} +(?P<packets_in_input_hold_queue>\d+) +(?P<packets_dropped_from_input_queue>\d+) +(?P<packets_in_output_hold_queue>\d+) +(?P<packets_dropped_from_output_queue>\d+) +(?P<bits_per_second_received>\d+) +(?P<packets_per_second_received>\d+) +(?P<bits_per_second_sent>\d+) +(?P<packets_per_second_sent>\d+) +(?P<throttle_count>\d+)"
}
