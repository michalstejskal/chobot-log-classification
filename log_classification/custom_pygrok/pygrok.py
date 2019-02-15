__author__ = 'drathier'

import re


# import custom_pygrok patterns

class Pygrok():
    def __init__(self, *pattern):
        self.pattern = self._pattern_parser(r"(?:.|\n)*".join(pattern))
        print(pattern)
        print(r"(?:.|\n)*".join(pattern))
        print(self.pattern)

    def _pattern_parser(self, pattern):
        matches = re.sub(r'%{(?:(\w+)\.)?(\w+)(?::(\w+))?}', lambda m: self._parser(m), pattern)
        return matches

    def _parser(self, matches):
        pattern_group, pattern_key, result_key = matches.groups()

        if pattern_group == "cisco":
            pattern_dict = cisco
        elif pattern_group == "whitespace":
            pattern_dict = whitespace
        else:
            pattern_dict = base

        pattern = self._pattern_parser(pattern_dict[pattern_key])

        if result_key:
            return "(?P<" + result_key + ">" + pattern + ")"
        else:
            return "(?:" + pattern + ")"

    def _strip_none_values(self, inputdict):
        retdict = {}
        for elem in inputdict:
            if inputdict[elem] is not None:
                retdict[elem] = inputdict[elem]
        return retdict

    def search(self, input):
        # print "pattern", self.pattern
        ret = re.search(self.pattern, input)
        if ret:
            return self._strip_none_values(ret.groupdict())
        else:
            return {}

    def multisearch(self, inputList):
        ret = []
        for row in inputList:
            ret.append(self.search(row))
        return ret


whitespace = {
    "ANY": r"(\n|\t|\r| )+"
}

base = {
    'JAVACLASS' : r'''(?:[a-zA-Z$_][a-zA-Z$_0-9]*\.)*[a-zA-Z$_][a-zA-Z$_0-9]*''',
    'USERNAME': r'''[a-zA-Z0-9._-]+''',
    'USER': r'''%{USERNAME}''',
    'EMAILLOCALPART': r'''[a-zA-Z][a-zA-Z0-9_.+-=:]+''',
    'EMAILADDRESS': r'''%{EMAILLOCALPART}@%{HOSTNAME}''',
    'HTTPDUSER': r'''%{EMAILADDRESS}|%{USER}''',
    'INT': r'''(?:[+-]?(?:[0-9]+))''',
    'BASE10NUM': r'''(?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))''',
    'NUMBER': r'''(?:%{BASE10NUM})''',
    'BASE16NUM': r'''(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))''',
    'BASE16FLOAT': r'''\b(?<![0-9A-Fa-f.])(?:[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+)))\b''',
    'POSINT': r'''\b(?:[1-9][0-9]*)\b''',
    'NONNEGINT': r'''\b(?:[0-9]+)\b''',
    'WORD': r'''\b\w+\b''',
    'NOTSPACE': r'''\S+''',
    'SPACE': r'''\s*''',
    'DATA': r'''.*?''',
    'GREEDYDATA': r'''.*''',
    'QUOTEDSTRING': r'''(?>(?<!\\)(?>"(?>\\.|[^\\"]+)+"|""|(?>'(?>\\.|[^\\']+)+')|''|(?>`(?>\\.|[^\\`]+)+`)|``))''',
    'UUID': r'''[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}''',
    'MAC': r'''(?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})''',
    'CISCOMAC': r'''(?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})''',
    'WINDOWSMAC': r'''(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})''',
    'COMMONMAC': r'''(?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})''',
    'IPV6': r'''((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?''',

    'IPV4': r'''(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])''',
    'IP': r'''(?:%{IPV6}|%{IPV4})''',
    'HOSTNAME': r'''\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)''',
    'IPORHOST': r'''(?:%{IP}|%{HOSTNAME})''',
    'HOSTPORT': r'''%{IPORHOST}:%{POSINT}''',
    'PATH': r'''(?:%{UNIXPATH}|%{WINPATH})''',
    'UNIXPATH': r'''(/([\w_%!$@:.,~-]+|\\.)*)+''',
    'TTY': r'''(?:/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+))''',
    'WINPATH': r'''(?>[A-Za-z]+:|\\)(?:\\[^\\?*]*)+''',
    'URIPROTO': r'''[A-Za-z]+(\+[A-Za-z+]+)?''',
    'URIHOST': r'''%{IPORHOST}(?::%{POSINT:port})?''',
    'URIPATH': r'''(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+''',
    'URIPARAM': r'''\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*''',
    'URIPATHPARAM': r'''%{URIPATH}(?:%{URIPARAM})?''',
    'URI': r'''%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?''',
    'MONTH': r'''\b(?:Jan(?:uary|uar)?|Feb(?:ruary|ruar)?|M(?:a|ä)?r(?:ch|z)?|Apr(?:il)?|Ma(?:y|i)?|Jun(?:e|i)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|O(?:c|k)?t(?:ober)?|Nov(?:ember)?|De(?:c|z)(?:ember)?)\b''',
    'MONTHNUM': r'''(?:0?[1-9]|1[0-2])''',
    'MONTHNUM2': r'''(?:0[1-9]|1[0-2])''',
    'MONTHDAY': r'''(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])''',
    'DAY': r'''(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)''',
    'YEAR': r'''(?>\d\d){1,2}''',
    'HOUR': r'''(?:2[0123]|[01]?[0-9])''',
    'MINUTE': r'''(?:[0-5][0-9])''',
    'SECOND': r'''(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)''',
    'TIME': r'''(?!<[0-9])%{HOUR}:%{MINUTE}(?::%{SECOND})(?![0-9])''',
    'DATE_US': r'''%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}''',
    'DATE_EU': r'''%{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}''',
    'ISO8601_TIMEZONE': r'''(?:Z|[+-]%{HOUR}(?::?%{MINUTE}))''',
    'ISO8601_SECOND': r'''(?:%{SECOND}|60)''',
    'TIMESTAMP_ISO8601': r'''%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?''',
    'DATE': r'''%{DATE_US}|%{DATE_EU}''',
    'DATESTAMP': r'''%{DATE}[- ]%{TIME}''',
    'TZ': r'''(?:[PMCE][SD]T|UTC)''',
    'DATESTAMP_RFC822': r'''%{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}''',
    'DATESTAMP_RFC2822': r'''%{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}''',
    'DATESTAMP_OTHER': r'''%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}''',
    'DATESTAMP_EVENTLOG': r'''%{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}''',
    'HTTPDERROR_DATE': r'''%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}''',
    'SYSLOGTIMESTAMP': r'''%{MONTH} +%{MONTHDAY} %{TIME}''',
    'PROG': r'''[\x21-\x5a\x5c\x5e-\x7e]+''',
    'SYSLOGPROG': r'''%{PROG:program}(?:\[%{POSINT:pid}\])?''',
    'SYSLOGHOST': r'''%{IPORHOST}''',
    'SYSLOGFACILITY': r'''<%{NONNEGINT:facility}.%{NONNEGINT:priority}>''',
    'HTTPDATE': r'''%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}''',
    'QS': r'''%{QUOTEDSTRING}''',
    'SYSLOGBASE': r'''%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:''',
    'COMMONAPACHELOG': r'''%{IPORHOST:clientip} %{HTTPDUSER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)''',
    'COMBINEDAPACHELOG': r'''%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}''',
    'HTTPD20_ERRORLOG': r'''\[%{HTTPDERROR_DATE:timestamp}\] \[%{LOGLEVEL:loglevel}\] (?:\[client %{IPORHOST:clientip}\] ){0,1}%{GREEDYDATA:errormsg}''',

    'HTTPD24_ERRORLOG': r'''\[%{HTTPDERROR_DATE:timestamp}\] \[%{WORD:module}:%{LOGLEVEL:loglevel}\] \[pid %{POSINT:pid}:tid %{NUMBER:tid}\]( \(%{POSINT:proxy_errorcode}\)%{DATA:proxy_errormessage}:)?( \[client %{IPORHOST:client}:%{POSINT:clientport}\])? %{DATA:errorcode}: %{GREEDYDATA:message}''',
    'HTTPD_ERRORLOG': r'''%{HTTPD20_ERRORLOG}|%{HTTPD24_ERRORLOG}''',
    'LOGLEVEL': r'''([Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?)''',
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
