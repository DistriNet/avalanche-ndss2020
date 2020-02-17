import csv
import datetime
import json
import os
import traceback

import dateutil.parser as dateparser

# Reminder: this only applies to already registered domains, e.g. these domains would have to be seized if they turn out
#           to be malicious.
import feature_generation.retrieve_sinkhole_data as retrieve_sinkhole_data

families = ['Andromeda', 'Bolek', 'Citadel', 'CoreBot', 'Gozi2', 'Goznym', 'Goznym Stage 1', 'KINS', 'MS-Andromeda',
            'Marcher', 'Matsnu', 'Nymaim', 'Pandabanker', 'Ranbyus', 'Rovnix', 'Smart App', 'Smoke Loader / Dofoil',
            'TeslaCrypt', 'Tiny Banker', 'Trusteer App', 'Unknown', 'UrlZone', 'Vawtrak', 'Xswkit']
# source: DGArchive https://dgarchive.caad.fkie.fraunhofer.de/site/families.html with manual corrections of family names
malware_family_validities = {'CoreBot': '2015-01-01',
                             'Gozi2': '2010-01-01', # 'Gozi (Days+Monthly+Seasonal)': '2010-01-01', cf. https://malpedia.caad.fkie.fraunhofer.de/details/win.isfb
                             'Goznym': '2016-01-01', 'Goznym Stage 1': '2016-01-01', # 'GozNym 2nd Stage': '2016-01-01',
                             'Matsnu': '2014-01-01', 'Nymaim': '2014-01-01', 'PandaBanker': '2016-08-01', 'Ranbyus': '2015-01-01', 'Rovnix': '2015-01-01',
                             'Tiny Banker': '2014-01-01', 'UrlZone': '2014-01-01', 'Vawtrak': '2016-01-01',

                             'Bobax': '2008-01-01', 'BeeBone': None, 'Blackhole': '2012-06-01', 'Bedep': '2015-01-01',
                             'Banjori': '2013-01-01', 'Bamital': '2010-11-01', 'Cryptolocker': '2013-01-01',
                             'CCleaner DGA': '2017-01-01', 'Conficker': '2008-11-01',
                             'Chinad': None, 'Chir': '2011-01-01', 'Darkshell': None, 'Dyre': '2014-01-01',
                             'DNS Changer': '2011-01-01', 'DiamondFox': '2015-01-01', 'DirCrypt': '2013-01-01',
                             'Emotet.C': '2014-10-01', 'EKforward': '2014-01-01', 'Feodo': '2012-02-01',
                             'Fobber': '2015-01-01',
                             'Gameover P2P': '2011-01-01', 'Gameover DGA': '2014-01-01',
                             'Gspy': None, 'Hesperbot': '2013-01-01', 'Infy': '2015-01-01', 'Locky': '2016-01-01',
                             'ModPack (Andromeda?)': '2016-01-01',  'Murofet': '2010-01-01',
                             'Mirai': '2016-12-01', 'MadMax DGA': '2015-01-01',  'Necurs': '2013-01-01',
                             'Omexo': None, 'Oderoor': '2013-01-01', 'Pushdo (TID version)': '2011-01-01',
                             'Pykspa 2': '2013-04-01', 'Proslikefan DGA': '2016-01-01',
                             'Pykspa': '2009-10-01', 'Pushdo': '2013-01-01', 'PadCrypt': '2016-01-01', 'QakBot': '2013-01-01',
                             'Qadars': '2016-01-01',  'Ramdo': '2013-01-01', 'Redyms': '2012-01-01',
                             'Ramnit': '2012-01-01', 'Symmi': '2014-01-01', 'SuppoBox': '2013-01-01',
                             'Sisron': '2013-01-01', 'Sphinx Zeus DGA': '2016-09-01', 'Szribi': '2007-01-01', 'Shifu': '2015-01-01',
                             'Sutra TDS': '2012-01-01', 'Simda': '2012-01-01', 'Tsifiri': None, 'Tempedreve': '2014-01-01',
                             'Tempedreve TDD': '2015-01-01', 'Torpig': '2007-01-01',
                             'Tofsee DGA': '2016-01-01', 'UD4': '2016-01-01', 'VolatileCedar': '2014-01-01',
                             'Vidro(TID)': None, 'Virut': '2011-08-01', 'WD': '2017-01-01',
                             'XxHex DGA': '2016-01-01'}

wordlist_families = {"Matsnu", "Gozi2", "SuppoBox", # https://dgarchive.caad.fkie.fraunhofer.de/site/families.html, paper Plohmann (TDD-W type)
                     "Banjori", "Rovnix", # https://arxiv.org/abs/1810.02023 (high 'smashword' score), in addition to previous sources
                     "Pizd", # https://osint.bambenekconsulting.com/feeds/pizd-domlist.txt
                     }
shadowserver_sinkholes_ns = ["ns1.kryptoslogicsinkhole.com", "ns2.kryptoslogicsinkhole.net", "ns3.kryptoslogicsinkhole.org", "ns4.kryptoslogicsinkhole.me",
"b66.microsoftinternetsafety.net", "b67.microsoftinternetsafety.net",
'ns1.markmonitor.com', 'ns2.markmonitor.com', 'ns3.markmonitor.com', 'ns4.markmonitor.com', 'ns5.markmonitor.com', 'ns6.markmonitor.com', 'ns7.markmonitor.com',
'ns1.i56a4c1dlzcdsohkwr.biz', 'ns2.i56a4c1dlzcdsohkwr.biz', 'ns3.i56a4c1dlzcdsohkwr.biz', 'ns4.i56a4c1dlzcdsohkwr.biz',
"ns1.honeybot.us", "ns2.honeybot.us",
"sc-a.sinkhole.shadowserver.org", "sc-b.sinkhole.shadowserver.org", "sc-c.sinkhole.shadowserver.org", "sc-d.sinkhole.shadowserver.org",
'ns1.csof.net', 'ns2.csof.net', 'ns3.csof.net', 'ns4.csof.net',
"ns1.arbors1nkh0le.com", "ns1.arbor-sinkhole.net", "ns2.arbor-sinkhole.net", "ns1.asertdns.com", "ns2.asertdns.com"]
shadowserver_sinkholes_a = ["82.112.184.197"]

initialized = False
auxiliary_data = {}

def initialize(formatted_snapshot_date):
    auxiliary_data[formatted_snapshot_date] = {}

    if os.path.exists("input_data/{}/disposable_email_addresses_exact.json".format(formatted_snapshot_date)):
        with open("input_data/{}/disposable_email_addresses_exact.json".format(formatted_snapshot_date)) as tempmail_exact_json:
            tempmail_exact = json.load(tempmail_exact_json)
        with open("input_data/{}/disposable_email_addresses_wildcard.json".format(formatted_snapshot_date)) as tempmail_wildcard_json:
            tempmail_wildcard = json.load(tempmail_wildcard_json)
        tempmail_data = (tempmail_exact, tempmail_wildcard)
    else:
        tempmail_data = None

    auxiliary_data[formatted_snapshot_date]["tempmail_data"] = tempmail_data

    with open("input_data/{}/sinkhole_results.csv".format(formatted_snapshot_date)) as sinkhole_csv:
        sinkhole_csvr = csv.reader(sinkhole_csv)
        auxiliary_data[formatted_snapshot_date]["sinkhole_data"] = {r[0]: True if r[1] == "True" else (False if r[1] == "False" else None) for r in sinkhole_csvr}

    with open("input_data/{}/wayback_results_domain.csv".format(formatted_snapshot_date)) as wayback_domain_csv:
        wayback_domain_csvr = csv.reader(wayback_domain_csv)
        auxiliary_data[formatted_snapshot_date]["wayback_domain_data"] = {r[0]: r[1:] for r in wayback_domain_csvr}

    with open("input_data/{}/ct_results.txt".format(formatted_snapshot_date)) as ct_csv:
        ct_csvr = csv.reader(ct_csv)
        auxiliary_data[formatted_snapshot_date]["ct_data"] = {r[0]: r[1:] for r in ct_csvr}

    if os.path.exists("input_data/{}/openintel_results.csv".format(formatted_snapshot_date)):
        with open("input_data/{}/openintel_results.csv".format(formatted_snapshot_date)) as openintel_csv:
            openintel_csvr = csv.reader(openintel_csv)
            auxiliary_data[formatted_snapshot_date]["openintel_data"] = {r[0]: r[1:] for r in openintel_csvr}
    else:
        auxiliary_data[formatted_snapshot_date]["openintel_data"] = {}


openintel_cap = 333  # nb days between 1 Jan and 29 Nov (inclusive)


class FeatureSet:
    @classmethod
    def get_feature_names(cls):
        return [func[2:] for func in dir(cls) if callable(getattr(cls, func)) and func.startswith("f_")]

    def __init__(self, domain, snapshot_date, malware_data, pdns_data, whois_data, topsites_data, suffix_data, renewal_data, whois_validity_data, wordlist_based_data):#, adns_data):
        self.domain = domain
        self.snapshot_date = snapshot_date
        self.formatted_snapshot_date = snapshot_date.strftime("%Y%m%d")

        if self.formatted_snapshot_date not in auxiliary_data:
            initialize(self.formatted_snapshot_date)

        self.malware_data = malware_data
        self.pdns_data = pdns_data
        self.whois_data = whois_data
        self.topsites_data = topsites_data
        self.suffix_data = suffix_data
        self.renewal_data = renewal_data
        self.whois_validity_data = whois_validity_data
        self.wordlist_based_data = wordlist_based_data
        self.adns_data = [self.domain] + auxiliary_data[self.formatted_snapshot_date]["openintel_data"][self.domain] if self.domain in auxiliary_data[self.formatted_snapshot_date]["openintel_data"] else None
        self.features = {}

    def check_datasets(self, abridged=True):
        if abridged:
            datasets_to_check = [self.pdns_data, self.whois_data,
                                 self.renewal_data, self.whois_validity_data,
                                 self.adns_data]
        else:
            datasets_to_check = [self.pdns_data, self.whois_data,
                                 self.topsites_data["alexa"], self.topsites_data["umbrella"],
                                 self.topsites_data["majestic"], self.topsites_data["quantcast"], self.suffix_data,
                                 self.renewal_data, self.whois_validity_data,
                                 self.wordlist_based_data,
                                 auxiliary_data[self.formatted_snapshot_date]["wayback_domain_data"].get(self.domain, None),
                                 auxiliary_data[self.formatted_snapshot_date]["ct_data"].get(self.domain, None),
                                 self.adns_data]

        result = [not dataset for dataset in datasets_to_check]
        return result

    def export(self):
        return [self.features[k] for k in FeatureSet.get_feature_names()]

    def generate_feature(self):
        for feature_name in FeatureSet.get_feature_names():
            self.features[feature_name] = getattr(FeatureSet, "f_" + feature_name)(self)

    def f_domain(self):
        return self.domain

    ### Malware-based features ###

    def f_malware_family(self):
        """
        Type: categorical
        Indicates the family of malware that generated the DGA domain.
        Intuition: Some DGAs generate random strings, while others concatenate words from a wordlist. There is a higher
                    chance that the latter collides with a benign domain.
        :return:
        """
        return self.malware_data[1]

    def f_malware_validity_start(self):
        """
        Type: numeric
        Start of validity of the AGD. (only for post-analysis)
        :return:
        """
        return dateparser.parse(self.malware_data[2]).timestamp()

    def f_malware_validity_end(self):
        """
        Type: numeric
        End of validity of the AGD. (only for post-analysis)
        :return:
        """
        return dateparser.parse(self.malware_data[3]).timestamp()

    def f_malware_validity_length(self):
        """
        Type: numeric
        Length in days of the period of validity of the AGD.
        Intuition: An AGD that is valid for a short period of time is potentially less likely to be registered by the
                    malicious party upfront.
        :return:
        """
        return (dateparser.parse(self.malware_data[3]) - dateparser.parse(self.malware_data[2])).days + 1

    def f_whois_registration_date(self):
        """
        Type: date
        Creation date of the domain. Do not use in model.
        :return:
        """
        if not self._is_whois_available("created_date"):
            return None
        try:
            return self._parse_whois_date(self.whois_data["created_date"]).timestamp()
        except:
            return None

    def f_whois_registration_and_family_start_date(self):
        """
        Type: numeric
        Difference between start date of malware and creation date of the domain.
        Intuition: Sites with registration dates a long time
                    before the malware started operating could be more likely to be benign.
        :return:
        """
        family = self.malware_data[1]
        if family not in malware_family_validities or not malware_family_validities[family]:
            return None
        else:
            if not self._is_whois_available("created_date"):
                return None
            try:
                return (self._parse_whois_date(self.whois_data["created_date"]) -
                    datetime.datetime.strptime(malware_family_validities[family], "%Y-%m-%d")).days
            except:
                return None

    def f_whois_registration_and_validity_start_date(self):
        """
        Type: numeric
        Difference between start date of validity of the AGD and creation date of the domain.
        Intuition: Combining with the registration date of the AGD, sites with registration dates a long time
                    before the validity of the AGD could be more likely to be benign.
        :return:
        """
        if not self._is_whois_available("created_date"):
            return None
        try:
            return (self._parse_whois_date(self.whois_data["created_date"]) -
                dateparser.parse(self.malware_data[2])).days
        except:
            return None

    def f_malware_wordlist_based_dga(self):
        """
        Type: categorical
        Indicates whether the DGA uses a wordlist to generate domains.
        Intuition: AGDs based on wordlists can resemble regular phrases and are therefore more likely to collide with legitimate domains.
        :return:
        """
        if not self.wordlist_based_data:
            return None
        return self.wordlist_based_data[1] == "True" # self.malware_data[1] in wordlist_families

    ### Domain name features ###

    def f_domain_length(self):
        """
        Type: numeric
        Length of the domain (without the suffix).
        Intuition: Shorter domains have a higher chance of collision with a benign domain.
        Source: FANCI; PREDATOR; Liu2017CCS; ?
        :return:
        """
        if not self.suffix_data:
            return None
        return len(self.suffix_data[5] + self.suffix_data[4])

    def f_domain_digit_ratio(self):
        """
        Type: numeric
        Proportion of digits over all characters (for the domain without the suffix).
        Intuition: Malicious domains / AGDs are more likely to contain digits.
        Source: EXPOSURE < ? ; FANCI
        :return:
        """
        if not self.suffix_data:
            return None
        return sum(list(map(lambda x: 1 if x.isdigit() else 0, self.suffix_data[5] + self.suffix_data[4])))/len(self.suffix_data[5] + self.suffix_data[4])

    ### DNS features ###

    def f_known_sinkhole(self):
        """
        Type: categorical (sinkdb|email|stamparm|none)
        Indicates whether the domain belongs to a known sinkhole (Evaluation Scheme - 4).
        Based on: A record + listing in SinkDB, whois email, A record + listing in Miroslav Stampar's sinkhole list.
        Intuition: Sinkholed domains shouldn't be seized.
        :return:
        """
        try:
            if self.pdns_data and self.pdns_data[4] and any(auxiliary_data[self.formatted_snapshot_date]["sinkhole_data"].get(ip_address, False) for ip_address in eval(self.pdns_data[4])): # A records
                result = "dns_a_sinkdb"
            elif self.pdns_data and self.pdns_data[4] and any(ip_address in shadowserver_sinkholes_a for ip_address in eval(self.pdns_data[4])):
                result = "dns_a_shadowserver"
            elif self.pdns_data and self.pdns_data[5] and any(ns.strip(".") in shadowserver_sinkholes_ns for ns in eval(self.pdns_data[5])):
                result = "dns_ns_stamparm"
            elif self._is_whois_available("nameserver") and any(
                    ns.strip(".") in shadowserver_sinkholes_ns for ns in (
                    eval(self.whois_data["nameserver"]) if self.whois_data["nameserver"].startswith("[") else [
                        self.whois_data["nameserver"]])):
                result = "whois_ns_stamparm"
            elif self.pdns_data and self.pdns_data[4] and any(retrieve_sinkhole_data.check_against_stamparm_ip(ip_address) for ip_address in eval(self.pdns_data[4])):
                result = "dns_a_stamparm"
            elif self.pdns_data and self.pdns_data[5] and any(retrieve_sinkhole_data.check_against_stamparm_ns(ns.strip(".")) for ns in eval(self.pdns_data[5])):
                result = "dns_ns_stamparm"
            elif self._is_whois_available("nameserver") and any(retrieve_sinkhole_data.check_against_stamparm_ns(ns.strip(".")) for ns in (eval(self.whois_data["nameserver"]) if self.whois_data["nameserver"].startswith("[") else [self.whois_data["nameserver"]])):
                result = "whois_ns_stamparm"
            elif self.pdns_data and self.pdns_data[5] and any(
                    retrieve_sinkhole_data.check_against_alowaisheq_ns(ns.strip(".")) for ns in eval(self.pdns_data[5])):
                result = "dns_ns_alowaisheq"
            elif self._is_whois_available("nameserver") and any(
                    retrieve_sinkhole_data.check_against_alowaisheq_ns(ns.strip(".")) for ns in (
                    eval(self.whois_data["nameserver"]) if self.whois_data["nameserver"].startswith("[") else [
                        self.whois_data["nameserver"]])):
                result = "whois_ns_alowaisheq"
            elif self._is_whois_available("reg_email") and retrieve_sinkhole_data.check_against_sinkhole_emails(self.whois_data["reg_email"]):
                result = "whois_email"
            else:
                result = None
            return result
        except:
            traceback.print_exc()
            return None

    def f_dnsdb_available(self):
        return self.pdns_data is not None

    def f_dnsdb_nb_queries(self):
        """
        Type: numeric
        Number of DNS queries observed for the domain. (from DNSDB)
        Intuition: Benign sites will actually receive (more) queries.
        Source: Lison2017BIGDATA
        :return:
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[3]

    def f_dnsdb_active_period(self):
        """
        Type: numeric
        Time between last seen query and first seen query. (from DNSDB)
        Intuition: Sites active for longer are more likely to be benign.
        :return:
        """
        if not self.pdns_data:
            return None
        return (datetime.datetime.strptime(self.pdns_data[2], "%Y-%m-%d %H:%M:%S") - datetime.datetime.strptime(self.pdns_data[1], "%Y-%m-%d %H:%M:%S")).seconds

    def f_dnsdbwhois_first_seen_after_registration(self):
        """
        Type: numeric
        Time between first seen query and domain creation date. (from DNSDB + WHOIS)
        Intuition: Sites active quickly after registration are less likely to be dormant malicious domains.
        :return:
        """
        if not self.pdns_data or not self._is_whois_available("created_date"):
            return None
        return (datetime.datetime.strptime(self.pdns_data[1], "%Y-%m-%d %H:%M:%S") - self._parse_whois_date(self.whois_data["created_date"])).seconds

    def f_dnsdb_first_seen_before_validity(self):
        """
        Type: numeric
        Time between first seen query and AGD validity date. (from DNSDB)
        Intuition: Sites registered a long time before validity are more likely to be benign.
        :return:
        """
        if not self.pdns_data:
            return None
        return (dateparser.parse(self.malware_data[2]) - datetime.datetime.strptime(self.pdns_data[1], "%Y-%m-%d %H:%M:%S")).seconds
        # return (datetime.datetime.strptime(self.malware_data[2], "%Y-%m-%d %H:%M:%S") - datetime.datetime.strptime(self.pdns_data[1], "%Y-%m-%d %H:%M:%S")).seconds

    def f_dnsdb_first_seen_before_now(self):
        """
        Type: numeric
        Time between first seen query and domain creation date. (from DNSDB + WHOIS)
        Intuition: Sites active quickly after registration are less likely to be dormant malicious domains.
        :return:
        """
        if not self.pdns_data:
            return None
        return (self.snapshot_date - datetime.datetime.strptime(self.pdns_data[1], "%Y-%m-%d %H:%M:%S")).seconds

    def f_dnsdb_record_A(self):
        """
        Type: categorical (true|false)
        Record type A seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[6]

    def f_dnsdb_record_AAAA(self):
        """
        Type: categorical (true|false)
        Record type AAAA seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[7]

    def f_dnsdb_record_CAA(self):
        """
        Type: categorical (true|false)
        Record type CAA seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[8]

    def f_dnsdb_record_CNAME(self):
        """
        Type: categorical (true|false)
        Record type CNAME seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[9]

    def f_dnsdb_record_HINFO(self):
        """
        Type: categorical (true|false)
        Record type HINFO seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[10]

    def f_dnsdb_record_MX(self):
        """
        Type: categorical (true|false)
        Record type MX seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[11]

    def f_dnsdb_record_NS(self):
        """
        Type: categorical (true|false)
        Record type NS seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[12]

    def f_dnsdb_record_PTR(self):
        """
        Type: categorical (true|false)
        Record type PTR seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[13]

    def f_dnsdb_record_RP(self):
        """
        Type: categorical (true|false)
        Record type RP seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[14]

    def f_dnsdb_record_SOA(self):
        """
        Type: categorical (true|false)
        Record type SOA seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[15]

    def f_dnsdb_record_SPF(self):
        """
        Type: categorical (true|false)
        Record type SPF seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[16]

    def f_dnsdb_record_TXT(self):
        """
        Type: categorical (true|false)
        Record type TXT seen on this domain (from DNSDB).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.pdns_data:
            return None
        return self.pdns_data[17]

    def f_openintel_available(self):
        return self.adns_data is not None

    def f_openintel_first_seen_before_now(self):
        """
        Type: numeric
        Time between last seen query and first seen query. (from OpenIntel)
        Intuition: Sites active for longer are more likely to be benign.
        :return:
        """
        if not self.adns_data:
            return None
        return ( min(openintel_cap,
                   max(int(self.adns_data[1]) if self.adns_data[1] else 0,
                   int(self.adns_data[2]) if self.adns_data[2] else 0,
                   int(self.adns_data[3]) if self.adns_data[3] else 0,
                   int(self.adns_data[4]) if self.adns_data[4] else 0,
                   int(self.adns_data[15] if self.adns_data[15] else 0))
        ))

    def f_openintel_first_seen_before_validity(self):
        """
        Type: numeric
        Time between last seen query and first seen query. (from OpenIntel)
        Intuition: Sites active for longer are more likely to be benign.
        :return:
        """
        if not self.adns_data:
            return None
        if not self.adns_data[1] and not self.adns_data[2] and not self.adns_data[3] and not self.adns_data[4] and not self.adns_data[15]:
            return 0
        return (min(openintel_cap,
                   max(int(self.adns_data[1]) if self.adns_data[1] else 0,
                   int(self.adns_data[2]) if self.adns_data[2] else 0,
                   int(self.adns_data[3]) if self.adns_data[3] else 0,
                   int(self.adns_data[4]) if self.adns_data[4] else 0,
                   int(self.adns_data[15] if self.adns_data[15] else 0))) +
               (dateparser.parse(self.malware_data[2]) - self.snapshot_date).days)

    def f_openintel_nb_days_seen_A(self):
        """
        Type: numeric
        Record type A seen on this domain (from OpenIntel).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.adns_data:
            return None
        return min(openintel_cap,int(self.adns_data[5])) if self.adns_data[5] else 0

    def f_openintel_nb_days_seen_AAAA(self):
        """
        Type: numeric
        Record type AAAA seen on this domain (from OpenIntel).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.adns_data:
            return None
        return min(openintel_cap,int(self.adns_data[6])) if self.adns_data[6] else 0

    def f_openintel_nb_days_seen_MX(self):
        """
        Type: numeric
        Record type MX seen on this domain (from OpenIntel).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.adns_data:
            return None
        return min(openintel_cap,int(self.adns_data[8])) if self.adns_data[8] else 0

    def f_openintel_nb_days_seen_NS(self):
        """
        Type: numeric
        Record type NS seen on this domain (from OpenIntel).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.adns_data:
            return None
        return min(openintel_cap,int(self.adns_data[7])) if self.adns_data[7] else 0

    def f_openintel_nb_days_seen_SOA(self):
        """
        Type: numeric
        Record type SOA seen on this domain (from OpenIntel).
        Intuition: Benign sites may have certain 'rarer' record types.
        Source: Fraunhofer report
        """
        if not self.adns_data:
            return None
        return min(openintel_cap,int(self.adns_data[14])) if self.adns_data[14] else 0

    ### Registration/WHOIS features ###

    def f_whois_available(self):
        return self.whois_data is not None

    def f_whois_registrar(self):
        """
        Type: categorical
        The registrar used for the latest registration of the domain.
        Intuition: Malicious parties may prefer certain registrars e.g. due to low prices or few validity checks.
        Source: PREDATOR paper < Felegyhazi2010 + Hao2013
        :return:
        """
        if not self._is_whois_available("registrar"):
            return None
        if "registrar_iana_id" in self.whois_data and self.whois_data["registrar_iana_id"]:
            return "reg-{}".format(self.whois_data["registrar_iana_id"])
        else:
            return self.whois_data["registrar"]

    def f_whois_registration_age(self):
        """
        Type: numeric
        Length in days of the period between the date of registration and today. (~ Evaluation Scheme - 7)
        Intuition: Domains that have been registered a long time ago are more likely to be 'real' benign sites.
        Source: PREDENTIFIER
        :return:
        """
        if not self._is_whois_available("created_date"):
            return None
        try:
            return (self.snapshot_date - self._parse_whois_date(self.whois_data["created_date"])).days
        except:
            return None

    def f_whois_registration_period(self):
        """
        Type: numeric
        Length in days of the period for which a domain is registered. (~ Evaluation Scheme - 7)
        Intuition: Malicious domains will be registered for short periods (e.g. 1 year), while domains registered for
                    a longer time are more likely to be benign.
        Source: PREDATOR

        Keep in mind (from "WHOIS Lost In Translation"):
            When a registrar does not renew or delete a domain before its expiration date, the registry automatically
            extends the registration by one year by moving the domain into the auto-renew state.
        :return:
        """
        if (not self._is_whois_available("expired_date")) or (not self._is_whois_available("created_date")):
            return None
        try:
            return (self._parse_whois_date(self.whois_data["expired_date"]) -
                self._parse_whois_date(self.whois_data["created_date"])).days
        except:
            return None

    def f_whois_has_been_renewed(self):
        """
        Type: categorical (true|false)
        Indicates whether a domain has been renewed.
        Intuition: Malicious domains are short-lived and therefore unlikely to be renewed.
        :return:
        """
        return self.renewal_data[1] if self.renewal_data else None

    def f_whois_privacy(self):
        """
        Type: categorical (true|false)
        The WHOIS privacy used for the domain, or None if no privacy service is used.
        Intuition: abusive domains tend to use Privacy and Proxy services
        (but using a WHOIS Privacy and Proxy is not a reliable indicator of malicious activity)
         ~ not using privacy/proxy -> rather benign; using it -> unknown
        Source: Cybercrime gTLDs Korczynski
        :return:
        """
        for property in ["reg_org", "reg_name", "reg_street", "reg_city", "reg_state", "reg_postal", "reg_country", "reg_email", "reg_phone", "reg_fax", "reg_id"]:
            if self._is_whois_available(property):
                value = self.whois_data[property]
                for keyword in ["privacy", "private", "proxy", "protect", "redacted"]:  # actively using privacy service
                    if keyword in value.lower():
                        return True
        return None

    def f_whois_temporary_mail(self):
        """
        Type: categorical (true|false)
        The mail address used to register the domain belongs to a temporary mail service.
        Uses the data collected by `disposable_email_service.py`
        Intuition: malicious actors may not want to bother setting up 'real' mail addresses, and therefore resort to
                   temporary mail services.
        :return:
        """
        if not self._is_whois_available("reg_email"):
            return None
        if "@" in self.whois_data["reg_email"]:
            email_parts = self.whois_data["reg_email"].split("@")
            if len(email_parts) == 2:
                tempmail_data = auxiliary_data[self.formatted_snapshot_date]["tempmail_data"]
                return (email_parts[1].lower() in tempmail_data[0]) or any(d.endswith(email_parts[1].lower()) for d in tempmail_data[1])
                 #       domain         in exact domains     /           wildcard domains
            else:  # invalid email address / not checked
                return None
        else:
            return None

    def f_whois_valid_phone(self):
        """
        Type: categorical
        0 if the phone number provided in WHOIS is valid, 1 if invalid, 2 if not present.
        :return:
        """
        if not self.whois_validity_data:
            return None
        status = self.whois_validity_data[3]
        return True if status == "VALID" else (False if status == "INVALID" else None)


    ### Top websites lists features (~ Evaluation Scheme - 1) ###

    def f_topsites_alexa_presence(self):
        """
        Type: numeric
        Number of days when the domain appeared in Alexa's top websites list.
        Intuition: Presence over a long period suggests actual popularity and benignness.
        Source: ~ Lison2017BIGDATA
        :return:
        """
        if not self.topsites_data["alexa"]:
            return None
        return self.topsites_data["alexa"][0]

    def f_topsites_alexa_average_rank(self):
        """
        Type: numeric
        Average rank of the domain for all appearances in Alexa's top websites list.
        Intuition: Better ranks suggest actual popularity and benignness.
        Source: Lison2017BIGDATA
        :return:
        """
        if not self.topsites_data["alexa"]:
            return None
        average_rank = round(self.topsites_data["alexa"][1]/self.topsites_data["alexa"][0] if self.topsites_data["alexa"][1] else 0)
        return average_rank if average_rank > 0 else None

    def f_topsites_umbrella_presence(self):
        """
        Type: numeric
        Number of days when the domain appeared in Umbrella's top websites list.
        Intuition: Presence over a long period suggests actual popularity and benignness.
        :return:
        """
        if not self.topsites_data["umbrella"]:
            return None
        return self.topsites_data["umbrella"][0]

    def f_topsites_umbrella_average_rank(self):
        """
        Type: numeric
        Average rank of the domain for all appearances in Umbrella's top websites list.
        Intuition: Better ranks suggest actual popularity and benignness.
        :return:
        """
        if not self.topsites_data["umbrella"]:
            return None
        average_rank = round(self.topsites_data["umbrella"][1]/self.topsites_data["umbrella"][0] if self.topsites_data["umbrella"][1] else 0)
        return average_rank if average_rank > 0 else None

    def f_topsites_majestic_presence(self):
        """
        Type: numeric
        Number of days when the domain appeared in Majestic's top websites list.
        Intuition: Presence over a long period suggests actual popularity and benignness.
        :return:
        """
        if not self.topsites_data["majestic"]:
            return None
        return self.topsites_data["majestic"][0]

    def f_topsites_majestic_average_rank(self):
        """
        Type: numeric
        Average rank of the domain for all appearances in Majestic's top websites list.
        Intuition: Better ranks suggest actual popularity and benignness.
        :return:
        """
        if not self.topsites_data["majestic"]:
            return None
        average_rank = round(self.topsites_data["majestic"][1]/self.topsites_data["majestic"][0] if self.topsites_data["majestic"][1] else 0)
        return average_rank if average_rank > 0 else None

    def f_topsites_quantcast_presence(self):
        """
        Type: numeric
        Number of days when the domain appeared in Quantcast's top websites list.
        Intuition: Presence over a long period suggests actual popularity and benignness.
        :return:
        """
        if not self.topsites_data["quantcast"]:
            return None
        return self.topsites_data["quantcast"][0]

    def f_topsites_quantcast_average_rank(self):
        """
        Type: numeric
        Average rank of the domain for all appearances in Quantcast's top websites list.
        Intuition: Better ranks suggest actual popularity and benignness.
        :return:
        """
        if not self.topsites_data["quantcast"]:
            return None
        average_rank = round(self.topsites_data["quantcast"][1]/self.topsites_data["quantcast"][0] if self.topsites_data["quantcast"][1] else 0)
        return average_rank if average_rank > 0 else None

    ### Content-based features ###

    def f_search_pages_found_wayback_machine(self):
        """
        Type: numeric
        Number of scraped pages on the Wayback Machine.
        Intuition: many pages & found/crawled by search engine -> more likely to be real content
                   <-> malicious: don't bother setting up a real website / not found
        :return:
        """
        if self.domain not in auxiliary_data[self.formatted_snapshot_date]["wayback_domain_data"]:
            return None
        return auxiliary_data[self.formatted_snapshot_date]["wayback_domain_data"][self.domain][1]

    def f_search_wayback_machine_first_seen_before_now(self):
        """
        Type: numeric
        Difference between the snapshot date and when the site was first seen on the Wayback Machine.
        Intuition: existing for longer time -> more likely to be benign
        :return:
        """
        if self.domain not in auxiliary_data[self.formatted_snapshot_date]["wayback_domain_data"]:
            return None
        wayback_timestamp = auxiliary_data[self.formatted_snapshot_date]["wayback_domain_data"][self.domain][2]
        if wayback_timestamp == "-1":
            return None
        return (self.snapshot_date - datetime.datetime.strptime(wayback_timestamp, "%Y%m%d%H%M%S")).seconds

    def f_search_wayback_machine_first_seen_before_validity(self):
        """
        Type: numeric
        Difference between the validity start date and when the site was first seen on the Wayback Machine.
        Intuition: existing for longer time -> more likely to be benign
        :return:
        """
        if self.domain not in auxiliary_data[self.formatted_snapshot_date]["wayback_domain_data"]:
            return None
        wayback_timestamp = auxiliary_data[self.formatted_snapshot_date]["wayback_domain_data"][self.domain][2]
        if wayback_timestamp == "-1":
            return None
        return (dateparser.parse(self.malware_data[2]) - datetime.datetime.strptime(wayback_timestamp, "%Y%m%d%H%M%S")).seconds

    ### Certificate transparency logs ###

    def f_ct_has_certificate(self):
        """
        Type: binary
        The domain had a certificate.
        Intuition: Acquiring a certificate requires (setup) effort, indicating benignness.
        :return:
        """
        d = auxiliary_data[self.formatted_snapshot_date]["ct_data"].get(self.domain, None)
        if d:
            return d[0] == "True"
        else:
            return None

    ### Helper methods ###

    def _is_whois_available(self, field):
        return self.whois_data and field in self.whois_data and self.whois_data[field]

    def _parse_whois_date(self, whois_date):
        try:
            return dateparser.parse(whois_date.strip("[]':")).replace(tzinfo=None)
        except:
            return None