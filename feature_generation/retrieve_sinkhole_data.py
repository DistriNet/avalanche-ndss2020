import csv
import os
import time
import urllib.request
from glob import glob
import socket

import requests

from credentials import SINKDB_HTTP_API_KEY


def download_sinkholes_stamparm(formatted_snapshot_date):
    """
    ns = document.querySelectorAll(".js-navigation-open");
    results = [];
    for (i = 0; i < ns.length; i++) {
        let n = ns[i].text;
        if (n.startsWith("sinkhole_")) {
            results.push("https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/" + n)
        }
    };
    console.log(results);

    @ https://github.com/stamparm/maltrail/tree/master/trails/static/malware
    """
    urls = [
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_abuse.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_anubis.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_arbor.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_bitdefender.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_blacklab.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_botnethunter.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_certgovau.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_certpl.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_checkpoint.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_cirtdk.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_collector.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_conficker.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_cryptolocker.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_drweb.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_dynadot.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_dyre.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_farsight.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_fbizeus.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_fitsec.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_fnord.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_fraunhofer.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_gameoverzeus.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_georgiatech.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_gladtech.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_honeybot.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_hyas.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_kaspersky.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_kryptoslogic.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_microsoft.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_noip.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_rsa.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_secureworks.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_shadowserver.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_sidnlabs.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_sinkdns.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_sofacy.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_sugarbucket.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_supportintel.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_switch.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_tech.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_tsway.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_unknown.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_virustracker.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_wapacklabs.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_xaayda.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_yourtrap.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/sinkhole_zinkhole.txt"
    ]
    for url in urls:
        urllib.request.urlretrieve(url, "input_data/{}/stamparm_sinkhole/{}".format(formatted_snapshot_date, url.split("/")[-1]))


def parse_sinkholes_stamparm(formatted_snapshot_date):
    sinkholes_ip = set()
    sinkholes_ip_with_source = set()
    sinkholes_ns = set()
    sinkholes_ns_with_source = set()
    for fp in glob(os.path.join(os.path.dirname(__file__), "input_data/{}/stamparm_sinkhole/*.txt".format(formatted_snapshot_date))):
        source = fp[:-4].split("_")[-1]
        with open(fp) as f:
            for line in f:
                line = line.rstrip()
                if line and not line.startswith("#"):
                    try:
                        socket.inet_aton(line)
                        # is an IP address
                        sinkholes_ip.add(line)
                        sinkholes_ip_with_source.add((line, source))
                    except socket.error:
                        # is not an IP address
                        sinkholes_ns.add(line)
                        sinkholes_ns_with_source.add((line, source))
    return sinkholes_ip, sinkholes_ns, sinkholes_ip_with_source, sinkholes_ns_with_source


def parse_sinkholes_alowaisheq_ns():
    sinkholes_ns = set()
    with open(os.path.join(os.path.dirname(__file__), "alowaisheq_sinkholes_ns.txt")) as f:
        for line in f:
            line = line.rstrip()
            if line:
                sinkholes_ns.add(line)
    return sinkholes_ns


def load_sinkdb_cache(record, folder):
    if not os.path.exists(os.path.join(folder, "sinkdb_cache_{record}.csv".format(record=record))):
        return {}
    with open(os.path.join(folder, "sinkdb_cache_{record}.csv".format(record=record))) as sc:
        csvr = csv.reader(sc)
        return {entry: True if status == "True" else False for entry, status in csvr}


def check_a_against_sinkdb(ip_address, sinkdb_a_cache, cache_folder):
    if ip_address in sinkdb_a_cache:
        return sinkdb_a_cache[ip_address]
    try:
        r = requests.post("https://sinkdb-api.abuse.ch/api/v1/", data={"api_key": SINKDB_HTTP_API_KEY, "ipv4": ip_address})
        answer = r.json()
        if answer["query_status"] == "no_results":
            result = False
        elif answer["query_status"] == "ok":
            result = any(result["source"] == "sinkhole" for result in answer["results"])
        else:
            result = False
    except:
        result = False
    with open(os.path.join(cache_folder, "sinkdb_cache_a.csv"), "a") as sc:
        sc.write("{},{}\n".format(ip_address, result))
    return result


def check_ns_against_sinkdb(nameserver, sinkdb_ns_cache, cache_folder):
    if nameserver in sinkdb_ns_cache:
        return sinkdb_ns_cache[nameserver]
    try:
        r = requests.post("https://sinkdb-api.abuse.ch/api/v1/", data={"api_key": SINKDB_HTTP_API_KEY, "domain": nameserver})
        answer = r.json()
        if answer["query_status"] == "no_results":
            result = False
        elif answer["query_status"] == "ok":
            result = any(result["source"] == "sinkhole" for result in answer["results"])
        else:
            result = False
    except:
        # NXDOMAIN
        result = False
    with open(os.path.join(cache_folder, "sinkdb_cache_ns.csv"), "a") as sc:
        sc.write("{},{}\n".format(nameserver, result))
    return result

sinkholes_stamparm_ip, sinkholes_stamparm_ns, _, _ = parse_sinkholes_stamparm("20191129")

def check_against_stamparm_ip(ip_address):
    return ip_address in sinkholes_stamparm_ip

def check_against_stamparm_ns(ns):
    return ns in sinkholes_stamparm_ns

sinkholes_alowaisheq_ns = parse_sinkholes_alowaisheq_ns()

def check_against_alowaisheq_ns(ns):
    return ns in sinkholes_alowaisheq_ns

def load_whois_sinkhole_emails():
    with open("sinkhole_emails.txt") as sem:
        return [mail_address.rstrip() for mail_address in sem if mail_address.rstrip() and not mail_address.startswith("#")]


def check_against_sinkhole_emails(mail_address):
    whois_sinkhole_emails = load_whois_sinkhole_emails()
    return mail_address in whois_sinkhole_emails


def check_all_against_sinkdb(input_file, cache_folder, rrtype):
    sinkdb_a_cache = load_sinkdb_cache(rrtype, cache_folder)

    with open(input_file) as input:
            for line in input:
                ip = line.split(",")[0]
                if rrtype == "a":
                    res = check_a_against_sinkdb(ip, sinkdb_a_cache, cache_folder)
                elif rrtype == "ns":
                    res = check_ns_against_sinkdb(ip, sinkdb_a_cache, cache_folder)

                if res == True:
                    print(ip, res)
