import csv
import os
from subprocess import run

# Execute after generating feature values. (generate_feature_values)

def prepare_files_oneset(snapshot_date, classification_types, input_folder, output_folder, with_classification=True):
    classification = {}

    if os.path.exists("{}/{}/domains_classification.csv".format(input_folder, snapshot_date)):
        with open("{}/{}/domains_classification.csv".format(input_folder, snapshot_date)) as classification_file:
            classification_csvr = csv.reader(classification_file)
            for row in classification_csvr:
                classification[row[0]] = row[1:]
    for classification_type in classification_types:
        with open("{}/{}/feature_values_{}.csv".format(output_folder, snapshot_date, classification_type)) as values_file:
            csvr = csv.reader(values_file)
            header = next(csvr)
            domain_idx = header.index("domain")
            with open("{}/{}/weka_output_{}.csv".format(output_folder, snapshot_date, classification_type), "w") as weka_output:
                csvw = csv.writer(weka_output)
                csvw.writerow(["domain"] + header[:domain_idx] + header[domain_idx + 1:] + ["class"])
                for row in csvr:
                    domain = row[domain_idx]
                    if with_classification:
                        if domain not in classification:
                            print("Not classified:", domain)
                            continue
                        domain_class_row = classification.get(domain)
                        if domain_class_row[2] == "undetermined":
                            continue
                        domain_class = "malicious" if domain_class_row[3] == "True" else "benign"
                    else:
                        domain_class = None
                    csvw.writerow([domain] + row[:domain_idx] + row[domain_idx + 1:] + [domain_class])
    cmd = '''head -n 1 weka_output_{}.csv > use_in_weka.csv; for f in '''.format(classification_types[0])
    cmd += " ".join(["weka_output_{}.csv".format(t) for t in classification_types])
    cmd += '''; do tail -n +2 $f | sed 's/"Limited Liability Company ""Registrar of domain names REG.RU"""/"Limited Liability Company Registrar of domain names REG.RU"/g' >> use_in_weka.csv; done;'''
    run(cmd,
        cwd=os.path.join(os.path.dirname(os.path.realpath(__file__)), output_folder, snapshot_date), shell=True )

def prepare_files_multiplesets_split_by_features_all_instances(snapshot_date, classification_types, input_folder, output_folder, with_classification=True):

    with open("{}/{}/feature_values_{}.csv".format(output_folder, snapshot_date, classification_types[0])) as values_file:
        csvr = csv.reader(values_file)
        header = next(csvr)
        domain_idx = header.index("domain")
        dnsdb_idx = header.index("dnsdb_available")
        whois_idx = header.index("whois_available")
        # openintel_idx = header.index("openintel_available")


    output_files = {}
    for available in ["dnsdb", "whois",  "none"]: #"openintel",
        output_file = open("{}/{}/weka_multi_output_features_all_instances_{}.csv".format(output_folder, snapshot_date, available), "w")
        output_csvw = csv.writer(output_file)
        output_header = header.copy()
        idxes_to_keep = set()
        # if available == "none":
        idxes_to_keep.update({header.index(f) for f in header if not f.startswith("dnsdb") and not f.startswith("whois") and f != "domain" and f != "suffix_type"})
        if available == "dnsdb":
            idxes_to_keep.update({header.index(f) for f in header if f.startswith("dnsdb_") and f.split("_")[-1] not in "CAA HINFO PTR RP SPF".split()})
            idxes_to_keep -= {dnsdb_idx}
        elif available == "whois":
            idxes_to_keep.update({header.index(f) for f in header if f.startswith("whois_") }) # and f != "whois_registrar"
            idxes_to_keep -= {whois_idx}
        # elif available == "openintel":
        #     idxes_to_keep.update({header.index(f) for f in header if f.startswith("openintel_") }) # and f != "whois_registrar"
        #     idxes_to_keep -= {openintel_idx}

        output_header = [el for idx, el in enumerate(output_header) if idx in idxes_to_keep]
        output_files[available] = (output_csvw, idxes_to_keep)

        output_csvw.writerow(["domain"] + output_header +["class"])

    classification = {}
    if os.path.exists("{}/{}/domains_classification.csv".format(input_folder, snapshot_date)):
        with open("{}/{}/domains_classification.csv".format(input_folder, snapshot_date)) as classification_file:
            classification_csvr = csv.reader(classification_file)
            for row in classification_csvr:
                classification[row[0]] = row[1:]

    for classification_type in classification_types:
        with open("{}/{}/feature_values_{}.csv".format(output_folder, snapshot_date, classification_type)) as values_file:
            csvr = csv.reader(values_file)
            next(csvr)
            for row in csvr:
                domain = row[domain_idx]
                if with_classification:
                    if domain not in classification:
                        print("Not classified:", domain)
                        continue
                    domain_class_row = classification.get(domain)
                    if domain_class_row[2] == "undetermined":
                        continue
                    domain_class = "malicious" if domain_class_row[3] == "True" else "benign"
                else:
                    domain_class = None

                dnsdb_available = row[dnsdb_idx]
                whois_available = row[whois_idx]
                # openintel_available = row[openintel_idx]

                # While passive DNS is considered a different data set in terms of cost/...,
                # the absence of data from passive DNS can be considered equal to having 0 queries.
                if True or dnsdb_available == "True":
                    output_dnsdb, idxes_to_keep_dnsdb = output_files["dnsdb"]
                    dnsdb_row = [el for idx, el in enumerate(row) if idx in idxes_to_keep_dnsdb]
                    output_dnsdb.writerow([domain] + dnsdb_row + [domain_class])

                if whois_available == "True":
                    output_whois, idxes_to_keep_whois = output_files["whois"]
                    whois_row = [el for idx, el in enumerate(row) if idx in idxes_to_keep_whois]
                    output_whois.writerow([domain] + whois_row + [domain_class])

                # if openintel_available == "True":
                #     output_openintel, idxes_to_keep_openintel = output_files["openintel"]
                #     openintel_row = [el for idx, el in enumerate(row) if idx in idxes_to_keep_openintel]
                #     output_openintel.writerow([domain] + openintel_row + [domain_class])

                output_none, idxes_to_keep_none = output_files["none"]
                none_row = [el for idx, el in enumerate(row) if idx in idxes_to_keep_none]
                output_none.writerow([domain] + none_row + [domain_class])

if __name__ == '__main__':
    input_tuples = [("20171129", ["no_action", "action_seize"]),
                    ("20181129", ["no_action", "action_seize"]),
                    ("20191129", ["no_action", "action_seize"])]

    input_folder = "input_data"
    output_folder = "output_data"

    for snapshot_date, classification_types in input_tuples:

        prepare_files_multiplesets_split_by_features_all_instances(snapshot_date, classification_types, input_folder, output_folder, with_classification=True)
        prepare_files_oneset(snapshot_date, classification_types, input_folder, output_folder, with_classification=True)
