import csv
import datetime
import os
import re
import traceback

from feature_generation.features import FeatureSet

def traverse_file(file, input_new_domain):
    orig_new_domain = input_new_domain
    new_domain = re.sub(r'[^\w]', '', input_new_domain) if input_new_domain else input_new_domain
    return_line = None
    if file not in file_traversal_cache:
        file_traversal_cache[file] = {"next_domain": None, "next_record": None, "finished": False}
    orig_next_domain = file_traversal_cache[file]["next_domain"]
    if orig_next_domain:
        next_domain = re.sub(r'[^\w]', '', orig_next_domain)
    else:
        next_domain = orig_next_domain
    while not file_traversal_cache[file]["finished"] and (not orig_next_domain or not new_domain or next_domain < new_domain
                                                          or ((next_domain == new_domain) and (orig_next_domain != input_new_domain))) :
        try:
            next_record = next(file)
            file_traversal_cache[file]["next_record"] = next_record
            orig_next_domain = next_record[0].lower()
            next_domain = re.sub(r'[^\w]', '', orig_next_domain)
            file_traversal_cache[file]["next_domain"] = orig_next_domain
            if not new_domain:
                new_domain = next_domain
        except StopIteration:
            file_traversal_cache[file]["next_record"] = None
            file_traversal_cache[file]["finished"] = True
    if new_domain and next_domain == new_domain and orig_new_domain == orig_next_domain:
        next_record = file_traversal_cache[file]["next_record"]
        return_line = next_record.copy() if next_record else None
    return return_line

def generate(formatted_snapshot_date, classification_types, input_folder, output_folder):
    snapshot_date = datetime.datetime.strptime(formatted_snapshot_date[:8], "%Y%m%d")

    feature_names = FeatureSet.get_feature_names()
    remove_sinkholed = True
    sinkholed_index = feature_names.inpredex("known_sinkhole")
    if remove_sinkholed:
        del feature_names[sinkholed_index]

    sinkholed_removed_count = 0
    total_count = 0
    classes_counts = {c:0 for c in classification_types}

    abridged = False

    if abridged:
        dataset_check_descriptors = "DNSDB WHOIS Renewal Validity OpenIntel".split(" ")
    else:
        dataset_check_descriptors = "DNSDB WHOIS Alexa Umbrella Majestic Quantcast Suffix Renewal Validity Wordlist Wayback CT OpenIntel".split(
        " ")

    for classification_type in classification_types:
        agd_path = "{}/{}/{}.csv".format(input_folder, formatted_snapshot_date, classification_type)
        try:
            feature_output_file = open("{}/{}/feature_values_{}.csv".format(output_folder, formatted_snapshot_date, classification_type), "w")
            feature_output = csv.writer(feature_output_file)

            # alphabetically ordered data sets
            agd_file = open(agd_path)
            agd_csvr = csv.reader(agd_file)
            # _header = next(malware_csvr)  -- header stripped

            dnsdb_pdns_file = open("{}/{}/dnsdb_results_snapshot.csv".format(input_folder, formatted_snapshot_date))
            dnsdb_pdns_csvr = csv.reader(dnsdb_pdns_file)

            whois_file = open("{}/{}/whois_data_snapshot.csv".format(input_folder, formatted_snapshot_date))
            whois_csvr = csv.reader(whois_file)
            whois_header = next(whois_csvr)
            if not whois_header[0].startswith("domain"):
                raise ValueError("Incorrect header on WHOIS file!")

            all_toplists_data = {}
            for provider in "alexa majestic quantcast umbrella".split(" "):
                all_toplists_data[provider] = {}
                with open("{}/{}/topsites_results_{}.csv".format(input_folder, formatted_snapshot_date, provider)) as toplists_data:
                    toplists_csvr = csv.reader(toplists_data)
                    for row in toplists_csvr:
                        domain, occurrences, ranksum = row
                        all_toplists_data[provider][domain] = (int(occurrences), float(ranksum) if ranksum else None)

            suffix_file = open("{}/{}/suffix_results.csv".format(input_folder, formatted_snapshot_date))
            suffix_csvr = csv.reader(suffix_file)

            if os.path.exists("{}/{}/renewal_results.csv".format(input_folder, formatted_snapshot_date)):
                renewal_file = open("{}/{}/renewal_results.csv".format(input_folder, formatted_snapshot_date))
                renewal_csvr = csv.reader(renewal_file)
            else:
                renewal_file = None
                renewal_csvr = None

            if os.path.exists("{}/{}/whois_validity_data.csv".format(input_folder, formatted_snapshot_date)):
                whois_validity_file = open("{}/{}/whois_validity_data.csv".format(input_folder, formatted_snapshot_date))
                whois_validity_csvr = csv.reader(whois_validity_file)
            else:
                whois_validity_file = None
                whois_validity_csvr = None

            wordlist_based_file = open("{}/{}/wordlist_based_results.csv".format(input_folder, formatted_snapshot_date))
            wordlist_based_csvr = csv.reader(wordlist_based_file)

            feature_output.writerow(feature_names)

            dataset_check_results = []

            for domain_data in agd_csvr:
                domain = domain_data[0]

                whois_line = traverse_file(whois_csvr, domain)
                if whois_line:
                    if domain != whois_line[0]:
                        print(domain, whois_line)
                whois_data = dict(zip(whois_header, whois_line)) if whois_line else None
                dnsdb_pdns_data = traverse_file(dnsdb_pdns_csvr, domain)
                toplists_data = {}
                for provider in "alexa majestic quantcast umbrella".split(" "):
                    toplists_data[provider] = all_toplists_data[provider].get(domain, None)
                suffix_data = traverse_file(suffix_csvr, domain)
                renewal_data = traverse_file(renewal_csvr, domain) if renewal_csvr else None
                whois_validity_data = traverse_file(whois_validity_csvr, domain)  if whois_validity_csvr else None
                wordlist_based_data = traverse_file(wordlist_based_csvr, domain)
                # openintel_adns_data = traverse_file(openintel_adns_csvr, domain)

                fs = FeatureSet(domain, snapshot_date, domain_data, dnsdb_pdns_data, whois_data, toplists_data, suffix_data, renewal_data, whois_validity_data, wordlist_based_data)

                try:
                    fs.generate_feature()
                    exported_feature = fs.export()
                    if remove_sinkholed:
                        if exported_feature[sinkholed_index] != None:
                            sinkholed_removed_count += 1
                            continue
                        else:
                            total_count += 1
                            classes_counts[classification_type] += 1
                            del exported_feature[sinkholed_index]
                            feature_output.writerow(exported_feature)

                    datasets_available = fs.check_datasets(abridged=abridged)
                    dataset_check_results.append(datasets_available)

                except: # feature generation failed
                    traceback.print_exc()
                    continue
        finally:
            agd_file.close()
            dnsdb_pdns_file.close()
            whois_file.close()
            suffix_file.close()
            if renewal_file: renewal_file.close()
            if whois_validity_file: whois_validity_file.close()
            wordlist_based_file.close()

        print(classification_type, snapshot_date, "(stats after sinkholing)")
        for idx, results_row in enumerate(zip(*dataset_check_results)):
            print(dataset_check_descriptors[idx].ljust(15), str(len([r for r in results_row if r is not False])).rjust(6), str(len([r for r in results_row if r is False])).rjust(6))

    print("Sinkholed domains", sinkholed_removed_count)
    print("Retained domains", total_count)
    print("Counts per class", classes_counts)


if __name__ == '__main__':
    input_tuples = [
        ("20171129", ["no_action", "action_seize"]),
        ("20181129", ["no_action", "action_seize"]),
        ("20191129", ["no_action", "action_seize"])
    ]

    input_folder = "input_data"
    output_folder = "output_data"

    for snapshot_date, classification_types in input_tuples:
        file_traversal_cache = {}

        generate(snapshot_date, classification_types, input_folder, output_folder)