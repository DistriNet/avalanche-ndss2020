import pandas as pd
from sklearn.preprocessing import Binarizer, OneHotEncoder, LabelBinarizer, LabelEncoder
from sklearn.impute import SimpleImputer
import numpy as np

import os

def loadDataIntersectSamples(sourcepattern, malwareFamily, year):
    '''Loads the data. Every dataset combination leads contains domains of the most restrictive dataset,
    i.e. 1111 (all datasources available). Thus, 1011 will have the same amount of domains as 1111'''

    DATAPATH = 'datasets/' + year
    FILENAME1 = 'weka_multi_output_features_all_instances_whois.csv'
    FILENAME2 = 'weka_multi_output_features_all_instances_dnsdb.csv'

    whois = pd.read_csv(os.path.join(DATAPATH, FILENAME1))
    whois.index = whois['domain']
    whois.drop(whois.index.duplicated())

    label = pd.DataFrame(whois.iloc[:, -1])
    reputation = whois.iloc[:, 0:28]
    openintel = whois.iloc[:, 9:17]
    whois = whois.iloc[:, 28:-1]

    print()

    dns = pd.read_csv(os.path.join(DATAPATH, FILENAME2), parse_dates=['malware_validity_start', 'malware_validity_end'])
    dns.index = dns['domain']
    dns = dns.drop(dns.index.duplicated())
    dns = dns.iloc[:, 2:13]

    #### Open Intel clean up ####
    openintel = pd.concat([openintel, label], axis=1, join='inner')
    openintel = openintel[openintel['openintel_available'] == True]
    # redifine label, as openintel offers least amount of labels
    label = pd.DataFrame(openintel.iloc[:, -1])
    openintel = openintel.drop(['openintel_available', 'class'], axis=1)

    more_columns_to_drop = ['openintel_available', 'openintel_first_seen_before_now',
                            'openintel_first_seen_before_validity', 'openintel_nb_days_seen_A',
                            'openintel_nb_days_seen_AAAA', 'openintel_nb_days_seen_MX', 'openintel_nb_days_seen_NS',
                            'openintel_nb_days_seen_SOA']
    reputation = reputation.drop(more_columns_to_drop, axis=1)

    ### Dates ###
    reputation['malware_validity_start'] = pd.to_datetime(reputation['malware_validity_start'], unit='s')
    reputation['malware_validity_end'] = pd.to_datetime(reputation['malware_validity_end'], unit='s')
    whois['whois_registration_date'] = pd.to_datetime(whois['whois_registration_date'], unit='s')

    # binarize
    if malwareFamily == True:
        to_binarize = reputation.loc[:, ['malware_wordlist_based_dga','ct_has_certificate', 'topsites_alexa_presence', 'topsites_majestic_presence',
                                         'topsites_quantcast_presence', 'topsites_umbrella_presence']]
        binarized = Binarizer().transform(to_binarize)
        reputation.loc[:,
        ['malware_wordlist_based_dga', 'ct_has_certificate', 'topsites_alexa_presence', 'topsites_majestic_presence', 'topsites_quantcast_presence',
         'topsites_umbrella_presence']] = binarized
    else:
        to_binarize = reputation.loc[:, ['ct_has_certificate', 'topsites_alexa_presence',
                                         'topsites_majestic_presence',
                                         'topsites_quantcast_presence', 'topsites_umbrella_presence']]
        binarized = Binarizer().transform(to_binarize)
        reputation.loc[:,
        ['ct_has_certificate', 'topsites_alexa_presence', 'topsites_majestic_presence',
         'topsites_quantcast_presence',
         'topsites_umbrella_presence']] = binarized

    # encode categorical feature
    if malwareFamily == True:
        enco = OneHotEncoder()
        categorical = enco.fit_transform(reputation.loc[:, ['malware_family']])
        df = pd.DataFrame(categorical.toarray(), columns=enco.get_feature_names(
            ['malware_family']), index=reputation.index)
        reputation = pd.concat([reputation, df], axis=1)
        reputation = reputation.drop(['malware_family'], axis=1)

    # impute search_wayback
    to_impute = reputation.loc[:, ['search_pages_found_wayback_machine', 'search_wayback_machine_first_seen_before_now',
                                   'search_wayback_machine_first_seen_before_validity']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=0).fit_transform(to_impute)
    reputation.loc[:, ['search_pages_found_wayback_machine', 'search_wayback_machine_first_seen_before_now',
                       'search_wayback_machine_first_seen_before_validity']] = imputed

    #### whois clean up ####
    # impute whois_privacy and whois_temporary_mail with Not known
    booleanDictionary = {True: 'TRUE', False: 'FALSE'}
    whois.loc[:, 'whois_privacy'] = whois.loc[:, 'whois_privacy'].map(booleanDictionary)
    whois.loc[:, 'whois_temporary_mail'] = whois.loc[:, 'whois_temporary_mail'].map(booleanDictionary)
    whois.loc[:, 'whois_has_been_renewed'] = whois.loc[:, 'whois_has_been_renewed'].map(booleanDictionary)
    whois.loc[:, 'whois_valid_phone'] = whois.loc[:, 'whois_valid_phone'].map(booleanDictionary)
    to_impute = whois.loc[:, ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value='Not known').fit_transform(to_impute)
    whois.loc[:, ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']] = imputed

    # categroical features, those that are imputed
    enc = OneHotEncoder()
    categorical = enc.fit_transform(
        whois.loc[:, ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']])
    df = pd.DataFrame(categorical.toarray(), columns=enc.get_feature_names(
        ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']), index=whois.index)
    whois = pd.concat([whois, df], axis=1)
    whois = whois.drop(['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone'], axis=1)

    # impute with mean whois_registration_age and whois_registration_and_validity_start_date and whois_registration_period
    to_impute = whois.loc[:, ['whois_registration_age', 'whois_registration_and_family_start_date',
                              'whois_registration_and_validity_start_date', 'whois_registration_period']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='mean').fit_transform(to_impute)
    whois.loc[:,
    ['whois_registration_age', 'whois_registration_and_family_start_date', 'whois_registration_and_validity_start_date',
     'whois_registration_period']] = imputed

    #### dsndb clean up ####
    # impute DNS records to False
    to_impute = dns.loc[:,
                ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                 'dnsdb_record_SOA', 'dnsdb_record_TXT']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=False).fit_transform(to_impute)
    dns.loc[:, ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                'dnsdb_record_SOA', 'dnsdb_record_TXT']] = imputed

    # binarize DNS record booleans
    to_binarize = dns.loc[:,
                  ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                   'dnsdb_record_SOA', 'dnsdb_record_TXT']]
    binarized = LabelBinarizer().fit_transform(to_binarize)
    dns.loc[:, ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                'dnsdb_record_SOA', 'dnsdb_record_TXT']] = binarized

    # impute dns nb_queries, active_period
    to_impute = dns.loc[:, ['dnsdb_active_period', 'dnsdb_nb_queries']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=0).fit_transform(to_impute)
    dns.loc[:, ['dnsdb_active_period', 'dnsdb_nb_queries']] = imputed

    # impute dns timestamps
    to_impute = dns.loc[:, ['dnsdb_first_seen_before_now', 'dnsdb_first_seen_before_validity']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=0).fit_transform(to_impute)
    dns.loc[:, ['dnsdb_first_seen_before_now', 'dnsdb_first_seen_before_validity']] = imputed

    #### Join data ####
    post_analysis_columns = ['malware_family', 'malware_wordlist_based_dga'] + \
                            ['domain', 'malware_validity_length',
                            'topsites_alexa_average_rank', 'topsites_majestic_average_rank',
                            'topsites_quantcast_average_rank', 'topsites_umbrella_average_rank',
                             'malware_validity_start', 'malware_validity_end', 'whois_registration_date', 'whois_registrar']
                            # ['openintel_available', 'openintel_first_seen_before_now',
                            # 'openintel_first_seen_before_validity', 'openintel_nb_days_seen_A',
                            # 'openintel_nb_days_seen_AAAA', 'openintel_nb_days_seen_MX', 'openintel_nb_days_seen_NS',
                            # 'openintel_nb_days_seen_SOA']
    datasources = [source for p, source in zip(sourcepattern, [reputation, dns, whois, openintel]) if int(p)]
    columnnames = [cn for p, cn in zip(sourcepattern, [reputation.columns, dns.columns, whois.columns, openintel.columns]) if int(p)]
    post_analysis_columns = [x for x in post_analysis_columns if x in np.concatenate(columnnames)]
    print(len(datasources[0].index))
    print(len(label.index))
    data = pd.concat(datasources + [label], axis=1, join='inner')
    features = data.drop(['class']+post_analysis_columns, axis=1)
    labels = data['class']
    post_analysis_labels = data[post_analysis_columns]

    # encode the labels
    le = LabelEncoder()
    labels = le.fit_transform(labels)
    # print(le.classes_)
    # print("Benign is ", le.transform(["benign"]))
    # print("** FINAL COLUMNS: **")
    # print(features.columns)
    # print(features.shape)

    return features, labels, post_analysis_labels

def loadAndCleanDataMaxDom(sourcepattern, malwareFamily, year, whoisdatacompl=True):
    DATAPATH = 'datasets/' + year
    FILENAME = 'weka_multi_output_features_all_instances_none.csv'
    FILENAME1 = 'weka_multi_output_features_all_instances_whois.csv'
    FILENAME2 = 'weka_multi_output_features_all_instances_dnsdb.csv'
    FILENAME3 = 'use_in_weka.csv'

    weka = pd.read_csv(os.path.join(DATAPATH, FILENAME3))
    weka.index = weka['domain']
    available = weka.loc[:, ['dnsdb_available', 'whois_available', 'openintel_available']]

    none = pd.read_csv(os.path.join(DATAPATH, FILENAME))
    none.index = none['domain']
    reputation = none.iloc[:, 0:28]
    label = pd.DataFrame(none['class'])

    whois = pd.read_csv(os.path.join(DATAPATH, FILENAME1))
    whois.index = whois['domain']

    whois = whois.iloc[:, 28:-1]
    openintel = none.iloc[:, 9:17]
    openintel = openintel[openintel['openintel_available'] == True]

    print()

    dns = pd.read_csv(os.path.join(DATAPATH, FILENAME2), parse_dates=['malware_validity_start', 'malware_validity_end'])
    dns.index = dns['domain']
    dns = dns.iloc[:, 2:13]
    available_dns = pd.concat([dns, available], axis=1, join='inner')
    dns = dns[available_dns['dnsdb_available'] == True]


    #### Open Intel clean up ####
    # redifine label, as openintel offers least amount of labels
    openintel = openintel.drop(['openintel_available'], axis=1)

    #### Reputation clean up ####
    more_columns_to_drop = ['openintel_available', 'openintel_first_seen_before_now',
                            'openintel_first_seen_before_validity', 'openintel_nb_days_seen_A',
                            'openintel_nb_days_seen_AAAA', 'openintel_nb_days_seen_MX', 'openintel_nb_days_seen_NS',
                            'openintel_nb_days_seen_SOA']
    reputation = reputation.drop(more_columns_to_drop, axis=1)

    ### Dates ###
    reputation['malware_validity_start'] = pd.to_datetime(reputation['malware_validity_start'], unit='s')
    reputation['malware_validity_end'] = pd.to_datetime(reputation['malware_validity_end'], unit='s')
    whois['whois_registration_date'] = pd.to_datetime(whois['whois_registration_date'], unit='s')

    # binarize
    if malwareFamily == True:
        to_binarize = reputation.loc[:, ['malware_wordlist_based_dga','ct_has_certificate', 'topsites_alexa_presence', 'topsites_majestic_presence',
                                         'topsites_quantcast_presence', 'topsites_umbrella_presence']]
        binarized = Binarizer().transform(to_binarize)
        reputation.loc[:,
        ['malware_wordlist_based_dga', 'ct_has_certificate', 'topsites_alexa_presence', 'topsites_majestic_presence', 'topsites_quantcast_presence',
         'topsites_umbrella_presence']] = binarized
    else:
        to_binarize = reputation.loc[:, ['ct_has_certificate', 'topsites_alexa_presence',
                                         'topsites_majestic_presence',
                                         'topsites_quantcast_presence', 'topsites_umbrella_presence']]
        binarized = Binarizer().transform(to_binarize)
        reputation.loc[:,
        ['ct_has_certificate', 'topsites_alexa_presence', 'topsites_majestic_presence',
         'topsites_quantcast_presence',
         'topsites_umbrella_presence']] = binarized

    # encode categorical feature
    if malwareFamily == True:
        enco = OneHotEncoder()
        categorical = enco.fit_transform(reputation.loc[:, ['malware_family']])
        df = pd.DataFrame(categorical.toarray(), columns=enco.get_feature_names(
            ['malware_family']), index=reputation.index)
        reputation = pd.concat([reputation, df], axis=1)
        reputation = reputation.drop(['malware_family'], axis=1)

    # impute search_wayback
    to_impute = reputation.loc[:, ['search_pages_found_wayback_machine', 'search_wayback_machine_first_seen_before_now',
                                   'search_wayback_machine_first_seen_before_validity']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=0).fit_transform(to_impute)
    reputation.loc[:, ['search_pages_found_wayback_machine', 'search_wayback_machine_first_seen_before_now',
                       'search_wayback_machine_first_seen_before_validity']] = imputed

    #### whois clean up ####
    # impute whois_privacy and whois_temporary_mail with Not known
    booleanDictionary = {True: 'TRUE', False: 'FALSE'}
    whois.loc[:, 'whois_privacy'] = whois.loc[:, 'whois_privacy'].map(booleanDictionary)
    whois.loc[:, 'whois_temporary_mail'] = whois.loc[:, 'whois_temporary_mail'].map(booleanDictionary)
    whois.loc[:, 'whois_has_been_renewed'] = whois.loc[:, 'whois_has_been_renewed'].map(booleanDictionary)
    whois.loc[:, 'whois_valid_phone'] = whois.loc[:, 'whois_valid_phone'].map(booleanDictionary)
    to_impute = whois.loc[:, ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value='Not known').fit_transform(to_impute)
    whois.loc[:, ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']] = imputed

    # categroical features, those that are imputed
    whoisdatacomplete = whoisdatacompl
    if whoisdatacomplete:
        enc = OneHotEncoder()
        categorical = enc.fit_transform(
            whois.loc[:, ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']])
        df = pd.DataFrame(categorical.toarray(), columns=enc.get_feature_names(
            ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']),
                          index=whois.index)
        whois = pd.concat([whois, df], axis=1)
        whois = whois.drop(['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone'],
                           axis=1)
    else:

        enc = OneHotEncoder()
        categorical = enc.fit_transform(
            whois.loc[:, ['whois_privacy', 'whois_valid_phone']])
        df = pd.DataFrame(categorical.toarray(), columns=enc.get_feature_names(
            ['whois_privacy', 'whois_valid_phone']), index=whois.index)
        whois = pd.concat([whois, df], axis=1)
        whois = whois.drop(['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone'], axis=1)

    # impute with mean whois_registration_age and whois_registration_and_validity_start_date and whois_registration_period
    to_impute = whois.loc[:, ['whois_registration_age', 'whois_registration_and_family_start_date',
                              'whois_registration_and_validity_start_date', 'whois_registration_period']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='mean').fit_transform(to_impute)
    whois.loc[:,
    ['whois_registration_age', 'whois_registration_and_family_start_date', 'whois_registration_and_validity_start_date',
     'whois_registration_period']] = imputed

    #### dsndb clean up ####
    # impute DNS records to False
    to_impute = dns.loc[:,
                ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                 'dnsdb_record_SOA', 'dnsdb_record_TXT']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=False).fit_transform(to_impute)
    dns.loc[:, ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                'dnsdb_record_SOA', 'dnsdb_record_TXT']] = imputed

    # binarize DNS record booleans
    to_binarize = dns.loc[:,
                  ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                   'dnsdb_record_SOA', 'dnsdb_record_TXT']]
    binarized = LabelBinarizer().fit_transform(to_binarize)
    dns.loc[:, ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                'dnsdb_record_SOA', 'dnsdb_record_TXT']] = binarized

    # impute dns nb_queries, active_period
    to_impute = dns.loc[:, ['dnsdb_active_period', 'dnsdb_nb_queries']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=0).fit_transform(to_impute)
    dns.loc[:, ['dnsdb_active_period', 'dnsdb_nb_queries']] = imputed

    # impute dns timestamps
    to_impute = dns.loc[:, ['dnsdb_first_seen_before_now', 'dnsdb_first_seen_before_validity']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=0).fit_transform(to_impute)
    dns.loc[:, ['dnsdb_first_seen_before_now', 'dnsdb_first_seen_before_validity']] = imputed

    #### Join data ####
    post_analysis_columns = ['malware_family', 'malware_wordlist_based_dga'] + \
                            ['domain', 'malware_validity_length',
                            'topsites_alexa_average_rank', 'topsites_majestic_average_rank',
                            'topsites_quantcast_average_rank', 'topsites_umbrella_average_rank',
                             'malware_validity_start', 'malware_validity_end', 'whois_registration_date', 'whois_registrar']
                            # ['openintel_available', 'openintel_first_seen_before_now',
                            # 'openintel_first_seen_before_validity', 'openintel_nb_days_seen_A',
                            # 'openintel_nb_days_seen_AAAA', 'openintel_nb_days_seen_MX', 'openintel_nb_days_seen_NS',
                            # 'openintel_nb_days_seen_SOA']
    datasources = [source for p, source in zip(sourcepattern, [reputation, dns, whois, openintel]) if int(p)]
    columnnames = [cn for p, cn in
                   zip(sourcepattern, [reputation.columns, dns.columns, whois.columns, openintel.columns]) if int(p)]
    post_analysis_columns = [x for x in post_analysis_columns if x in np.concatenate(columnnames)]
    data = pd.concat(datasources + [label], axis=1, join='inner')
    features = data.drop(['class'] + post_analysis_columns, axis=1)
    labels = data['class']
    post_analysis_labels = data[post_analysis_columns]

    # encode the labels
    le = LabelEncoder()
    labels = le.fit_transform(labels)

    # print(le.classes_)
    # print("Benign is ", le.transform(["benign"]))
    # print("** FINAL COLUMNS: **")
    # print(features.columns)
    # print(features.shape)

    return features, labels, post_analysis_labels

def loadAndCleanDataPerDataSet(malwareFamily, year, whoisdatacompl=True):
    '''
    Contains all data
    :param malwareFamily: whether to include malware family as a feature
    :param year: dataset
    :return:
    '''
    DATAPATH = 'datasets/' + year
    FILENAME = 'weka_multi_output_features_all_instances_none.csv'
    FILENAME1 = 'weka_multi_output_features_all_instances_whois.csv'
    FILENAME2 = 'weka_multi_output_features_all_instances_dnsdb.csv'
    FILENAME3 = 'use_in_weka.csv'

    weka = pd.read_csv(os.path.join(DATAPATH, FILENAME3))
    weka.index = weka['domain']
    weka = weka.drop_duplicates()
    available = weka.loc[:,['dnsdb_available', 'whois_available', 'openintel_available']]

    none = pd.read_csv(os.path.join(DATAPATH, FILENAME))
    none.index = none['domain']
    none = none.drop_duplicates()
    none = none.loc[none['ct_has_certificate'].isnull()==False]
    label = none.iloc[:,-1]
    reputation = none.iloc[:, 0:28]

    whois = pd.read_csv(os.path.join(DATAPATH, FILENAME1))
    whois.index = whois['domain']
    whois = whois.drop_duplicates()

    # label = pd.DataFrame(whois.iloc[:, -1])
    openintel = none.iloc[:, 9:17]
    whois = whois.iloc[:, 28:-1]

    dns = pd.read_csv(os.path.join(DATAPATH, FILENAME2), parse_dates=['malware_validity_start', 'malware_validity_end'])
    dns.index = dns['domain']
    dns = dns.drop_duplicates()
    dns = dns.iloc[:, 2:13]
    ind_intersection = available[available['dnsdb_available']==True].index.intersection(dns.index)
    dns = dns.loc[ind_intersection]


    #### Open Intel clean up ####
    openintel = openintel[openintel['openintel_available'] == True]
    # redifine label, as openintel offers least amount of labels
    # label = pd.DataFrame(openintel.iloc[:, -1])
    openintel = openintel.drop(['openintel_available'], axis=1)


    more_columns_to_drop = ['openintel_available', 'openintel_first_seen_before_now',
                            'openintel_first_seen_before_validity', 'openintel_nb_days_seen_A',
                            'openintel_nb_days_seen_AAAA', 'openintel_nb_days_seen_MX', 'openintel_nb_days_seen_NS',
                            'openintel_nb_days_seen_SOA', 'malware_family', 'malware_wordlist_based_dga',
                            'topsites_alexa_average_rank', 'topsites_majestic_average_rank',
                            'topsites_quantcast_average_rank', 'topsites_umbrella_average_rank',
                            'malware_validity_start', 'malware_validity_end', 'domain', 'malware_validity_length'
                            ]
    reputation = reputation.drop(more_columns_to_drop, axis=1)

    ### Dates ###
    # reputation['malware_validity_start'] = pd.to_datetime(reputation['malware_validity_start'], unit='s')
    # reputation['malware_validity_end'] = pd.to_datetime(reputation['malware_validity_end'], unit='s')
    whois['whois_registration_date'] = pd.to_datetime(whois['whois_registration_date'], unit='s')

    # binarize
    if malwareFamily == True:
        to_binarize = reputation.loc[:, ['malware_wordlist_based_dga','ct_has_certificate', 'topsites_alexa_presence', 'topsites_majestic_presence',
                                         'topsites_quantcast_presence', 'topsites_umbrella_presence']]
        binarized = Binarizer().transform(to_binarize)
        reputation.loc[:,
        ['malware_wordlist_based_dga', 'ct_has_certificate', 'topsites_alexa_presence', 'topsites_majestic_presence', 'topsites_quantcast_presence',
         'topsites_umbrella_presence']] = binarized
    else:
        to_binarize = reputation.loc[:, ['ct_has_certificate', 'topsites_alexa_presence',
                                         'topsites_majestic_presence',
                                         'topsites_quantcast_presence', 'topsites_umbrella_presence']]
        binarized = Binarizer().transform(to_binarize)
        reputation.loc[:,
        ['ct_has_certificate', 'topsites_alexa_presence', 'topsites_majestic_presence',
         'topsites_quantcast_presence',
         'topsites_umbrella_presence']] = binarized

    # encode categorical feature
    if malwareFamily == True:
        enco = OneHotEncoder()
        categorical = enco.fit_transform(reputation.loc[:, ['malware_family']])
        df = pd.DataFrame(categorical.toarray(), columns=enco.get_feature_names(
            ['malware_family']), index=reputation.index)
        reputation = pd.concat([reputation, df], axis=1)
        reputation = reputation.drop(['malware_family'], axis=1)

    # impute search_wayback
    to_impute = reputation.loc[:, ['search_pages_found_wayback_machine', 'search_wayback_machine_first_seen_before_now',
                                   'search_wayback_machine_first_seen_before_validity']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=0).fit_transform(to_impute)
    reputation.loc[:, ['search_pages_found_wayback_machine', 'search_wayback_machine_first_seen_before_now',
                       'search_wayback_machine_first_seen_before_validity']] = imputed

    #### whois clean up ####
    # impute whois_privacy and whois_temporary_mail with Not known
    booleanDictionary = {True: 'TRUE', False: 'FALSE'}
    whois.loc[:, 'whois_privacy'] = whois.loc[:, 'whois_privacy'].map(booleanDictionary)
    whois.loc[:, 'whois_temporary_mail'] = whois.loc[:, 'whois_temporary_mail'].map(booleanDictionary)
    whois.loc[:, 'whois_has_been_renewed'] = whois.loc[:, 'whois_has_been_renewed'].map(booleanDictionary)
    whois.loc[:, 'whois_valid_phone'] = whois.loc[:, 'whois_valid_phone'].map(booleanDictionary)
    to_impute = whois.loc[:, ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value='Not known').fit_transform(to_impute)
    whois.loc[:, ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']] = imputed

    # categroical features, those that are imputed
    whoisdatacomplete = whoisdatacompl
    if whoisdatacomplete:
        enc = OneHotEncoder()
        categorical = enc.fit_transform(
            whois.loc[:, ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']])
        df = pd.DataFrame(categorical.toarray(), columns=enc.get_feature_names(
            ['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone']),
                          index=whois.index)
        whois = pd.concat([whois, df], axis=1)
        whois = whois.drop(['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone'],
                           axis=1)
    else:

        enc = OneHotEncoder()
        categorical = enc.fit_transform(
            whois.loc[:, ['whois_privacy', 'whois_valid_phone']])
        df = pd.DataFrame(categorical.toarray(), columns=enc.get_feature_names(
            ['whois_privacy', 'whois_valid_phone']), index=whois.index)
        whois = pd.concat([whois, df], axis=1)
        whois = whois.drop(['whois_privacy', 'whois_temporary_mail', 'whois_has_been_renewed', 'whois_valid_phone'],
                           axis=1)
    whois = whois.drop(['whois_registration_date', 'whois_registrar'], axis=1)

    # impute with mean whois_registration_age and whois_registration_and_validity_start_date and whois_registration_period
    to_impute = whois.loc[:, ['whois_registration_age', 'whois_registration_and_family_start_date',
                              'whois_registration_and_validity_start_date', 'whois_registration_period']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='mean').fit_transform(to_impute)
    whois.loc[:,
    ['whois_registration_age', 'whois_registration_and_family_start_date', 'whois_registration_and_validity_start_date',
     'whois_registration_period']] = imputed

    #### dsndb clean up ####
    # impute DNS records to False
    to_impute = dns.loc[:,
                ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                 'dnsdb_record_SOA', 'dnsdb_record_TXT']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=False).fit_transform(to_impute)
    dns.loc[:, ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                'dnsdb_record_SOA', 'dnsdb_record_TXT']] = imputed

    # binarize DNS record booleans
    to_binarize = dns.loc[:,
                  ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                   'dnsdb_record_SOA', 'dnsdb_record_TXT']]
    binarized = LabelBinarizer().fit_transform(to_binarize)
    dns.loc[:, ['dnsdb_record_A', 'dnsdb_record_AAAA', 'dnsdb_record_CNAME', 'dnsdb_record_MX', 'dnsdb_record_NS',
                'dnsdb_record_SOA', 'dnsdb_record_TXT']] = binarized

    # impute dns nb_queries, active_period
    to_impute = dns.loc[:, ['dnsdb_active_period', 'dnsdb_nb_queries']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=0).fit_transform(to_impute)
    dns.loc[:, ['dnsdb_active_period', 'dnsdb_nb_queries']] = imputed

    # impute dns timestamps
    to_impute = dns.loc[:, ['dnsdb_first_seen_before_now', 'dnsdb_first_seen_before_validity']]
    imputed = SimpleImputer(missing_values=np.nan, strategy='constant', fill_value=0).fit_transform(to_impute)
    dns.loc[:, ['dnsdb_first_seen_before_now', 'dnsdb_first_seen_before_validity']] = imputed

    return available, reputation, dns, whois, openintel, label

def loadAndCleanDataExactPattern(code, available, reputation, dns, whois, openintel, label):
    if code[0]:
        df = available.loc[(available['dnsdb_available'] == code[1]) &
                           (available['whois_available'] == code[2]) &
                           (available['openintel_available'] == code[3])]
        datasets = [ds for ds, i in zip([dns, whois, openintel], code[1:]) if i]
        features = pd.concat([reputation] + datasets + [df], axis=1, join='inner')
        features = features.drop(['dnsdb_available', 'whois_available', 'openintel_available'], axis=1)

        labelzz = pd.concat([label, df], axis=1, join='inner')
        labelzz = labelzz.loc[:, 'class']
        classDictionary = {'malicious': 1, 'benign': 0}
        labelzz = labelzz.map(classDictionary)
    else:
        features = pd.DataFrame()
        labelzz = pd.Series()


    return features.sort_index(), labelzz.sort_index()

def loadAndCleanDataExactPatternAlt(code, available, reputation, dns, whois, openintel, label):

    df = available.loc[(available['reputation_available'] == code[0]) &
                       (available['dnsdb_available'] == code[1]) &
                       (available['whois_available'] == code[2]) &
                       (available['openintel_available'] == code[3])]
    datasets = [ds for ds, i in zip([reputation, dns, whois, openintel], code) if i]
    features = pd.concat(datasets + [df], axis=1, join='inner')
    features = features.drop(['reputation_available','dnsdb_available', 'whois_available', 'openintel_available'], axis=1)

    labelzz = pd.concat([label, df], axis=1, join='inner')
    labelzz = labelzz.loc[:, 'class']
    classDictionary = {'malicious': 1, 'benign': 0}
    labelzz = labelzz.map(classDictionary)

    return features.sort_index(), labelzz.sort_index()


