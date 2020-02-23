import datetime
import os
import argparse
import json

import matplotlib.ticker
import matplotlib.patches as patches
import pandas as pd
import numpy as np
import utils

from sklearn.preprocessing import StandardScaler, Binarizer, LabelEncoder, LabelBinarizer, OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.impute import SimpleImputer
from joblib import load
import itertools
from sklearn.metrics import confusion_matrix, f1_score, roc_auc_score, precision_score, recall_score, accuracy_score
from evaluation.metrics import workReducedPostLoadThr

import dataprocessing.preprocessing as pre
import macroify

import bob.measure


import warnings
warnings.filterwarnings("ignore")

if __name__ == "__main__":
    # 'Do the avalanche experiments, dataset impact evaluation of the extended model'
    results_posteriori = {'work_reduction_metric':[], 'fnr_metric': [], 'fpr_metric': [], 'accuracy_metric': [], 'f1_metric': [],
               'precision_metric': [],'recall_metric': [], 'eer_metric':[]}
    results_priori = {'work_reduction_metric': [], 'fnr_metric': [], 'fpr_metric': [], 'accuracy_metric': [], 'f1_metric': [],
               'precision_metric': [], 'recall_metric': [], 'eer_metric': []}
    missing_column = []

    for to_drop in ['None','reputation_available', 'dnsdb_available', 'whois_available', 'openintel_available']:
        available, reputation, dns, whois, openintel, label = pre.loadAndCleanDataPerDataSet(False, '2018')
        available['reputation_available'] = [True] * len(available.index)

        # real amount of labels with extra_train
        total_amount_of_2018_domains = len(available.index)
        classDictionary = {'malicious': 1, 'benign': 0}
        labelzsss = label.map(classDictionary)
        total_amount_2018_positive = labelzsss.sum()
        total_amount_2018_negative = len(labelzsss.index) - labelzsss.sum()

        # dropping train labels
        ind_extra_train = load('models/' + 'extended' + '/additionaltrainindices.joblib')
        manual_added_to_trainingset = len(ind_extra_train)
        available = available.drop(ind_extra_train)
        reputation = reputation.drop(ind_extra_train)
        dns = dns.drop(ind_extra_train)
        whois = whois.drop(ind_extra_train)
        openintel = openintel.drop(ind_extra_train)
        label = label.drop(ind_extra_train)

        # amount of evaluation data
        total_amount_of_domains = len(available.index)
        classDictionary = {'malicious': 1, 'benign': 0}
        labelzsss = label.map(classDictionary)
        total_amount_positive = labelzsss.sum()
        total_amount_negative = len(labelzsss.index) - labelzsss.sum()

        if to_drop == 'activeandpassive':
            available['dnsdb_available'] = [False] * len(available.index)
            available['openintel_available'] = [False] * len(available.index)
        elif not to_drop == 'None':
            available[to_drop] = [False]*len(available.index)

        # keeping track of results
        total_fp = 0
        total_fn = 0
        total_manual = 0
        total_pred = 0
        total_amount_of_domains = len(available.index)

        dfs = []
        codesz = []
        ensemble_predictions = []
        ensemble_labels = []
        ensemble_scores_pos = []
        ensemble_scores_neg = []
        ensemble_predictions_priori = []
        ensemble_labels_priori = []

        metrics = { 'f1': [], 'precision': [], 'recall': [], 'acc_train': [], 'acc_test': [], 'eer': [], 'fnr_work_reduced': [],
                    'fpr_work_reduced': [], 'work_reduced': [], 'work_reduced_negative': [], 'work_reduced_positive': []}

        l = [False, True]
        for x in itertools.product(l,repeat=4):
            code = ''.join(['1' if i else '0' for i in x])
            features, labelzz = pre.loadAndCleanDataExactPatternAlt(x, available, reputation, dns, whois, openintel,
                                                                    label)
            amount_of_domains = len(features.index)
            print(amount_of_domains, 'domains to classify for sourcepattern', code)
            if code != '0000':  # code[0] != '0'
                clf = load('models/' + 'extended' + '/model' + code + '.joblib')

                # Construct domains that should be classified by this model

                if len(labelzz.index != 0):
                    print('With', amount_of_domains-labelzz.sum(), 'negative domains and', labelzz.sum(), 'positive domains')

                    index = features.index
                    scores = clf.predict_proba(features)
                    predictions = clf.predict(features)
                    df = pd.DataFrame(list(zip(predictions, scores[:,1], len(predictions)*[code])),
                                      index=features.index, columns=['classification 0=benign, 1=malicious', 'score', 'model code'])

                    positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
                    work_reduced_positive, _, _ = workReducedPostLoadThr('extended', code, scores, labelzz)

                    total_fp += (len(positive_pred) - sum(positive_pred))
                    total_fn += sum(negative_pred)
                    total_manual += len(no_action_pred)
                    total_pred += (len(positive_pred) + len(negative_pred))

                    ensemble_predictions = ensemble_predictions + [1]*len(positive_pred) + [0]*len(negative_pred) + no_action_pred
                    ensemble_labels = ensemble_labels + positive_pred + negative_pred + no_action_pred

                    ensemble_predictions_priori = ensemble_predictions_priori + predictions.tolist()
                    ensemble_labels_priori = ensemble_labels_priori + labelzz.values.tolist()

                    ensemble_scores_neg = ensemble_scores_neg + scores[:, 1][labelzz == 0].tolist()
                    ensemble_scores_pos = ensemble_scores_pos + scores[:, 1][labelzz == 1].tolist()

                    print('Makes a prediction for', (len(positive_pred) + len(negative_pred)), 'domains')
                    print('Would predict', np.sum(predictions), 'domains malicious')
            else:
                total_manual += len(labelzz.index)
                ensemble_predictions = ensemble_predictions + labelzz.values.tolist()
                ensemble_labels = ensemble_labels + labelzz.values.tolist()

        print('Total work reduced', (total_amount_of_domains-total_manual)/total_amount_of_domains)
        print('Total FNR', total_fp/total_amount_negative)
        print('Total FPR', total_fn/total_amount_positive)
        print('Total work reduced real', (total_amount_of_2018_domains - total_manual - manual_added_to_trainingset) / total_amount_of_2018_domains)
        print('Total FNR real', total_fn / total_amount_2018_positive)
        print('Total FPR real', total_fp / total_amount_2018_negative)

        print('Accuracy', accuracy_score(ensemble_labels, ensemble_predictions))
        print('F1', f1_score(ensemble_labels, ensemble_predictions))
        print('Precision', precision_score(ensemble_labels, ensemble_predictions))
        print('Recall', recall_score(ensemble_labels, ensemble_predictions))

        print('Little check', total_amount_positive+total_amount_negative == total_amount_of_domains)
        print('Little check', total_pred+total_manual == total_amount_of_domains)
        print('Little check', len(ensemble_scores_pos) + len(ensemble_scores_neg) == total_amount_of_domains)
        print('Little check', len(ensemble_scores_pos) == total_amount_positive)
        print('Little check', len(ensemble_scores_neg) == total_amount_negative)
        print('Little check', total_amount_of_domains + manual_added_to_trainingset == total_amount_of_2018_domains)

        results_posteriori['work_reduction_metric'].append((total_amount_of_2018_domains - total_manual - manual_added_to_trainingset) / total_amount_of_2018_domains)
        results_posteriori['fnr_metric'].append(total_fn / total_amount_2018_positive)
        results_posteriori['fpr_metric'].append(total_fp / total_amount_2018_negative)
        results_posteriori['accuracy_metric'].append(accuracy_score(ensemble_labels, ensemble_predictions))
        results_posteriori['f1_metric'].append(f1_score(ensemble_labels, ensemble_predictions))
        results_posteriori['precision_metric'].append(precision_score(ensemble_labels, ensemble_predictions))
        results_posteriori['recall_metric'].append(recall_score(ensemble_labels, ensemble_predictions))

        results_posteriori['eer_metric'].append(bob.measure.eer(ensemble_scores_neg,ensemble_scores_pos))
        results_priori['eer_metric'].append(bob.measure.eer(ensemble_scores_neg,ensemble_scores_pos))

        results_priori['work_reduction_metric'].append((total_amount_of_2018_domains - total_manual - manual_added_to_trainingset) / total_amount_of_2018_domains)
        results_priori['fnr_metric'].append(total_fn / total_amount_2018_positive)
        results_priori['fpr_metric'].append(total_fp / total_amount_2018_negative)
        results_priori['accuracy_metric'].append(accuracy_score(ensemble_labels_priori, ensemble_predictions_priori))
        results_priori['f1_metric'].append(f1_score(ensemble_labels_priori, ensemble_predictions_priori))
        results_priori['precision_metric'].append(precision_score(ensemble_labels_priori, ensemble_predictions_priori))
        results_priori['recall_metric'].append(recall_score(ensemble_labels_priori, ensemble_predictions_priori))

        missing_column.append(to_drop)

    df = pd.DataFrame(results_posteriori, index=missing_column)
    df.to_csv('dfs/' + 'extended' + '/dataset_impact_posteriori.csv')

    df = pd.DataFrame(results_priori, index=missing_column)
    df.to_csv('dfs/' + 'extended' + '/dataset_impact_priori.csv')
