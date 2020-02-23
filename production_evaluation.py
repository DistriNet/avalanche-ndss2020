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

# import bob.measure


import warnings
warnings.filterwarnings("ignore")

def saveimportance(importances, featurenames):
    df = pd.DataFrame({'featurename':featurenames, 'score':importances})
    df = df.sort_values('score',ascending=False)
    print(df)
    df.to_csv('dfs/importance1.csv')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Do the avalanche experiments')

    parser.add_argument('--trainyear', '-tr',
                        type=str,
                        default='2017',
                        help='year to consider')

    parser.add_argument('--testyear', '-te',
                        type=str,
                        default='2018',
                        help='year to consider')

    args = parser.parse_args()

    testyear = args.testyear
    trainyear = args.trainyear
    results = {}
    y = utils.translateyear(trainyear)
    z = utils.translateyear(testyear)

    available, reputation, dns, whois, openintel, label = pre.loadAndCleanDataPerDataSet(False, testyear)

    total_fp = 0
    total_fn = 0
    total_manual = 0
    total_pred = 0
    total_amount_of_domains = len(available.index)
    classDictionary = {'malicious': 1, 'benign': 0}
    labelzsss = label.map(classDictionary)
    total_amount_positive = labelzsss.sum()
    total_amount_negative = len(labelzsss.index) - labelzsss.sum()
    l = [False,True]
    dfs = []
    codesz = []
    ensemble_scores_pos = []
    ensemble_scores_neg = []
    ensemble_predictions = []
    ensemble_predictions_priori = []
    ensemble_labels_priori = []
    ensemble_labels = []
    metrics = { 'f1': [], 'precision': [], 'recall': [], 'acc_train': [], 'acc_test': [], 'eer': [], 'fnr_work_reduced': [],
                'fpr_work_reduced': [], 'work_reduced': [], 'work_reduced_negative': [], 'work_reduced_positive': []}
    for x in itertools.product(l,repeat=4):
        code = ''.join(['1' if i else '0' for i in x])
        if code != '0000':  # code[0] != '0'
            clf = load('models/' + trainyear + '/model' + code + '.joblib')
            features_maxdata, labelzz_max_data, _ = pre.loadAndCleanDataMaxDom(code, False, testyear)

            # Evaluate model performance on max domains
            predictions = clf.predict(features_maxdata)
            metrics['acc_test'].append(accuracy_score(labelzz_max_data, predictions))
            metrics['f1'].append(f1_score(labelzz_max_data, predictions))
            metrics['precision'].append(precision_score(labelzz_max_data, predictions))
            metrics['recall'].append(recall_score(labelzz_max_data, predictions))

            # Evaluate model performance work reduced
            scores = clf.predict_proba(features_maxdata)
            positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
            work_reduced_positive, _, _ = workReducedPostLoadThr(trainyear, code, scores, labelzz_max_data)
            metrics['work_reduced_negative'].append(work_reduced_negative)
            metrics['work_reduced_positive'].append(work_reduced_positive)
            metrics['work_reduced'].append(work_reduced)
            metrics['fnr_work_reduced'].append(fnr)
            metrics['fpr_work_reduced'].append(fpr)

            # Construct domains that should be classified by this model
            features, labelzz = pre.loadAndCleanDataExactPattern(x, available, reputation, dns, whois, openintel, label)
            amount_of_domains = len(features.index)
            codesz.append(code)
            print(amount_of_domains, 'domains to classify for sourcepattern', code)
            if len(labelzz.index != 0):
                print('With', amount_of_domains-labelzz.sum(), 'negative domains and', labelzz.sum(), 'positive domains')

                index = features.index
                scores = clf.predict_proba(features)
                predictions = clf.predict(features)
                df = pd.DataFrame(list(zip(predictions, scores[:,1], len(predictions)*[code])),
                                  index=features.index, columns=['classification 0=benign, 1=malicious', 'score', 'model code'])

                positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
                work_reduced_positive, _, _ = workReducedPostLoadThr(trainyear, code, scores, labelzz)

                total_fp += (len(positive_pred) - sum(positive_pred))
                total_fn += sum(negative_pred)
                total_manual += len(no_action_pred)
                total_pred += (len(positive_pred) + len(negative_pred))

                ensemble_predictions = ensemble_predictions + [1]*len(positive_pred) + [0]*len(negative_pred) + no_action_pred
                ensemble_labels = ensemble_labels + positive_pred + negative_pred + no_action_pred

                ensemble_predictions_priori = ensemble_predictions_priori + predictions.tolist()
                ensemble_labels_priori = ensemble_labels_priori + labelzz.values.tolist()

                dfs.append(df)

                ensemble_scores_neg = ensemble_scores_neg + scores[:, 1][labelzz == 0].tolist()
                ensemble_scores_pos = ensemble_scores_pos + scores[:, 1][labelzz == 1].tolist()

                print('Makes a prediction for', (len(positive_pred) + len(negative_pred)), 'domains')
                print('Would predict', np.sum(predictions), 'domains malicious')

    # Save predictions
    df = pd.concat(dfs)
    print(len(df.index)," predictions made")
    df.to_csv('dfs/predictions.csv')

    # Print performance per model
    print('===============================================================================')
    for key, value in metrics.items():
        if value:
            print('========== %s ============' % (key))
            for i,v in enumerate(value):
                print('Model %s: %.3f' % (codesz[i], v))
                # codestr = utils.translatecode(code)
                # results[y+z+key + codestr] = v
    print('===============================================================================')

    print('Total work reduced', (total_amount_of_domains-total_manual)/total_amount_of_domains)
    print('Total FNR', total_fn/total_amount_positive)
    print('Total FPR', total_fp/total_amount_negative)

    print('Accuracy', accuracy_score(ensemble_labels, ensemble_predictions))
    print('F1', f1_score(ensemble_labels, ensemble_predictions))
    print('Precision', precision_score(ensemble_labels, ensemble_predictions))
    print('Recall', recall_score(ensemble_labels, ensemble_predictions))

    print('Little check', total_amount_positive+total_amount_negative == total_amount_of_domains)
    print('Little check', total_pred+total_manual == total_amount_of_domains)

    results[y+z+'workreduced'+ 'posteriori'] = (total_amount_of_domains-total_manual)/total_amount_of_domains *100
    results[y+z+'fnr'+ 'posteriori'] = total_fn/total_amount_positive *100
    results[y+z+'fpr'+ 'posteriori'] = total_fp/total_amount_negative *100
    results[y+z+'accuracy'+ 'posteriori'] = accuracy_score(ensemble_labels, ensemble_predictions) *100
    results[y+z+'fone'+ 'posteriori'] = f1_score(ensemble_labels, ensemble_predictions) *100
    results[y+z+'precision'+ 'posteriori'] = precision_score(ensemble_labels, ensemble_predictions) *100
    results[y+z+'recall'+ 'posteriori'] = recall_score(ensemble_labels, ensemble_predictions) *100

    results[y + z + 'accuracy'] = accuracy_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
    results[y + z + 'fone'] = f1_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
    results[y + z + 'precision'] = precision_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
    results[y + z + 'recall'] = recall_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
    results[y + z + 'eer'] = bob.measure.eer(ensemble_scores_neg, ensemble_scores_pos) * 100
    # fpr, fnr = bob.measure.farfrr(ensemble_scores_neg, ensemble_scores_pos, 0.5)
    results[y + z + 'fpr'] = fpr*100
    results[y + z + 'fnr'] = fnr*100

    macroify.append_file(results)

    print('Little check 2', len(ensemble_scores_neg) + len(ensemble_scores_pos) == total_amount_of_domains)

    np.savez('dfs/' + trainyear + '_' + testyear + 'ensemble_det_curve.npz', pos=ensemble_scores_pos, neg=ensemble_scores_neg)
