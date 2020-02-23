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
from evaluation.metrics import workReducedPostDetermineThrOneGoBis
import evaluation.preanalysis as prean

import dataprocessing.preprocessing as pre
import macroify

if __name__ == "__main__":
    results = {}

    features_2017, labelzz_2017, _ = pre.loadAndCleanDataMaxDom('1111', False, '2017', whoisdatacompl=True)
    features_2018, labelzz_2018, _ = pre.loadAndCleanDataMaxDom('1111', False, '2018', whoisdatacompl=True)

    x_train = pd.concat([features_2017, features_2018])
    y_train = np.concatenate([labelzz_2017, labelzz_2018])

    prean.covMatrix(x_train,y_train,'extended/')
    available, reputation, dns, whois, openintel, label = pre.loadAndCleanDataPerDataSet(False, '2019', whoisdatacompl=False)
    
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
            features_2017, labelzz_2017, _ = pre.loadAndCleanDataMaxDom(code, False, '2017', whoisdatacompl=False)
            features_2018, labelzz_2018, _ = pre.loadAndCleanDataMaxDom(code, False, '2018', whoisdatacompl=False)

            x_train = pd.concat([features_2017, features_2018])
            y_train = np.concatenate([labelzz_2017, labelzz_2018])
            y_train_category = np.concatenate([labelzz_2017, labelzz_2018*2])

            clf_tuned = load('models/2017/model' + code + '.joblib')
            if isinstance(clf_tuned, GradientBoostingClassifier):
                params = clf_tuned.get_params()
                clf = GradientBoostingClassifier(**params)
            else:
                params = clf_tuned.best_params_
                clf = GradientBoostingClassifier(**params, random_state=42)
            clf.fit(x_train, y_train)

            # Construct domains that should be classified by this model
            features, labelzz = pre.loadAndCleanDataExactPattern(x, available, reputation, dns, whois, openintel, label)
            amount_of_domains = len(features.index)
            codesz.append(code)
            print(amount_of_domains, 'domains to classify for sourcepattern', code)
            if len(labelzz.index != 0):
                print(features.columns)
                print('With', amount_of_domains-labelzz.sum(), 'negative domains and', labelzz.sum(), 'positive domains')
                scores = clf.predict_proba(features)
                predictions = clf.predict(features)
                df = pd.DataFrame(list(zip(predictions, scores[:,1], len(predictions)*[code])),
                                  index=features.index, columns=['classification 0=benign, 1=malicious', 'score', 'model code'])

                positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
                work_reduced_positive, _, _ = workReducedPostDetermineThrOneGoBis(x_train, y_train, code, scores,
                                                                                  labelzz, y_train_category, [0.02])
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
    df.to_csv('dfs/2019/predictions.csv')

    print('Total work reduced', (total_amount_of_domains-total_manual - total_amount_of_domains*0.15)/total_amount_of_domains)
    print('Total FNR', total_fn/total_amount_positive)
    print('Total FPR', total_fp/total_amount_negative)

    print('Accuracy', accuracy_score(ensemble_labels, ensemble_predictions))
    print('F1', f1_score(ensemble_labels, ensemble_predictions))
    print('Precision', precision_score(ensemble_labels, ensemble_predictions))
    print('Recall', recall_score(ensemble_labels, ensemble_predictions))

    print('Little check', total_amount_positive+total_amount_negative == total_amount_of_domains)
    print('Little check', total_pred+total_manual == total_amount_of_domains)

    results['Cworkreducedextended'] = (total_amount_of_domains-total_manual)/total_amount_of_domains *100
    results['Cworkreduced'] = (total_amount_of_domains-total_manual - total_amount_of_domains*0.15)/total_amount_of_domains*100

    macroify.append_file(results)

    print('Little check 2', len(ensemble_scores_neg) + len(ensemble_scores_pos) == total_amount_of_domains)

