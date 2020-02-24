import pandas as pd
import numpy as np
import utils
import argparse

from joblib import load
import itertools
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import KFold, StratifiedKFold
from sklearn.metrics import confusion_matrix, f1_score, roc_auc_score, precision_score, recall_score, accuracy_score
from evaluation.metrics import workReducedPostLoadThr, workReducedPostDetermineThrOneGo, workReducedPostDetermineThr

import dataprocessing.preprocessing as pre
import macroify

import bob.measure

'''Evaluates the ensemble when training and testing on the same year. Thus, executes experiment.py for every model.'''

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Do the avalanche experiments')

    parser.add_argument('--year', '-y',
                        type=str,
                        default='2018',
                        help='year to consider')

    args = parser.parse_args()
    year = args.year

    available, reputation, dns, whois, openintel, label = pre.loadAndCleanDataPerDataSet(False, year)

    total_fp = 0
    total_fn = 0
    total_manual = 0
    total_pred = 0
    total_amount_of_domains = len(available.index)
    classDictionary = {'malicious': 1, 'benign': 0}
    labelzsss = label.map(classDictionary)
    total_amount_positive = labelzsss.sum()
    total_amount_negative = len(labelzsss.index) - labelzsss.sum()
    l = [False, True]
    dfs = []
    codesz = []
    ensemble_predictions = []
    ensemble_labels = []
    ensemble_scores_pos = []
    ensemble_scores_neg = []
    ensemble_predictions_priori = []
    ensemble_labels_priori = []
    metrics = {'f1': [], 'precision': [], 'recall': [], 'acc_train': [], 'acc_test': [], 'eer': [],
               'fnr_work_reduced': [],
               'fpr_work_reduced': [], 'work_reduced': [], 'work_reduced_negative': [], 'work_reduced_positive': []}

    i = 1
    kf = StratifiedKFold(n_splits=10, shuffle=True, random_state=44)
    for train_index, test_index in kf.split(available.values, label):
        # Df index.
        df_train_ind, df_test_ind = available.iloc[train_index].index, available.iloc[test_index].index

        for x in itertools.product(l, repeat=4):
            code = ''.join(['1' if i else '0' for i in x])
            if code != '0000':
                features_maxdata, labelzz_max_data, _ = pre.loadAndCleanDataMaxDom(code, False, year)
                labelzz_max_data = pd.Series(labelzz_max_data, index=features_maxdata.index)

                tr_index = df_train_ind.intersection(features_maxdata.index)
                te_index = df_test_ind.intersection(features_maxdata.index)

                x_train, x_test = features_maxdata.loc[tr_index], features_maxdata.loc[te_index]
                y_train, y_test = labelzz_max_data.loc[tr_index], labelzz_max_data.loc[te_index]

                clf_tuned = load('models/'+ year +'/model' + code + '.joblib')
                if isinstance(clf_tuned, GradientBoostingClassifier):
                    params = clf_tuned.get_params()
                    clf = GradientBoostingClassifier(**params)
                else:
                    params = clf_tuned.best_params_
                    clf = GradientBoostingClassifier(**params, random_state=42)
                clf.fit(x_train, y_train)

                y_pred = clf.predict(x_test)
                scores = clf.predict_proba(x_test)

                features, labelzz = pre.loadAndCleanDataExactPattern(x, available, reputation, dns, whois, openintel,
                                                                     label)
                ind_now_in_test_set = features.index.intersection(df_test_ind)
                features = features.loc[ind_now_in_test_set]
                labelzz = labelzz.loc[ind_now_in_test_set]
                amount_of_domains = len(features.index)
                codesz.append(code)
                print(amount_of_domains, 'domains to classify for sourcepattern', code)
                if len(labelzz.index != 0):

                    scores = clf.predict_proba(features)
                    predictions = clf.predict(features)

                    positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
                    work_reduced_positive, _, _ = workReducedPostDetermineThrOneGo(x_train, y_train, code, scores, labelzz)

                    total_fp += (len(positive_pred) - sum(positive_pred))
                    total_fn += sum(negative_pred)
                    total_manual += len(no_action_pred)
                    total_pred += (len(positive_pred) + len(negative_pred))

                    ensemble_predictions = ensemble_predictions + [1] * len(positive_pred) + [0] * len(
                        negative_pred) + no_action_pred
                    ensemble_labels = ensemble_labels + positive_pred + negative_pred + no_action_pred
                    ensemble_predictions_priori = ensemble_predictions_priori + predictions.tolist()
                    ensemble_labels_priori = ensemble_labels_priori + labelzz.values.tolist()
                    ensemble_scores_neg = ensemble_scores_neg + scores[:, 1][labelzz == 0].tolist()
                    ensemble_scores_pos = ensemble_scores_pos + scores[:, 1][labelzz == 1].tolist()

                    print('Makes a prediction for', (len(positive_pred) + len(negative_pred)), 'domains')
                    print('Would predict', np.sum(predictions), 'domains malicious')

print('Total work reduced', (total_amount_of_domains-total_manual)/total_amount_of_domains)
print('Total FNR', total_fn/total_amount_positive)
print('Total FPR', total_fp/total_amount_negative)

print('Accuracy', accuracy_score(ensemble_labels, ensemble_predictions))
print('F1', f1_score(ensemble_labels, ensemble_predictions))
print('Precision', precision_score(ensemble_labels, ensemble_predictions))
print('Recall', recall_score(ensemble_labels, ensemble_predictions))

print('Little check', total_amount_positive+total_amount_negative == total_amount_of_domains)
print('Little check', total_pred+total_manual == total_amount_of_domains)

results = {}
y = utils.translateyear(year)
z = utils.translateyear(year)

results[y+z+'workreduced'+ 'posteriori'] = (total_amount_of_domains-total_manual)/total_amount_of_domains *100
results[y+z+'fnr'+ 'posteriori'] = total_fn/total_amount_positive *100
results[y+z+'fpr'+ 'posteriori'] = total_fp/total_amount_negative *100
results[y+z+'accuracy'+ 'posteriori'] = accuracy_score(ensemble_labels, ensemble_predictions) *100
results[y+z+'fone'+ 'posteriori'] = f1_score(ensemble_labels, ensemble_predictions) *100
results[y+z+'precision'+ 'posteriori'] = precision_score(ensemble_labels, ensemble_predictions) *100
results[y+z+'recall' + 'posteriori'] = recall_score(ensemble_labels, ensemble_predictions) *100
results[y+z+'accuracy'] = accuracy_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
results[y+z+'fone'] = f1_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
results[y+z+'precision'] = precision_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
results[y+z+'recall'] = recall_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
results[y+z+'eer'] = bob.measure.eer(ensemble_scores_neg,ensemble_scores_pos) *100


macroify.append_file(results)
