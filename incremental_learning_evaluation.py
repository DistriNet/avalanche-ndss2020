import dataprocessing.preprocessing as pre

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from joblib import load
import utils

import argparse
import pandas as pd
import numpy as np
import itertools
from joblib import dump

from sklearn.metrics import confusion_matrix, f1_score, roc_auc_score, precision_score, recall_score, accuracy_score
from evaluation.metrics import workReducedPostLoadThr, workReducedPostDetermineThr, workReducedPostDetermineThrOneGo, \
    workReducedPostDetermineThrOneGoOneYear, workReducedPost, workReducedPostDetermineThrOneGoBis
import dataprocessing.sampleselection as ss
import evaluation.postanalysis as postan
import macroify
import bob.measure

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Train production classifier with some 2018 data. This code implements more techniques than described in the NDSS 2020 paper')

    parser.add_argument('--strategy', '-st',
                        type=str,
                        default='random',
                        help='How to select the additional samples that have to be added, should be either random')

    args = parser.parse_args()
    strategy = args.strategy

    # We tried more strategies to select additional data than described in the NDSS paper.
    strategies = {'random': ss.random, 'practical': ss.practical, 'practicalFraction':ss.practicalFraction}
    if strategy == 'random':
        fraction = 0.15
    else:
        fraction = 100

    results = {}

    method = {'random':ss.random, 'practical':ss.practical, 'practicalFraction':ss.practicalFraction}

    available, reputation, dns, whois, openintel, label = pre.loadAndCleanDataPerDataSet(False, '2018')
    total_amount_of_2018_domains = len(available.index)

    costs = [0.001, 0.005, 0.01, 0.02]
    workreduceddict = {}
    for c in costs:
        workreduceddict[c] = {}
        workreduceddict[c]['total_fp'] = 0
        workreduceddict[c]['total_fn'] = 0
        workreduceddict[c]['total_manual'] = 0
        workreduceddict[c]['total_pred'] = 0
        workreduceddict[c]['ensemble_predictions'] = []
        workreduceddict[c]['ensemble_labels'] = []
        workreduceddict[c]['ensemble_scores_pos'] = []
        workreduceddict[c]['ensemble_scores_neg'] = []
        workreduceddict[c]['ensemble_predictions_priori'] = []
        workreduceddict[c]['ensemble_labels_priori'] = []
    whoisclassified_domians_dfs = []
    whoisclassified_domains_labels = []
    whoisclassified_domains_prediction = []

    classDictionary = {'malicious': 1, 'benign': 0}
    labelzsss = label.map(classDictionary)
    total_amount_2018_positive = labelzsss.sum()
    total_amount_2018_negative = len(labelzsss.index) - labelzsss.sum()
    l = [False,True]
    dfs = []
    codesz = []
    metrics = { 'f1': [], 'precision': [], 'recall': [], 'acc_train': [], 'acc_test': [], 'eer': [], 'fnr_work_reduced': [],
                'fpr_work_reduced': [], 'work_reduced': [], 'work_reduced_negative': [],
                'work_reduced_positive': [], 'work_reduced_real':[]}

    # Select training data - features2 need to be added to the training set.
    features2, labels2, post_analysis_labels2 = pre.loadAndCleanDataMaxDom('1111', False, '2018')

    features2, features_test_domains, labels2, labels_test_domains = \
        method[strategy](features2, labels2, **{'fraction':fraction, 'code': '1111'})

    manual_added_to_trainingset = len(labels2)
    print('From 2018', manual_added_to_trainingset ,'samples are added to the training set')
    labels2 = pd.Series(labels2, index=features2.index)

    labels_test_domains = pd.Series(labels_test_domains, index=features_test_domains.index)
    amount_of_test_domains = len(labelzsss) - len(features2)
    total_amount_positive_test = total_amount_2018_positive - labels2.sum()
    total_amount_negative_test = total_amount_2018_negative - (len(labels2.index) - labels2.sum())
    ind_extra_train = features2.index

    # save extra_train_indices to drop them when models are used
    dump(ind_extra_train, 'models/' + 'extended' + '/additionaltrainindices.joblib')

    for x in itertools.product(l,repeat=4):
        code = ''.join(['1' if i else '0' for i in x])
        if code != '0000':
            # features1 is the 2017 data and is first part of the training set.
            features1, labels1, post_analysis_labels1 = pre.loadAndCleanDataMaxDom(code, False, '2017')
            # select training and testing indices from 'correct' (=abiding model code) featureset
            features3, labels3, post_analysis_labels3 = pre.loadAndCleanDataMaxDom(code, False, '2018')
            labels3 = pd.Series(labels3, index=features3.index)

            features_extra_train = features3.loc[ind_extra_train]
            labels_extra_train = labels3.loc[ind_extra_train]

            features_test = features3.drop(ind_extra_train)
            labels_test = labels3.drop(ind_extra_train)

            features_train = pd.concat([features1, features_extra_train])
            labels_train = np.concatenate([labels1, labels_extra_train])
            labels_train_year = np.concatenate([labels1, labels_extra_train*2])

            nb_test_domains = len(labels_test)
            nb_test_domains_with_extra_train = len(labels3)

            print('Total training set size', len(labels_train))

            # Load hyperparameters and train classifier
            clf_tuned = load('models/2017/model' + code + '.joblib')
            if isinstance(clf_tuned, GradientBoostingClassifier):
                params = clf_tuned.get_params()
                clf = GradientBoostingClassifier(**params)
            else:
                params = clf_tuned.best_params_
                clf = GradientBoostingClassifier(**params, random_state=42)
            clf.fit(features_train, labels_train)

            #save clf
            dump(clf, 'models/' + 'extended' + '/model' + code + '.joblib')

            # Evaluate
            predictions = clf.predict(features_test)
            scores = clf.predict_proba(features_test)

            acc = accuracy_score(labels_test, predictions)
            f1 = f1_score(labels_test, predictions)
            prec = precision_score(labels_test, predictions)
            reca = recall_score(labels_test, predictions)

            # TODO: choose threshold selection method
            # positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
            # work_reduced_positive, lower, upper = \
            #     workReducedPostLoadThr('2017', code, scores, labels_test)

            positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
            work_reduced_positive, thresholdsfnr, thresholdsfpr = \
                workReducedPostDetermineThrOneGoBis(features_train, labels_train, code, scores, labels_test,
                                                    labels_train_year, costs, plot=True, savemetrics=True, path='extended/' + code + '_')

            if code == '1111':
                postan.thresholdsToLatex(path='dfs/extended/1111_workreduced.csv')
                postan.saveimportance(clf.feature_importances_, features_test.columns, 'extended/1111_')
            # positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
            # work_reduced_positive, lower, upper = \
            #     workReducedPostDetermineThrOneGoOneYear(features1, labels1, features_extra_train, labels_extra_train, code,
            #                                             scores, labels_test)

            print('Manual work for', len(no_action_pred), 'domains. This work is on top of the',
                  len(labels_extra_train), 'that had to be labeled manually to add them to the trainingset')
            codesz.append(code)
            metrics['acc_test'].append(acc)
            metrics['f1'].append(f1)
            metrics['precision'].append(prec)
            metrics['work_reduced_negative'].append(len(negative_pred) / nb_test_domains)
            metrics['work_reduced_positive'].append(len(positive_pred) / nb_test_domains)
            metrics['work_reduced'].append(len(negative_pred) / nb_test_domains + len(positive_pred) / nb_test_domains)
            metrics['work_reduced_real'].append((nb_test_domains - len(no_action_pred)) / nb_test_domains_with_extra_train)
            metrics['fnr_work_reduced'].append(fnr)
            metrics['fpr_work_reduced'].append(fpr)

            # Construct domains that should be classified by this model
            features, labelzz = pre.loadAndCleanDataExactPattern(x, available, reputation, dns, whois, openintel, label)
            iters = features.index.intersection(features_test.index)
            features_to_classify = features_test.loc[iters]
            labelzz = labelzz.loc[iters]
            amount_of_domains = len(features_to_classify.index)

            print(amount_of_domains, 'domains to classify for code', code)
            if len(labelzz.index != 0):

                scores = clf.predict_proba(features_to_classify)
                predictions = clf.predict(features_to_classify)
 
                if code[2] == '1':
                    df = whois.loc[features_to_classify.index]
                    whoisclassified_domians_dfs.append(df)
                    whoisclassified_domains_labels.append(labelzz.loc[df.index])
                    print(type(predictions))
                    whoisclassified_domains_prediction.append(predictions)

                for i,c in enumerate(costs):
                    lower = thresholdsfnr[i]
                    upper = thresholdsfpr[i]
                    positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
                    work_reduced_positive = workReducedPost(lower, upper, scores, labelzz)

                    workreduceddict[c]['total_fp'] += (len(positive_pred) - sum(positive_pred))
                    workreduceddict[c]['total_fn'] += sum(negative_pred)
                    workreduceddict[c]['total_manual'] += len(no_action_pred)
                    workreduceddict[c]['total_pred'] += (len(positive_pred) + len(negative_pred))

                    workreduceddict[c]['ensemble_predictions'] = workreduceddict[c]['ensemble_predictions'] + [1] * len(positive_pred) + [0] * len(negative_pred) + no_action_pred
                    workreduceddict[c]['ensemble_labels'] = workreduceddict[c]['ensemble_labels'] + positive_pred + negative_pred + no_action_pred

                    workreduceddict[c]['ensemble_predictions_priori'] = workreduceddict[c]['ensemble_predictions_priori'] + predictions.tolist()
                    workreduceddict[c]['ensemble_labels_priori'] = workreduceddict[c]['ensemble_labels_priori'] + labelzz.values.tolist()

                    workreduceddict[c]['ensemble_scores_neg'] = workreduceddict[c]['ensemble_scores_neg'] + scores[:, 1][labelzz == 0].tolist()
                    workreduceddict[c]['ensemble_scores_pos'] = workreduceddict[c]['ensemble_scores_pos'] + scores[:, 1][labelzz == 1].tolist()

                # dfs.append(df)

                print('Makes a prediction for', (len(positive_pred) + len(negative_pred)), 'domains')
                print('Would predict', np.sum(predictions), 'domains malicious')
            print('=========================================')

    # Print performance per model
    print('===============================================================================')
    for key, value in metrics.items():
        if value:
            print('========== %s ============' % (key))
            for i,v in enumerate(value):
                print('Model %s: %.3f' % (codesz[i], v))
                # codestr = utils.translatecode(code)
                # results[key + codestr] = v
    print('===============================================================================')

    total_fp = workreduceddict[0.02]['total_fp']
    total_fn = workreduceddict[0.02]['total_fn']
    total_manual = workreduceddict[0.02]['total_manual']
    total_pred = workreduceddict[0.02]['total_pred']

    # Test set + what has to be added to training set.
    print('Total work reduced real', (total_amount_of_2018_domains - total_manual - manual_added_to_trainingset) / total_amount_of_2018_domains)
    print('Total FNR', total_fn / total_amount_2018_positive)
    print('Total FPR', total_fp / total_amount_2018_negative)
    # Only test set.
    print('Total work reduced only test set', (amount_of_test_domains-total_manual)/amount_of_test_domains)
    print('Total FNR only test set', total_fn/total_amount_positive_test)
    print('Total FPR only test set', total_fp/total_amount_negative_test)

    ensemble_labels = workreduceddict[0.02]['ensemble_labels']
    ensemble_predictions = workreduceddict[0.02]['ensemble_predictions']
    ensemble_labels_priori = workreduceddict[0.02]['ensemble_labels_priori']
    ensemble_predictions_priori = workreduceddict[0.02]['ensemble_predictions_priori']
    ensemble_scores_pos = workreduceddict[0.02]['ensemble_scores_pos']
    ensemble_scores_neg = workreduceddict[0.02]['ensemble_scores_neg']

    # FP and FN to file
    df_data = pd.concat(whoisclassified_domians_dfs)
    df_labels = pd.concat(whoisclassified_domains_labels)
    labels_pred = np.concatenate(whoisclassified_domains_prediction)
    postan.saveFpFnDfBis(df_data, df_labels, labels_pred, 'extended/')

    np.savez('dfs/' + 'ensemble_extended_det_curve.npz', pos=ensemble_scores_pos, neg=ensemble_scores_neg)

    print('AccuracyPosteriori', accuracy_score(ensemble_labels, ensemble_predictions))
    print('F1Posteriori', f1_score(ensemble_labels, ensemble_predictions))
    print('PrecisionPosteriori', precision_score(ensemble_labels, ensemble_predictions))
    print('RecallPosteriori', recall_score(ensemble_labels, ensemble_predictions))

    print('Little check', total_amount_2018_positive + total_amount_2018_negative == total_amount_of_2018_domains)
    print('Little check', total_amount_positive_test+total_amount_negative_test == amount_of_test_domains)
    print('Little check', total_pred + total_manual + manual_added_to_trainingset == total_amount_of_2018_domains)
    print('Little check', amount_of_test_domains + manual_added_to_trainingset == total_amount_of_2018_domains)


    results[strategy + 'workreduced'] = (total_amount_of_2018_domains - total_manual - manual_added_to_trainingset) / total_amount_of_2018_domains *100
    results[strategy + 'fnr'+ 'posteriori'] = total_fn / total_amount_2018_positive *100
    results[strategy + 'fpr'+ 'posteriori'] = total_fp/total_amount_2018_negative *100
    results[strategy + 'accuracy' + 'posteriori'] = accuracy_score(ensemble_labels, ensemble_predictions) *100
    results[strategy + 'fone' + 'posteriori'] = f1_score(ensemble_labels, ensemble_predictions) *100
    results[strategy + 'precision' + 'posteriori'] = precision_score(ensemble_labels, ensemble_predictions) *100
    results[strategy + 'recall' + 'posteriori'] = recall_score(ensemble_labels, ensemble_predictions) *100

    results[strategy + 'accuracy'] = accuracy_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
    results[strategy + 'fone'] = f1_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
    results[strategy + 'precision'] = precision_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
    results[strategy + 'recall'] = recall_score(ensemble_labels_priori, ensemble_predictions_priori) * 100
    results[strategy + 'eer'] = bob.measure.eer(ensemble_scores_neg, ensemble_scores_pos) * 100
    fpr, fnr = bob.measure.farfrr(ensemble_scores_neg, ensemble_scores_pos, 0.5)
    results[strategy + 'fpr'] = fpr*100
    results[strategy + 'fnr'] = fnr*100

    print('Accuracy', accuracy_score(ensemble_labels_priori, ensemble_predictions_priori) * 100)
    print('F1', f1_score(ensemble_labels_priori, ensemble_predictions_priori) * 100)
    print('Precision', precision_score(ensemble_labels_priori, ensemble_predictions_priori) * 100)
    print('Recall', recall_score(ensemble_labels_priori, ensemble_predictions_priori) * 100)

    total_manual = workreduceddict[0.01]['total_manual']
    results[strategy + 'WorkReducedOnePercent'] = (total_amount_of_2018_domains - total_manual - manual_added_to_trainingset) / total_amount_of_2018_domains *100
    total_manual = workreduceddict[0.005]['total_manual']
    results[strategy + 'WorkReducedPointFivePercent'] = (total_amount_of_2018_domains - total_manual - manual_added_to_trainingset) / total_amount_of_2018_domains *100
    total_manual = workreduceddict[0.001]['total_manual']
    results[strategy + 'WorkReducedPointOnePercent'] = (total_amount_of_2018_domains - total_manual - manual_added_to_trainingset) / total_amount_of_2018_domains *100


    macroify.append_file(results)

