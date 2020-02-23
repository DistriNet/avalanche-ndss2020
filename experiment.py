import argparse
import json

import pandas as pd
import numpy as np

from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, KFold, StratifiedKFold
from sklearn.metrics import confusion_matrix, f1_score, roc_auc_score, precision_score, recall_score

from joblib import dump, load
import evaluation.metrics as m
import evaluation.postanalysis as postan
import evaluation.preanalysis as prean

from dataprocessing.preprocessing import loadAndCleanDataMaxDom

from matplotlib import pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings("ignore")

'''This script runs the experiments within one year. This allows to compute the estimated total work reduced'''


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Do the avalanche experiments within one year')

    parser.add_argument('--sources', '-s',
                        type=str,
                        default="0111",
                        help='what datasets to use in a binary pattern, reputation + lexicographic, passivedns, whois, activedns')

    parser.add_argument('--year', '-y',
                        type=str,
                        default='2017',
                        help='year to consider')

    args = parser.parse_args()
    sourcepattern = args.sources
    year = args.year
    path = year + '/' + sourcepattern + '_'

    features, labels, post_analysis_labels = loadAndCleanDataMaxDom(sourcepattern, False, year)

    prean.pcaAnalysis(features,labels, path)
    prean.covMatrix(features, labels, path)

    print("Input sizes:")
    print("Total", len(labels), "Negative (0, benign)", (labels == 0).sum(), "Positive (1, malicious)", (labels == 1).sum())

    # pipeline
    i = 1
    kf = StratifiedKFold(n_splits=10, shuffle=True, random_state=44)
    metrics = {'f1': [], 'precision': [], 'recall': [], 'auc': [], 'acc_train': [], 'acc_test': [], 'eer': []}
    data = {'x_test': np.empty((0, features.shape[1])), 'y_test': np.empty((0,)), 'y_pred': np.empty((0,)),
            'importance': np.zeros(len(features.columns)), 'agg_scores_train': [], 'agg_scores_test': [],
            'labels_train': [], 'labels_test': [], 'estimators':[], 'y_post': np.empty((0, post_analysis_labels.shape[1])),
            'domainname_test':[]}
    for train_index, test_index in kf.split(features.values, labels):
        # Split the training and testing data
        X_train, X_test = features.values[train_index], features.values[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        y_post = post_analysis_labels.iloc[test_index].values
        domainname_test = features.index[test_index]

        # Load parameters of the hyperparameter tuned model. Note that we do not tune in each iteration.
        # It is possible that tuning within the split leads to other hyperparameters, however, the hyperparameters
        # should transfer quite well as the problem and data remains the same. At worst performance could be slightly better.
        clf_tuned = load('models/2017/model' + sourcepattern + '.joblib')
        if isinstance(clf_tuned, GradientBoostingClassifier):
            params = clf_tuned.get_params()
            pipe = Pipeline([('clf', GradientBoostingClassifier(**params))])  # ('scl', StandardScaler()),

        else:
            params = clf_tuned.best_params_
            pipe = Pipeline([('clf', GradientBoostingClassifier(random_state=44, **params))]) #('scl', StandardScaler()),

        # Train the model
        pipe.fit(X_train, y_train)

        # Calculate metrics for this split
        metrics['acc_train'].append(pipe.score(X_train, y_train))
        metrics['acc_test'].append(pipe.score(X_test, y_test))
        y_pred = pipe.predict(X_test)
        metrics['f1'].append(f1_score(y_test, y_pred))
        metrics['auc'].append(roc_auc_score(y_test, y_pred))
        metrics['precision'].append(precision_score(y_test, y_pred))
        metrics['recall'].append(recall_score(y_test, y_pred))

        # Some post processing information for this split
        data['x_test'] = np.append(data['x_test'], X_test, axis=0)
        data['y_test'] = np.append(data['y_test'], y_test)
        data['y_pred'] = np.append(data['y_pred'], y_pred)
        data['y_post'] = np.append(data['y_post'], y_post, axis=0)
        data['importance'] = np.sum([data['importance'], pipe.named_steps['clf'].feature_importances_], axis=0)
        data['estimators'].append(pipe.named_steps['clf'].estimators_)
        data['domainname_test'] = np.append(data['domainname_test'], domainname_test)

        malicious = X_test[y_test == 1]
        benign = X_test[y_test == 0]
        negatives = pipe.predict_proba(benign)[:, 1]
        positives = pipe.predict_proba(malicious)[:, 1]
        scores_test = pipe.predict_proba(X_test)[:, 1]
        scores_train = pipe.predict_proba(X_train)[:, 1]

        data['agg_scores_train'] = np.append(data['agg_scores_train'], scores_train)
        data['agg_scores_test'] = np.append(data['agg_scores_test'], scores_test)
        data['labels_train'] = np.append(data['labels_train'], y_train)
        data['labels_test'] = np.append(data['labels_test'], y_test)
        
    ind = []
    mean = []
    std = []
    print('===============================================================================')
    for key, value in metrics.items():
        if value:
            print('GBC pipeline test %s and std: %.3f +- %.3f' % (key, np.array(value).mean(), np.array(value).std()))
            ind.append(key)
            mean.append(np.array(value).mean())
            std.append(np.array(value).std())
    print('===============================================================================')
    df = pd.DataFrame({'mean': mean, 'std': std}, index=ind)
    df.to_csv('dfs/' + year + '/' + sourcepattern + '_' + 'performance_metrics.csv')

    costs = [0.001, 0.005, 0.01, 0.02]

    metricsfnr, metricsfpr = m.workreduced(data['agg_scores_test'], data['labels_test'], costs, plot= True, savemetrics=True, path=path)

    postan.saveFpFnDf(data['x_test'], data['y_test'], data['y_pred'], features.columns, data['domainname_test'], path)
    postan.saveimportance(data['importance'] / kf.n_splits, features.columns, path)

    for c, vfnr, vfpr in zip(costs, metricsfnr, metricsfpr):
        print('Testing: When a fnr and fpr of', c*100 , '% is acceptable, work saved is', vfnr , vfpr ,
              'total', vfnr + vfpr )

    print('===============================================================================')

    distributions = dict()
    for name in features.columns:
        distributions[name] = []
    for estims in data['estimators']:
        postan.featureDistribution(features.columns, estims, distributions)

    with open('dfs/' + year + '/' + sourcepattern + '_' + 'thresholds.json', 'w') as fp:
        json.dump(distributions, fp)
