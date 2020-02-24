import argparse

import pandas as pd
import numpy as np

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import GridSearchCV
from joblib import dump, load

from dataprocessing.preprocessing import loadAndCleanDataMaxDom

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Train classifier in one year, tune its hyperparameters with 10 fold cross validation')

    parser.add_argument('--sources', '-s',
                        type=str,
                        default="1111",
                        help='what datasets to use in a binary pattern, reputation + lexicographic, passivedns, whois, activedns')

    parser.add_argument('--tuning', '-t',
                        type=bool,
                        default=False,
                        help='Whether to tune or take hyperparameters of past')

    parser.add_argument('--year', '-y',
                        type=str,
                        default='2017',
                        help='year to consider')



    args = parser.parse_args()
    sourcepattern = args.sources
    tune = args.tuning
    year = args.year

    features, labels, post_analysis_labels = loadAndCleanDataMaxDom(sourcepattern, False, year)
    print(labels.sum())
    metrics = {'f1': [], 'precision': [], 'recall': [], 'auc': [], 'acc_train': [], 'acc_test': [], 'eer': []}
    data = {'x_test': np.empty((0, features.shape[1])), 'y_test': np.empty((0,)), 'y_pred': np.empty((0,)),
            'importance': np.zeros(len(features.columns)), 'agg_scores_train': [], 'agg_scores_test': [],
            'labels_train': [], 'labels_test': [], 'estimators': [],
            'y_post': np.empty((0, post_analysis_labels.shape[1])),
            'domainname_test': []}

    param_grid = [
        {'loss': ['deviance', 'exponential'], 'learning_rate': [2 ** x for x in range(-5, 2, 1)], \
         'n_estimators': [2 ** x for x in range(4, 10)], 'min_samples_split': [2, 3, 4, 6], \
         'min_samples_leaf': [2, 3, 4, 6], 'max_features': ['auto', 'log2', 'sqrt'], 'max_depth': [3, 6, 12]}
    ]

    if tune:
        gbc = GradientBoostingClassifier()
        clf = GridSearchCV(gbc, param_grid, cv=10, scoring='f1', n_jobs=4)
        clf.fit(features, labels)
        params = clf.best_params_
    else:
        clf_tuned = load('models/2017/model' + sourcepattern + '.joblib')
        if isinstance(clf_tuned, GradientBoostingClassifier):
            params = clf_tuned.get_params()
            clf = GradientBoostingClassifier(**params)
        else:
            params = clf_tuned.best_params_
            clf = GradientBoostingClassifier(**params, random_state=44)
    clf.fit(features, labels)

    dump(clf, 'models/' + year + '/model' + sourcepattern + '.joblib')
