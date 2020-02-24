import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from evaluation.postanalysis import workReducedPostDomains
from joblib import load

import random as rand

def random(x, y, **kwargs):
    '''randomly pick domains'''
    try:
        fraction = kwargs['fraction']
    except KeyError:
        fraction = 0.1
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=1-fraction, shuffle=True)
    return x_train, x_test, y_train, y_test

def practical(x, y, **kwargs):
    '''pick domains in the most practical manner, those that are most likely to have to be classified manually'''
    sourcepattern = kwargs['code']

    clf = load('models/2017/model' + sourcepattern + '.joblib')
    scores = clf.predict_proba(x)

    negative_pred_ind, no_action_pred_ind, positive_pred_ind = workReducedPostDomains('2017', sourcepattern, scores)
    positive_pred = x.loc[positive_pred_ind]
    negative_pred = x.loc[negative_pred_ind]
    x_train = x.loc[no_action_pred_ind]

    y_train = y[no_action_pred_ind]
    print('benign', len(y_train)-sum(y_train), 'malicious', sum(y_train))
    positive_pred_labels = y[positive_pred_ind]
    negative_pred_labels = y[negative_pred_ind]

    x_test = pd.concat([positive_pred, negative_pred])
    y_test = np.concatenate((positive_pred_labels, negative_pred_labels))

    return x_train, x_test, y_train, y_test

def createTrueFalseList(length, true_indices):
    out = []
    for i in range(length):
        if i in true_indices:
            out.append(True)
        else:
            out.append(False)
    return out

def practicalFraction(x,y, **kwargs):
    try:
        fraction = kwargs['fraction']
    except KeyError:
        fraction = 0.5

    sourcepattern = kwargs['code']

    clf = load('models/2017/model' + sourcepattern + '.joblib')
    scores = clf.predict_proba(x)

    negative_pred_ind, no_action_pred_ind, positive_pred_ind = workReducedPostDomains('2017', sourcepattern, scores)

    ind_where_true = [i for i, b in zip(range(len(no_action_pred_ind)), no_action_pred_ind) if b]
    if fraction <= 1:
        amount_of_train_domains = int(fraction*len(ind_where_true))
    else:
        amount_of_train_domains = fraction
    ind_where_true_train = rand.sample(ind_where_true, amount_of_train_domains)
    ind_where_true_test = [i for i in ind_where_true if i not in ind_where_true_train]
    no_action_pred_ind_train = createTrueFalseList(len(no_action_pred_ind), ind_where_true_train)
    no_action_pred_ind_test = createTrueFalseList(len(no_action_pred_ind), ind_where_true_test)

    positive_pred = x.loc[positive_pred_ind]
    negative_pred = x.loc[negative_pred_ind]
    no_action_test = x.loc[no_action_pred_ind_test]
    x_train = x.loc[no_action_pred_ind_train]

    y_train = y[no_action_pred_ind_train]
    no_action_test_labels = y[no_action_pred_ind_test]
    print('benign', len(y_train) - sum(y_train), 'malicious', sum(y_train))
    positive_pred_labels = y[positive_pred_ind]
    negative_pred_labels = y[negative_pred_ind]

    x_test = pd.concat([positive_pred, negative_pred, no_action_test])
    y_test = np.concatenate((positive_pred_labels, negative_pred_labels, no_action_test_labels))
    print('practical')

    return x_train, x_test, y_train, y_test
