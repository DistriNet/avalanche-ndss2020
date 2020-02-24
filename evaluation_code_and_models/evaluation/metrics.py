from matplotlib import pyplot as plt
import matplotlib.ticker
import matplotlib.patches as patches
import pandas as pd
import numpy as np
from sklearn.model_selection import KFold, StratifiedKFold
from sklearn.ensemble import GradientBoostingClassifier
from joblib import load

import warnings
warnings.filterwarnings("ignore")

# import bob.measure

def workreduced(scores, labels, costs, plot, savemetrics, path):
    df = pd.DataFrame({'scores': scores, 'labels':labels, 'inverse_labels':np.bitwise_xor(labels.astype(int),np.ones(len(labels),dtype=int))})
    #FNR
    sorted_asc = df.sort_values('scores', ascending=True)
    cumsum = np.cumsum(sorted_asc['labels'])
    total_malicious = cumsum.iloc[-1]
    sorted_asc['cumsum'] = cumsum
    sorted_asc.index = range(0,len(sorted_asc.index))
    sorted_asc['malrate'] = sorted_asc['cumsum']/sorted_asc.index
    metricsfnr = []
    thresholdsfnr = []
    for c in costs:
        filtered = sorted_asc[sorted_asc['cumsum']/total_malicious < c]
        if len(filtered.index) != 0:
            # print(filtered.iloc[-1,2])
            ind = filtered.index[-1]
            metricsfnr.append(ind/len(sorted_asc.index))
            thresholdsfnr.append(filtered.loc[:,'scores'].iloc[-1])
        else:
            metricsfnr.append(0)
            thresholdsfnr.append(0)
            print('For cost', c, 'df fnr is empty')



    #FPR
    sorted_desc = df.sort_values('scores', ascending=False)
    cumsum = np.cumsum(sorted_desc['inverse_labels'])
    total_benign = cumsum.iloc[-1]
    sorted_desc['cumsum'] = cumsum
    sorted_desc.index = range(0,len(sorted_desc.index))
    sorted_desc['benignrate'] = sorted_desc['cumsum']
    metricsfpr = []
    thresholdsfpr = []

    for c in costs:
        filtered = sorted_desc[sorted_desc['cumsum'] / total_benign < c]
        if len(filtered.index) != 0:
            ind = filtered.index[-1]
            metricsfpr.append(ind / len(sorted_desc.index))
            thresholdsfpr.append(filtered.loc[:,'scores'].iloc[-1])
        else:
            metricsfpr.append(0)
            thresholdsfpr.append(1)
            print('For cost', c, 'df fpr is empty')

    if plot:
        plotBins(costs, sorted_desc, total_benign, sorted_asc, total_malicious, metricsfnr, metricsfpr, path, scores, labels)
    if savemetrics:
        saveBinMetrics(metricsfnr, metricsfpr, costs, thresholdsfnr, thresholdsfpr, path)

    return metricsfnr, metricsfpr

def workreducedThrBis(scores, labels, costs, plot, savemetrics, path):
    df = pd.DataFrame({'scores': scores, 'labels':labels, 'inverse_labels':np.bitwise_xor(labels.astype(int),np.ones(len(labels),dtype=int))})
    #FNR
    sorted_asc = df.sort_values('scores', ascending=True)
    cumsum = np.cumsum(sorted_asc['labels'])
    total_malicious = cumsum.iloc[-1]
    sorted_asc['cumsum'] = cumsum
    sorted_asc.index = range(0,len(sorted_asc.index))
    sorted_asc['malrate'] = sorted_asc['cumsum']/sorted_asc.index
    metricsfnr = []
    thresholdsfnr = []
    for c in costs:
        filtered = sorted_asc[sorted_asc['cumsum']/total_malicious < c]
        if len(filtered.index) != 0:
            # print(filtered.iloc[-1,2])
            ind = filtered.index[-1]
            metricsfnr.append(ind/len(sorted_asc.index))
            thresholdsfnr.append(filtered.loc[:,'scores'].iloc[-1])
        else:
            metricsfnr.append(0)
            thresholdsfnr.append(0)
            print('For cost', c, 'df fnr is empty')



    #FPR
    sorted_desc = df.sort_values('scores', ascending=False)
    cumsum = np.cumsum(sorted_desc['inverse_labels'])
    total_benign = cumsum.iloc[-1]
    sorted_desc['cumsum'] = cumsum
    sorted_desc.index = range(0,len(sorted_desc.index))
    sorted_desc['benignrate'] = sorted_desc['cumsum']
    metricsfpr = []
    thresholdsfpr = []

    for c in costs:
        filtered = sorted_desc[sorted_desc['cumsum'] / total_benign < c]
        if len(filtered.index) != 0:
            ind = filtered.index[-1]
            metricsfpr.append(ind / len(sorted_desc.index))
            thresholdsfpr.append(filtered.loc[:,'scores'].iloc[-1])
        else:
            metricsfpr.append(0)
            thresholdsfpr.append(1)
            print('For cost', c, 'df fpr is empty')

    if plot:
        plotBins(costs, sorted_desc, total_benign, sorted_asc, total_malicious, metricsfnr, metricsfpr, path, scores, labels)
    if savemetrics:
        saveBinMetrics(metricsfnr, metricsfpr, costs, thresholdsfnr, thresholdsfpr, path)

    return metricsfnr, metricsfpr, thresholdsfnr, thresholdsfpr

def workreducedThr(scores, labels, c):
    df = pd.DataFrame({'scores': scores, 'labels':labels, 'inverse_labels':np.bitwise_xor(labels.astype(int),np.ones(len(labels),dtype=int))})
    #FNR
    sorted_asc = df.sort_values('scores', ascending=True)
    cumsum = np.cumsum(sorted_asc['labels'])
    total_malicious = cumsum.iloc[-1]
    sorted_asc['cumsum'] = cumsum
    sorted_asc.index = range(0,len(sorted_asc.index))
    sorted_asc['malrate'] = sorted_asc['cumsum']/sorted_asc.index

    filtered = sorted_asc[sorted_asc['cumsum']/total_malicious < c]
    if len(filtered.index) != 0:
        # print(filtered.iloc[-1,2])
        ind = filtered.index[-1]
        metricsfnr = ind/len(sorted_asc.index)
        thresholdsfnr = filtered.loc[:,'scores'].iloc[-1]
    else:
        metricsfnr = 0
        thresholdsfnr = 0
        print('For cost', c, 'df fnr is empty')



    #FPR
    sorted_desc = df.sort_values('scores', ascending=False)
    cumsum = np.cumsum(sorted_desc['inverse_labels'])
    total_benign = cumsum.iloc[-1]
    sorted_desc['cumsum'] = cumsum
    sorted_desc.index = range(0,len(sorted_desc.index))
    sorted_desc['benignrate'] = sorted_desc['cumsum']
    filtered = sorted_desc[sorted_desc['cumsum'] / total_benign < c]
    if len(filtered.index) != 0:
        ind = filtered.index[-1]
        metricsfpr = ind / len(sorted_desc.index)
        thresholdsfpr = filtered.loc[:,'scores'].iloc[-1]
    else:
        metricsfpr = 0
        thresholdsfpr = 1
        print('For cost', c, 'df fpr is empty')

    return metricsfnr, metricsfpr, thresholdsfnr, thresholdsfpr


def plotBins(costs, sorted_desc, total_benign, sorted_asc, total_malicious, metricsfnr, metricsfpr, path, scores, labels):
    figsize = (6.4, 3.2)
    f = plt.figure(figsize=figsize)

    plt.semilogy(sorted_asc.index/len(sorted_asc.index)*100, sorted_asc['cumsum']/total_malicious *100, label='False negative rate')


    plt.semilogy((sorted_desc.index/len(sorted_desc.index)*100), (sorted_desc['cumsum']/total_benign *100)[::-1], label='False positive rate')
    plt.legend()
    plt.gca().yaxis.set_major_formatter(matplotlib.ticker.ScalarFormatter())

    # find intersection of two curves
    isec = ((sorted_asc['cumsum']/total_malicious *100) - (sorted_desc['cumsum']/total_benign *100)[::-1]).abs()
    # plt.semilogy((isec.index/len(isec.index)*100), 100-isec)
    idxmin = ((100-isec).argsort()[0:2])
    print(isec[idxmin[0]-2:idxmin[0]+2])
    eer = ((sorted_asc['cumsum']/total_malicious *100).iloc[idxmin]).mean()
    print("eer", eer)
    scores_neg = scores[labels == 0].tolist()
    scores_pos = scores[labels == 1].tolist()
    # eer = bob.measure.eer(scores_neg, scores_pos)*100

    plt.gca().yaxis.set_ticks([0.1,1,10,100,0.5,2])
    plt.gca().yaxis.set_ticklabels(["0.1"]+["1.0"]+["10.0"]+["100.0"]+["0.5"]+["2.0"])
    plt.ylim((0.05,100))
    plt.xlim((0,100))
    plt.xlabel('Fraction of domains (%)')
    plt.ylabel('Error rate (%)')

    axis_to_data = plt.gca().transAxes + plt.gca().transData.inverted()
    data_to_axis = axis_to_data.inverted()

    half_spacing_between_arrows = 0.00

    for c, max_fnr, max_fpr in zip([costs[-1]],[metricsfnr[-1]], [metricsfpr[-1]]):
        # points_data = axis_to_data.transform([(0, c*100), (max_fnr*100, c*100)])
        print(data_to_axis.transform([(0, c*100), (max_fnr*100, c*100)]))
        # plt.hlines(c*100, 0, max*100, linestyles='dashed', colors="black" if c == 0.02 else "grey")
        plt.annotate('', xytext=data_to_axis.transform([(0, c*100)])[0] + [0, half_spacing_between_arrows], textcoords='axes fraction',
                     xy=data_to_axis.transform([(max_fnr*100, c*100)])[0] + [0, half_spacing_between_arrows],  xycoords='axes fraction',
                     arrowprops={'arrowstyle': '-|>', 'color': "C2" if c == 0.02 else "lightgrey", "linestyle": "--", "linewidth":1, "shrinkA": 0, "shrinkB": 0})
        plt.annotate('', xytext=data_to_axis.transform([(100, c*100)])[0] - [0, half_spacing_between_arrows], textcoords='axes fraction',
                     xy=data_to_axis.transform([(100 - max_fpr*100, c*100)])[0] - [0, half_spacing_between_arrows],  xycoords='axes fraction',
                     arrowprops={'arrowstyle': '-|>', 'color': "C3" if c == 0.02 else "lightgrey", "linestyle": "--", "linewidth":1, "shrinkA": 0, "shrinkB": 0})
        if c == 0.02:
            plt.annotate('', xytext=data_to_axis.transform([(max_fnr * 100, c * 100)])[0],
                         textcoords='axes fraction',
                         xy=[data_to_axis.transform([(max_fnr * 100, 1)])[0][0], 0],
                         xycoords='axes fraction',
                         arrowprops={'arrowstyle': '-|>', 'color': "C2" , "linestyle": "--",
                                     "linewidth": 1, "shrinkA": 0, "shrinkB": 0})
            plt.annotate('', xytext=data_to_axis.transform([(100 - max_fpr * 100, c * 100)])[0],
                         textcoords='axes fraction',
                         xy=[data_to_axis.transform([(100 - max_fpr * 100, 1)])[0][0], 0],
                         xycoords='axes fraction',
                         arrowprops={'arrowstyle': '-|>', 'color': "C3" , "linestyle": "--",
                                     "linewidth": 1, "shrinkA": 0, "shrinkB": 0})
            ticks_list = list(plt.xticks()[0])
            ticks_list.remove(60)
            plt.xticks(ticks_list + [max_fnr * 100, 100 - max_fpr * 100])

        p = patches.Rectangle((0,eer), 100, 100-eer, linewidth=0, fill=None, hatch='///', color='lightgrey') # data_to_axis.transform([(5.1 * 100, 0)])[0]
        plt.gca().add_patch(p)

        bbox_props = dict(boxstyle="rarrow", fc="white", ec="C0", lw=1)
        plt.text(50, eer, "Equal error rate", ha="center", va="center", rotation=0,
                    size=10,
                    bbox=bbox_props)

        plt.text(50, 25, "Above equal error rate: use 100% of automated classification", size=10, rotation=0,
                 ha="center", va="center",
                 bbox=dict(boxstyle="round",
                           ec="white",
                           facecolor="white",
                           )
                 )
    f.savefig('figures/' + path + 'bins.pdf',bbox_inches='tight', dpi=600)
    plt.close()

def saveBinMetrics(metricsfnr, metricsfpr, costs, thresholdsfnr, thresholdsfpr, path):
    metricsfnr = [mfnr * 100 for mfnr in metricsfnr]
    metricsfpr = [mfpr * 100 for mfpr in metricsfpr]
    costs = [cost * 100 for cost in costs]
    sum = [x + y for x, y in zip(metricsfnr, metricsfpr)]
    df = pd.DataFrame({'fnr': metricsfnr, 'fpr': metricsfpr, 'thresholds_fnr': thresholdsfnr,
                       'thresholds_fpr': thresholdsfpr, 'sum': sum}, index=costs)
    df.to_csv('dfs/' + path + 'workreduced.csv')


def workReducedPost(lower, upper, scores, y_true):
    # scores lower than thresh, higher than threshold, in the middle. Calculate fraction and calculate metrics -> labels and predictions
    negative_pred = [l for s, l in zip(scores[:, 1], y_true) if s < lower]
    no_action_pred = [l for s, l in zip(scores[:, 1], y_true) if s >= lower and s <= upper]
    positive_pred = [l for s, l in zip(scores[:, 1], y_true) if s > upper]

    total_malicious = y_true.sum()
    total_benign = len(y_true) - total_malicious

    fnr = sum(negative_pred) / total_malicious
    fpr = (len(positive_pred) - sum(positive_pred)) / total_benign

    work_reduced_negative = len(negative_pred) / len(y_true)
    work_reduced_positive = len(positive_pred) / len(y_true)
    work_reduced = work_reduced_negative + work_reduced_positive

    return positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, work_reduced_positive


def workReducedPostLoadThr(trainyear, code, scores, y_true):
    thresholds = pd.read_csv('dfs/' + trainyear + '/' + code + '_workreduced.csv', index_col=0).loc[:,
                 ['thresholds_fnr', 'thresholds_fpr']]
    upper = thresholds.iloc[3, 1]
    lower = thresholds.iloc[3, 0]

    positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
    work_reduced_positive = workReducedPost(lower, upper, scores, y_true)

    return positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
           work_reduced_positive, lower, upper

def workReducedPostDetermineThr(features, labels, code, scoreszz, y_true):
    fnr = []
    fpr = []
    thr_fnr = []
    thr_fpr = []

    kf = StratifiedKFold(n_splits=10, shuffle=True, random_state=44)
    for train_index, test_index in kf.split(features.values, labels):
        # Split the training and testing data
        X_train, X_test = features.values[train_index], features.values[test_index]
        y_train, y_test = labels[train_index], labels[test_index]

        # Load parameters of the hyperparameter tuned model.
        clf_tuned = load('models/2017/model' + code + '.joblib')
        if isinstance(clf_tuned, GradientBoostingClassifier):
            params = clf_tuned.get_params()
            clf = GradientBoostingClassifier(**params)
        else:
            params = clf_tuned.best_params_
            clf = GradientBoostingClassifier(**params, random_state=44)
        clf.fit(X_train, y_train)

        scores = clf.predict_proba(X_test)

        metricsfnr, metricsfpr, thresholdsfnr, thresholdsfpr = workreducedThr(scores[:,1], y_test, 0.02)
        fnr.append(metricsfnr)
        fpr.append(metricsfpr)
        thr_fnr.append(thresholdsfnr)
        thr_fpr.append(thresholdsfpr)

    fnr = np.array(fnr)
    fpr = np.array(fpr)
    thr_fnr = np.array(thr_fnr)
    thr_fpr = np.array(thr_fpr)
    print('FNR work reduced', fnr.mean(), '+/-', fnr.std())
    print('FPR work reduced', fpr.mean(), '+/-', fpr.std())
    print('Total work reduced', fnr.mean() + fpr.mean())
    print('Lower thr', thr_fnr.mean(), '+/-', thr_fnr.std())
    print('Upper thr', fpr.mean(), '+/-', fpr.std())
    print()

    lower, upper = thr_fnr.mean(), thr_fpr.mean()
    # lower, upper = thr_fnr.mean() - thr_fnr.std(), thr_fpr.mean() + thr_fpr.std()


    positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
    work_reduced_positive = workReducedPost(lower, upper, scoreszz, y_true)

    return positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
           work_reduced_positive, lower, upper


def workReducedPostDetermineThrOneGo(features, labels, code, scoreszz, y_true):
    scores = []
    labelsz = []

    kf = StratifiedKFold(n_splits=10, shuffle=True, random_state=44)
    for train_index, test_index in kf.split(features.values, labels):
        # Split the training and testing data
        X_train, X_test = features.values[train_index], features.values[test_index]
        y_train, y_test = labels[train_index], labels[test_index]

        # Load parameters of the hyperparameter tuned model.
        clf_tuned = load('models/2017/model' + code + '.joblib')
        if isinstance(clf_tuned, GradientBoostingClassifier):
            params = clf_tuned.get_params()
            clf = GradientBoostingClassifier(**params)
        else:
            params = clf_tuned.best_params_
            clf = GradientBoostingClassifier(**params, random_state=44)
        clf.fit(X_train, y_train)

        s = clf.predict_proba(X_test)
        scores = np.append(scores, s[:,1])
        labelsz = np.append(labelsz, y_test)

    metricsfnr, metricsfpr, thresholdsfnr, thresholdsfpr = workreducedThr(scores, labelsz, 0.02)

    lower, upper = thresholdsfnr, thresholdsfpr
    # lower, upper = thr_fnr.mean() - thr_fnr.std(), thr_fpr.mean() + thr_fpr.std()


    positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
    work_reduced_positive = workReducedPost(lower, upper, scoreszz, y_true)

    return positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
           work_reduced_positive, lower, upper

def workReducedPostDetermineThrOneGoBis(features, labels, code, scoreszz, y_true, stratify_classes, costs, plot=False,
                                        savemetrics=False, path=''):
    scores = []
    labelsz = []

    kf = StratifiedKFold(n_splits=10, shuffle=True, random_state=44)
    for train_index, test_index in kf.split(features.values, stratify_classes):
        # Split the training and testing data
        X_train, X_test = features.values[train_index], features.values[test_index]
        y_train, y_test = labels[train_index], labels[test_index]

        # Load parameters of the hyperparameter tuned model.
        clf_tuned = load('models/2017/model' + code + '.joblib')
        if isinstance(clf_tuned, GradientBoostingClassifier):
            params = clf_tuned.get_params()
            clf = GradientBoostingClassifier(**params)
        else:
            params = clf_tuned.best_params_
            clf = GradientBoostingClassifier(**params, random_state=44)
        clf.fit(X_train, y_train)

        s = clf.predict_proba(X_test)
        scores = np.append(scores, s[:,1])
        labelsz = np.append(labelsz, y_test)

    metricsfnr, metricsfpr, thresholdsfnr, thresholdsfpr = workreducedThrBis(scores, labelsz, costs,
                                                                             plot=plot, savemetrics=savemetrics, path=path)

    lower, upper = thresholdsfnr[-1], thresholdsfpr[-1]

    positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
    work_reduced_positive = workReducedPost(lower, upper, scoreszz, y_true)

    return positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
           work_reduced_positive, thresholdsfnr, thresholdsfpr


def workReducedPostDetermineThrOneGoOneYear(features, labels, additional_features, addtional_labels,  code, scoreszz, y_true):
    '''Only look for thresholds on the additional dataset'''

    scores = []
    labelsz = []

    kf = StratifiedKFold(n_splits=10, shuffle=True, random_state=44)
    for train_index, test_index in kf.split(additional_features.values, addtional_labels):
        # Split the training and testing data
        X_train_add, X_test = additional_features.values[train_index], additional_features.values[test_index]
        y_train_add, y_test = addtional_labels[train_index], addtional_labels[test_index]

        X_train = np.concatenate((features.values, X_train_add))
        y_train = np.concatenate((labels, y_train_add))

        # Load parameters of the hyperparameter tuned model.
        clf_tuned = load('models/2017/model' + code + '.joblib')
        if isinstance(clf_tuned, GradientBoostingClassifier):
            params = clf_tuned.get_params()
            clf = GradientBoostingClassifier(**params)
        else:
            params = clf_tuned.best_params_
            clf = GradientBoostingClassifier(**params, random_state=44)
        clf.fit(X_train, y_train)

        s = clf.predict_proba(X_test)
        scores = np.append(scores, s[:,1])
        labelsz = np.append(labelsz, y_test)

    metricsfnr, metricsfpr, thresholdsfnr, thresholdsfpr = workreducedThr(scores, labelsz, 0.02)

    # print('Total work reduced', metricsfnr, metricsfpr, metricsfnr + metricsfpr)
    # print('Lower thr', thresholdsfnr)
    # print('Upper thr', thresholdsfpr)
    # print()

    lower, upper = thresholdsfnr, thresholdsfpr
    # lower, upper = thr_fnr.mean() - thr_fnr.std(), thr_fpr.mean() + thr_fpr.std()


    positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
    work_reduced_positive = workReducedPost(lower, upper, scoreszz, y_true)

    return positive_pred, negative_pred, no_action_pred, fnr, fpr, work_reduced, work_reduced_negative, \
           work_reduced_positive, lower, upper


def plotBinsGreyScale(costs, sorted_desc, total_benign, sorted_asc, total_malicious, metricsfnr, metricsfpr, path, scores, labels):
    figsize = (6.4, 3.2)
    f = plt.figure(figsize=figsize)

    plt.semilogy(sorted_asc.index/len(sorted_asc.index)*100, sorted_asc['cumsum']/total_malicious *100, label='False negative rate')


    plt.semilogy((sorted_desc.index/len(sorted_desc.index)*100), (sorted_desc['cumsum']/total_benign *100)[::-1], label='False positive rate')
    plt.legend()
    plt.gca().yaxis.set_major_formatter(matplotlib.ticker.ScalarFormatter())

    # find intersection of two curves
    isec = ((sorted_asc['cumsum']/total_malicious *100) - (sorted_desc['cumsum']/total_benign *100)[::-1]).abs()
    # plt.semilogy((isec.index/len(isec.index)*100), 100-isec)
    idxmin = ((100-isec).argsort()[0:2])
    print(isec[idxmin[0]-2:idxmin[0]+2])
    eer = ((sorted_asc['cumsum']/total_malicious *100).iloc[idxmin]).mean()
    print("eer", eer)
    scores_neg = scores[labels == 0].tolist()
    scores_pos = scores[labels == 1].tolist()
    # eer = bob.measure.eer(scores_neg, scores_pos)*100

    plt.gca().yaxis.set_ticks([0.1,1,10,100,0.5,2])
    plt.gca().yaxis.set_ticklabels(["0.1"]+["1.0"]+["10.0"]+["100.0"]+["0.5"]+["2.0"])
    plt.ylim((0.05,100))
    plt.xlim((0,100))
    plt.xlabel('Fraction of domains (%)')
    plt.ylabel('Error rate (%)')

    axis_to_data = plt.gca().transAxes + plt.gca().transData.inverted()
    data_to_axis = axis_to_data.inverted()

    half_spacing_between_arrows = 0.00

    for c, max_fnr, max_fpr in zip([costs[-1]],[metricsfnr[-1]], [metricsfpr[-1]]):
        print(data_to_axis.transform([(0, c*100), (max_fnr*100, c*100)]))
        plt.annotate('', xytext=data_to_axis.transform([(0, c*100)])[0] + [0, half_spacing_between_arrows], textcoords='axes fraction',
                     xy=data_to_axis.transform([(max_fnr*100, c*100)])[0] + [0, half_spacing_between_arrows],  xycoords='axes fraction',
                     arrowprops={'arrowstyle': '-|>', 'color': "C2" if c == 0.02 else "lightgrey", "linestyle": "--", "linewidth":1, "shrinkA": 0, "shrinkB": 0})
        plt.annotate('', xytext=data_to_axis.transform([(100, c*100)])[0] - [0, half_spacing_between_arrows], textcoords='axes fraction',
                     xy=data_to_axis.transform([(100 - max_fpr*100, c*100)])[0] - [0, half_spacing_between_arrows],  xycoords='axes fraction',
                     arrowprops={'arrowstyle': '-|>', 'color': "C3" if c == 0.02 else "lightgrey", "linestyle": "--", "linewidth":1, "shrinkA": 0, "shrinkB": 0})
        if c == 0.02:
            plt.annotate('', xytext=data_to_axis.transform([(max_fnr * 100, c * 100)])[0],
                         textcoords='axes fraction',
                         xy=[data_to_axis.transform([(max_fnr * 100, 1)])[0][0], 0],
                         xycoords='axes fraction',
                         arrowprops={'arrowstyle': '-|>', 'color': "C2" , "linestyle": "--",
                                     "linewidth": 1, "shrinkA": 0, "shrinkB": 0})
            plt.annotate('', xytext=data_to_axis.transform([(100 - max_fpr * 100, c * 100)])[0],
                         textcoords='axes fraction',
                         xy=[data_to_axis.transform([(100 - max_fpr * 100, 1)])[0][0], 0],
                         xycoords='axes fraction',
                         arrowprops={'arrowstyle': '-|>', 'color': "C3" , "linestyle": "--",
                                     "linewidth": 1, "shrinkA": 0, "shrinkB": 0})
            ticks_list = list(plt.xticks()[0])
            ticks_list.remove(60)
            plt.xticks(ticks_list + [max_fnr * 100, 100 - max_fpr * 100])

        p = patches.Rectangle((0,eer), 100, 100-eer, linewidth=0, fill=None, hatch='///', color='lightgrey') # data_to_axis.transform([(5.1 * 100, 0)])[0]
        plt.gca().add_patch(p)

        bbox_props = dict(boxstyle="rarrow", fc="white", ec="C0", lw=1)
        plt.text(50, eer, "Equal error rate", ha="center", va="center", rotation=0,
                    size=10,
                    bbox=bbox_props)

        plt.text(50, 25, "Above equal error rate: use 100% of automated classification", size=10, rotation=0,
                 ha="center", va="center",
                 bbox=dict(boxstyle="round",
                           ec="white",
                           facecolor="white",
                           )
                 )
    f.savefig('figures/' + path + 'bins.pdf',bbox_inches='tight', dpi=600)
    plt.close()
