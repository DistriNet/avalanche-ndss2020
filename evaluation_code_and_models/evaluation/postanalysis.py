import pandas as pd
import numpy as np
import datetime

from sklearn.metrics import confusion_matrix
import macroify

def saveFpFnDf(x_test,y_test,y_pred,columnnames,domainname,  path):
    ''' Save the domains that were falsy classified. FP and FN are saved in sperate files
    :param x_test: features of the data points
    :param y_test: real labels
    :param y_pred: predicted labels
    :param columnnames: names of the features
    :param domainname: list of domainnnames
    :param path: path to save to
    '''
    df = pd.DataFrame(x_test, columns=columnnames, index = domainname)
    fpdf = df[np.logical_and(y_test != y_pred, y_pred == 1)]
    fndf = df[np.logical_and(y_test != y_pred, y_pred == 0)]
    fpdf.to_csv('dfs/' + path + 'falsepositives.csv')
    fndf.to_csv('dfs/' + path + 'falsenegatives.csv')

def saveFpFnDfBis(df, labels,labels_pred, path):
    ''' Save the domains that were falsy classified. FP and FN are saved in sperate files
    :param x_test: features of the data points
    :param y_test: real labels
    :param y_pred: predicted labels
    :param columnnames: names of the features
    :param domainname: list of domainnnames
    :param path: path to save to
    '''
    y_test = labels.values
    y_pred = labels_pred
    print(y_test)
    print(y_pred)
    print(y_test != y_pred)
    fpdf = df[np.logical_and(y_test != y_pred, y_pred == 1)]
    fndf = df[np.logical_and(y_test != y_pred, y_pred == 0)]
    fpdf.to_csv('dfs/' + path + 'falsepositives.csv')
    fndf.to_csv('dfs/' + path + 'falsenegatives.csv')

def saveimportance(importances, featurenames, path):
    ''' Save the feature importances
    :param importances: the importance scores
    :param featurenames: the name of the features
    :param path: path to save to
    '''
    df = pd.DataFrame({'featurename':featurenames, 'score':importances})
    df = df.sort_values('score',ascending=False)
    df.to_csv('dfs/' + path + 'importance.csv')

def featureDistribution(columnnames, estimators, distributions):
    for estimator in estimators:
        estimator = estimator[0]
        for fid,thr in zip(estimator.tree_.feature, estimator.tree_.threshold):
            if fid >= 0:
                distributions[columnnames[fid]].append(thr)


def understandDecisionTree(estimator):
    n_nodes = estimator.tree_.node_count
    children_left = estimator.tree_.children_left
    children_right = estimator.tree_.children_right
    feature = estimator.tree_.feature
    threshold = estimator.tree_.threshold

    node_depth = np.zeros(shape=n_nodes, dtype=np.int64)
    is_leaves = np.zeros(shape=n_nodes, dtype=bool)
    stack = [(0, -1)]  # seed is the root node id and its parent depth
    while len(stack) > 0:
        node_id, parent_depth = stack.pop()
        node_depth[node_id] = parent_depth + 1

        # If we have a test node
        if (children_left[node_id] != children_right[node_id]):
            stack.append((children_left[node_id], parent_depth + 1))
            stack.append((children_right[node_id], parent_depth + 1))
        else:
            is_leaves[node_id] = True

    print("The binary tree structure has %s nodes and has "
          "the following tree structure:"
          % n_nodes)
    for i in range(n_nodes):
        if is_leaves[i]:
            print("%snode=%s leaf node." % (node_depth[i] * "\t", i))
        else:
            print("%snode=%s test node: go to node %s if X[:, %s] <= %s else to "
                  "node %s."
                  % (node_depth[i] * "\t",
                     i,
                     children_left[i],
                     feature[i],
                     threshold[i],
                     children_right[i],
                     ))

def print_performance_per_malware_family(y_test, y_pred, y_post, column_malware_family = 0, print_to_tex=False):
    '''
    Analyse the performance for each malware family
    :param y_test: real labels
    :param y_pred: predicted labels
    :param y_post: the accounting information for each data point, i.e. malware family
    :param column_malware_family: where the malware family column is located
    :param print_to_tex:
    :return:
    '''
    malware_families = set(y_post[:,column_malware_family])
    s = 0

    if print_to_tex:
        print("Family & \# samples & Acc. & Prec. & Rec. & FNR & FPR \\\\")
    for family in malware_families:
        y_test_family = y_test[y_post[:,column_malware_family] == family]
        y_pred_family = y_pred[y_post[:,column_malware_family] == family]
        try:
            tn, fp, fn, tp = confusion_matrix(y_test_family, y_pred_family).ravel()
            print('{} got {} tp, {} fp, {} tn, {} fn, {:.2f} accuracy, {:.2f} fnr, {:.2f} fpr'.format(\
                family, tp, fp, tn, fn, (tp + tn) / (tp + tn + fp + fn), fn / (fn + tp), fp / (fp+tn)))
            if tp + fp + tn + fn > 50:
                if print_to_tex:
                    print('{} & {} & {:.1f}\\% & {:.1f}\\%  & {:.1f}\\%  & {:.1f}\\%  & {:.1f}\\% \\\\'.format(
                        family, tp + fp + tn + fn, 100*(tp + tn) / (tp + tn + fp + fn),  100*tp/(tp+fp), 100*tp/(tp+fn),  100*fn / (fn + tp) , 100*fp / (fp+tn)))
                else:
                    print('{} got {} samples, {:.2f} accuracy, {:.2f} fnr, {:.2f} fpr, {:.2f} precision, {:.2f} recall'.format(\
                        family, tp + fp + tn + fn, (tp + tn) / (tp + tn + fp + fn), fn / (fn + tp), fp / (fp+tn), tp/(tp+fp), tp/(tp+fn)))
            s = s + tn + fp + fn + tp
        except ValueError:
            print('family {} got no result'.format(family))

    print('Total amount of domains ' + str(s))

def print_performance_per_malware_validity_timestamp(y_test, y_pred, y_post, column_timestamp=-1):
    '''
    Print the performance per malware validity timestamp
    :param y_test:
    :param y_pred:
    :param y_post:
    :param column_timestamp:
    :return:
    '''
    timestamps = [datetime.datetime(2017, 11, 30, 0, 0, 0)] + \
                 [datetime.datetime(2017, month, 1, 0, 0, 0) for month in range(12, 12+1)] + \
                 [datetime.datetime(2018, month, 1, 0, 0, 0) for month in range(1, 12 + 1)] + \
                 [datetime.datetime(2019, 1, 1, 0, 0, 0)] + \
                 [datetime.datetime(2049, 1, 1, 0, 0, 0)]
    s = 0
    plot_data = []

    for timestamp_idx in range(len(timestamps) - 1):
        y_test_family = y_test[(timestamps[timestamp_idx] <= y_post[:, column_timestamp]) & (y_post[:, column_timestamp] < timestamps[timestamp_idx+1])]
        y_pred_family = y_pred[(timestamps[timestamp_idx] <= y_post[:, column_timestamp]) & (y_post[:, column_timestamp] < timestamps[timestamp_idx+1])]
        try:
            tn, fp, fn, tp = confusion_matrix(y_test_family, y_pred_family).ravel()
            print('{} got {} tp, {} fp, {} tn, {} fn, {:.2f} accuracy, {:.2f} fnr, {:.2f} fpr'.format(
                timestamps[timestamp_idx].month, tp, fp, tn, fn, (tp + tn) / (tp + tn + fp + fn), fn / (fn + tp), fp / (fp + tn)))
            plot_data.append(("{}-{}".format(timestamps[timestamp_idx].month, timestamps[timestamp_idx].year),
                              tp, fp, tn, fn, (tp + tn) / (tp + tn + fp + fn), fn / (fn + tp), fp / (fp + tn)))
            s = s + tn + fp + fn + tp
        except ValueError:
            print('got no result')
    import matplotlib.pyplot as plt
    labels = "tp fp tn fn accuracy fnr fpr".split(" ")
    plt.plot([d[0] for d in plot_data], [sum(d[1:5]) for d in plot_data]   )
    plt.plot([d[0] for d in plot_data], [sum(d[1:3]) for d in plot_data]       )
    plt.plot([d[0] for d in plot_data], [sum(d[3:5]) for d in plot_data])

    plt.show()
    for i in range(4,len(labels)):
        plt.plot([d[0] for d in plot_data], [d[i+1] for d in plot_data],
                     label=labels[i])
    plt.show()

def workReducedPostDomains(trainyear, code, scores):
    '''returns the actual domains'''
    thresholds = pd.read_csv('dfs/' + trainyear + '/' + code + '_workreduced.csv', index_col=0).loc[:,
                 ['thresholds_fnr', 'thresholds_fpr']]
    upper = thresholds.iloc[3, 1]
    lower = thresholds.iloc[3, 0]

    negative_pred_ind = [ s < lower for s in scores[:,1]]
    no_action_pred_ind = [ (s >= lower) and (s <= upper) for s in scores[:,1]]
    positive_pred_ind = [ s > upper for s in scores[:,1]]

    return negative_pred_ind, no_action_pred_ind, positive_pred_ind

def thresholdsToLatex(path='dfs/2017/1111_workreduced.csv'):
    df = pd.read_csv(path,index_col=0)
    results = {}
    results['WorkReducedLowerBound'] = df.loc[:,'fnr'].iloc[-1]
    results['WorkReducedUpperBound'] = 100-df.loc[:,'fpr'].iloc[-1]
    results['WorkReducedHundredMinusUpperBound'] = df.loc[:,'fpr'].iloc[-1]
    results['WorkReducedTwoPercent'] = df.loc[:,'sum'].iloc[-1]
    results['WorkReducedHundredMinusTwoPercent'] = 100 - df.loc[:,'sum'].iloc[-1]
    # results['WorkReducedOnePercent'] = df.iloc[2,2]
    # results['WorkReducedPointFivePercent'] = df.iloc[1,2]
    # results['WorkReducedPointOnePercent'] = df.iloc[0,2]

    macroify.append_file(results)


