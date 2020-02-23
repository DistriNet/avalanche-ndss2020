import numpy as np

import seaborn as sns
from matplotlib import pyplot as plt

from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.covariance import empirical_covariance
from scipy.ndimage import gaussian_filter

def pcaAnalysis(features, labels, path):
    '''
    Do a PCA.
    :param features: the features of the data points
    :param labels: labels for data points
    :param path: paht to save to
    '''
    #### PCA
    pca = PCA()
    scl = StandardScaler()
    standardized = scl.fit_transform(features,labels)
    reduced = pca.fit_transform(standardized, labels)
    sum = np.zeros(pca.components_.shape[0])
    for row, sv in zip(pca.components_, pca.singular_values_):
        sum = sum + np.abs(row * sv)
    for i, v in enumerate(sorted(range(len(sum)), key=lambda k: sum[k])):
        print(str(i), '. ', features.columns[v])
    sns.heatmap(pca.inverse_transform(np.eye(features.shape[1])), cmap='hot', cbar=False)
    plt.xlabel('feature index')
    plt.ylabel('principal component')
    plt.savefig('figures/'  + path + 'pcaheatmap.pdf')
    plt.close()

def covMatrix(features, labels, path):
    '''
    Calculate feature correlations
    :param features: feature values of the data points
    :param labels: labels of the data points
    :param path: path to save to
    '''
    scl = StandardScaler()
    standardized = scl.fit_transform(features, labels)
    corr = empirical_covariance(standardized)
    # mask = np.zeros_like(corr, dtype=np.bool)
    # mask[np.triu_indices_from(mask)] = True
    f, ax = plt.subplots(figsize=(11, 9))
    cmap = sns.diverging_palette(220, 10, as_cmap=True)
    sns.heatmap(corr, cmap=cmap, center=0,
                square=True, linewidths=.5, cbar_kws={"shrink": .5})
    plt.savefig('figures/' + path + 'covmatrix.pdf')
    plt.close()

    filtered = gaussian_filter(np.abs(corr), sigma=2)
    # mask = np.zeros_like(corr, dtype=np.bool)
    # mask[np.triu_indices_from(mask)] = True
    f, ax = plt.subplots(figsize=(11, 9))
    cmap = sns.diverging_palette(220, 10, as_cmap=True)
    sns.heatmap(filtered, cmap=cmap, center=0,
                square=True, linewidths=.5, cbar_kws={"shrink": .5})
    plt.savefig('figures/' + path + 'filtered.pdf')
    plt.close()

    filtered = gaussian_filter(np.clip(corr, a_min=-1, a_max=0), sigma=2)
    # mask = np.zeros_like(corr, dtype=np.bool)
    # mask[np.triu_indices_from(mask)] = True
    f, ax = plt.subplots(figsize=(11, 9))
    cmap = sns.diverging_palette(220, 10, as_cmap=True)
    sns.heatmap(filtered, cmap=cmap, center=0,
                square=True, linewidths=.5, cbar_kws={"shrink": .5})
    plt.savefig('figures/' + path + 'negativecorrelated.pdf')
    plt.close()

    filtered = gaussian_filter(np.clip(corr, a_min=0, a_max=1), sigma=2)
    # mask = np.zeros_like(corr, dtype=np.bool)
    # mask[np.triu_indices_from(mask)] = True
    f, ax = plt.subplots(figsize=(11, 9))
    cmap = sns.diverging_palette(220, 10, as_cmap=True)
    sns.heatmap(filtered, cmap=cmap, center=0,
                square=True, linewidths=.5, cbar_kws={"shrink": .5})
    plt.savefig('figures/' + path + 'positivecorrelatedcov.pdf')
    plt.close()

    abs_corr = np.abs(corr)
    mat = abs_corr[0:10,0:10]
    jj = np.sum(mat)/(mat.shape[0]*mat.shape[1])
    mat = abs_corr[0:10,10:21]
    jp = np.sum(mat) / (mat.shape[0] * mat.shape[1])
    mat = abs_corr[0:10, 21:36]
    jw = np.sum(mat) / (mat.shape[0] * mat.shape[1])
    mat = abs_corr[0:10, 36:]
    ja = np.sum(mat) / (mat.shape[0] * mat.shape[1])

    mat = abs_corr[10:21, 10:21]
    pp = np.sum(mat) / (mat.shape[0] * mat.shape[1])
    mat = abs_corr[10:21, 21:36]
    pw = np.sum(mat) / (mat.shape[0] * mat.shape[1])
    mat = abs_corr[10:21, 36:]
    pa = np.sum(mat) / (mat.shape[0] * mat.shape[1])

    mat = abs_corr[21:36, 21:36]
    ww = np.sum(mat) / (mat.shape[0] * mat.shape[1])
    mat = abs_corr[21:36, 36:]
    wa = np.sum(mat) / (mat.shape[0] * mat.shape[1])

    mat = abs_corr[36:, 36:]
    aa = np.sum(mat) / (mat.shape[0] * mat.shape[1])

    average = np.array([[jj, jp, jw, ja], [jp, pp, pw, pa], [jw, pw, ww, wa], [ja, pa, wa, aa]])
    f, ax = plt.subplots(figsize=(4,1.8))
    cmap = sns.diverging_palette(220, 10, as_cmap=True)
    sns.heatmap(average, cmap=cmap, center=0, vmax=0.2, annot=True,
                square=False, linewidths=.5, cbar_kws={"shrink": 1},
                xticklabels=["Joint", "Passive\nDNS", "WHOIS", "Active\nDNS"],
                yticklabels=["Joint", "Passive DNS", "WHOIS", "Active DNS"])
    plt.tight_layout()
    plt.savefig('figures/' + path + 'averageperdatasetcov.pdf',bbox_inches='tight', dpi=600)
    plt.close()