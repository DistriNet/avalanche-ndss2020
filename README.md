# A Practical Approach for Taking Down Avalanche Botnets Under Real-World Constraints

*By Victor Le Pochat, Tim Van hamme, Sourena Maroofi, Tom Van Goethem, Davy Preuveneers, Andrzej Duda, Wouter Joosen, and Maciej Korczyński*

This repository contains the source code and models of our NDSS 2020 paper [A Practical Approach for Taking Down Avalanche Botnets Under Real-World Constraints](https://lepoch.at/files/avalanche-ndss20.pdf).

* `feature_generation` contains the code for parsing raw input data, extracting feature values and ground truth, and exporting them to input files for the machine learning classifier.
* `evaluation_code_and_models` contains the code for the evaluation and the models that were trained during it. The evaluation procedure that is followed can be found in the `paper.sh` bash script, it is as follows:
     1. train the models within 1 year by using `production_train.py`, do this for all dataset combinations and both the 2017 and 2018 iterations
     2. evaluate the performance of every iteration and every dataset combination by using `experiment.py`, this also finds the thresholds for the work reduced metric
     3. do the above evaluation for the full ensemble by calling `ensemble_evaluation.py`
     4. evaluate ensemble performance when trained on one iteration and tested on another by calling `incremental_learning_evaluation.py`
     5. evaluate the extended model trained on 2017 data + a part of 2018 data by calling `incremental_learning_evaluation.py`
     6. the dataset impact evaluation for both the extended and base models are found in `dataset_impact_evaluation_extended.py` and `dataset_impact_evaluation.py`
* The evaluation code depends on scikitk-learn for training the models. To obtain the equal error rate evaluation metric we rely on [bob suite](https://www.idiap.ch/software/bob/). Other used packages: numpy, pandas.

Due to the sensitivity of the ground truth provided by law enforcement and commercial agreements for the third-party data sets, we cannot share the raw input data.
