#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    import numpy as np
    import pandas as pd
    import sys
    import argparse
    import re

    from xgboost import XGBRegressor, XGBClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.ensemble import AdaBoostClassifier 
    from sklearn.linear_model import SGDClassifier

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.ensemble import IsolationForest
    from sklearn.tree import DecisionTreeClassifier, export_graphviz
    from sklearn import tree
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.svm import SVC
    from sklearn.svm import OneClassSVM

    from sklearn.feature_extraction.text import CountVectorizer, TfidfTransformer, TfidfVectorizer, HashingVectorizer
    from sklearn import metrics
    from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
    from sklearn.metrics import accuracy_score, roc_auc_score, precision_score, recall_score, f1_score, balanced_accuracy_score, brier_score_loss

    from sklearn.preprocessing import StandardScaler, MinMaxScaler, MaxAbsScaler, OneHotEncoder, OrdinalEncoder
    from sklearn import preprocessing

    import warnings
    warnings.simplefilter(action='ignore', category=FutureWarning)

except Exception as e:
    print('Unmet dependency:', e)
    sys.exit(1)


class DwarfClassifier():
    """
    python3 data_analysis.py --dataset webassembly_dwarf_dataset.csv
    """

    def __init__(self, dataset):
        self.dataset = dataset

       ## Config ##
        self.randomState = 42

    def read_data(self):
        try:

            data = pd.read_csv(self.dataset, header=0, delimiter=",", na_filter=True, index_col=False)
            
            pd.set_option('display.max_columns', None)
            pd.set_option('display.max_rows', None)
            # print(data.describe())

            data = data.loc[:, (data != 0).any(axis=0)]
            print(data.describe())
 
            y = data['malicioso']

            data_benigno = data[data['malicioso'] == 0]
            y_benigno = data_benigno['malicioso']

            data = data.drop(['id','malicioso'], axis=1)
            X = data.reset_index(drop=True)

            data_benigno = data_benigno.drop(['id','malicioso'], axis=1)
            X_benigno = data_benigno.reset_index(drop=True)

            print(X.columns.values)


            #tokenization multi class
            encode = 'language'
            le = preprocessing.LabelEncoder()


            encoded_label = le.fit_transform(X[encode])
            X[encode] = encoded_label

            encoded_label = le.fit_transform(X_benigno[encode])
            X_benigno[encode] = encoded_label

            #normalization
            X_normalized = preprocessing.normalize(X, norm='l1')
            X_benigno = preprocessing.normalize(X_benigno, norm='l1')

            X_train, X_test, y_train, y_test = train_test_split(X_normalized, y, test_size=0.5, shuffle=True)
            X_train_benigno, X_test_oneClass, y_train_benigno, y_test_benigno = train_test_split(X_benigno, y_benigno, test_size=0.5, shuffle=True)
            
            
            y_test_oneclass = y_test
            y_test_oneclass = y_test_oneclass.replace(1, -1)
            y_test_oneclass = y_test_oneclass.replace(0, 1)


            return X_train, X_test, y_train, y_test, X_normalized, y, X_train_benigno, y_test_oneclass
        
        except Exception as e:
            print("read_data: ", e)

    def get_score_clf(self, name, y_test, y_pred, y_score):
        try:
            print(name, \
                  "precision", round(precision_score(y_test, y_pred), 4), \
                  "recall", round(recall_score(y_test, y_pred), 4), \
                  "f1", round(f1_score(y_test, y_pred), 4), \
                  "accuracy", round(accuracy_score(y_test, y_pred), 4), \
                  "bac", round(balanced_accuracy_score(y_test, y_pred), 4) , \
                  "brier", round(brier_score_loss(y_test, y_pred), 4)
                  )

        except Exception as e:
            print("get_score_clf", e)


    def get_score_clf_oneclass(self, name, y_test, y_pred, y_score):
        try:
            print(name, \
                  "precision", round(precision_score(y_test, y_pred, average="weighted"), 4), \
                  "recall", round(recall_score(y_test, y_pred, average="weighted"), 4), \
                  "f1", round(f1_score(y_test, y_pred, average="weighted"), 4), \
                  "accuracy", round(accuracy_score(y_test, y_pred), 4), \
                  "bac", round(balanced_accuracy_score(y_test, y_pred), 4)
                  )

        except Exception as e:
            print("get_score_clf", e)


    def main(self):
        X_train, X_test, y_train, y_test, X, y, X_train_benigno, y_test_oneclass = self.read_data()

        print("Running test function")
        # The Frame for metrics
        index = ['roc_auc', 'precision', 'recall', 'f1_score', 'accuracy', 'balanced_accuracy_score']
        metrics = pd.DataFrame(index=index)

        # One Class SVM
        svm = OneClassSVM()
        svm.fit(X_train_benigno)
        y_pred_svm = svm.predict(X_test)
        y_score_svm = svm.decision_function(X_test)
        self.get_score_clf_oneclass("svm_one_class", y_test_oneclass, y_pred_svm, y_score_svm)

        # Isolation Forest
        clf = IsolationForest(random_state=42)
        clf.fit(X_train_benigno)
        y_pred_clf = clf.predict(X_test)
        y_score_clf = clf.decision_function(X_test)
        self.get_score_clf_oneclass("clf_one_class", y_test_oneclass, y_pred_clf, y_score_clf)

        # MLP
        mlp = MLPClassifier(random_state=42)
        mlp.fit(X_train, y_train)
        y_pred_mlp = mlp.predict(X_test)
        y_score_mlp = mlp.predict_proba(X_test)[:,1:]
        self.get_score_clf("mlp", y_test, y_pred_mlp, y_score_mlp)

        # SVM
        svm = SVC(class_weight='balanced', probability=True)
        svm.fit(X_train, y_train)
        y_pred_svm = svm.predict(X_test)
        y_score_svm = svm.predict_proba(X_test)[:,1:]
        self.get_score_clf("svm", y_test, y_pred_svm, y_score_svm)

        # KNN
        knc = KNeighborsClassifier()
        knc.fit(X_train, y_train)
        y_pred_knc = knc.predict(X_test)
        y_score_knc = knc.predict_proba(X_test)[:,1:]
        self.get_score_clf("knn", y_test, y_pred_knc, y_score_knc)

        # Decision tree
        dtc = DecisionTreeClassifier(class_weight='balanced')
        dtc.fit(X_train, y_train)
        y_pred_dtc = dtc.predict(X_test)
        y_score_dtc = dtc.predict_proba(X_test)[:,1:]
        self.get_score_clf("dtc", y_test, y_pred_dtc, y_score_dtc)

        # Random Forest
        rfc = RandomForestClassifier(class_weight='balanced')
        rfc.fit(X_train, y_train)
        y_pred_rfc = rfc.predict(X_test)
        y_score_rfc = rfc.predict_proba(X_test)[:,1:]
        self.get_score_clf("rfc", y_test, y_pred_rfc, y_score_rfc)

        # XGBoost
        xgb = XGBClassifier()
        xgb.fit(X_train, y_train)
        y_pred_xgb = xgb.predict(X_test)
        y_score_xgb = xgb.predict_proba(X_test)[:,1:]
        self.get_score_clf("xgb", y_test, y_pred_xgb, y_score_xgb)

        # Ada Boost
        ab = AdaBoostClassifier()
        ab.fit(X_train, y_train)
        y_pred_ab = ab.predict(X_test)
        y_score_ab = ab.predict_proba(X_test)[:,1:]
        self.get_score_clf("ab", y_test, y_pred_ab, y_score_ab)

        sgdc = SGDClassifier(max_iter=1000, loss='modified_huber')
        sgdc.fit(X_train, y_train)
        y_pred_sgdc = sgdc.predict(X_test)
        y_score_sgdc = sgdc.predict_proba(X_test)[:,1:]
        self.get_score_clf("sgdc", y_test, y_pred_sgdc, y_score_sgdc)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='.')
    parser.add_argument('--version', '-v', '-vvv', '-version', action='version', version=str('Base 2.1'))
    parser.add_argument('--dataset', type=str, required=True, help='This option define the dataset.')

    # get args
    args = parser.parse_args()
    kwargs = {
        'dataset': args.dataset
    }

    args = parser.parse_args()

    try:
        worker = DwarfClassifier(**kwargs)
        worker.main()
    except KeyboardInterrupt as e:
        print('Exit using ctrl^C')
