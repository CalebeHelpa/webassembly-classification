# WebAssembly Classification
In this repository we present the source code used for classification of WebAssembly Binaries using DWARF (Debugging With Attributed Record Formats) informations.

# How do I get set up?
The following components should be installed:
```
* python 3.8.5
* pip3 20.0.2
* scikit-learn 0.22.2
```

# Install
Ubuntu instalation guide:
```
sudo apt install python3 python3-pip
```

# Setup
Clone this repository:
```
git clone https://github.com/CalebeHelpa/webassembly-classification.git
```
Install the dependencies using pip3:
```
cd webassembly-classification/
pip3 install scikit-learn pandas xgboost
```

# Example
Step by step on how to run the tests:
1. Insert your DWARF files relative to your **normal** dataset of binaries in `webassembly-classification/data/normal-dwarf/`;
2. Insert your DWARF files relative to your **anomaly** dataset of binaries in `webassembly-classification/data/anomaly-dwarf/`;
3. Use the variable `path` in `data_extraction.py` to indicate the type of binaries you are using to extract the atributes, its required to run one time for each (normal and anomaly), using the command `python3 data_extraction.py`;
4. Finaly, with your csv file containing the data extracted from the normal and the anomaly binaries, run the command `python3 data_analysis.py --dataset webassembly_dwarf_dataset.csv`
