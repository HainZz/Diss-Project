import pandas as pd 
import numpy as np
import matplotlib.pyplot as plt 
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import plot_tree
from sklearn.metrics import ConfusionMatrixDisplay
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import pickle

FEATURES_TO_SELECT = 15

def ApplyColumnNames(dataset): # This function simply applys column names too the dataset
    print("Applying Column Names")
    #Because the first row of the CSV is column names we can get all the column names by getting the values of the first row and apply them to the dataframe.
    column_names = np.array(dataset)[0]
    Column_Names_List = column_names.tolist()
    for x in range(len(Column_Names_List)):
        Column_Names_List[x] = Column_Names_List[x].strip() #Removes Trailing and leading whitespaces
    dataset.columns = Column_Names_List #Apply all the names gathered from the first row to the dataset.
    #SOURCE: https://stackoverflow.com/questions/14984119/python-pandas-remove-duplicate-columns
    #Remove Duplicate Fwd Header Length Column
    dataset = dataset.loc[:,~dataset.columns.duplicated()]
    #Remove First Row From Dataset
    dataset = dataset.iloc[1:,:]
    #print(list(dataset))
    return dataset
    
def FeatureSelection(dataset): #Purpose of this function is to control the number of features being inputted to the & Clean up non-features from the dataset.
    ##Feature Rank Based Off Work Done SOURCE: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9142219
    All_column_list = list(dataset)
    #print(All_column_list)
    Feature_Rank_List = [ #Ordered list of based off features information gain of features
        'Packet Length Std',
        'Total Length of Bwd Packets',
        'Subflow Bwd Bytes',
        'Destination Port',
        'Packet Length Variance',
        'Bwd Packet Length Mean',
        'Avg Bwd Segment Size',
        'Bwd Packet Length Max',
        'Init_Win_bytes_backward',
        'Total Length of Fwd Packets',
        'Subflow Fwd Bytes',
        'Init_Win_bytes_forward',
        'Average Packet Size',
        'Packet Length Mean',
        'Max Packet Length',
        'Fwd Packet Length Max',
        'Flow IAT Max',
        'Bwd Header Length',
        'Flow Duration',
        'Fwd IAT Max',
        'Fwd Header Length',
        'Fwd IAT Total',
        'Fwd IAT Mean',
        'Flow IAT Mean',
        'Flow Bytes/s',
        'Bwd Packet Length Std',
        'Subflow Bwd Packets',
        'Total Backward Packets',
        'Fwd Packet Length Mean',
        'Avg Fwd Segment Size',
        'Bwd Packet Length Min',
        'Flow Packets/s',
        'Fwd Packets/s',
        'Bwd IAT Max',
        'Bwd Packets/s',
        'Total Fwd Packets',
        'Subflow Fwd Packets',
        'Bwd IAT Total',
        'Flow IAT Std',
        'Fwd Packet Length Std',
        'Bwd IAT Mean',
        'Fwd IAT Std',
        'Fwd Packet Length Min',
        'Min Packet Length',
        'Active Mean',
        'Fwd IAT Min',
        'Active Min',
        'min_seg_size_forward',
        'Active Max',
        'Bwd IAT Min',
        'Flow IAT Min',
        'Idle Max',
        'Idle Mean',
        'Idle Min',
        'act_data_pkt_fwd',
        'Bwd IAT Std',
        'PSH Flag Count',
        'Down/Up Ratio',
        'ACK Flag Count',
        'Idle Std',
        'FIN Flag Count',
        'URG Flag Count',
        'Active Std',
        'SYN Flag Count',
        'Fwd PSH Flags',
        'RST Flag Count',
        'ECE Flag Count',
        'Bwd Avg Bulk Rate',
        'CWE Flag Count',
        'Fwd Avg Packets/Bulk',
        'Fwd Avg Bytes/Bulk',
        'Fwd URG Flags',
        'Bwd PSH Flags',
        'Bwd URG Flags',
        'Bwd Avg Packets/Bulk',
        'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk',
    ]
    Columns_To_Remove = []
    for column in All_column_list:
        if column not in Feature_Rank_List[0:FEATURES_TO_SELECT] and column != 'Label': #Here we generate a columns to remove list based off the numbers of features we want to select.
            Columns_To_Remove.append(column)
    #print(*Columns_To_Remove,sep='\n')
    #SOURCE: https://www.educative.io/edpresso/how-to-delete-a-column-in-pandas
    #print(Columns_To_Remove)
    print("Columns Before Deleting column")
    print(list(dataset))
    for column in Columns_To_Remove: #Iterate over columns to remove list. Removing columns within the list from the dataframe
        #print(column)
        dataset.drop(column,inplace=True,axis=1)
        #print(list(dataset))
    print("Columns after deleting columns")
    print(list(dataset))
    return dataset

#Sci-Kit natively does not support strings therefore its important to encode values 
#SOURCE: https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.LabelEncoder.html
#This converts Benign = 0, PortScan = 1

def GetColumnIndex(columnName,df):
    ColumnIndex = df.columns.get_loc(columnName)
    #print(ColumnIndex)
    return ColumnIndex

def EncodeLabels(dataset):
    le  = LabelEncoder()
    column = "Label"
    ColumnIndex = GetColumnIndex(column,dataset)
    dataset.iloc[:,ColumnIndex] = le.fit_transform(dataset.iloc[:,ColumnIndex])
    #print(dataset['Label'].unique()) #Testing that we have 0,1 as the new Label values.
    return dataset  

def DatasetImport():
    #Read In Dataset
    dataset = pd.read_csv('C:\Project\Code\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',header=None,dtype=object) #Note this file is placed within the same directory as the program if u want to run this either change this to match the file location of downloaded CSV
    dataset = ApplyColumnNames(dataset) #Apply's Column Names to all columns before removal. This helps format dataset easier 
    print(dataset['Label'].value_counts())
    dataset = FeatureSelection(dataset) #This selects the features to be classified & Removes non features.
    dataset = EncodeLabels(dataset)
    dataset.to_csv('Code\Formatted_CSV\output.csv')
   
## BEGGINING OF ACTUAL DECISION TREE CODE

#SOURCE: https://machinelearningmastery.com/train-test-split-for-evaluating-machine-learning-algorithms/
def GetSplitData(X,Y):
    #This splits our entire dataset into 77% training data and 33% test data 
    X_train,X_test,Y_train,Y_test = train_test_split(X,Y, test_size = 0.33)
    return X_train,X_test,Y_train,Y_test

def DecisionTree():
    df = pd.read_csv('C:\Project\Code\Formatted_CSV\output.csv')
    LabelIndex = GetColumnIndex("Label", df)
    ##Separting Class labels from data. This is required for classification theres no point putting the lables within X training samples 
    LabelTrainingSamples = df.iloc[:,LabelIndex]
    NonLabelTrainingSamples = df.drop(df.columns[LabelIndex],axis=1)
    X_train,X_test,Y_train,Y_test = GetSplitData(NonLabelTrainingSamples,LabelTrainingSamples)
    CreateTreeModel(X_train,X_test,Y_train,Y_test)


##SOURCE: https://scikit-learn.org/stable/auto_examples/model_selection/plot_confusion_matrix.html#sphx-glr-auto-examples-model-selection-plot-confusion-matrix-py
def GenerateConfusionMatrix(X_test,Y_test,model):
    titles_options = [("Unormalized Confusion Matrix",None),("Normalized Confusion Matrix","true")]
    for title, normalize in titles_options:
        disp = ConfusionMatrixDisplay.from_estimator(
            model,
            X_test,
            Y_test,
            display_labels=["PortScan","Benign"],
            cmap=plt.cm.Blues,
            normalize=normalize,
        )
        disp.ax_.set_title(title)
        print(title)
        print(disp.confusion_matrix)
    plt.savefig()

def CreateTreeModel(X_train,X_test,Y_train,Y_test):
    model = DecisionTreeClassifier()
    model.fit(X_train,Y_train)
    print("Training Decision Tree Complete")
    prediction = model.predict(X_test)
    print(prediction)
    pred_acc = accuracy_score(Y_test, prediction)
    print(pred_acc)
    GenerateConfusionMatrix(X_test,Y_test,model)
    pickle.dump(model,open("C:\Project\Model_Dump\model.obj","wb"))

def main():
    DatasetImport()
    DecisionTree()


main()