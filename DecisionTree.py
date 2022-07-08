import pandas as pd 
import numpy as np
import matplotlib.pyplot as plt 
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import plot_tree
from sklearn.metrics import ConfusionMatrixDisplay
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.tree import export_graphviz
from six import StringIO
from IPython.display import Image 
import pickle
import pydotplus
import os
import dataframe_image as dfi

TRAINING_CSV =  'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
TESTING_CSV = 'Individual-Nmap-Flows\\nmap-sS-Base-Flow.csv'
TESTING_MODE = False
INDIVIDUAL_FEATURE_TEST = True #Global variables dictating the operation of the program
MODELNAME = "TestModel" #Change this to change the model name if not doing Individual Feature Test
FEATURESTOINCLUDE = ['Packet Length Std','Packet Length Variance',] #This list is the features to include within the decision tree note these are case sensitive and need to match the features contained within the features rank list.

def ApplyLabels(df): #This function applies whether a flow was portscan or Benign when passing in a test dataset.
    df['Label'] = np.where(df['src_ip']=='10.20.2.251','PortScan','BENIGN')
    return df

def ChangeColumnNames(df):
    #Both lists. Each index of both lists are the same feature therefore we can convert to a dict and rename the entire df
    Feature_Rank_List_Unormalised = [ 'pkt_len_std', 'totlen_bwd_pkts', 'subflow_bwd_byts', 'dst_port', 'pkt_len_var', 'bwd_pkt_len_mean', 'bwd_seg_size_avg', 'bwd_pkt_len_max', 'init_bwd_win_byts', 'totlen_fwd_pkts', 'subflow_fwd_byts', 'init_fwd_win_byts', 'pkt_size_avg', 'pkt_len_mean', 'pkt_len_max', 'fwd_pkt_len_max', 'flow_iat_max', 'bwd_header_len', 'flow_duration', 'fwd_iat_max', 'fwd_header_len', 'fwd_iat_tot', 'fwd_iat_mean', 'flow_iat_mean', 'flow_byts_s', 'bwd_pkt_len_std', 'subflow_bwd_pkts', 'tot_bwd_pkts', 'fwd_pkt_len_mean', 'fwd_seg_size_avg', 'bwd_pkt_len_min', 'flow_pkts_s', 'fwd_pkts_s', 'bwd_iat_max', 'bwd_pkts_s', 'tot_fwd_pkts', 'subflow_fwd_pkts', 'bwd_iat_tot', 'flow_iat_std', 'fwd_pkt_len_std', 'bwd_iat_mean', 'fwd_iat_std', 'fwd_pkt_len_min', 'pkt_len_min', 'active_mean', 'fwd_iat_min', 'active_min', 'fwd_seg_size_min', 'active_max', 'bwd_iat_min', 'flow_iat_min', 'idle_max', 'idle_mean', 'idle_min', 'fwd_act_data_pkts', 'bwd_iat_std', 'psh_flag_cnt', 'down_up_ratio', 'ack_flag_cnt', 'idle_std', 'fin_flag_cnt', 'urg_flag_cnt', 'active_std', 'syn_flag_cnt', 'fwd_psh_flags', 'rst_flag_cnt', 'ece_flag_cnt', 'bwd_blk_rate_avg', 'cwe_flag_count', 'fwd_pkts_b_avg', 'fwd_byts_b_avg', 'fwd_urg_flags', 'bwd_psh_flags', 'bwd_urg_flags', 'bwd_pkts_b_avg', 'fwd_blk_rate_avg', 'bwd_byts_b_avg', ]
    Feature_Rank_List_Normalised = ['Packet Length Std', 'Total Length of Bwd Packets', 'Subflow Bwd Bytes', 'Destination Port', 'Packet Length Variance', 'Bwd Packet Length Mean', 'Avg Bwd Segment Size', 'Bwd Packet Length Max', 'Init_Win_bytes_backward', 'Total Length of Fwd Packets', 'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Average Packet Size', 'Packet Length Mean', 'Max Packet Length', 'Fwd Packet Length Max', 'Flow IAT Max', 'Bwd Header Length', 'Flow Duration', 'Fwd IAT Max', 'Fwd Header Length', 'Fwd IAT Total', 'Fwd IAT Mean', 'Flow IAT Mean', 'Flow Bytes/s', 'Bwd Packet Length Std', 'Subflow Bwd Packets', 'Total Backward Packets', 'Fwd Packet Length Mean', 'Avg Fwd Segment Size', 'Bwd Packet Length Min', 'Flow Packets/s', 'Fwd Packets/s', 'Bwd IAT Max', 'Bwd Packets/s', 'Total Fwd Packets', 'Subflow Fwd Packets', 'Bwd IAT Total', 'Flow IAT Std', 'Fwd Packet Length Std', 'Bwd IAT Mean', 'Fwd IAT Std', 'Fwd Packet Length Min', 'Min Packet Length', 'Active Mean', 'Fwd IAT Min', 'Active Min', 'min_seg_size_forward', 'Active Max', 'Bwd IAT Min', 'Flow IAT Min', 'Idle Max', 'Idle Mean', 'Idle Min', 'act_data_pkt_fwd', 'Bwd IAT Std', 'PSH Flag Count', 'Down/Up Ratio', 'ACK Flag Count', 'Idle Std', 'FIN Flag Count', 'URG Flag Count', 'Active Std', 'SYN Flag Count', 'Fwd PSH Flags', 'RST Flag Count', 'ECE Flag Count', 'Bwd Avg Bulk Rate', 'CWE Flag Count', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bytes/Bulk', 'Fwd URG Flags', 'Bwd PSH Flags', 'Bwd URG Flags', 'Bwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', ]
    Rename_Dict = {}
    Counter = 0
    for feature in Feature_Rank_List_Unormalised: #Create Dict for the rename operation
        Rename_Dict[feature] = Feature_Rank_List_Normalised[Counter]
        Counter += 1 
    NewDF = df.rename(columns=Rename_Dict)
    return NewDF 

def ApplyColumnNames(dataset): # This function simply applys column names too the dataset
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
    return dataset
    
def FeatureSelection(dataset,Features_To_Include): #Purpose of this function is to control the number of features being inputted to the & Clean up non-features from the dataset.
    ##Feature Rank Based Off Work Done SOURCE: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9142219
    All_column_list = list(dataset)
    Columns_To_Remove = []
    for column in All_column_list:
        if column not in Features_To_Include and column != 'Label': #Here we generate a columns to remove list based off the numbers of features we want to select.
            Columns_To_Remove.append(column)
    #SOURCE: https://www.educative.io/edpresso/Show-to-delete-a-column-in-pandas
    for column in Columns_To_Remove: #Iterate over columns to remove list. Removing columns within the list from the dataframe
        dataset = dataset.drop(column,axis=1)
    Ordered_Column_List = Features_To_Include #Feature_Rank_List[0:FEATURES_TO_SELECT]
    Ordered_Column_List.append('Label')
    dataset = dataset[Ordered_Column_List]
    return dataset

#Sci-Kit natively does not support strings therefore its important to encode values 
#SOURCE: https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.LabelEncoder.html
#This converts Benign = 0, PortScan = 1

def GetColumnIndex(columnName,df): #Returns the index of a given column name within the DF
    ColumnIndex = df.columns.get_loc(columnName)
    return ColumnIndex

def EncodeLabels(dataset): #Encodes labels with numbers instead off strings for example BENIGN is encoded to 0 and PortScan is encoded to 1. 
    le  = LabelEncoder()
    column = "Label"
    ColumnIndex = GetColumnIndex(column,dataset) #Get the index of the label column
    dataset.iloc[:,ColumnIndex] = le.fit_transform(dataset.iloc[:,ColumnIndex]) #Convert labels to numbers
    return dataset  

def DatasetImport():
    #Read In Dataset
    if TESTING_MODE != True:
        Orginaldataset = pd.read_csv(TRAINING_CSV,header=None,dtype=object) #Note this file is placed within the same directory as the program if u want to run this either change this to match the file location of downloaded CSV
    else:
        Orginaldataset = pd.read_csv(TESTING_CSV,header=None,dtype=object)
    #Cleanup the dataset by replacing INF values with Nans then removing rows with a NAN value 
    Orginaldataset = Orginaldataset.replace(to_replace=np.inf, value=np.nan)
    Orginaldataset = Orginaldataset.replace(to_replace=-np.inf, value=np.nan)
    Orginaldataset = Orginaldataset.replace(to_replace="Infinity", value=np.nan)
    Orginaldataset = Orginaldataset.dropna(how="any")
    Orginaldataset = ApplyColumnNames(Orginaldataset) #Apply's Column Names to all columns before removal. This helps format dataset easier 
    if TESTING_MODE == True:
        Feature_Rank_List_Unormalised = [ 'pkt_len_std', 'totlen_bwd_pkts', 'subflow_bwd_byts', 'dst_port', 'pkt_len_var', 'bwd_pkt_len_mean', 'bwd_seg_size_avg', 'bwd_pkt_len_max', 'init_bwd_win_byts', 'totlen_fwd_pkts', 'subflow_fwd_byts', 'init_fwd_win_byts', 'pkt_size_avg', 'pkt_len_mean', 'pkt_len_max', 'fwd_pkt_len_max', 'flow_iat_max', 'bwd_header_len', 'flow_duration', 'fwd_iat_max', 'fwd_header_len', 'fwd_iat_tot', 'fwd_iat_mean', 'flow_iat_mean', 'flow_byts_s', 'bwd_pkt_len_std', 'subflow_bwd_pkts', 'tot_bwd_pkts', 'fwd_pkt_len_mean', 'fwd_seg_size_avg', 'bwd_pkt_len_min', 'flow_pkts_s', 'fwd_pkts_s', 'bwd_iat_max', 'bwd_pkts_s', 'tot_fwd_pkts', 'subflow_fwd_pkts', 'bwd_iat_tot', 'flow_iat_std', 'fwd_pkt_len_std', 'bwd_iat_mean', 'fwd_iat_std', 'fwd_pkt_len_min', 'pkt_len_min', 'active_mean', 'fwd_iat_min', 'active_min', 'fwd_seg_size_min', 'active_max', 'bwd_iat_min', 'flow_iat_min', 'idle_max', 'idle_mean', 'idle_min', 'fwd_act_data_pkts', 'bwd_iat_std', 'psh_flag_cnt', 'down_up_ratio', 'ack_flag_cnt', 'idle_std', 'fin_flag_cnt', 'urg_flag_cnt', 'active_std', 'syn_flag_cnt', 'fwd_psh_flags', 'rst_flag_cnt', 'ece_flag_cnt', 'bwd_blk_rate_avg', 'cwe_flag_count', 'fwd_pkts_b_avg', 'fwd_byts_b_avg', 'fwd_urg_flags', 'bwd_psh_flags', 'bwd_urg_flags', 'bwd_pkts_b_avg', 'fwd_blk_rate_avg', 'bwd_byts_b_avg', ]
        Orginaldataset = ApplyLabels(Orginaldataset) #Apply labels then change column names to match the normalised list of features. 
        Orginaldataset = ChangeColumnNames(Orginaldataset)
    print(Orginaldataset['Label'].value_counts())
    Orginaldataset = EncodeLabels(Orginaldataset)
    OrderAccuracySet = [] #This array stores the stats off an model. 
    if INDIVIDUAL_FEATURE_TEST == True: #Test/Train each individual feature
        Feature_Rank_List = ['Packet Length Std', 'Total Length of Bwd Packets', 'Subflow Bwd Bytes', 'Destination Port', 'Packet Length Variance', 'Bwd Packet Length Mean', 'Avg Bwd Segment Size', 'Bwd Packet Length Max', 'Init_Win_bytes_backward', 'Total Length of Fwd Packets', 'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Average Packet Size', 'Packet Length Mean', 'Max Packet Length', 'Fwd Packet Length Max', 'Flow IAT Max', 'Bwd Header Length', 'Flow Duration', 'Fwd IAT Max', 'Fwd Header Length', 'Fwd IAT Total', 'Fwd IAT Mean', 'Flow IAT Mean', 'Flow Bytes/s', 'Bwd Packet Length Std', 'Subflow Bwd Packets', 'Total Backward Packets', 'Fwd Packet Length Mean', 'Avg Fwd Segment Size', 'Bwd Packet Length Min', 'Flow Packets/s', 'Fwd Packets/s', 'Bwd IAT Max', 'Bwd Packets/s', 'Total Fwd Packets', 'Subflow Fwd Packets', 'Bwd IAT Total', 'Flow IAT Std', 'Fwd Packet Length Std', 'Bwd IAT Mean', 'Fwd IAT Std', 'Fwd Packet Length Min', 'Min Packet Length', 'Active Mean', 'Fwd IAT Min', 'Active Min', 'min_seg_size_forward', 'Active Max', 'Bwd IAT Min', 'Flow IAT Min', 'Idle Max', 'Idle Mean', 'Idle Min', 'act_data_pkt_fwd', 'Bwd IAT Std', 'PSH Flag Count', 'Down/Up Ratio', 'ACK Flag Count', 'Idle Std', 'FIN Flag Count', 'URG Flag Count', 'Active Std', 'SYN Flag Count', 'Fwd PSH Flags', 'RST Flag Count', 'ECE Flag Count', 'Bwd Avg Bulk Rate', 'CWE Flag Count', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bytes/Bulk', 'Fwd URG Flags', 'Bwd PSH Flags', 'Bwd URG Flags', 'Bwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk']
        for feature in Feature_Rank_List:
            featureList = [feature]
            dataset = FeatureSelection(Orginaldataset,featureList) #Remove all other features.
            if TESTING_MODE != True:
                OrderAccuracySet = DecisionTree(dataset,feature,OrderAccuracySet) #Either train or test a model based off global variable
            else:
                OrderAccuracySet = TestModel(dataset,feature,OrderAccuracySet)
    ##TODO: IMPLEMENT
    else: #Test/Train an model
        dataset = FeatureSelection(Orginaldataset,FEATURESTOINCLUDE)
        if TESTING_MODE != True:
            OrderAccuracySet = DecisionTree(dataset, MODELNAME, OrderAccuracySet)
        else:
            OrderAccuracySet = TestModel(dataset, MODELNAME, OrderAccuracySet)
    #Style and extract results: 
    if INDIVIDUAL_FEATURE_TEST == True:
        ResultsDF = pd.DataFrame(OrderAccuracySet,columns=["Feature Name","False Postive Rate","True Postive Rate","False Negative Rate","True Negative Rate","Overall Score"])
        OrderedResultsDF = ResultsDF.sort_values('Overall Score',ascending=False)
        OrderedResultsDF = OrderedResultsDF.reset_index(drop=True)
        OrderedResultsStyle = OrderedResultsDF.style.background_gradient()
    else:
        ModelResultsDF = pd.DataFrame(OrderAccuracySet,columns=["Model Name","False Postive Rate","True Postive Rate","False Negative Rate","True Negative Rate","Overall Score"])
        ModelResultsDF = ModelResultsDF.sort_values('Model Name',ascending=False)
        ModelDFStyle = ModelResultsDF.style.background_gradient() 
        #Stylise the array where background is based on value. 
    if TESTING_MODE != True:
        if INDIVIDUAL_FEATURE_TEST == True: #Save results for testing individual features 
            dfi.export(OrderedResultsStyle,"Accuracy Results\FeatureTrainResults.png") #Saving files for testing individual features during training
            with open('Accuracy Results\FeatureTrainResults.obj','wb') as handle:
                pickle.dump(OrderedResultsDF, handle)
        else:
            PNGPath = "Accuracy Results\\" + MODELNAME + ".png" #Save PNG File based off model name
            ObjPath = "Accuracy Results\\" + MODELNAME + ".obj" #Save stats dataframe object to allow for anaylsis
            dfi.export(ModelDFStyle,PNGPath)
            with open(ObjPath,"wb") as handle:
                pickle.dump(ModelResultsDF,handle)
    else:
        if INDIVIDUAL_FEATURE_TEST == True:
            dfi.export(OrderedResultsStyle,"Accuracy Results\FeatureTestResults.png")
            with open('Accuracy Results\FeatureTestResults.obj',"wb") as handle:
                pickle.dump(OrderedResultsDF,handle)
        else:
            PNGPath = "Accuracy Results\\" + MODELNAME + "Test.png"
            ObjPath = "Accuracy Results\\" + MODELNAME + "Test.obj"
            dfi.export(ModelDFStyle,PNGPath)
            with open(ObjPath,"wb") as handle:
                pickle.dump(ModelResultsDF,handle)
    
## BEGGINING OF ACTUAL DECISION TREE CODE
#SOURCE: https://machinelearningmastery.com/train-test-split-for-evaluating-machine-learning-algorithms/
def GetSplitData(X,Y):
    #This splits our entire dataset into 77% training data and 33% test data 
    X_train,X_test,Y_train,Y_test = train_test_split(X,Y, test_size = 0.33)
    return X_train,X_test,Y_train,Y_test

def DecisionTree(df,feature,OrderAccuracySet):
    LabelIndex = GetColumnIndex("Label", df)
    print(df)
    ##Separting Class labels from data. This is required for classification theres no point putting the lables within X training samples 
    LabelTrainingSamples = df.iloc[:,LabelIndex]
    NonLabelTrainingSamples = df.drop(df.columns[LabelIndex],axis=1) #Drop the label column 
    X_train,X_test,Y_train,Y_test = GetSplitData(NonLabelTrainingSamples,LabelTrainingSamples) # Returns a set of test and training data for the DT model. 
    OrderAccuracySet = CreateTreeModel(X_train,X_test,Y_train,Y_test,feature,OrderAccuracySet)
    return OrderAccuracySet

def PlotTree(X_test,model,TitlePrepend):
    data = StringIO()
    export_graphviz(model,out_file=data,feature_names=X_test.columns,class_names=["Benign","Portscan"],filled=True,rounded=True,special_characters=True)
    graph = pydotplus.graph_from_dot_data(data.getvalue())
    graph.write_png("Tree Dump\\" + TitlePrepend +"Tree.png")

##SOURCE: https://scikit-learn.org/stable/auto_examples/model_selection/plot_confusion_matrix.html#sphx-glr-auto-examples-model-selection-plot-confusion-matrix-py
#This function generates a confuson matrix for a given model
def GenerateConfusionMatrix(X_test,Y_test,model,TitlePrepend):
    if TESTING_MODE != True:
        title = TitlePrepend + " Unormalized Confusion Matrix" + " Train" #Sets the title of the confusion matrix
    else:
        title = TitlePrepend + " Unormalized Confusion Matrix" + " Test"
    #This sorts out the filepath for the confusion matrix based off the mode chosen. 
    if TESTING_MODE != True:
        if INDIVIDUAL_FEATURE_TEST == True:
            FirstPart = 'Feature Graphs-Train\\'
        else:
            FirstPart = 'Model Graphs-Train\\ '
    else:
        if INDIVIDUAL_FEATURE_TEST == True:
            FirstPart = 'Feature Graphs-Test\\'
        else:
            FirstPart = 'Model Graphs-Test\\'
    Path = FirstPart + TitlePrepend + ".png"
    titles_options = [(title,None)]
    for name, normalize in titles_options: #Create the confusion matrix
        disp = ConfusionMatrixDisplay.from_estimator(
            model,
            X_test,
            Y_test,
            display_labels=["Benign","Portscan"],
            cmap=plt.cm.Blues,
            normalize=normalize,
        )
        disp.ax_.set_title(name)
    #If we are in a training mode we want to see the outputted tree
    if TESTING_MODE != True:
        PlotTree(X_test,model,TitlePrepend)
    #Save the confusion matrix created
    plt.savefig(Path)
    #plt.show()

##SOURCE: https://stackoverflow.com/questions/31324218/scikit-learn-how-to-obtain-true-positive-true-negative-false-positive-and-fal
#This function takes in a set of prediciton,actual values,feature/Name,generalscore and calculates various stats such as FP,TP,FN,TN and appends the set of stats to a 2d array returning it
def Add_Stats(Y_prediction,Y_actual,OrderAccuracySet,feature,score):
    TotalPredictions = len(Y_prediction)
    TP = 0
    FP = 0
    TN = 0
    FN = 0
    Y_actual = list(Y_actual)
    DataList = [feature] 
    #Run through the prediction list. Comparing the values it predicted vs true values and adding up the number of FP etc. the model made. 
    for i in range(len(Y_prediction)):
        if Y_actual[i]==Y_prediction[i]==1:
            TP += 1
        if Y_prediction[i] == 1 and Y_actual[i]!=Y_prediction[i]:
            FP += 1
        if Y_actual[i]==Y_prediction[i]==0:
            TN += 1
        if Y_prediction[i] == 0 and Y_actual[i]!=Y_prediction[i]:
            FN += 1
    #Calculate %s for the FP,TP,FN,TN for the model
    FPRate = FP / (FP + TN) * 100
    TPRate = TP / (TP + FN) * 100
    FNRate = FN / (FN + TP) * 100
    TNRate = TN / (TN + FP) * 100
    #Append the model to the temp datalist 
    DataList.append(FPRate)
    DataList.append(TPRate)
    DataList.append(FNRate)
    DataList.append(TNRate)
    DataList.append(score)
    #Append the model to the wider 2d array. This is a len of 1 when the INDIVIDUAL_FEATURE_TEST option is false. 
    OrderAccuracySet.append(DataList)
    return OrderAccuracySet

#This function is responsible for the creation off a model 
def CreateTreeModel(X_train,X_test,Y_train,Y_test,feature,OrderAccuracySet):
    model = DecisionTreeClassifier()
    model.fit(X_train,Y_train) #Actual creation of the model based off data. 
    prediction = model.predict(X_test)
    score = accuracy_score(Y_test,prediction) #Total accuracy score of the model 
    Add_Stats(prediction,Y_test,OrderAccuracySet,feature,score) #Add stats to our dataframe
    FeatureStripped = feature.replace("/",'')
    ObjPath = "Model_Dump\\" + FeatureStripped + ".obj" #Save the decision tree model for use in testing. 
    pickle.dump(model,open(ObjPath,"wb"))
    GenerateConfusionMatrix(X_test,Y_test,model,FeatureStripped)
    return OrderAccuracySet

def TestModel(df,feature,AccuracyDict):
    LabelIndex = GetColumnIndex("Label",df)
    FeatureStripped = feature.replace("/",'')
    ObjPath = "Model_Dump\\" + FeatureStripped + ".obj" #Get machine learning model from folder
    file = open(ObjPath , "rb")
    model = pickle.load(file)
    #Splits label from dataframe: 
    Y = df.iloc[:,LabelIndex]
    X = df.drop(df.columns[LabelIndex],axis=1)
    #Get a list of predicitons 
    prediction = model.predict(X)
    #Generate accuracy score and add_stats to the array
    pred_acc = accuracy_score(Y,prediction)
    Add_Stats(prediction,Y,AccuracyDict,feature,pred_acc)
    GenerateConfusionMatrix(X, Y, model,FeatureStripped)
    return AccuracyDict

def main(): 
    DatasetImport() 

if __name__ == '__main__':
    main()