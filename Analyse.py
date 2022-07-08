import pandas as pd
import pickle
import dataframe_image as dfi
from matplotlib import colors
import matplotlib as plt
import seaborn as sns
import numpy as np



##SOURCE:https://stackoverflow.com/questions/56202218/pandas-styling-conditionally-change-background-color-of-column-by-absolute-valu
def background(x):
    cm=sns.light_palette("blue",as_cmap=True)
    df = x.copy() #Copy so we dont change any data. 
    Columns = list(df)
    Columns.remove('Feature Name') #Get a list of columns removing the Feature Name as we dont want to colour gradient it 
    print(Columns)
    for ColumName in Columns:
        ColumnArray = df[ColumName]
        max_val = max(ColumnArray.max(),abs(ColumnArray.min()))
        norm = colors.Normalize(0,max_val)
        normed = norm(abs(ColumnArray.values))
        c = [colors.rgb2hex(x) for x in plt.cm.get_cmap(cm)(normed)] #Colour grade based off normalized values
        ColumnColours = ['background-color: %s' % color for color in c]
        df[ColumName] = ColumnColours #Apply colour gradient to the columns
    return df


def FeatureDifference():
    #Purpose of this function is to find the different between a set off results
    #Load in saved Dataframe objects
    TestfileHandle = open("Accuracy Results\FeatureTestResults.obj","rb")
    TestData = pickle.load(TestfileHandle)
    TrainfileHandle = open("Accuracy Results\FeatureTrainResults.obj","rb")
    TrainData = pickle.load(TrainfileHandle)
    #Sort values by feature
    SortedTrainData = TrainData.sort_values('Feature Name')
    SortedTestData = TestData.sort_values('Feature Name')
    #Subtract Test Data from Train Data
    SubtractedDataset = SortedTestData.set_index('Feature Name').subtract(SortedTrainData.set_index('Feature Name'),fill_value=0)
    print(SortedTestData)
    print(SortedTrainData)
    RetrievedIndexDF = SubtractedDataset.reset_index()
    #Relabel dataset
    RenameDict = {"False Postive Rate":"False Positive Rate Difference","True Postive Rate":"True Positive Rate Difference","False Negative Rate":"False Negative Rate Difference","True Negative Rate":"True Negative Rate Difference","Overall Score":"Overall Score Difference"}
    RenamedDF = RetrievedIndexDF.rename(columns=RenameDict)
    NewDf = background(RetrievedIndexDF)
    StyledDf = RenamedDF.style.apply(background,axis=None)
    dfi.export(StyledDf,"Accuracy Results\\DifferenceResults.png")

def ExtractData():
    TrainDataset = pd.read_csv("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    BenignLabel = TrainDataset.loc[TrainDataset[' Label'] == "BENIGN"]
    PortScanLabel = TrainDataset.loc[TrainDataset[' Label'] == "PortScan"]
    print(PortScanLabel[' Flow IAT Mean'].value_counts())
    print(BenignLabel[' Flow IAT Mean'].value_counts())
    

FeatureDifference()
#ExtractData()