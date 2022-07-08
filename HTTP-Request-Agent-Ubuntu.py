## HTTP/HTTPS Request Agent To Be Placed on Windows / Ubuntu Clients For Generating  HTTP/HTTPS Packets&Netflow Within Testbed
## The main aim of this is to simulate someone browsing the web. HTTP traffic is less random than as its hard to find http URLS to add to the lists.
from bs4 import BeautifulSoup
from urllib.parse import urlparse,urljoin
import requests
import random
from time import sleep

#Global URL Lists. Initalize values are "seed" values for the web crawler, Whats important is they have a variety of links to build out our lists.
Https_External_Url_List = ["https://www.amazon.co.uk/","https://www.reddit.com/"]
Http_External_Url_List =["http://www.reading.ac.uk/","http://www.wikidot.com/advertise","http://www.consultant.ru/","http://yimg.com/"] #Hopefully This will fill out as the program runs and we manage to slowly find more HTTP links.

#Control Variable This Lets me Decide how many Requests are made using HTTP and how many HTTPS. Default Value is 80% HTTPS before testing.
HTTPSURLPOOLRATE = 8

#Function to check if a URL is valid and actually has 
def Check_URL(url):
    parsedurl = urlparse(url)
    netlocBool = bool(parsedurl.netloc) #Checks domain name exists in URL
    pathBool = bool(parsedurl.scheme) #Checks that it has a proper protocol e.g http/https
    return netlocBool, pathBool

def GetPageContent(url): #Opens URL.
    page = requests.get(url)
    html_source = page.text
    soup = BeautifulSoup(html_source,'html.parser')
    return soup

##SOURCE: https://www.thepythoncode.com/article/extract-all-website-links-python
def GetURLs(url,soup,InternalURLs):
    domain_name = urlparse(url).netloc
    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            continue
        NewUrl = urljoin(url,href)
        ParsedNewURL = urlparse(NewUrl)
        Protocol = ParsedNewURL.scheme #We wanna save this for later to much external URL's with the correct list.
        FinalURL = Protocol + "://" + ParsedNewURL.netloc + ParsedNewURL.path #Removing URL GET Parameters, URL Fragments
        netlocBool,pathBool = Check_URL(FinalURL)
        if not Check_URL(FinalURL): #Dont Add bad URL's to our lists.
            continue
        if FinalURL not in InternalURLs:
            InternalURLs.append(FinalURL) #Append Internal URL's the
        if domain_name not in FinalURL:
            if FinalURL not in Http_External_Url_List or Https_External_Url_List:
                if Protocol == "https":
                    Https_External_Url_List.append(FinalURL)
                elif Protocol == "http":
                    Http_External_Url_List.append(FinalURL)
    return InternalURLs

def main():
    while True: #Run Request agent permanently until manual cancel
        RequestTimeout = random.randrange(120,300) #"Browsing Events" are made at an interval between 2-5 mins.
        sleep(RequestTimeout)
        ExternalUrlCount = random.randrange(1,3) #Number of External URL to visit this repersents the number of pages an workstation might visit during a single "browsing event"
        print(ExternalUrlCount)
        for x in range(ExternalUrlCount):
            print("EXTENRAL-URL-CHECKED")
            PoolNumber = random.randint(1,10) #Generate Number To Chose
            #Choose Pool for extenral URL
            if PoolNumber <= HTTPSURLPOOLRATE:
                url = random.choice(Https_External_Url_List) #Get random URL From List. This allows sites to be revisted during a browsing event but as extenral URL's are added this less common introducing some randomness
            else:
                url = random.choice(Http_External_Url_List)
            InternalURLList = []
            InternalUrlCount = random.randint(1,5) #Number of Internal URL's to visit on a single External URL. This tries to repersent browsing an individual website before moving onto another.
            print(url)
            try:
                soup = GetPageContent(url)
            except Exception as e:
                continue
            InternalURLList = GetURLs(url,soup,InternalURLList)
            sleep(20)
            if len(InternalURLList) != 0:
                for y in range(InternalUrlCount):
                  url = random.choice(InternalURLList)
                  print("INTERNAL-URL-CHECKED")
                  InternalURLList.remove(url)
                  print(url)
                  try:
                      soup = GetPageContent(url) #Perform Request
                  except Exception as e:
                     InternalURLList.remove(url)
                     continue
                  InternalURLList = GetURLs(url,soup,InternalURLList)
                  if len(InternalURLList) == 0: #If we ever in rare cases visit a website with no internal links return a bool breaking out of
                     break
                sleep(20)

main()