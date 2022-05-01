import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import imaplib
import poplib
from time import sleep
import random
import string
import os
import ssl
from multiprocessing import Process
#Imports


#NOTE: MAKE SURE TO CHANGE EMAIL's IN VARIABLES
USER_EMAIL = "windows1@mylab.local"

#Generates Random Body For Email
#Important to generate emails of varying size for a more "realistic" enviroment
def GetRandomBody():
	Length = random.randint(25,500)
	body = ''.join(random.choices(string.ascii_uppercase + string.digits, k = Length))
	return body

def GenerateRandomAttatch():
	size = random.randint(1000,30000000) #Generate random binary file from 1KB-30MB
	filename = "attatch.bin"
	with open(filename,'wb') as fout:
		fout.write(os.urandom(size))
	print(size)

def ReadGeneratedFile():
	with open('attatch.bin','rb') as attatchment:
		part = MIMEBase('application','ocet-stream')
		part.set_payload(attatchment.read())
	encoders.encode_base64(part)
	part.add_header("Content-Disposition",f"attachment; filename={'attatch.bin'}",)
	return part

#Function to send mail to server via SMTP
#SOURCE: https://realpython.com/python-send-email/#sending-your-plain-text-email
def SmtpSend():
	subject = "Email To Generate SMTP Traffic"
	body = GetRandomBody() #Get body text
	sender = USER_EMAIL
	Receiver_List = ["ubuntu1@mylab.local"]
	receiver = random.choices(Receiver_List,k=len(Receiver_List)) #Get Random List Of Receivers. Sending mail to 1 or more Inboxes
	#Create multipart message with proper email headers
	receiver_formatted = ", ".join(receiver)
	msg = MIMEMultipart()
	msg['From'] = sender
	msg['To'] = receiver_formatted
	msg['Subject'] = subject
	msg['Bcc'] = receiver_formatted
	msg.attach(MIMEText(body,"plain"))
	attatchfile = random.randint(0,1) #50% chancea file is attatched to the email
	if attatchfile == 1:
		print("attatching file")
		GenerateRandomAttatch()
		FileToAttatch = ReadGeneratedFile()
		msg.attach(FileToAttatch)
	text = msg.as_string()
	#send email
	server = smtplib.SMTP('mail.mylab.local',465)
	server.sendmail(sender,receiver_formatted,text)
	print("Email Sent")

#Function To get mail from inbox using IMAP protocol
def IMAPGetMail():
	#SOURCE: https://www.thepythoncode.com/article/reading-emails-in-python
	server = imaplib.IMAP4_SSL('mail.mylab.local')
	server.login(USER_EMAIL,'abc123')
	server.select("INBOX") #Access Inbox Folder
	status,messages = server.search(None,"ALL")
	NoOfEmails = messages[0].split(b' ') #Convert messages to a list of email ID's
	print(NoOfEmails)
	for id in NoOfEmails:
		#Catching error if we try and parse through empty mailbox
		try:
			res,msg = server.fetch(id,"(RFC822)")
			print(res)
		except imaplib.IMAP4.error:
			print("Caught Fetch Error")
			break
	for id in NoOfEmails: #Loop to go through emails and delete
		try:
			server.store(id, "+FLAGS", "\\Deleted") #Flag email for deletion
		except imaplib.IMAP4.error:
			print("Caught Deletion Error")
			break
	#Perma delete emails and log out.
	server.expunge()
	server.close()
	server.logout()


#Function to get mail from inbox using POP3 protocol
#SOURCE: https://www.code-learner.com/python-use-pop3-to-read-email-example/
def POPGetMail():
	#Open connection and authenticate with server
	pop3server = poplib.POP3_SSL('mail.mylab.local')
	pop3server.user(USER_EMAIL)
	pop3server.pass_('abc123')
	#Get mailbox status including number of emails 
	resp,mails,octets = pop3server.list()
	emailIndex = len(mails)
	print(emailIndex)
	for x in range(1,emailIndex):
		pop3server.retr(x)
	for x in range(1,emailIndex):
		print(x)
		pop3server.dele(x)
	pop3server.quit()

#Mail Function deals with scheduling for the IMAP/POP3 & SMTP

def SMTPWhile():
	while True:
		print("SMTP Process Started")
		SMTPWait = random.randint(60,600) #Currently between 1-10M send an email.
		sleep(SMTPWait)
		print("SendingEmail")
		SmtpSend()

def IMAP_POP3_While():
	while True:
		print("Inbox Process Started")
		InboxWait = random.randint(60,1800) #Pseudorandom interval between 1-30M access inbox
		sleep(InboxWait)
		ProtoChoice = random.randint(0,1)
		if ProtoChoice == 0:
			print("Inbox via POP")
			POPGetMail()
		else:
			print("Inbox via IMAP")
			IMAPGetMail()

def main():
	p = Process(target=IMAP_POP3_While) #Start Inbox access in a seperate thread we want SMTP & POP3/IMAP Protocols not be reliant on one or the other
	p.start()
	SMTPWhile()

if __name__ == '__main__':
	#freeze_support()
	main()



