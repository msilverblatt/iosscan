#import fileinput
import sys
import argparse
import os
import subprocess
import time
import itertools

def update_counts():
			subprocess.call('clear')
			# Prints to terminal in bold
			print '\033[1m'
			print header
			print '\033[0m'
			whichrequests = ""
			if check_get:
				whichrequests += "Checking GET requests | "
			else:
				whichrequests += "Not checking GET requests | "
			if check_post:
				whichrequests += "Checking POST requests"
			else:
				whichrequests += "Not checking POST requests"
			print whichrequests
			print "Private information sent to servers:"
			print "Tracking:     {} Location: {} Contacts: {}".format(counts['tracking'],counts['location'],counts['contacts'])
			print "Phone number: {} UDID:     {} Password: {}".format(counts['phone'],counts['udid'], counts['pwd'])
			print "Requests scanned: {}".format(reps)
			return

def check_location(line):
	if line.count('location') > 0:
		return True
	elif line.count('geo') > 0:
		return True
	elif line.count('lat') > 0:
		return True
	elif line.count('lng') > 0:
		return True
	elif line.count('loc') > 0:
		return True
	elif line.count('coordinates') > 0:
		return True
	else:
		return False

def check_contacts(line):
	if line.count('contact') > 0:
		return True
	elif line.count('contacts') > 0:
		return True
	elif line.count('address') > 0:
		return True
	else:
		return False

def check_tracking(line):
	if line.count('track') > 0:
		return True
	elif line.count('log') > 0:
		return True
	elif line.count('mixpanel') > 0:
		return True
	elif line.count('flurry') > 0:
		return True
	elif line.count('localytics') > 0:
		return True
	elif line.count('crittercism') > 0:
		return True
	elif line.count('mobilelogs') > 0:
		return True
	elif line.count('appsflyer') > 0:
		return True
	elif line.count('analytics') > 0:
		return True
	elif line.count('scorecardresearch') > 0:
		return True
	else:
		return False

def check_udid(line):
	if line.count('udid') > 0:
		return True
	elif line.count('Udid') > 0:
		return True
	elif line.count('UDID') > 0:
		return True
	else:
		return False

def check_phone(line):
	pass #implement

def check_passwords(line):
	if line.count('passwd') > 0:
		return True
	elif line.count('password') > 0:
		return True
	elif line.count('pword') > 0:
		return True
	elif line.count('pass') > 0:
		return True
	elif line.count('pwd') > 0:
		return True
	else:
		return False

def check_host(line):
	attr = line.split(':',1)[0]
	if attr.count('Host') > 0:
		try:
			host = line.split(': ', 1)[1].rstrip()
			try:
				hosts[host] += 1
				return True
			except KeyError:
				hosts[host] = 1
		except:
			return False
	else:
		return False

def skip_request():
	while True:
		line = sys.stdin.readline()
		try:
			method_checker = line.split(" ", 2)[1]
			if method_checker in {'POST', 'GET', 'PUT', 'DELETE'}:
				s = line
				s = s.split(" ", 2)
				ip = s[0]
				ip = ip.split(".", 1)[0]
				method = s[1]
				break
		except: 
			pass


def print_hosts():
	print "limit: " + str(limit)
	print "   # of requests   |      host"
	try:
		columns = os.environ["COLUMNS"]
	except:
		columns = 80
	i = 0
	myline = ""
	while i < columns:
		myline += "-"
		i += 1
	print myline
	i = 0
	# Offsets to maintain column width
	onedigit = "          |    "
	twodigit = "         |    "
	threedigit = "         |    "
	for h in itertools.islice(sorted(hosts, key=hosts.get, reverse=True),int(limit)):
		if i < limit:
			toprint = "        " + str(hosts[h])
			if len(str(hosts[h])) == 1:
				toprint += onedigit
			elif len(str(hosts[h])) == 2:
				toprint += twodigit
			elif len(str(hosts[h])) == 3:
				toprint += threedigit
			toprint += h
			print toprint
			# + "          |    " + h
		i += 1
# Determines if a line of input is the beginning of a request
def isstart(line):
	try:
		temp = line.split(" ",2)[1]
		if temp in {'POST', 'GET', 'PUT', 'DELETE'}:
			return True
		else:
			return False
	except:
		return False

# Checks if a line of input contains private information
def checkline(line):
	if not host_mode:
		check_host(line)
	if check_location(line):
		counts['location'] += 1
		if host_mode:
			print 'Possible GPS location leakage in {} request to {}'.format(method,host)
	if check_passwords(line):
		counts['pwd'] += 1
		if host_mode:
			print 'Possible plain-text password leakage in {} request to {}'.format(method,host)
	if check_contacts(line):
		counts['contacts'] += 1
		if host_mode:
			print 'Possible contacts/address book leakage in {} request to {}'.format(method,host)
	if check_phone(line):
		counts['phone'] += 1
		if host_mode:
			print 'Possible phone number leakage in {} request to {}'.format(method,host)
	if check_udid(line):
		counts['udid'] += 1
		if host_mode:
			print 'Possible Unique Device Identifier (UDID) leakage in {} request to {}'.format(method,host)
	if check_tracking(line):
		counts['tracking'] += 1
		if host_mode:
			print 'Possible usage tracking/logging in {} request to {}'.format(method,host)


# Assumes line is beginning of request, reads until it finds beginning of response
def checkrequest():
	# Set method variable
	# Read new lines until request is found, and process
	checkline(url)
	while True:
		line = sys.stdin.readline()
		if line.count('<<') > 0:
			break
		else:
			checkline(line)

def findhost():
	while True:
		line = sys.stdin.readline()
		if check_host(line):
			return True
	return False




# Setting arguments
parser = argparse.ArgumentParser(prog="iosscan",description='Detect possible private information leakage in iOS applications. Requires mitmdump and python to run.')
parser.add_argument('-l', '--limit', help='Limit number of hosts to display, default is 10')
parser.add_argument('-s', '--server', help='Specify a host server to inspect')
parser.add_argument('-p', '--post', help='Only scan POST requests', action="store_true")
parser.add_argument('-g', '--get', help='Only scan GET requests', action="store_true")
display_counts = False


# Parsing Arguments
args = parser.parse_args()
host_mode = False
if args.server:
	host_mode = True
	user_host = args.server
if args.limit:
	limit = args.limit
else:
	limit = 10
if args.post:
	check_post = True
	check_get = False
	if args.get:
		check_get = True
elif args.get:
	check_post = False
	check_get = True
else:
	check_post = True
	check_get = True


# Startup display
header = "Starting iOS scanner"
i = 0
while i < 6:
	time.sleep(.3)
	subprocess.call('clear')
	print header
	header = header + "."
	i += 1
header = "iOS Scanner: Track Your Apps"



#for line in fileinput.input():
reps = 0
counts = { 'tracking':0, 'location':0, 'contacts':0, 'phone':0, 'udid':0, 'pwd':0 }
update_counts()
hosts = dict()

# Read first line

line = sys.stdin.readline()
while True:
# If line is beginning of request, check request
	if isstart(line):
		temp = line.split(" ", 2)
		ip = temp[0]
		method = temp[1]
		url = temp[2]
		## Check if user is filtering by host api
		if host_mode:
			line = sys.stdin.readline()
			try:
				host = line.split(":",1)[1].rstrip()
				if host.count(user_host) > 0:
					reps += 1
					checkrequest()
					update_counts()
			except:
				pass
		## Check if user only wants one type of request
		elif not (check_get and check_post):
			if check_get:
				if method == 'GET':
					checkrequest()
					reps += 1
					update_counts()
					print_hosts()
				else:
					line = sys.stdin.readline()
			elif check_post:
				if method == 'POST':
					checkrequest()
					reps += 1
					update_counts()
					print_hosts()
				else:
					line = sys.stdin.readline()
		## User has not chosen a particular mode
		else:
			checkrequest()
			reps += 1
			update_counts()
			print_hosts()
# Otherwise, read a new line
	else:
		line = sys.stdin.readline()






