#!/usr/bin/python3

# Plainsight: Platform/Service Discovery Script For Target Domains

import argparse
import colorama
import requests
from colorama import Fore as foreground_colour
from colorama import Style, init
import dns.resolver
import time
import os
import sys

colorama.init(autoreset=True)

white_text = foreground_colour.WHITE
red_text = foreground_colour.RED
green_text = foreground_colour.GREEN
cyan_text = foreground_colour.CYAN
pink_text = foreground_colour.MAGENTA
yellow_text = foreground_colour.YELLOW

parser = argparse.ArgumentParser(description="Plainsight: Platform/Service Discovery Script For Target Domains")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-t", "--target", nargs='+', help="Specify the targets, delimited with spaces")
group.add_argument("-w", "--wordlist", help="Specify the wordlist file containing target domains, seperated by newlines")
parser.add_argument("-v", "--verbose", action="count",default=0, help="Output verbose information to console")

args = parser.parse_args()
target = args.target
target_list = args.wordlist

def banner():
	print('\n')
	print(colour_output(green_text,"""   _ (`-.              ('-.                  .-') _   .-')                         ('-. .-. .-') _
  ( (OO  )            ( OO ).-.             ( OO ) ) ( OO ).                      ( OO )  /(  OO) )
 _.`     \ ,--.       / . --. /  ,-.-') ,--./ ,--,' (_)---\_)  ,-.-')   ,----.    ,--. ,--./     '._
(__...--'' |  |.-')   | \-.  \   |  |OO)|   \ |  |\ /    _ |   |  |OO) '  .-./-') |  | |  ||'--...__)
 |  /  | | |  | OO ).-'-'  |  |  |  |  \|    \|  | )\  :` `.   |  |  \ |  |_( O- )|   .|  |'--.  .--'
 |  |_.' | |  |`-' | \| |_.'  |  |  |(_/|  .     |/  '..`''.)  |  |(_/ |  | .--, \|       |   |  |
 |  .___.'(|  '---.'  |  .-.  | ,|  |_.'|  |\    |  .-._)   \ ,|  |_.'(|  | '. (_/|  .-.  |   |  |
 |  |      |      |   |  | |  |(_|  |   |  | \   |  \       /(_|  |    |  '--'  | |  | |  |   |  |
 `--'      `------'   `--' `--'  `--'   `--'  `--'   `-----'   `--'     `------'  `--' `--'   `--'    """))
	print('\n')
	return 0

def seperator(char, text):
    header = (colour_output(white_text,(char*60) + '\n' + text + '\n' + (char*60) + '\n'))
    print(header)
    return 0

def read_from_file(file):
	try:
		with open(file, 'r') as target:
			targets = target.read().splitlines()
	except Exception as e:
		print_general_exception(e)
		print('Please specify a file that exists\n')
		sys.exit(1)
	else:
		return targets

def print_general_exception(exception):
	print(colour_output(red_text,"[-] " + str(exception)+'\n'))
	return 0

def dns_txt_query(target):
	dns_state = False
	dns_result = dns.resolver.resolve(target, 'TXT')
	checks = read_from_file(f"{os.path.dirname(sys.argv[0])}/definitions/dns_txt_strings.txt")
	verbose(colour_output(cyan_text,"[~] Checking if DNS TXT records contain the following strings: \n" + ', '.join(checks) + "\n"))
	try:
		for record in dns_result:
			for check in checks:
				if check in record.to_text().lower():
					print(colour_output(green_text, "[+] " + check + " record exists"))
					verbose(colour_output(cyan_text,'TXT Record: ' + record.to_text()))
					dns_state = True
		print("")
		if dns_state == False:
			print(colour_output(red_text, "[-] Nothing interesting found.\n"))
		else:
			pass
	except:
		pass
	return dns_result

def check_services(target):
	public_services = read_from_file(f"{os.path.dirname(sys.argv[0])}/definitions/public_services.txt")
	header = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
	for service in public_services:
		url=("https://" + target + "." +  service)
		
		try:
		    response = requests.get(url,headers=header)

		    if (response.status_code == 200) or (response.status_code == 301) or (response.status_code == 302) :
		    	print(colour_output(green_text, "[+] " + service + " is probably used at " + url))
		    elif (response.status_code != 200) or (response.status_code != 301) or (response.status_code != 302):
		    	print(colour_output(red_text,"[-] " + service + " is probably not used"))
		    else:
		    	pass
		    verbose(colour_output(cyan_text, "[~] URL: " + url + "\n[~] Response Code: " + str(response.status_code)))
		except requests.exceptions.HTTPError as errh:
			print(colour_output(red_text,"[-] An HTTPError occurred when trying to connect to " + service + " this implies its not used"))
			verbose(colour_output(cyan_text,"[~] " + str(errh)))
		except requests.exceptions.ConnectionError as errc:
			print(colour_output(red_text,"[-] " + service + " is unavailable at " + url + ", this implies its not used"))
			verbose(colour_output(cyan_text,"[~] " + str(errc)))
	return 0 	

def enumerate(target):
	try:
		seperator("=","Checking DNS TXT records for " + target)
		txt_records = dns_txt_query(target)
	except Exception as e:
		print_general_exception(e)
	
	try:
		seperator("=","Checking for public services used by " + target)
		name = target.split('.')[0]
		services = check_services(name)
	except Exception as e:
		print_general_exception(e)
	else:
		return 0

def verbose(verbose_output):
	if args.verbose:
		print(verbose_output)
	else:
		pass
	return 0

def colour_output(colour,output):
	coloured_text = (colour + Style.BRIGHT + output + foreground_colour.RESET)
	return coloured_text

def main():
	banner()
	start_time = time.time()
	print(colour_output(white_text,'Initiating Plainsight on {}\n'.format(time.ctime())))
	if target_list is not None:
		targets = read_from_file(target_list)
		verbose('Using Provided target list ' + colour_output(cyan_text,'{}\n\n').format(targets))
		for host in targets:
			enumerate(host)
	elif target is not None:
		verbose('Using Provided target(s) ' + colour_output(cyan_text,'{}\n\n').format(target))
		for host in target:
			enumerate(host)
	else:
		print('No targets specified!')
	print(colour_output(white_text,'\nPlainsight Completed on {}\nTargets Enumerated in {} Seconds\n'.format(time.ctime(),round(time.time() - start_time, 2))))
	return 0

if __name__ == "__main__":
	main()