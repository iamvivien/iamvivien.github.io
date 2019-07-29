# import necessary libraries
from neo4j import GraphDatabase
import json
import re

# make a connection to the 
uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "team08"))

# source of the unified logs (produced by Fluentd)
allLogs = "/home/osboxes/Documents/GUI/scripts/extra/allLogs.json"

# empty lists
data = [] # to store the logs
checkBrute = []	# for checking of brute force logs
ipaddrBrute = [] # to store IP address of the brute force attackers (to only get 1 unique IP)
checkDoS = [] # for checking of dos logs
ipaddrDoS = [] # to store IP address of the dos attackers (to only get 1 unique IP)
ipaddrAll = [] # to store IP addresses of all the attackers (to aid with flow of attack if attackers did more than 1 attack)
sameAttackers = [] # logs from same attackers
remainingData = [] # to store all the remaining logs

# populating the data list with the logs
with open(allLogs) as f:
	for line in f:
		data.append(json.loads(line))
f.close()

for item in data:

# to confirm if it is an XSRF attack (Fluentd only detects if it is not null, this codes will check if the referer is not the same as the path)
	if item['attack-type'] == 'XSRF':
		path = item['path']
		referer = item['referer']
		
		if path != referer:
			data.remove(item)
			
	# to add to list for checking
	if item['attack-type'] == 'BruteForce':
		checkBrute.append(item)

	# to add to list for checking
	if item['attack-type'] == 'DoS':
		checkDoS.append(item)

# creating a "new" list while removing the brute force and dos logs to prevent same logs
data = [x for x in data if x['attack-type'] != 'BruteForce']
data = [x for x in data if x['attack-type'] != 'DoS']
			
# checking brute force logs
for item in checkBrute:
	ipaddr = re.findall( r'[0-9]+(?:\.[0-9]+){3}', item['message'] ) # getting the IP address
	item['host'] = ipaddr # setting the host as the IP address (the host will now be the attacker's IP address)

	if item['host'] not in ipaddrBrute:
		ipaddrBrute.append(item['host']) # store the unique IP addresses of the brute force attackers
		data.append(item) # store the logs back into the original list of logs

# checking dos logs		
for item in checkDoS:
	ipaddr = re.findall( r'[0-9]+(?:\.[0-9]+){3}', item['message'] ) # getting the IP address
	item['host'] = ipaddr # setting the host as the IP address (the host will now be the attacker's IP address)

	if item['host'] not in ipaddrDoS:
		ipaddrDoS.append(item['host']) # store the unique IP addresses of the brute force attackers
		data.append(item) # store the logs back into the original list of logs
		
# checking if attackers have conducted multiple attacks (for the flow in the graph)		
for item in data:
	if item['host'] not in ipaddrAll:
		ipaddrAll.append(item['host']) # store the unique IP addresses of the attackers
		sameAttackers.append(item) # store the log with unique IP address (this list contains only one log from each attacker)
	
	elif item['host'] in ipaddrAll:
		for existing in sameAttackers:
			if item['host'] == existing['host']: # if the same attacker
				if item['time'] > existing['time']: # check if the time is later, if it is the more recent time:
					sameAttackers.remove(existing) # replace the previous log with the new log which happened the most recent
					sameAttackers.append(item)
					remainingData.append(existing) # store the remaining log (older logs) into a separate list to create the nodes separately later on

#print (sorted(remainingData, key = lambda i: i['time'],reverse=True))

	
# create a server node for all the attack nodes to point to
def add_server(tx, name):
	tx.run("CREATE (w:Server { name: $name })", name=name)

# create all the sqli nodes
def add_sqli(tx, ip):
	tx.run("CREATE (sqli:SQLi { ip: $ip, attackType: 'SQLi' })", ip=ip)

# create the relationship between sqli nodes and server
def add_sqli_relationship(tx):
	tx.run("MATCH (sqli:SQLi { attackType: 'SQLi' }) MATCH (w:Server) CREATE (sqli)-[r:SQLi]->(w)")

# create the relationship between attack nodes from same attacker
def add_sqli_multiple(tx, ip):
	tx.run("MATCH (n {ip: $ip}) CREATE (sqli:SQLi {ip: $ip, attackType: 'SQLi'})-[r:SQLi]->(n)", ip=ip)



# create all the xss nodes
def add_xss(tx, ip):
	tx.run("CREATE (xss:XSS { ip: $ip, attackType: 'XSS' })", ip=ip)

# create all the xsrf nodes
def add_xsrf(tx, ip):
	tx.run("CREATE (xsrf:XSRF { ip: $ip, attackType: 'XSRF' })", ip=ip)

# create all the brute force nodes
def add_brute(tx, ip):
	tx.run("CREATE (brute:BruteForce { ip: $ip, attackType: 'BruteForce' })", ip=ip)
			
# create all the dos nodes
def add_dos(tx, ip):
	tx.run("CREATE (dos:DoS { ip: $ip, attackType: 'DoS' })", ip=ip)



# create the relationship between xss nodes and server
def add_xss_relationship(tx):
	tx.run("MATCH (xss:XSS { attackType: 'XSS' }) MATCH (w:Server) CREATE (xss)-[r:XSS]->(w)")

# create the relationship between xsrf nodes and server
def add_xsrf_relationship(tx):
	tx.run("MATCH (xsrf:XSRF { attackType: 'XSRF' }) MATCH (w:Server) CREATE (xsrf)-[r:XSRF]->(w)")

# create the relationship between brute force nodes and server
def add_brute_relationship(tx):
	tx.run("MATCH (brute:BruteForce { attackType: 'BruteForce' }) MATCH (w:Server) CREATE (brute)-[r:BruteForce]->(w)")

# create the relationship between dos nodes and server
def add_dos_relationship(tx):
	tx.run("MATCH (dos:DoS { attackType: 'DoS' }) MATCH (w:Server) CREATE (dos)-[r:DoS]->(w)")

# create the relationship between attack nodes from same attacker
def add_xss_multiple(tx, ip):
	tx.run("MATCH (n {ip: $ip}) CREATE (xss:XSS {ip: $ip, attackType: 'XSS'})-[r:XSS]->(n)",
			ip=ip)
			
# create the relationship between attack nodes from same attacker	
def add_xsrf_multiple(tx, ip):
	tx.run("MATCH (n {ip: $ip}) CREATE (xsrf:XSRF {ip: $ip, attackType: 'XSRF'})-[r:XSRF]->(n)",
			ip=ip)

# create the relationship between attack nodes from same attacker
def add_brute_multiple(tx, ip):
	tx.run("MATCH (n {ip: $ip}) CREATE (brute:BruteForce {ip: $ip, attackType: 'BruteForce'})-[r:BruteForce]->(n)",
			ip=ip)

# create the relationship between attack nodes from same attacker
def add_dos_multiple(tx, ip):
	tx.run("MATCH (n {ip: $ip}) CREATE (dos:DoS {ip: $ip, attackType: 'DoS'})-[r:DoS]->(n)",
			ip=ip)

# clear database (no graph will be generated)
# delete relationships (this has to run first before clearing nodes)
def clear_relationship(tx):
	tx.run("MATCH ()-[r:SQLi]-() DELETE r")
	tx.run("MATCH ()-[r:XSS]-() DELETE r")
	tx.run("MATCH ()-[r:XSRF]-() DELETE r")
	tx.run("MATCH ()-[r:BruteForce]-() DELETE r")
	tx.run("MATCH ()-[r:DoS]-() DELETE r")

# delete all the nodes
def clear_nodes(tx):
	tx.run("MATCH (n) DELETE (n)")
			
with driver.session() as session:
	# clear database at the start
	session.write_transaction(clear_relationship)
	session.write_transaction(clear_nodes)
	
	# create the first node which is the server
	session.write_transaction(add_server, "Server")

	for i in range(len(sameAttackers)):
	
		# create the sqli nodes
		if sameAttackers[i]['attack-type'] == 'SQLi':
			ip = sameAttackers[i]['host']
			session.write_transaction(add_sqli, ip)	
	
		# create the xss nodes
		if sameAttackers[i]['attack-type'] == 'XSS':
			ip = sameAttackers[i]['host']
			session.write_transaction(add_xss, ip)
		
		# create the xsrf nodes
		if sameAttackers[i]['attack-type'] == 'XSRF':
			ip = sameAttackers[i]['host']
			session.write_transaction(add_xsrf, ip)

		# create the brute force nodes
		if sameAttackers[i]['attack-type'] == 'BruteForce':
			ip = sameAttackers[i]['host']
			session.write_transaction(add_brute, ip)
			
		# create the dos nodes
		if sameAttackers[i]['attack-type'] == 'DoS':
			ip = sameAttackers[i]['host']
			session.write_transaction(add_dos, ip)
			
	# create the relationships from nodes to server
	session.write_transaction(add_sqli_relationship)
	session.write_transaction(add_xss_relationship)
	session.write_transaction(add_xsrf_relationship)
	session.write_transaction(add_brute_relationship)
	session.write_transaction(add_dos_relationship)
			
	for i in range(len(remainingData)):
		# create the remaining sqli relationships
		if remainingData[i]['attack-type'] == 'SQLi':
			ip = remainingData[i]['host']
			session.write_transaction(add_sqli_multiple, ip)
			
		# create the remaining xss relationships
		if remainingData[i]['attack-type'] == 'XSS':
			ip = remainingData[i]['host']
			session.write_transaction(add_xss_multiple, ip)
			
		# create the remaining xsrf relationships
		if remainingData[i]['attack-type'] == 'XSRF':
			ip = remainingData[i]['host']
			session.write_transaction(add_xsrf_multiple, ip)
			
		# create the remaining brute force relationships
		if remainingData[i]['attack-type'] == 'BruteForce':
			ip = remainingData[i]['host']
			session.write_transaction(add_brute_multiple, ip)
		
		# create the remaining dos relationships
		if remainingData[i]['attack-type'] == 'DoS':
			ip = remainingData[i]['host']
			session.write_transaction(add_dos_multiple, ip)	
