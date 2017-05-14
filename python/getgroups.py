#! /bin/python
import sys, re, json, yaml
 
#get hosts inventory from ansible.cfg file.
ansible_conf_file = open(sys.argv[1]).read()
hosts_file = re.findall('inventory\s*=\s*(.*)', ansible_conf_file)[0]
 
#Get groups from inventory file and add it to array. 
cat_hosts_file = open(hosts_file).readlines()
group = 'Default' # for hosts without a group
groups_list = []
for line in cat_hosts_file:

	# Skip comments & empty lines
	line = line.strip()
	if not line or line.startswith('#') or line.endswith('children]'):
		continue
	if line.startswith('['): # group
		group = re.sub(r'[\[\]]', '', line) 
		groups_list.append(group.upper())
 
#Create groups from inventory file in json foramt
jsondata = '{ "inventory_groups": '+ json.dumps(groups_list) +'}'
with open('inventory_groups.yaml', 'w') as stream:
    yaml.safe_dump(json.loads(jsondata), stream, default_flow_style=False)
