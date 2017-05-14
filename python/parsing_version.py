import urllib2
import subprocess
import shlex
from BeautifulSoup import *
from optparse import OptionParser


#Command line option to pass to script
parser = OptionParser()
parser.process_default_values = True
parser.set_defaults(mode="advanced")
parser.add_option("--login", type='string', dest='login')
parser.add_option("--password", type='string', dest='password')
parser.add_option("--host", type='string', dest='host', default='lx-dev-repo01.saas-n.com')
parser.add_option("--port", type=int, dest='port', default=50080)
parser.add_option("--repo_prefix", type='string', dest='repo_prefix', default='deployment')
parser.add_option("--project", type='string', dest='project')
parser.add_option("--env", type='string', dest='env', default='DEV6')
parser.add_option("--comp_ver", type='string', dest='comp_ver')
parser.add_option("--comp_name", type='string', dest='comp_name')
parser.add_option("--transport", type='string', dest='transport', default='http')

(options, args) = parser.parse_args()

#Concatinate the basic url for connection to repository server

url = args.transport + '://' + args.host + args.repo_prefix + ':' + args.port
print url

#Retrive information about component

def get_version(repo_prefix,component_name,component_version):
    url = urllib2.urlopen(url)
    return version

def get_list_of_version():
    return list_of_versions


#If component version is not defined
if not component_version or component_version == None:
    get_version()
else:
    component_version = args.component_version
    


#Set the enviroment variable for current shell session
def create_env_variables(component_name, component_version):
    shlex.split( "LOGIN=login PASSWORD=password COMPONENT=component_name VERSION=version_version" )



def main():
    return



if __name__=="__main__":
    main()
