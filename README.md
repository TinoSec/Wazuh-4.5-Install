# Wazuh 4.5-Guide
This guide will help you in the Wazuh install and configure Wazuh 4.5 with Elasticsearch

# Installing prerequisites

Some extra packages are needed for the installation

```bash
sudo apt-get install apt-transport-https zip unzip lsb-release curl gnupg
```

# Installing Elasticsearch
Install the GPG key:

```bash
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/elasticsearch.gpg --import && chmod 644 /usr/share/keyrings/elasticsearch.gpg
```
Add the repository

```bash
echo "deb [signed-by=/usr/share/keyrings/elasticsearch.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list
```
Update the package information

```bash
sudo apt update
```
Install Elasticsearch

```bash
apt-get install elasticsearch=7.17.12
```
Download config file for Elasticsearch

*Change  ther network-host value with your server ip*
(/etc/elasticsearch/elasticsearch.yml)

```bash
curl -so /etc/elasticsearch/elasticsearch.yml https://packages.wazuh.com/4.5/tpl/elastic-basic/elasticsearch_all_in_one.yml
```
Download configuration file for certificates creation

```bash
curl -so /usr/share/elasticsearch/instances.yml https://packages.wazuh.com/4.5/tpl/elastic-basic/instances_aio.yml
```
 In the following steps, a file that contains a folder named after the instance defined here will be created. This folder will contain the certificates and the keys necessary to communicate with the Elasticsearch node using SSL.
 
  *Modify /usr/share/elasticsearch/instances.yml with the your server ip address!*

 The certificates can be created using the elasticsearch-certutil tool

```bash
/usr/share/elasticsearch/bin/elasticsearch-certutil cert ca --pem --in instances.yml --keep-ca-key --out ~/certs.zip
```
Extract the generated /usr/share/elasticsearch/certs.zip file from the previous step.

```bash
unzip ~/certs.zip -d ~/certs
```
The next step is to create the directory /etc/elasticsearch/certs, and then copy the CA file, the certificate and the key there

```bash
mkdir /etc/elasticsearch/certs/ca -p
cp -R ~/certs/ca/ ~/certs/elasticsearch/* /etc/elasticsearch/certs/
chown -R elasticsearch: /etc/elasticsearch/certs
chmod -R 500 /etc/elasticsearch/certs
chmod 400 /etc/elasticsearch/certs/ca/ca.* /etc/elasticsearch/certs/elasticsearch.*
rm -rf ~/certs/ ~/certs.zip
```

Enable and start the Elasticsearch service

```bash
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch
```

Generate credentials for all the Elastic Stack pre-built roles and users

```bash
/usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto
```
To check that the installation was made successfully, run the following command replacing *localhost* with your server ip and *<elastic_password>* with the password generated in the previous step for elastic user

```bash
curl -XGET https://localhost:9200 -u elastic:<elastic_password> -k
```
<details>
  <summary>Output Elasticsearch Curl</summary>
  
  ```json
  {
    "name" : "elasticsearch",
    "cluster_name" : "elasticsearch",
    "cluster_uuid" : "44FdoqYaQxaYMtN_Ge7_dQ",
    "version" : {
      "number" : "7.17.12",
      "build_flavor" : "default",
      "build_type" : "deb",
      "build_hash" : "e3b0c3d3c5c130e1dc6d567d6baef1c73eeb2059",
      "build_date" : "2023-07-20T05:33:33.690180787Z",
      "build_snapshot" : false,
      "lucene_version" : "8.11.1",
      "minimum_wire_compatibility_version" : "6.8.0",
      "minimum_index_compatibility_version" : "6.0.0-beta1"
    },
    "tagline" : "You Know, for Search"
  }
```
</details>

# Install Wazuh-Server
Install GPG key
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
```
Add repository

```bash
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
```
Update packages

```bash
sudo apt update
```
Install Wazuh Package

```bash
apt-get install wazuh-manager
```
Enable and start the Wazuh manager service

```bash
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
```
Run the following command to check if the Wazuh manager is active

```bash
systemctl status wazuh-manager
```

# Install Filebeat
Install Filebeat package

```bash
apt-get install filebeat=7.17.12
```
Download the pre-configured Filebeat config file used to forward Wazuh alerts to Elasticsearch

```bash
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.5/tpl/elastic-basic/filebeat_all_in_one.yml
```
Download the alerts template for Elasticsearch

```bash
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.5/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
```
Download the Wazuh module for Filebeat

```bash
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.2.tar.gz | tar -xvz -C /usr/share/filebeat/module
```
*Edit the file /etc/filebeat/filebeat.yml and add the following line:*

*output.elasticsearch.password: <elasticsearch_password>*

*Also edit output.elasticsearch.hosts value with your server ip  *

Replace elasticsearch_password with the previously generated password for elastic user.

Copy the certificates into /etc/filebeat/certs/

```bash
cp -r /etc/elasticsearch/certs/ca/ /etc/filebeat/certs/
cp /etc/elasticsearch/certs/elasticsearch.crt /etc/filebeat/certs/filebeat.crt
cp /etc/elasticsearch/certs/elasticsearch.key /etc/filebeat/certs/filebeat.key
```
Enable and start the Filebeat service

```bash
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat
```

Test filebeat configuration

```bash
filebeat test output
```
Correct configuration output

<details>
  <summary>Output Filebeat Test</summary>
  
  ```
  {
elasticsearch: https://192.168.1.1:9200...
  parse url... OK
  connection...
    parse host... OK
    dns lookup... OK
    addresses: 192.168.1.1
    dial up... OK
  TLS...
    security: server's certificate chain verification is enabled
    handshake... OK
    TLS version: TLSv1.3
    dial up... OK
  talk to server... OK
  version: 7.17.12
  }
```
</details>

# Install Kibana

```bash
apt-get install kibana=7.17.12
```
Copy the Elasticsearch certificates into the Kibana configuration folder

```bash
mkdir /etc/kibana/certs/ca -p
cp -R /etc/elasticsearch/certs/ca/ /etc/kibana/certs/
cp /etc/elasticsearch/certs/elasticsearch.key /etc/kibana/certs/kibana.key
cp /etc/elasticsearch/certs/elasticsearch.crt /etc/kibana/certs/kibana.crt
chown -R kibana:kibana /etc/kibana/
chmod -R 500 /etc/kibana/certs
chmod 440 /etc/kibana/certs/ca/ca.* /etc/kibana/certs/kibana.*
```
Download the Kibana configuration file

```bash
curl -so /etc/kibana/kibana.yml https://packages.wazuh.com/4.5/tpl/elastic-basic/kibana_all_in_one.yml
```
*Edit the /etc/kibana/kibana.yml file*
*elasticsearch.password: <elasticsearch_password>*

Create the /usr/share/kibana/data directory

```bash
mkdir /usr/share/kibana/data
chown -R kibana:kibana /usr/share/kibana
```
Install the Wazuh Kibana plugin. The installation of the plugin must be done from the Kibana home directory as follows

```bash
cd /usr/share/kibana
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.5.2_7.17.12-1.zip
```
Link Kibana's socket to privileged port 443

```bash
setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node
```
Enable and start the Kibana service

```bash
systemctl daemon-reload
systemctl enable kibana
systemctl start kibana
```
Access the web interface using the password generated during the Elasticsearch installation process

URL: https://<wazuh_server_ip>

user: elastic

password: <PASSWORD_elastic>

# Disable repositories

```bash
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/elastic-7.x.list
apt-get update
```

# Configure Vulnerabilities Scan
Edit /var/ossec/etc/ossec.conf, chage the value *<enabled>": "no"*, to *"<enabled>":"yes",*

Look at the example

<details>
  <summary>ossec.conf (vulnerability-scan)</summary>
  
  ```xml
<?xml version='1.0'?>
<configuration>
	<vulnerability-detector>
		<enabled>yes</enabled>
		<run_on_start>yes</run_on_start>
		<interval>300</interval>
		<min_full_scan_interval>21600</min_full_scan_interval>
		<retry_interval>30</retry_interval>
		<providers>
			<name>canonical</name>
			<version>TRUSTY</version>
			<url>https://security-metadata.canonical.com/oval/com.ubuntu.trusty.cve.oval.xml.bz2</url>
			<update_interval>3600</update_interval>
			<download_timeout>300</download_timeout>
		</providers>
		<providers>
			<name>canonical</name>
			<version>XENIAL</version>
			<url>https://security-metadata.canonical.com/oval/com.ubuntu.xenial.cve.oval.xml.bz2</url>
			<update_interval>3600</update_interval>
			<download_timeout>300</download_timeout>
		</providers>
		<providers>
			<name>canonical</name>
			<version>BIONIC</version>
			<url>https://security-metadata.canonical.com/oval/com.ubuntu.bionic.cve.oval.xml.bz2</url>
			<update_interval>3600</update_interval>
			<download_timeout>300</download_timeout>
		</providers>
		<providers>
			<name>canonical</name>
			<version>FOCAL</version>
			<url>https://security-metadata.canonical.com/oval/com.ubuntu.focal.cve.oval.xml.bz2</url>
			<update_interval>3600</update_interval>
			<download_timeout>300</download_timeout>
		</providers>
		<providers>
			<name>canonical</name>
			<version>JAMMY</version>
			<url>https://security-metadata.canonical.com/oval/com.ubuntu.jammy.cve.oval.xml.bz2</url>
			<update_interval>3600</update_interval>
			<download_timeout>300</download_timeout>
		</providers>
		<providers>
			<name>debian</name>
			<version>BUSTER</version>
			<url>https://www.debian.org/security/oval/oval-definitions-buster.xml.bz2</url>
			<update_interval>3600</update_interval>
			<download_timeout>300</download_timeout>
		</providers>
		<providers>
			<name>debian</name>
			<version>BULLSEYE</version>
			<url>https://www.debian.org/security/oval/oval-definitions-bullseye.xml.bz2</url>
			<update_interval>3600</update_interval>
			<download_timeout>300</download_timeout>
		</providers>
		<providers>
			<name>nvd</name>
			<update_interval>3600</update_interval>
			<download_timeout>300</download_timeout>
		</providers>
		<providers>
			<name>msu</name>
			<update_interval>3600</update_interval>
			<download_timeout>300</download_timeout>
		</providers>
	</vulnerability-detector>
</configuration>
```
</details>

# Configure CIS-CAT

Edit /var/ossec/etc/ossec.conf, chage the value *"disabled": "yes"*, to *"disabled":"no",*

Look at the example

<details>
  <summary>ossec.conf (add this)</summary>
  
  ```xml
<?xml version='1.0'?>
<configuration>
	<cis-cat>
		<disabled>no</disabled>
		<scan-on-start>yes</scan-on-start>
		<interval>86400</interval>
		<java_path>wodles/java</java_path>
		<ciscat_path>wodles/ciscat</ciscat_path>
		<ciscat_binary>CIS-CAT.sh</ciscat_binary>
		<timeout>1800</timeout>
	</cis-cat>
</configuration>

```
</details>

# Configure Osquery


Edit /var/ossec/etc/ossec.conf, chage the value *"<disabled>": "yes"*, to *"<disabled>":"no",*

Look at the example

<details>
  <summary>ossec.conf (add this)</summary>
  
  ```xml
<?xml version='1.0'?>
<configuration>
	<osquery>
		<disabled>no</disabled>
		<run_daemon>yes</run_daemon>
		<add_labels>yes</add_labels>
		<log_path>/var/log/osquery/osqueryd.results.log</log_path>
		<config_path>/etc/osquery/osquery.conf</config_path>
	</osquery>
</configuration>
```
</details>


# Integration with TheHive
Update pip

```bash
/var/ossec/framework/python/bin/python3.9 -m pip install --upgrade pip
```
Install module thehive4py 

```bash
sudo /var/ossec/framework/python/bin/pip3 install thehive4py==1.8.1
```

We create the custom integration script by pasting the following python code in /var/ossec/integrations/custom-w2thive.py. The lvl_threshold variable in the script indicates the minimum alert level that will be forwarded to TheHive. The variable can be customized so that only relevant alerts are forwarded to TheHive

<details>
  <summary>custom-w2thive.py</summary>
  
  ```python
#!/var/ossec/framework/python/bin/python3
import json
import sys
import os
import re
import logging
import uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

#start user config

# Global vars

#threshold for wazuh rules level
lvl_threshold=0
#threshold for suricata rules level
suricata_lvl_threshold=3

debug_enabled = False
#info about created alert
info_enabled = True

#end user config

# Set paths
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
logger = logging.getLogger(__name__)
#set logging level
logger.setLevel(logging.WARNING)
if info_enabled:
    logger.setLevel(logging.INFO)
if debug_enabled:
    logger.setLevel(logging.DEBUG)
# create the logging file handler
fh = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)



def main(args):
    logger.debug('#start main')
    logger.debug('#get alert file location')
    alert_file_location = args[1]
    logger.debug('#get TheHive url')
    thive = args[3]
    logger.debug('#get TheHive api key')
    thive_api_key = args[2]
    thive_api = TheHiveApi(thive, thive_api_key )
    logger.debug('#open alert file')
    w_alert = json.load(open(alert_file_location))
    logger.debug('#alert data')
    logger.debug(str(w_alert))
    logger.debug('#gen json to dot-key-text')
    alt = pr(w_alert,'',[])
    logger.debug('#formatting description')
    format_alt = md_format(alt)
    logger.debug('#search artifacts')
    artifacts_dict = artifact_detect(format_alt)
    alert = generate_alert(format_alt, artifacts_dict, w_alert)
    logger.debug('#threshold filtering')
    if w_alert['rule']['groups']==['ids','suricata']:
        #checking the existence of the data.alert.severity field
        if 'data' in w_alert.keys():
            if 'alert' in w_alert['data']:
                #checking the level of the source event
                if int(w_alert['data']['alert']['severity'])<=suricata_lvl_threshold:
                    send_alert(alert, thive_api)
    elif int(w_alert['rule']['level'])>=lvl_threshold:
        #if the event is different from suricata AND suricata-event-type: alert check lvl_threshold
        send_alert(alert, thive_api)


def pr(data,prefix, alt):
    for key,value in data.items():
        if hasattr(value,'keys'):
            pr(value,prefix+'.'+str(key),alt=alt)
        else:
            alt.append((prefix+'.'+str(key)+'|||'+str(value)))
    return alt



def md_format(alt,format_alt=''):
    md_title_dict = {}
    #sorted with first key
    for now in alt:
        now = now[1:]
        #fix first key last symbol
        dot = now.split('|||')[0].find('.')
        if dot==-1:
            md_title_dict[now.split('|||')[0]] =[now]
        else:
            if now[0:dot] in md_title_dict.keys():
                (md_title_dict[now[0:dot]]).append(now)
            else:
                md_title_dict[now[0:dot]]=[now]
    for now in md_title_dict.keys():
        format_alt+='### '+now.capitalize()+'\n'+'| key | val |\n| ------ | ------ |\n'
        for let in md_title_dict[now]:
            key,val = let.split('|||')[0],let.split('|||')[1]
            format_alt+='| **' + key + '** | ' + val + ' |\n'
    return format_alt


def artifact_detect(format_alt):
    artifacts_dict = {}
    artifacts_dict['ip'] = re.findall(r'\d+\.\d+\.\d+\.\d+',format_alt)
    artifacts_dict['url'] =  re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',format_alt)
    artifacts_dict['domain'] = []
    for now in artifacts_dict['url']: artifacts_dict['domain'].append(now.split('//')[1].split('/')[0])
    return artifacts_dict


def generate_alert(format_alt, artifacts_dict,w_alert):
    #generate alert sourceRef
    sourceRef = str(uuid.uuid4())[0:6]
    artifacts = []
    if 'agent' in w_alert.keys():
        if 'ip' not in w_alert['agent'].keys():
            w_alert['agent']['ip']='no agent ip'
    else:
        w_alert['agent'] = {'id':'no agent id', 'name':'no agent name'}

    for key,value in artifacts_dict.items():
        for val in value:
            artifacts.append(AlertArtifact(dataType=key, data=val))
    alert = Alert(title=w_alert['rule']['description'],
              tlp=2,
              tags=['wazuh', 
              'rule='+w_alert['rule']['id'], 
              'agent_name='+w_alert['agent']['name'],
              'agent_id='+w_alert['agent']['id'],
              'agent_ip='+w_alert['agent']['ip'],],
              description=format_alt ,
              type='wazuh_alert',
              source='wazuh',
              sourceRef=sourceRef,
              artifacts=artifacts,)
    return alert




def send_alert(alert, thive_api):
    response = thive_api.create_alert(alert)
    if response.status_code == 201:
        logger.info('Create TheHive alert: '+ str(response.json()['id']))
    else:
        logger.error('Error create TheHive alert: {}/{}'.format(response.status_code, response.text))



if __name__ == "__main__":

    try:
       logger.debug('debug mode') # if debug enabled       
       # Main function
       main(sys.argv)

    except Exception:
       logger.exception('EGOR')
```
</details>

We create a bash script as */var/ossec/integrations/custom-w2thive* . This will properly execute the .py script created in the previous step



<details>
  <summary>custom-w2thive</summary>
  
  ```bash
#!/bin/sh
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP>

WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"

DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi

    PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
    if [ -z "${WAZUH_PATH}" ]; then
        WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
    fi

    PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

    PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac


${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} $@

```
</details>


We change the files’ permission and the ownership to ensure that Wazuh has adequate permissions to access and run them

```bash
sudo chmod 755 /var/ossec/integrations/custom-w2thive.py
sudo chmod 755 /var/ossec/integrations/custom-w2thive
sudo chown root:wazuh /var/ossec/integrations/custom-w2thive.py
sudo chown root:wazuh /var/ossec/integrations/custom-w2thive
```
To allow Wazuh to run the integration script, we add the following lines to the manager configuration file located at /var/ossec/etc/ossec.conf

*edit hook_url with your thehive server ip & API Key*

<details>
  <summary>ossec.conf (add this)</summary>
  
  ```bash
<ossec_config>
…
  <integration>
    <name>custom-w2thive</name>
    <hook_url>http://TheHive_Server_IP:9000</hook_url>
    <api_key>RWw/Ii0yE6l+Nnd3nv3o3Uz+5UuHQYTM</api_key>
    <alert_format>json</alert_format>
  </integration>
…
</ossec_config>

```
</details>

Restart the manager to apply the changes

```bash
sudo systemctl restart wazuh-manager
```



```bash
```


```bash
```



