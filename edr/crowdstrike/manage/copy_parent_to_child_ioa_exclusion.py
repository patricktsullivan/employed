#!/usr/bin/env python
# -*-coding:utf-8 -*-

#########################################################################################################
"""
   parent_to_child_ioa_exclusion.py

   Copy an IOA Exclusion from your API Key's home CID into any given CID(s)

   This script uses the 1Password CLI to load credentials

"""

#########################################################################################################

import datetime
import json
import logging
import pathlib
import re
import subprocess
from falconpy import HostGroup, IOAExclusions 

# Secret reference: op://<vault-name>/<item-name>/[section-name/]<field-name>
OP_CLIENT_ID_REF = ""
OP_CLIENT_SECRET_REF = ""

# Logging Config
LOG_LEVEL = logging.INFO
LOG_FILE = f"{pathlib.Path(__file__).parent.resolve()}/{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_%(filename).log"

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(funcName)s:%(lineno)d - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE)]
)

# Import Secret(s) from 1Password using 1Password CLI
def op_read(reference: str) -> str:
    """Read a secret from 1Password using op:// URI."""
    try:
        result = subprocess.run(
            ["op", "read", reference],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"1Password error: {e.stderr.strip()}")
        raise RuntimeError(f"1Password error: {e.stderr.strip()}") from e
    except FileNotFoundError:
        logging.error(f"1Password CLI (op) not found")
        raise RuntimeError("1Password CLI (op) not found")

# Check API Response
def check_response(response):
    if response.get('status_code') == 200:
        return True
    else:
        logging.error(f"Error in response: {json.dumps(response, indent=2)}")
        return False

# initialize falcon api client
def init_falcon_client(client_id, client_secret, target_cid, context):
    cs_creds = {
            'client_id': client_id,
            'client_secret': client_secret, 
            'base_url': 'https://api.laggar.gcw.crowdstrike.com',
            'member_cid': target_cid
            }
    if context == "IOAExclusions":
        client = IOAExclusions(
            creds=cs_creds,base_url=cs_creds['base_url']
        )
    elif context == "HostGroup":
        client = HostGroup(
            creds=cs_creds,base_url=cs_creds['base_url']
        )
    else:
        # This shouldn't ever happen, we aren't letting users put in arbitrary context
        print("Invalid context provided.")
        return None
    return client


def get_ioa_exclusion_ids_from_cid(client):
    # Get list of IOA Exclusion IDs from CID
    exclusions_list = client.queryIOAExclusionsV1(
                                       limit=500,
                                       sort="name.asc"
                                       )
    
    # For each ID, print out the Info
    exclusion_id_list = exclusions_list.get('body', {}).get('resources', [])
    for exclusion_id in exclusion_id_list:
        exclusion_data = get_ioa_exclusion_data(client, id)
        print(f"Exclusion ID: {exclusion_id}\n{json.dumps(exclusion_data, indent=2)}")

    while (True):
        # Enter the Exclusion's unique ID to copy
        exclusion_id = input("Enter the IOA Exclusion ID you'd like to copy: ")
        get_ioa_exclusion_data(client, exclusion_id)
        # Check you've entered a valid Exclusion ID
        if exclusion_id not in exclusion_id_list:
            print("Invalid selection, please try again.")
            continue
        else:
            logging.info(f"Selected Exclusion ID: {exclusion_id}")
            break
        
    return get_ioa_exclusion_data(client, exclusion_id)
   
# Get IOA Exclusion Data     
def get_ioa_exclusion_data(client, exclusion_id):
    exclusion_getter = client.getIOAExclusionsV1(ids=exclusion_id)
    if check_response(exclusion_getter):
        exclusion_data = exclusion_getter.get('body', {}).get('resources', [])
        print("\nExclusion Data: ", json.dumps(exclusion_data, indent=2))
        return exclusion_data
    else:
        print(f"Error getting exclusion: {json.dumps(exclusion_getter)}")
        logging.error(f"Error getting exclusion: {json.dumps(exclusion_getter)}")
        
# Create IOA Exclusion targeting Host Group
def create_ioa_exclusion(client, exclusion_data, target_group):    
    exclusion_data[0].update({ "groups" : target_group })
    
    # Variables for all the Exclusion Info we want to pass along
    exclusion_pattern_id = exclusion_data[0].get("pattern_id")
    exclusion_pattern_name = exclusion_data[0].get("pattern_name")
    exclusion_description = exclusion_data[0].get("description")
    exclusion_group = exclusion_data[0].get("groups")
    exclusion_ifn_regex = exclusion_data[0].get("ifn_regex")
    exclusion_name = exclusion_data[0].get("name")
    
    # Creation time for audit log comment
    creation_time = datetime.datetime.now().strftime("%B %d, %Y %H:%M:%S")
    # create new ioa exclusion
    response = client.createIOAExclusionsV1(
                                            cl_regex=exclusion_data[0].get("cl_regex"),
                                            comment=f"Added via API on {creation_time}", 
                                            description=exclusion_description, 
                                            detection_json="",
                                            groups=exclusion_group,
                                            ifn_regex=exclusion_ifn_regex,
                                            name=exclusion_name, 
                                            pattern_id=exclusion_pattern_id,
                                            pattern_name=exclusion_pattern_name
                                            )

    # check if creation was successful
    if check_response(response):
        print("\nIOA exclusion successfully created.")
        logging.info(f"IOA Exclusion successfully created:\n{json.dumps(response, indent=2)}")
    
def get_target_host_group(client_id, client_secret, cid):
    host_group_client = init_falcon_client(client_id, client_secret, cid, "HostGroup")

    query_host_groups = host_group_client.queryHostGroups(
        limit=500
    )
    host_group_id_list = query_host_groups.get('body', {}).get('resources', [])
    host_groups = host_group_client.getHostGroups(ids=host_group_id_list)

    # Print out all the relevant Host Group Info
    for hg in host_groups.get('body', {}).get('resources', []):
        print("")
        print("id:", hg.get("id"))
        print("name:", hg.get("name"))
        print("description:", hg.get("description"))
        print("assignment_rule:", hg.get("assignment_rule"))
        print("")

    while (True):
        # Enter the Host Group's unique ID to copy
        target_group = input("Enter the target host group ID: ")
        if target_group not in host_group_id_list:
            print("Invalid selection, please try again.")
            continue
        else:
            copy_hg_array = host_groups.get('body', {}).get('resources', [])
            target_host_group = [x for x in copy_hg_array if x.get("id") == target_group]
            break

    return target_host_group

def get_target_cids():
    cid_input = input("Enter your Target CID(s) (or press Enter to skip): ") or None
    cid_list = re.split(r',\s*', cid_input) if cid_input else [None]
    return cid_list
            
def main():
    api_client_id = op_read(OP_CLIENT_ID_REF)
    api_client_secret = op_read(OP_CLIENT_SECRET_REF)

    ioa_getter = init_falcon_client(api_client_id, api_client_secret, "", "IOAExclusions")
    exclusion_data = get_ioa_exclusion_ids_from_cid(ioa_getter)
    
    cid_list = get_target_cids()
    
    for cid in cid_list:
        target_group = get_target_host_group(api_client_id, api_client_secret, cid)
            
        while(True):
            # Output a Summary of what will be passed
            print("=" * 80)
            print("CID: {} \n\nHost Group Information: {} \n\nExclusion Info: {}".format(cid, json.dumps(target_group, indent=2), json.dumps(exclusion_data, indent=2)))
            print("=" * 80)
            create_check = input("Proceed with creation? (yes/no): ")
            # If yes, create it
            if create_check == "yes":
                logging.info(f"Creating IOA Exclusion in CID: {cid}")
                logging.info("=" * 80)
                logging.info(f"CID: {cid} \n\nHost Group Information: {json.dumps(target_group, indent=2)} \n\nExclusion Info: {json.dumps(exclusion_data, indent=2)}")
                logging.info("=" * 80)
                break
            # if no, move back to whatever part you want to fix, then repeat summary
            elif create_check == "no":
                # what's wrong - exclusion id, host group, cid
                update_fix = input("What needs to be fixed? (cid/hg/ioa): ")
                if update_fix == "cid":
                    cid = get_target_cids()
                elif update_fix == "hg":
                    target_group = get_target_host_group(api_client_id, api_client_secret, cid)
                elif update_fix == "ioa":
                    exclusion_data = get_ioa_exclusion_ids_from_cid(ioa_getter)
                else:
                    continue
        ioa_creator = init_falcon_client(api_client_id, api_client_secret, cid, "IOAExclusions")
        create_ioa_exclusion(ioa_creator, exclusion_data, target_group[0].get("id"))

if __name__ == "__main__":
    main()
