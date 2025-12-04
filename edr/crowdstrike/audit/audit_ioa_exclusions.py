###############################################################################
#
#   audit_ioa_exclusions.py
#
#   Checks all IOA Exclusions across MCNC tenants
#
###############################################################################

import datetime
import json
from falconpy import IOAExclusions

CLIENT_ID = ""
CLIENT_SECRET = "b"

RUN_TIME = datetime.datetime.now().strftime("%Y%m%d_%H-%M-%S")
OUTPUT_PATH = f"/Users/psullivan/Documents/Projects/scripting/CrowdStrike/Auditing/Output/"
OUTPUT_FILE = f"{RUN_TIME}_ioa_exclusion_audit_report.json"

CUSTOMER_LIST = json.load(open("customer_list.json"))

# Check API Response
def check_response(response):
    if response.get('status_code') == 200:
        return True
    else:
        print(f"Error in response: {json.dumps(response, indent=2)}")
        return False
    
# initialize falcon api client
def init_falcon_client(cid):
    cs_creds = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET, 
            'base_url': 'https://api.laggar.gcw.crowdstrike.com',
            "member_cid": cid
            }
    client = IOAExclusions(
        creds=cs_creds,base_url=cs_creds['base_url']
    )
    return client

# Get list of IOA Exclusion IDs from CID
def get_ioa_exclusions_from_cid(ioa_api_client):
    exclusion_id_list_response = ioa_api_client.queryIOAExclusionsV1(
                                       limit=500,
                                       sort="name.asc"
                                       )
    if check_response(exclusion_id_list_response):
        # exclusion_id_list = [id1, id2, id3, ...]
        exclusion_id_list = exclusion_id_list_response.get('body', {}).get('resources], []')
        return exclusion_id_list
    else:
        print(f"Error getting Exclusion ID List: \n{json.dumps(exclusion_id_list, indent=2)}")
        return None
        
# From IOA Exclusion ID list, get exclusion data (name, description, regex, etc)    
def get_ioa_exclusion_data(ioa_api_client, exclusion_id_list):    
    # Get exclusion data for each exclusion id in exclusion_id_list from CID
    exclusion_getter = ioa_api_client.getIOAExclusionsV1(ids=exclusion_id_list)
    if check_response(exclusion_getter):
        exclusions_data = exclusion_getter.get('body', {}).get('resources', [])
        # exclusions_data = [{Exclusion Data}, {Exclusion Data}, ...]
        return exclusions_data
    else:
        print(f"Error getting exclusion: \n{json.dumps(exclusion_getter, indent=2)}")
        return None
    
# Output the JSON report
def print_json_output(output):
    with open(OUTPUT_PATH+OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)
        

def main():
    output = CUSTOMER_LIST.copy()    
    cid_list = CUSTOMER_LIST # TODO: Do we import this or just paste it into the script?
    
    for cid in cid_list["customer_list"]:
        
        ioa_api_client = init_falcon_client(cid)
        if check_response(ioa_api_client):
            print(f"Successfully initialized IOA Exclusions client for {cid}.")
        else:
            print(f"Error initializing API client for {cid}:\n{json.dumps(ioa_api_client, indent=2)}")
            continue
        
        # exclusion_id_list = [id1, id2, id3, ...]
        exclusion_id_list = get_ioa_exclusions_from_cid(ioa_api_client)
        
        # exclusion_list = [{Exclusion Data}, {Exclusion Data}, ...] 
        exclusion_list = get_ioa_exclusion_data(ioa_api_client, exclusion_id_list)
        
        for exclusion in exclusion_list:
            output['customer_list']['exclusions'].append(exclusion)

        # print the report
    print_json_output(output)
            

if __name__ == "__main__":
    main()