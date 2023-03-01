import requests, json, time, urllib3, csv
# Variables
ness_base_url = 'https://127.0.0.1:8834'
username = input("Username: \n")
password = input("Password: \n")
sleepPeriod = 5

# Turn off TLS warnings
urllib3.disable_warnings()

# Grab the token
Session_URL =ness_base_url+"/session"
TOKENPARAMS = {'username':username, 'password':password}
Session = requests.post(url = Session_URL, data = TOKENPARAMS, verify = False)
jsonData = Session.json()
token = str("token="+jsonData['token'])
#print (Session.json())

# Show all folders
Folder_URL=ness_base_url+"/folders"
TOKENPARAMS = {'username':username, 'password':password}
headers = {'X-Cookie': token, 'Content-type': 'application/json', 'Accept': 'text/plain'}
folder = requests.get(url = Folder_URL, headers=headers, verify = False)
jsonFolder = folder.json()
#print(jsonFolder)

#Loop through folders
folderID = []
for line in jsonFolder['folders']:
    folderID.append([line['id'],line['name']])
#print(folderID)

#Loop through folder ID's and enurmarate scan ID's
scan_list = []
for data in folderID:
    ID = data[0]
    NAME = data[1]
    ScanFolder_URL = ness_base_url+"/scans?folder_id="+str(ID)
    t = requests.get(url = ScanFolder_URL, headers=headers, verify = False)
    folder_data = t.json()
    scanIDs = []
    #print(folder_data)
    if folder_data['scans'] is not None:
        for lines in folder_data['scans']:
            if lines['status'] == 'completed':
                scanIDs.append([lines['id'],lines['name']])
    print (scanIDs)
    # Main loop for the program
    for listID in scanIDs:
        ID = listID[0]
        NAME = str(listID[1])
 
        # Call the POST /export function to collect details for each scan
        URL = ness_base_url+"/scans/"+str(ID)+"/export"
 
        # In this case, we're asking for a:
        #   - CSV export
        #   - Only requesting certain fields
        #   - Severity = 4 (aka Critical) only
        payload = {
            "format": "csv",
            "reportContents": {
                "csvColumns": {
                    "id": True,
                    "cve": True,
                    "cvss": True,
                    "risk": True,
                    "hostname": True,
                    "protocol": True,
                    "port": True,
                    "plugin_name": False,
                    "synopsis": False,
                    "description": False,
                    "solution": False,
                    "see_also": False,
                    "plugin_output": False,
                    "stig_severity": False,
                    "cvss3_base_score": False,
                    "cvss_temporal_score": False,
                    "cvss3_temporal_score": False,
                    "risk_factor": False,
                    "references": False,
                    "plugin_information": False,
                    "exploitable_with": False
                }
            },
            "extraFilters": {
                "host_ids": [],
                "plugin_ids": []
            },
            "filter.0.quality": "neq",
            "filter.0.filter": "severity",
            "filter.0.value": 0
        }
 
        # Pass the POST request in json format. Two items are returned, file and token
        jsonPayload = json.dumps(payload)
        r = requests.post(url = URL, headers=headers, data = jsonPayload, verify = False)
        jsonData = r.json()
        scanFile = str(jsonData['file'])
        scanToken = str(jsonData['token'])
 
        # Use the file just received and check to see if it's 'ready', otherwise sleep for sleepPeriod seconds and try again
        status = "loading"
        while status != 'ready':
            URL = ness_base_url+"/scans/"+str(ID)+"/export/"+scanFile+"/status"
            t = requests.get(url = URL, headers=headers, verify = False)
            data = t.json()
            if data['status'] == 'ready':
                status = 'ready'
            else:
                time.sleep(sleepPeriod)
 
        # Now that the report is ready, download
        URL = ness_base_url+"/scans/"+str(ID)+"/export/"+scanFile+"/download"
        d = requests.get(url = URL, headers=headers, verify = False)
        print(d)
        dataBack = d.text
        print (dataBack)

        # Clean up the CSV data
        csvData = dataBack.replace('"', "" )
        NAMECLEAN=NAME.replace('/','-',-1)
        print("-----------------------------------------------")
        print("Starting  "+NAMECLEAN)
        with open (NAMECLEAN+".csv", 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file, quotechar=',')
            writer.writerow([csvData])
        print("Completed "+NAMECLEAN)
        
    
