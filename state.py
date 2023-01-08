#!/usr/bin/env python3

# Copyright 2019-2021 Sophos Limited
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License.
# You may obtain a copy of the License at:  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and limitations under the
# License.
#
import sys
import os
import json
from pathlib import Path
from siem import parse_args_options, load_config, connect
from datetime import datetime

datastore =False

class State:
    def __init__(self, options, state_file, datastore= datastore ):
        """Class create state file and providing state file data"""

        if state_file and Path(state_file).suffix != ".json":
            raise SystemExit(
                "Sophos state file is not in valid format. it's must be with a .json extension"
            )
        self.options = options
        if "SOPHOS_SIEM_HOME" in os.environ:
            app_path = os.environ["SOPHOS_SIEM_HOME"]
        else:
            app_path = os.path.join(os.getcwd())
        if not datastore:
            self.state_file = self.get_state_file(app_path, state_file)
            self.create_state_dir(self.state_file)
            self.state_data = self.load_state_file()
        else:
            self.state_data = self.load_state_file()

    def log(self, log_message):
        """Write the log.
        Arguments:
            log_message {string} -- log content
        """
        if not self.options.quiet:
            sys.stderr.write("%s\n" % log_message)

    def create_state_dir(self, state_file):
        """Create state directory
        Arguments:
            state_file {string}: state file path
        """
        state_dir = os.path.dirname(state_file)
        if not os.path.exists(state_dir):
            try:
                os.makedirs(state_dir)
            except OSError as e:
                raise SystemExit("Failed to create %s, %s" % (state_dir, str(e)))

    def get_state_file(self, app_path, state_file):
        """Return state cache file path
        Arguments:
            app_path {string}: application path
            state_file {string}: state file path
        Returns:
            dict -- state file path
        """
        if not state_file:
            return os.path.join(app_path, "state", "siem_sophos.json")
        else:
            return (
                state_file
                if os.path.isabs(state_file)
                else os.path.join(app_path, state_file)
            )

    def load_state_file(self, datastore= datastore):
        """Get state file data
        Returns:
            dict -- Return state file data or exit if found any error
        """
        if not datastore:
            try:
                with open(self.state_file, "rb") as f:
                    return json.load(f)
            except IOError:
                self.log("Sophos state file not found")
            except json.decoder.JSONDecodeError:
                raise SystemExit("Sophos state file not in valid JSON format")
        elif datastore:
            try:
                return get_store_status_update()
            except Exception as e:
                raise( "Fail to get status from database" )
                return {}
        else:
            return {}

    def save_state(self, state_data_key, state_data_value):
        """save data in state file. Data store in nested object by splitting key with `.` separator
        Arguments:
            state_data_key {string}: state key
            state_data_value {string}: state value
        """
        # Store state
        key_arr = state_data_key.split(".")
        sub_data = self.state_data
        for item in key_arr[0:-1]:
            if item not in sub_data.keys():
                sub_data[item] = {}
            sub_data = sub_data[item]
        sub_data[key_arr[-1]] = state_data_value

        self.write_state_file(json.dumps(self.state_data, indent=4))

    def write_state_file(self, data, datastore= datastore):
        """Write data in state file
        Arguments:
            data {dict}: state data object
        """
        if not datastore:
            with open(self.state_file, "w") as f:
                try:
                    f.write(data)
                except Exception as e:
                    self.log("Error :: %s" % e)
                    pass
        else:
            set_store_status_update(data)
            print(f"\n\n\n\n\nwrinig to status...................\n{data}")


def prepstore():
    options = parse_args_options()
    config_data = load_config(options.config)
    conn = connect(config_data)
    if conn.closed ==  True:
        conn = connect()
    # cursor = conn.cursor()
    # conn.commit()
    return conn

def set_store_status_update(data):
    conn = prepstore()
    cursor = conn.cursor()
    data = json.loads(data)
    temp = []
    print(f"----------------------++-----\n\n {data.keys()}")
    if data["account"]:
        print(data["account"])
        for key in data["account"].keys():
            print(f"-----------------------**----\n\n{data}")
            accountid = key
            if "jwt" in data["account"][key].keys():
                jwt = data["account"][key]["jwt"]
                
            elif "jwt" not in data["account"][key].keys() :
                jwt = ""

            if  "jwtExpiresAt" in data["account"][key].keys():
                jwtExpiresAt = data["account"][key]["jwtExpiresAt"]
                
            elif  "jwtExpiresAt" not in data["account"][key].keys():
                jwtExpiresAt = ""

            if "whoami" in data["account"][key].keys():
                whoami = data["account"][key]["whoami"]
                for whokey in whoami.keys():
                    if "id" in whokey.keys():
                        whoami_id =  whoami[whokey]
                    elif "id" not in  whokey.keys():
                        whoami_id= ""

                    if "idType" in whokey.keys():
                        whoami_Type =  whoami[whokey]
                    elif "idType" not in whokey.keys():
                        whoami_Type= ""
                    print(f"********{whokey.lower()}\n********")
                    if "apihosts" in  whokey.keys():
                        apiHosts =  whoami[whokey]
                        for hostdata in apiHosts:
                            if "global" in hostdata.keys():
                                globalhost =  apiHosts[hostdata]
                            elif "global" not in  hostdata.keys(): 
                                globalhost = ""

                            if "dataRegion" in hostdata.keys():
                                dataRegion =  apiHosts[hostdata]
                            elif "dataRegion" not in hostdata.keys(): 
                                dataRegion = ""                                
                            
                    if "access_token" in whokey.keys():
                        access_token =  whoami[whokey]
                    elif "access_token" not in whokey.keys():
                        access_token= ""


            elif "whoami" not in data["account"][key].keys():
                whoami_id = ""
                dataRegion = "" 
                globalhost = ""
                whoami_Type= ""
            
            # conn = prepstore()
            # cursor = conn.cursor()
            # SQLInsertStatus = ("INSERT INTO  [sophos_test].[dbo].[siem_state_account]([accountid] , [jwt] , [jwtExpiresAt] , [whoami_id]  , [whoami_apiHost_dataRegion] , [whoami_apiHost_global], [access_token], [whoami_idtype]  ) VALUES (?,?,?,?,?,?,?,?);")
            # values = [accountid  , jwt  , jwtExpiresAt  , whoami_id  , dataRegion   , globalhost, access_token  , whoami_Type ]
            # print(values)
            # try:
            #     print("inserting status to db....................................")
            #     cursor.execute(SQLInsertStatus, values)
            #     # result = cursor.fetchall()
            #     conn.commit()
            #     print("Done inserting..............................................")
            # except Exception as e:
            #     print("^^^^^^^^^^^^^^^^^^",e)

    else:
        accountid = ""
        jwt = ""
        jwtExpiresAt = ""
        whoami_id = ""
        dataRegion = "" 
        globalhost = ""
        whoami_Type= ""
    conn = prepstore()
    cursor = conn.cursor()
    SQLInsertStatus = ("""INSERT INTO  [dbo].[siem_state_account]([accountid], [jwt] , 
                        [jwtExpiresAt] , [whoami_id], [whoami_apiHost_dataRegion], [whoami_apiHost_global], 
                        [access_token], [whoami_idtype], [date_created]) VALUES (?,?,?,?,?,?,?,?, ?);""")
    values = [accountid  , jwt  , jwtExpiresAt  , whoami_id  , dataRegion   , globalhost, access_token  , whoami_Type,  datetime.now()]
    try:
        cursor.execute(SQLInsertStatus, values)
        conn.commit()
        cursor.close()
    except: 
        if accountid:
            SQLUpsert = f"UPDATE [sophos_test].[dbo].[siem_state_account] SET [jwt]=?, [jwtExpiresAt]=?, [access_token] =? WHERE [accountid] = {accountid}, [date_mordified] ={datetime.now()}"
            values = [jwt, jwtExpiresAt, access_token,]
            cursor.execute(SQLUpsert, values)
        cursor.close()
      
    # return accountid  , jwt  , jwtExpiresAt  , whoami_id  , dataRegion   , globalhost  , whoami_Type 


def   get_store_status_update():          
    """
    SAMPLE
    {
        "account": {
            "afd4ae6a-2923-46ba-a190-69b034c22d4c": {
                "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjFIaXNtSjFSZmIwRWJqYjJ6dy01LVhTNlFiYXBaZWtOcVpsVU51TVdac2cifQ.eyJhcHBfaW5mbyI6eyJhY2NvdW50VHlwZSI6ImN1c3RvbWVyIn0sImF1ZCI6ImFwaTovL2NlbnRyYWwtcHJvdmlzaW9uaW5nIiwiYXV0aF90aW1lIjoxNjY5MjAyODI1LCJjbGllbnRfaWQiOiJhZmQ0YWU2YS0yOTIzLTQ2YmEtYTE5MC02OWIwMzRjMjJkNGMiLCJleHAiOjE2NjkyMDY0MjUsImdpZCI6ImJiNGJjZDZiLWIzNTktNDU4ZC05NzU2LTMzYjI4YWRmMTFkYyIsImp0aSI6IklELjQ0ODBjZTYyLTU1NDUtNGM4Yi04MTJlLWEwODk1Nzk0NmM3YiIsImlhdCI6MTY2OTIwMjgyNSwiaXNzIjoiaHR0cHM6Ly9pZC5zb3Bob3MuY29tIiwicnRfaGFzaCI6IkhGSHZzY2ErbGFVRjJyby85bFFIa1E9PSIsInZlciI6MX0.hef5u8T1_Gzx9t1pCzTKrdDYcZJ4nzvOVKImzE2h6280-N9pIH6lpg4KAzzS2i9uvKjVwIoA-2Tya37Dnw9tkqWM5VMueTKFrKz7TWo5cmeCzgmkxCmmUGSQJCRv05S00zwT_3oEYso4aATZYftUvyjxASLUgsGjGJbAVmzG8fy2o9TaHn3-hUroMfKz9sz1C2eRmp6qGNH5LN-u5WEsvV-aw1Mff6sqVKSUQ1Y8CIldPo-XWpDRT3Z8WVF7p7j1GiweZddXs6VJzhQyTlzYco-lvazbKLhKEIC27ahG4TfzrXDuMta_za83EB8y8A-yvkS7sBs56GEGmvC5oIO-6sfFtl0pNI0INXLecxaTJ2qQs2n8bGmjcIS7_tV45TWfI7NFCNFgYn9Zz05tf6CmTSUJPr8GX-EJUIUyQzYGmOW3FlsNcPuNrce9x8qCZizOP6J9CGVhJw9cZsP8HhzPr-6KuhDUzywaQAU0acl8OSciesud0AM2dA3PSUg5TKhgBuLdhc6xnxw5u1yhN899TGPSZkAhnq99NYCeshA3NXgs__0TKixrrcSzpNbJmk5k_-kP9nfm_p7KTHoLZzNyFyALfvD9D-8jgloVUDFPW7B96HQESdr7osI7QHytKXx4xK6t8EkjCSYuAAF2tnNRNZpZnk25uoME-UNx8ZcNvPE",
                "jwtExpiresAt": 1669206305.2094533,
                "whoami": {
                    "id": "bb4bcd6b-b359-458d-9756-33b28adf11dc",
                    "idType": "tenant",
                    "apiHosts": {
                        "global": "https://api.central.sophos.com",
                        "dataRegion": "https://api-eu01.central.sophos.com"
                    },
                    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjFIaXNtSjFSZmIwRWJqYjJ6dy01LVhTNlFiYXBaZWtOcVpsVU51TVdac2cifQ.eyJhcHBfaW5mbyI6eyJhY2NvdW50VHlwZSI6ImN1c3RvbWVyIn0sImF1ZCI6ImFwaTovL2NlbnRyYWwtcHJvdmlzaW9uaW5nIiwiYXV0aF90aW1lIjoxNjY5MjAyODI1LCJjbGllbnRfaWQiOiJhZmQ0YWU2YS0yOTIzLTQ2YmEtYTE5MC02OWIwMzRjMjJkNGMiLCJleHAiOjE2NjkyMDY0MjUsImdpZCI6ImJiNGJjZDZiLWIzNTktNDU4ZC05NzU2LTMzYjI4YWRmMTFkYyIsImp0aSI6IklELjQ0ODBjZTYyLTU1NDUtNGM4Yi04MTJlLWEwODk1Nzk0NmM3YiIsImlhdCI6MTY2OTIwMjgyNSwiaXNzIjoiaHR0cHM6Ly9pZC5zb3Bob3MuY29tIiwicnRfaGFzaCI6IkhGSHZzY2ErbGFVRjJyby85bFFIa1E9PSIsInZlciI6MX0.hef5u8T1_Gzx9t1pCzTKrdDYcZJ4nzvOVKImzE2h6280-N9pIH6lpg4KAzzS2i9uvKjVwIoA-2Tya37Dnw9tkqWM5VMueTKFrKz7TWo5cmeCzgmkxCmmUGSQJCRv05S00zwT_3oEYso4aATZYftUvyjxASLUgsGjGJbAVmzG8fy2o9TaHn3-hUroMfKz9sz1C2eRmp6qGNH5LN-u5WEsvV-aw1Mff6sqVKSUQ1Y8CIldPo-XWpDRT3Z8WVF7p7j1GiweZddXs6VJzhQyTlzYco-lvazbKLhKEIC27ahG4TfzrXDuMta_za83EB8y8A-yvkS7sBs56GEGmvC5oIO-6sfFtl0pNI0INXLecxaTJ2qQs2n8bGmjcIS7_tV45TWfI7NFCNFgYn9Zz05tf6CmTSUJPr8GX-EJUIUyQzYGmOW3FlsNcPuNrce9x8qCZizOP6J9CGVhJw9cZsP8HhzPr-6KuhDUzywaQAU0acl8OSciesud0AM2dA3PSUg5TKhgBuLdhc6xnxw5u1yhN899TGPSZkAhnq99NYCeshA3NXgs__0TKixrrcSzpNbJmk5k_-kP9nfm_p7KTHoLZzNyFyALfvD9D-8jgloVUDFPW7B96HQESdr7osI7QHytKXx4xK6t8EkjCSYuAAF2tnNRNZpZnk25uoME-UNx8ZcNvPE"
                }
            }
        }
    }
  
  KEYS
    accountid
    jwt
    jwtExpiresAt
    whoami_id
    whoami_idtype
    whoami_apiHost_global
    whoami_apiHost_dataRegion
    access_token
    """
    cursor = prepstore()
    SQLGETStatus = ("SELECT TOP 1 * FROM [dbo].[siem_state_account]")
    try:
        cursor.execute(SQLGETStatus)
        result = cursor.fetchall()
        cursor.close()
        temp=[]
        if len(result)>0:
            for row in result:
                [temp.append(x) for x in row]
            
                
                data = {}
                """
                accountid = result.accountid
                data[accountid] = {}
                data[accountid]["jwt"] = result.jwt
                data[accountid]["jwtExpiresAt"] = result.jwtExpiresAt
                data[accountid]["whoami"] = {}
                data[accountid]["whoami"] ["id"]  = result.whoami_id
                data[accountid]["whoami"] ["idType"] = result.whoami_apiHost_global
                data[accountid]["whoami"] ["apiHosts"] ={}
                data[accountid]["whoami"] ["apiHosts"]["global"] = result.whoami_apiHost_global
                data[accountid]["whoami"] ["apiHosts"]["dataRegion"] = result.whoami_apiHost_dataRegion
                data[accountid]["whoami"] ["access_token"] = result.access_token"""
                accountid = temp[0]
                data[accountid] = {}
                data[accountid]["jwt"] = temp[1]
                data[accountid]["jwtExpiresAt"] = temp[2]
                data[accountid]["whoami"] = {}
                data[accountid]["whoami"] ["id"]  = temp[3]
                data[accountid]["whoami"] ["idType"] = temp[4]
                data[accountid]["whoami"] ["apiHosts"] ={}
                data[accountid]["whoami"] ["apiHosts"]["global"] = temp[5]
                data[accountid]["whoami"] ["apiHosts"]["dataRegion"] = temp[6]
                data[accountid]["whoami"] ["access_token"] = temp[7]

            return data
        else:
            return {}
    except:
        # raise Exception("Error geting status from db")
        return {}
print(get_store_status_update())