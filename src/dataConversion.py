import urllib.parse
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import APIKeyHeader
from fastapi.params import Body, Form
from pathlib import PurePath
import xmltodict
import json
import secrets
import dotenv
import os
import requests
import xml.sax
import urllib

#load secrets from environemnt variables defined in deployement
dotenv.load_dotenv(PurePath(__file__).with_name('.env'))

#assign environment variables to globals
API_KEY = os.getenv('API_KEY')
URLDECODE_DEFAULT_FWD_URL = os.getenv('WEBHOOK')
DEFAULT_FORWARDING_URL = "DEFAULT_FORWARDING_URL"
DEFAULT_AUTH_TYPE = "DEFAULT_AUTH_TYPE"
DEFAULT_HEADER_KEY= "DEFAULT_HEADER_KEY"
DEFAULT_AUTH = "DEFAULT_AUTH"


#init app - rename with desired app name
app = FastAPI()

#init key for auth
api_key = APIKeyHeader(name='API-Key')

#auth key
def authorize(key: str = Depends(api_key)):
    if not secrets.compare_digest(key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid token')

def is_xml_formatting(data: str):
    handler = xml.sax.ContentHandler()
    try:
        xml.sax.parseString(data, handler)
        return True
    except Exception as e:
        return False

def clean_keys(dict):
    pass

#sample post
@app.post('/xml2json', dependencies=[Depends(authorize)])
def xml_to_json(xmlData: str = Form(None),
                preserveXMLMeta: bool = Form(True),
                forward: bool = Form(True),
                fwdEndpoint: str = Form(DEFAULT_FORWARDING_URL),
                fwdAuthType: str = Form(DEFAULT_AUTH_TYPE),
                fwdHeaderKey: str = Form(DEFAULT_HEADER_KEY),
                fwdAuth: str = Form(DEFAULT_AUTH)):
    #Steps:
    #1. Validate valid xml
    if is_xml_formatting(xmlData):
        #2. dump xml into dict with xmltodict\
        xmlDict = xmltodict.parse(xmlData)
        #3. load dict into json
        if not preserveXMLMeta:
            xmlDict = clean_keys(xmlDict)
        #4. clean json if neccissary
        #5. forward json payload to given endpoint, default serviceNow
        if forward:
            if fwdAuthType == 'Token':
                header = {
                    fwdHeaderKey : fwdAuth
                }
            elif fwdAuthType == "Basic":
                header = {
                    fwdHeaderKey : fwdAuth
                }
            else:
                header = {}
            try:
                response = requests.post(fwdEndpoint, json=xmlDict, headers=header)
                if response.status_code == 200:
                    return {'Msg' : 'json data successfully forwarded to forward api',
                            'data': xmlDict}
                else:
                    return {'Error': f'Problem with forward api: {response.status_code}'}
            except Exception as e:
                return {'Error' : f'Provided or default endpoint request failed {e}'}
        else:
            return xmlDict
    else:
        return {'Error': 'Please provide valid xml data'}


@app.post('/prtg_urldecode', response_model=None)
def prtg_urldecode(body: str=Body(...)):
    url_decode_body = urllib.parse.unquote(body)
    split_key = url_decode_body.split('&')
    if not secrets.compare_digest(split_key[1], API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid token')
    else:
        first_replace = split_key[0].replace('"', "'")
        sec_replace = first_replace.replace("''''", '"')
        header = {'Content-Type' : 'application/json'}
        requests.post(URLDECODE_DEFAULT_FWD_URL, sec_replace, headers=header)
        return json.loads(sec_replace)