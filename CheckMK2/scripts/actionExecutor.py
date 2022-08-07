import argparse
import json
import logging
import os
import sys
import time
import zipfile

import html
import requests
from requests.auth import HTTPBasicAuth

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)
parser.add_argument('-api_url', '--api_url', help='Check_mk Server URL', required=False)
parser.add_argument('-user', '--user', help='User', required=True)
parser.add_argument('-password', '--password', help='Password', required=True)
parser.add_argument('-timeout', '--timeout', help='HTTP Timeout', required=False)
parser.add_argument('-expire_acknowledgement_after', '-expire_acknowledgement_after',
                    help='Removes acknowledgement after given value (in minutes.)', required=False)
parser.add_argument('-insecure', '--insecure', help='Skip verifying SSL certificate', required=False)

args = vars(parser.parse_args())

queue_message_string = args['queuePayload']
queue_message = json.loads(queue_message_string)

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])


DIR_PATH = os.path.dirname(os.path.realpath(__file__))

def parse_field(key, mandatory):
    variable = queue_message[key]
    if not variable.strip():
        variable = args[key]
    if mandatory and not variable:
        raise ValueError(LOG_PREFIX + " Skipping action, Mandatory conf item '" + key +
                         "' is missing. Check your configuration file.")


def post_to_checkmkApi(url_path, content_map):
    url = args["api_url"] + url_path
    logging.debug(LOG_PREFIX + " Posting to Check_mk. Url " + url + ", content: " + str(content_map))

    headers = {
        "Accept": "application/json"
    }

    verify_ssl = verify=False if args['insecure'] == 'true' else True
    response = requests.post(url, json=content_map, timeout=HTTP_TIMEOUT,
                             auth=auth_token, headers=headers,
                             verify=verify_ssl)

    if response.status_code == 200:
        logging.info(LOG_PREFIX + " Successfully executed at Check_mk.")
        logging.debug(LOG_PREFIX + " Check_mk response: " + str(response.content))
    else:
        logging.warning(LOG_PREFIX + " Could not execute at Check_mk. Check_mk Response: " + str(response.content))


def send_acknowledge_request(content_map):
    source = queue_message["source"]
    if source and source["name"].lower().startswith("checkmk"):
        logging.warning("OpsGenie alert is already acknowledged by checkmk. Discarding!!!")
    else:
        content_map["notify"] = False
        content_map["sticky"] = False
        content_map["persistent"] = False
        content_map["comment"] = "Acknowledged by " + alert["username"] + " via OpsGenie"

        if content_map["acknowledge_type"] == "host":
            url_path = "/api/1.0/domain-types/acknowledge/collections/host"
            
            post_to_checkmkApi(url_path, content_map)

        elif content_map["acknowledge_type"] == "service":
            url_path = "/api/1.0/domain-types/acknowledge/collections/service"

            post_to_checkmkApi(url_path, content_map)

        


def parse_from_details(key):
    if key in alert_from_opsgenie["details"].keys():
        return alert_from_opsgenie["details"][key]
    return ""





def main():
    global LOG_PREFIX
    global HTTP_TIMEOUT
    global alert
    global auth_token
    global alert_from_opsgenie

    action = queue_message["action"]
    alert = queue_message["alert"]

    LOG_PREFIX = '[' + action + ']'
    username = args["user"]
    password = args['password']
    HTTP_TIMEOUT = args['timeout']
    auth_token = "Bearer " + username + password

    if not HTTP_TIMEOUT:
        HTTP_TIMEOUT = 30000
    else:
        HTTP_TIMEOUT = int(HTTP_TIMEOUT)

    logging.debug("Username: " + username)

    get_alert_url = args['opsgenieUrl'] + "/v2/alerts/" + alert["alertId"] + "?alertIdentifierType=id"

    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json",
        "Authorization": "GenieKey " + args['apiKey']
    }

    response = requests.get(get_alert_url, headers=headers, timeout=HTTP_TIMEOUT)

    content = response.json()
    if "data" in content.keys():
        alert_from_opsgenie = content["data"]
        host = parse_from_details("host_name")
        service = parse_from_details("service_desc")

        content_map = {}
        is_service_alert = service.strip() != ""

        if is_service_alert:
            content_map["type"] = "service"
            content_map["host_name"] = host 
            content_map["service_description"] = service
        else:
            content_map["type"] = "host"
            content_map["host_name"] = host

        if action == "Acknowledge":
            send_acknowledge_request(content_map)
    else:
        logging.warning(
            LOG_PREFIX + " Alert with id " + alert["alertId"] + " does not exist in Opsgenie. It is probably deleted.")


if __name__ == '__main__':
    main()
