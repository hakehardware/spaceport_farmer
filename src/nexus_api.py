from src.logger import logger
from datetime import datetime
import requests
import sys
import json
import time

class NexusAPI:
    @staticmethod
    def update_container(base_url, event):
        logger.info(f"Updating Container @ {base_url}")
        logger.info(f"Event Data: {event}")

    @staticmethod
    def upsert_entity(base_url, entity, event):
        local_url = f"{base_url}/upsert/{entity}"
        response = NexusAPI.push(local_url, event)
        if response.status_code < 300: return response.json()
        else: return False

    def create_event(base_url, event):
        local_url = f"{base_url}/insert/event"
        response = NexusAPI.push(local_url, event)
        if response.status_code == 201: return response.json()
        else: return False

    def get_events(base_url, name):
        local_url = f"{base_url}/get/events"
        response = requests.get(local_url)
        json_data = response.json()

        if response.status_code < 300:
            return json_data
        else:
            logger.error(f"Error getting events {json_data.get('message')}")
            return None
        
    def get_latest_events(base_url, name):
        local_url = f"{base_url}/get/events?event_source={name}&event_type=Farmer"
        response = requests.get(local_url)
        json_data = response.json()

        if response.status_code < 300:
            return json_data
        else:
            logger.error(f"Error getting events {json_data.get('message')}")
            return None

    def push(local_url, event):
        max_retries = 10
        retries = 0

        while True:
            try:
                response = requests.post(local_url, json=event)
                if response.status_code >= 300:
                    logger.error(response.json())
                    time.sleep(10)
                    
                return response

            except Exception as e:
                if retries == max_retries:
                    logger.error('Max retries reached. Exiting...')
                    sys.exit(1)
                retries+=1
                logger.error(f"Retries: {retries}, Max allowed: {max_retries}")
                time.sleep(1)