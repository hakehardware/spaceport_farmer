from src.logger import logger

class NexusAPI:
    @staticmethod
    def update_container(base_url, event):
        logger.info(f"Updating Container @ {base_url}")
        logger.info(f"Event Data: {event}")