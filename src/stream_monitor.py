from src.logger import logger
import sys
from datetime import datetime, timezone
from src.utils import Utils
import re
from src.nexus_api import NexusAPI

class StreamMonitor:
    @staticmethod
    def parse_log(log_str):
        log_pattern = re.compile(
            r'(?P<datetime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(?P<level>\w+)\s+(?P<data>.+)'
        )
        match = log_pattern.match(log_str)
        
        if match:
            return {
                'Event Datetime': Utils.normalize_date(match.group("datetime")),
                'Event Level': match.group("level"),
                'Event Data': match.group("data")
            }
        
        else:
            return None

    @staticmethod
    def extract_cpu_sets(text):
        cpu_sets = re.findall(r'CpuSet\((.*?)\)', text)
        split_values = []
        for cpu_set in cpu_sets:
            split_values.extend(cpu_set.split(','))
        return split_values

    @staticmethod
    def parse_event(log, name):
        try:

            event = {
                'Event Name': None,
                'Event Type': None,
                'Event Level': log["Event Level"],
                'Event Datetime': log["Event Datetime"],
                'Event Source': name,
                'Event Data': None
            }

            if 'Connecting to node RPC url' in log['Event Data']:
                event['Event Name'] = 'Register RPC URL'
                event['Event Type'] = 'Farmer'
                pattern = r'ws://([^ ]+)'
                match = re.search(pattern, log['Event Data'])
                if match:
                    rpc_url = match.group(1)
                    event['Event Data'] = {
                        'RPC URL': rpc_url
                    }
                    # logger.info(event)

            if 'l3_cache_groups' in log['Event Data']:
                event['Event Name'] = 'Detecting L3 Cache Groups'
                event['Event Type'] = 'Farmer'
                pattern = r'l3_cache_groups=(\d+)'
                match = re.search(pattern, log['Event Data'])
                if match:
                    l3_cache_groups_value = match.group(1)
                    event['Event Data'] = {
                        'L3 Cache Groups': l3_cache_groups_value
                    }
                    # logger.info(event)

            if 'plotting_thread_pool_core_indices' in log['Event Data']:
                event['Event Name'] = 'Preparing Plotting Thread Pools'
                event['Event Type'] = 'Farmer'

                plotting_pattern = r'plotting_thread_pool_core_indices=\[(.*?)\]'
                replotting_pattern = r'replotting_thread_pool_core_indices=\[(.*?)\]'

                # Search and extract the values for plotting_thread_pool_core_indices
                plotting_match = re.search(plotting_pattern, log['Event Data'])
                plotting_values = []
                if plotting_match:
                    plotting_values = StreamMonitor.extract_cpu_sets(plotting_match.group(1))

                # Search and extract the values for replotting_thread_pool_core_indices
                replotting_match = re.search(replotting_pattern, log['Event Data'])
                replotting_values = []
                if replotting_match:
                    replotting_values = StreamMonitor.extract_cpu_sets(replotting_match.group(1))

                event['Event Data'] = {
                    'Plotting CPU Sets': plotting_values,
                    'Replotting CPU Sets': replotting_values
                }
                
            if 'Checking plot cache contents' in log['Event Data']:
                event['Event Name'] = 'Checking Plot Cache Contents'
                event['Event Type'] = 'Farmer'
                event['Event Data'] = {
                    'Status': 'Checking Plot Cache Contents'
                }

            if 'Finished checking plot cache contents' in log['Event Data']:
                event['Event Name'] = 'Finished Checking Plot Cache Contents'
                event['Event Type'] = 'Farmer'
                event['Event Data'] = {
                    'Status': 'Finished Checking Plot Cache Contents'
                }

            if 'Benchmarking faster proving method' in log['Event Data']:
                event['Event Name'] = 'Benchmarking Proving Method'
                event['Event Type'] = 'Farm'
                event['Event Data'] = {
                    'Status': 'Benchmarking Proving Method'
                }

            if 'fastest_mode' in log['Event Data']:
                event['Event Name'] = 'Found Fastest Mode'
                event['Event Type'] = 'Farm'
                pattern = r"\{farm_index=(\d+)\}.*fastest_mode=(\w+)"
                match = re.search(pattern, log['Event Data'])

                if match:
                    event['Event Data'] = {
                        'Farm Index': match.group(1),
                        'Fastest Mode': match.group(2)
                    }
                    # logger.info(event)

            if 'ID:' in log['Event Data']:
                event['Event Name'] = 'Register Farm ID'
                event['Event Type'] = 'Farm'
                # Define the regex patterns
                farm_index_pattern = r'farm_index=(\d+)'
                id_pattern = r'ID:\s+(\S+)'

                # Search for the farm_index value
                farm_index_match = re.search(farm_index_pattern, log['Event Data'])
                farm_index_value = farm_index_match.group(1) if farm_index_match else None

                # Search for the ID value
                id_match = re.search(id_pattern, log['Event Data'])
                farm_id_value = id_match.group(1) if id_match else None

                event['Event Data'] = {
                    'Farm Index': farm_index_value,
                    'Farm ID': farm_id_value
                }
                # logger.info(event)

            if 'Genesis hash:' in log['Event Data']:
                event['Event Name'] = 'Register Genesis Hash'
                event['Event Type'] = 'Farm'

                # Define the regex patterns
                farm_index_pattern = r'farm_index=(\d+)'
                genesis_hash_pattern = r'Genesis hash:\s+(0x\S+)'

                # Search for the farm_index value
                farm_index_match = re.search(farm_index_pattern, log['Event Data'])
                farm_index_value = farm_index_match.group(1) if farm_index_match else None

                # Search for the Genesis hash value
                genesis_hash_match = re.search(genesis_hash_pattern, log['Event Data'])
                genesis_hash_value = genesis_hash_match.group(1) if genesis_hash_match else None

                event['Event Data'] = {
                    'Farm Index': farm_index_value,
                    'Genesis Hash': genesis_hash_value
                }
                # logger.info(event)

            if 'Public key:' in log['Event Data']:
                event['Event Name'] = 'Register Public Key'
                event['Event Type'] = 'Farm'

                # Define the regex patterns
                farm_index_pattern = r'farm_index=(\d+)'
                public_key_pattern = r'Public key:\s+(0x[0-9a-fA-F]+)'

                # Search for the farm_index value
                farm_index_match = re.search(farm_index_pattern, log['Event Data'])
                farm_index_value = farm_index_match.group(1) if farm_index_match else None

                # Search for the Public key value
                public_key_match = re.search(public_key_pattern, log['Event Data'])
                public_key_value = public_key_match.group(1) if public_key_match else None


                event['Event Data'] = {
                    'Farm Index': farm_index_value,
                    'Public Key': public_key_value
                }
                # logger.info(event)

            if 'Allocated space:' in log['Event Data']:
                event['Event Name'] = 'Register Allocated Space'
                event['Event Type'] = 'Farm'
                pattern = r'farm_index=(\d+).*Allocated space:\s+([\d.]+)\s+(GiB|TiB|GB|TB)\s+\(([\d.]+)\s+(GiB|TiB|GB|TB)\)'
                match = re.search(pattern, log['Event Data'])

                if match:
                    if match.group(3) == 'TiB':
                        allocated_gib = float(match.group(2)) * 1024
                    else:
                        allocated_gib = float(match.group(2))

                    event['Event Data'] = {
                        'Farm Index': int(match.group(1)),
                        'Farm Allocated Space': allocated_gib                    
                    }
                    # logger.info(event)

            if 'Directory:' in log['Event Data']:
                event['Event Name'] = 'Register Directory'
                event['Event Type'] = 'Farm'

                pattern = r'farm_index=(\d+).*Directory:\s+(.+)'
                match = re.search(pattern, log['Event Data'])
                if match:
                    event['Event Data'] = {
                        'Farm Index': int(match.group(1)),
                        'Farm Directory': match.group(2)
                    }

                    # logger.info(event)

            if 'Collecting already plotted pieces' in log['Event Data']:
                event['Event Name'] = 'Collecting Plotted Pieces'
                event['Event Type'] = 'Farmer'
                event['Event Data'] = {
                    'Status': 'Collecting Plotted Pieces'
                }

            if 'Finished collecting already plotted pieces successfully' in log['Event Data']:
                event['Event Name'] = 'Finished Collecting Plotted Pieces'
                event['Event Type'] = 'Farmer'
                event['Event Data'] = {
                    'Status': 'Finished Collecting Plotted Pieces'
                }

            if 'Initializing piece cache' in log['Event Data']:
                event['Event Name'] = 'Initializing Piece Cache'
                event['Event Type'] = 'Farmer'
                event['Event Data'] = {
                    'Status': 'Initializing Piece Cache'
                }

            if 'Synchronizing piece cache' in log['Event Data']:
                event['Event Name'] = 'Syncronizing Piece Cache'
                event['Event Type'] = 'Farmer'
                event['Event Data'] = {
                    'Status': 'Syncronizing Piece Cache'
                }

            if 'Piece cache sync' in log['Event Data']:
                event['Event Name'] = 'Piece Cache Sync'
                event['Event Type'] = 'Farmer'

                pattern = r'Piece cache sync (\d+\.\d+)% complete'
                match = re.search(pattern, log['Event Data'])

                if match:
                    event['Event Data'] = {
                        'Status': 'Syncronizing Piece Cache',
                        'Piece Cache Percent': float(match.group(1))
                    }
                    # logger.info(event)

            if 'Finished piece cache synchronization' in log['Event Data']:
                event['Event Name'] = 'Finished Piece Cache Syncronization'
                event['Event Type'] = 'Farmer'
                event['Event Data'] = {
                    'Status': 'Finished Piece Cache Syncronization',
                    'Piece Cache Percent': 100.00
                }
                
            if 'Plotting sector' in log['Event Data']:
                event['Event Name'] = 'Plotting Sector'
                event['Event Type'] = 'Farm'

                pattern = r'farm_index=(\d+).*?(\d+\.\d+)% complete.*?sector_index=(\d+)'      
                match = re.search(pattern, log['Event Data'])
                if match:
                    event['Event Data'] = {
                        'Farm Index': int(match.group(1)),
                        'Plot Percentage': float(match.group(2)),
                        'Plot Current Sector': int(match.group(3)),
                        'Plot Type': 'Plot',
                        'Status': 'Plotting Sector'
                    }
                    # logger.info(event)

            if 'Successfully signed reward hash' in log['Event Data']:
                event['Event Name'] = 'Signed Reward Hash'
                event['Event Type'] = 'Farm'
                pattern = r'farm_index=(\d+).*hash\s(0x[0-9a-fA-F]+)'
                match = re.search(pattern, log['Event Data'])
                event['Event Data'] = {
                    'Farm Index': match.group(1),
                    'Reward Hash': match.group(2),
                    'Reward Type': 'Reward'
                }
                # logger.info(event)

            if 'Received invalid piece from peer piece_index' in log['Event Data']:
                event['Event Name'] = 'Invalid Piece from Peer'
                event['Event Type'] = 'Farmer'
                event['Event Data'] = {
                    'Log': log['Event Data']
                }

            if 'Initial plotting complete' in log['Event Data']:
                event['Event Name'] = 'Initial Plotting Complete'
                event['Event Type'] = 'Farm'
                pattern = r"farm_index=(\d+)"
                match = re.search(pattern, log['Event Data'])

                if match:
                    event['Event Data'] = {
                        'Farm Index': int(match.group(1)),
                        'Plot Percentage': 100,
                        'Plot Current Sector': None,
                        'Plot Type': 'Plot',
                        'Status': 'Farming'
                    }

            if 'Replotting sector' in log['Event Data']:
                event['Event Name'] = 'Replotting Sector'
                event['Event Type'] = 'Farm'
                pattern = r'farm_index=(\d+).*?(\d+\.\d+)% complete.*?sector_index=(\d+)'      
                match = re.search(pattern, log['Event Data'])
                if match:
                    event['Event Data'] = {
                        'Farm Index': int(match.group(1)),
                        'Plot Percentage': float(match.group(2)),
                        'Plot Current Sector': int(match.group(3)),
                        'Plot Type': 'Replot',
                        'Status': 'Replotting Sector'
                    }
                    # logger.info(event)

            if 'Replotting complete' in log['Event Data']:
                event['Event Name'] = 'Replotting Complete'
                event['Event Type'] = 'Farm'
                pattern = r"farm_index=(\d+)"
                match = re.search(pattern, log['Event Data'])

                if match:
                    event['Event Data'] = {
                        'Farm Index': int(match.group(1)),
                        'Plot Percentage': 100,
                        'Plot Current Sector': None,
                        'Plot Type': 'Replot',
                        'Status': 'Farming'
                    }

            if 'Failed to send solution' in log['Event Data']:
                event['Event Name'] = 'Failed to Send Solution'
                event['Event Type'] = 'Farm'

                pattern = r"farm_index=(\d+)"
                match = re.search(pattern, log['Event Data'])

                if match:
                    event['Event Data'] = {
                        'Farm Index': int(match.group(1)),
                        'Reward Hash': None,
                        'Reward Type': 'Failed'
                    }
                
            if not event['Event Name']: return None
            else: return event
        
        except Exception as e:
            logger.error(f"Error in parse_event {log}:", exc_info=e)
    
    @staticmethod
    def monitor_stream(container_data, docker_client, stop_event, nexus_url):
        container = docker_client.containers.get(container_data['Container ID'])

        if not container:
            logger.error('Unable to get container. Fatal')
            sys.exit(1)

        while not stop_event.is_set():
            try:
                container.reload()
                if container.status != 'running':
                    logger.warn(f"Container must be running, current status: {container.status}")
                    stop_event.wait(30)
                    continue

                response = NexusAPI.get_events(nexus_url, container_data['Container Name'])
                if len(response.get('data')) > 0:
                    logger.info(response.get('data')[0].get('event_datetime'))
                    start = datetime.strptime(response.get('data')[0].get('event_datetime'), "%Y-%m-%d %H:%M:%S")
                else: 
                    start = datetime.min.replace(tzinfo=timezone.utc)

                generator = container.logs(since=start, stdout=True, stderr=True, stream=True)
                for log in generator:
                    try:
                        if stop_event.is_set():
                            break

                        parsed_log = StreamMonitor.parse_log(log.decode('utf-8').strip())
                        if not parsed_log:
                            # logger.warn(f"Unable to parse log: {log}")
                            continue

                        event = StreamMonitor.parse_event(parsed_log, container_data['Container Name'])
                        if not event:
                            continue

                        created = NexusAPI.create_event(nexus_url, event)

                        if not created:
                            continue
                        
                        logger.info(created)

                    except Exception as e:
                        logger.error("Error in generator:", exc_info=e)

            except Exception as e:
                logger.error("Error in monitor_stream:", exc_info=e)