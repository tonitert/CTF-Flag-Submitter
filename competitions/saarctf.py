from pwn import *
from submitter.flag_handler import SubmissionStatus
import requests

display_name = 'saarCTF'

# Regex that can be used to detect valid flags
flag_format = 'SAAR\\{[A-Za-z0-9\\+/=]{32}\\}'

# Round duration in seconds
round_duration = 120

# Flag lifetime in rounds
flag_lifetime = 10

# The ID (i.e. IP) of our team, this will mean that no exploits will be ran against this team.
our_team_id = '10.32.135.2'  # Set this to your team's IP, e.g., '10.32.2.2'

# The ID (i.e. IP) of the NOP team, this will mean that any local runs will automatically target this team,
# unless this value is set to `None`.
nop_team_id = '10.32.1.2'

# If enabled, this will also allow targeting this team which would be useful if there's no dedicated NOP team.
run_exploits_on_nop_team = False

# If the submission server supports bulk submissions, prefer that method.
bulk_submit_supported = False

# The preferred amount of flags to submit at once per flag submission
bulk_chunk_size = 32

def get_data():
    # Fetch data from the saarCTF API endpoint
    try:
        response = requests.get('https://scoreboard.ctf.saarland/api/attack.json', timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Transform the API response to the expected format
        teams = {}
        for team in data.get('teams', []):
            teams[team['ip']] = team['name']
        
        # Extract services from flag_ids
        services = {}
        flag_ids_by_ip = {}
        
        for service_id, service_data in data.get('flag_ids', {}).items():
            services[service_id] = {'name': service_id}
            
            # Transform flag_ids structure: service -> ip -> tick -> flag_ids
            # to: ip -> service -> tick -> flag_ids
            for ip, ticks in service_data.items():
                if ip not in flag_ids_by_ip:
                    flag_ids_by_ip[ip] = {}
                flag_ids_by_ip[ip][service_id] = ticks
        
        return {
            'teams': teams,
            'services': services,
            'flag_ids': flag_ids_by_ip
        }
    except Exception as e:
        print(f"Error fetching data from API: {e}")
        return {
            'teams': {},
            'services': {},
            'flag_ids': {}
        }

def get_scoreboard_data():
    # Alternatively, return an empty dict if you don't want to implement this/use monitoring
    return {
    #     'tick': 0,
    #     'scoreboard': [
    #         {
    #             'team_ip': '127.0.0.1',
    #             'team_name': 'No place like home!',
    #             'points': 1337,
    #             'rank': 1,
    #             'services': [
    #                 {
    #                     'service_id': 'service_1',
    #                     'offense': 0,
    #                     'defense': 0,
    #                     'sla': 0,
    #                     'gathered_flags': 1337,
    #                     'lost_flags': 0,
    #                     'online': True,
    #                 }
    #             ],
    #         }
    #     ]
    }

conn = None
def init_submitter():
    global conn

    conn = remote('submission.ctf.saarland', 31337)
    conn.recv(4096, timeout=3)

def submit_flag(flag):
    global conn

    print('Submitting flag %s.' % flag)
    conn.send(flag.encode() + b'\n')
    result = conn.recvuntil(b'\n').decode().strip()

    # Parse the response according to saarCTF protocol
    # Responses start with [OK], [ERR], or [OFFLINE]
    if result.startswith('[OK]'):
        return SubmissionStatus.Ok, result
    elif result.startswith('[OFFLINE]'):
        return SubmissionStatus.Err, result
    elif result.startswith('[ERR]'):
        # Map specific error messages to appropriate status codes
        if 'Already submitted' in result:
            return SubmissionStatus.Dup, result
        elif 'your own flag' in result:
            return SubmissionStatus.Own, result
        elif 'Expired' in result:
            return SubmissionStatus.Old, result
        elif 'Invalid' in result:
            return SubmissionStatus.Inv, result
        else:
            return SubmissionStatus.Err, result
    else:
        # Unknown response format
        return SubmissionStatus.Err, result

def submit_flags(flags):
    # Similar output to submit_flag(), but should be wrapped in a dict with the format of 'flag_id': (SubmissionStatus.{...}, raw)
    pass
