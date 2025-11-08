#!/bin/bash
###################################################################################################
#  DESCRIPTION:                                                                                   #
#  This script was designed to be executed by a NagiosXI Event Handler to run Semaphore Tasks     #
#                                                                                                 #
#   Company: OsbornePro LLC.                                                                      #
#   Website: https://osbornepro.com                                                               #
#   Author: Robert H. Osborne                                                                     #
#   Contact: rosborne@osbornepro.com                                                              #
###################################################################################################
SEMAPHORE_SERVER_FQDN="semaphore.domain.com"
USAGE="
#===============================================#
#   ___     _                      ___          #
#  / _ \ __| |__  ___ _ _ _ _  ___| _ \_ _ ___  #
# | (_) (_-< '_ \/ _ \ '_| ' \/ -_)  _/ '_/ _ \ #
#  \___//__/_.__/\___/_| |_||_\___|_| |_| \___/ #
#-----------------------------------------------#
#      If you can't beat 'em, tech 'em!         #
#===============================================#

SYNTAX:
    $0 [-h] -H <string hostaddress> -P <int project_id> -T <int template_id> -t <string target_host> -s <string service_name> -d <string drive_letter>


DESCRIPTION:
    This script is for executing Semaphore Tasks via Nagios Event Handlers

REQUIREMENTS:
    1.) You should have local Semaphore admin account credentials to authenticate to Semaphore
    2.) Define $USER#$ variables in your /usr/local/nagios/etc/resource.cfg file containing the Sempahore username and password 
    3.) Create a command in Nagios that runs this script, passing along the $USER$ variables for the -A and -X parameters in this script
         $USER1$/check_ncpa.py 

CONTACT INFORMATION
    Company: Vinebrook Technology Inc.
    Website: https://www.vinebrooktechnology.com
    Author: Robert Osborne (Vinebrook Technology)
    Contact: rosborne@vinebrooktech.com


USAGE:
    $0 [-h] -H <string hostaddress> -A USER31 -X USER32 -P <int project_id> -T <int template_id> -t <string target_host> -s <string service_name> -S SERVICESTATETYPE -a SERVICESTATE -o SERVICEOUTPUT -g HOSTGROUPNAMES -d <string drive_letter>

OPTIONS:
    -h : Displays the help information for the command
    -H : The host address (usually passed from Nagios as \$HOSTADDRESS\$)
    -A : The user to auth with
    -X : The password to auth with
    -P : The project ID
    -T : The template ID
    -t : The target host
    -s : The service name
    -S : The service state type
    -a : The service state
    -o : The service output
    -g : The host group names
    -d : The drive letter


EXAMPLES:
    $0 -h
    # This example returns the help information on how to use this command

    $0 -H 192.168.1.100 -P 1 -T 94 -t server01 -S HARD -a OK
    # This example runs task 94 in project 1 against target_host server01

    $0 -H 192.168.1.100 -P 1 -T 94 -t server01 -s wuauserv -S HARD -a DOWN
    # This example runs task 95 in project 1 against target_host server01 plugging in the variable name service_name with wuauserv

    $0 -H 192.168.1.100 -P 1 -T 94 -t server01 -d c -S SOFT -a WARNING
    # This example runs task 95 in project 1 against target_host server01 plugging in the variable name drive_letter with c

"

# Log file location
LOG_FILE="/tmp/run-ansible-playbook.log"

# File to temporarily store the session cookie
COOKIE_FILE="/dev/shm/.semaphore-cookie"

# Function to print help message
function print_usage {
    /bin/printf "$USAGE\n" >&2
    exit 3
}  # End function print_usage

# Function to log messages
log_message() {
    /bin/echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

log_message "[-] Script execution started."

# Parse command-line arguments
while getopts "hH:A:X:P:T:t:s:S:a:o:g:d:" OPTION; do
    case $OPTION in
        h)
            print_usage
            ;;
        H)
            HOSTADDRESS="${OPTARG,,}"
            ;;
        A)
            AUTHUSERNAME="$OPTARG"
            ;;
        X)
            AUTHPASSWORD="$OPTARG"
            ESCAPED_PASSWORD=$(/bin/echo "${AUTHPASSWORD}" | /bin/sed 's/\\/\\\\/g')
            ;;
        P)
            PROJECT_ID="$OPTARG"
            ;;
        T)
            TEMPLATE_ID="${OPTARG}"
            ;;
        t)
            TARGET_HOST="${OPTARG%%.*}"
            TARGET_HOST="${TARGET_HOST,,}"
            ;;
        s)
            SERVICE_NAME="$OPTARG"
            ;;
        S)
            SERVICE_STATE_TYPE="$OPTARG"
            ;;
        a)
            SERVICE_STATE="$OPTARG"
            ;;
        o)
            SERVICE_OUTPUT="$OPTARG"
            ;;
        g)
            HOST_GROUP_NAMES="$OPTARG"
            ;;
        d)
            DRIVE_LETTER="$OPTARG"
            ;;
        *)
            print_usage
            ;;
    esac
done

# Set a default value for SERVICE_STATE_TYPE if not defined
SERVICE_STATE_TYPE=${SERVICE_STATE_TYPE:-"UNDEFINED"}

# Debug log to confirm value
log_message "[-] SERVICE_STATE_TYPE is '${SERVICE_STATE_TYPE}'"

# NEW: Exit early if the service state is OK
if [ "${SERVICE_STATE,,}" == "ok" ]; then
    log_message "[-] Service state is OK. Exiting without triggering playbook."
    exit 0
fi
if [ "${SERVICE_STATE,,}" == "OK" ]; then
    log_message "[-] Service state is OK. Exiting without triggering playbook."
    exit 0
fi

# Conditional check
if [ "$SERVICE_STATE_TYPE" != "HARD" ] && [ ${#SERVICE_STATE_TYPE} -lt 2 ]; then
    log_message "[-] Service state type is not HARD, not defined, or length is less than 2. Exiting task for ${TARGET_HOST}."
    exit 0
fi

log_message "[-] Received arguments: HOSTADDRESS=$HOSTADDRESS, PROJECT_ID=$PROJECT_ID, TEMPLATE_ID=$TEMPLATE_ID, TARGET_HOST=$TARGET_HOST, SERVICE_NAME=$SERVICE_NAME, DRIVE_LETTER=$DRIVE_LETTER"
# Check if mandatory arguments are provided
if [ -z "$HOSTADDRESS" ] || [ -z "$PROJECT_ID" ] || [ -z "$TEMPLATE_ID" ] || [ -z "$TARGET_HOST" ]; then
    log_message "[x] Required arguments are missing."
    print_usage
fi

# Determine template ID based on freshness and host group, only if SERVICE_OUTPUT, SERVICE_STATE_TYPE, and HOST_GROUP_NAMES are defined
if [ -n "$SERVICE_OUTPUT" ] && [ -n "$SERVICE_STATE_TYPE" ] && [ -n "$HOST_GROUP_NAMES" ]; then
    if [[ "$SERVICE_STATE_TYPE" == "HARD" && "$SERVICE_OUTPUT" == *"No check result received"* ]]; then
        if [[ "${HOST_GROUP_NAMES,,}" == *"linux_servers"* ]]; then
            TEMPLATE_ID=19
        elif [[ "${HOST_GROUP_NAMES,,}" == *"windows-servers"* ]]; then
            TEMPLATE_ID=28
        else
            log_message "[x] Host group does not match expected groups (linux_servers or windows-servers). Exiting."
            exit 1
        fi
        log_message "[!] Freshness issue detected. Template ID set to $TEMPLATE_ID based on host group."
    else
        log_message "[-] No freshness issue detected or not a HARD state. Using provided template ID: $TEMPLATE_ID."
    fi
else
    log_message "[-] SERVICE_OUTPUT, HOST_GROUP_NAMES, or SERVICE_STATE_TYPE not defined. Skipping freshness check."
fi

# Ensure TEMPLATE_ID is set
if [ -z "$TEMPLATE_ID" ]; then
    log_message "[x] TEMPLATE_ID is not set after evaluating host group names. Exiting."
    exit 1
fi

# Semaphore API URLs
SEMAPHORE_API_URL="https://${SEMAPHORE_SERVER_FQDN}/api"
LOGIN_URL="${SEMAPHORE_API_URL}/auth/login"
TOKENS_URL="${SEMAPHORE_API_URL}/user/tokens"
TRIGGER_TASK_URL="${SEMAPHORE_API_URL}/project/${PROJECT_ID}/tasks"
DELETE_TOKEN_URL="${SEMAPHORE_API_URL}/user/tokens"
TASK_LIST_URL="${SEMAPHORE_API_URL}/project/${PROJECT_ID}/tasks"

# Login to Semaphore and store the session cookie
LOGIN_RESPONSE=$(/bin/curl -s -k -c "$COOKIE_FILE" -XPOST \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json' \
     -d "{\"auth\": \"$AUTHUSERNAME\", \"password\": \"$ESCAPED_PASSWORD\"}" \
     "$LOGIN_URL")

if [ $? -ne 0 ]; then
    log_message "[x] Failed to log in to Semaphore. Response: $LOGIN_RESPONSE"
    exit 1
else
    log_message "[-] Logged in to Semaphore successfully."
fi

# Check for jq dependency
if ! command -v jq &>/dev/null; then
    log_message "[x] 'jq' command not found. Please install it to proceed."
    exit 1
fi

# Attempt to retrieve an existing token
ACCESS_TOKEN="null"
if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    # Generate a new token
    NEW_TOKEN_RESPONSE=$(/bin/curl -s -k -b "$COOKIE_FILE" -XPOST \
         -H 'Content-Type: application/json' \
         -H 'Accept: application/json' \
         "$TOKENS_URL")

    ACCESS_TOKEN=$(/bin/echo "$NEW_TOKEN_RESPONSE" | /bin/jq -r '.id')
    if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
        log_message "[x] Failed to generate a new access token."
        exit 1
    fi
fi

TASKS_RESPONSE=$(/bin/curl -s -k -H "Authorization: Bearer $ACCESS_TOKEN" "$TASK_LIST_URL")
if [ $? -ne 0 ]; then
    log_message "[x] Failed to retrieve tasks from Semaphore."
    exit 1
fi

TASK_COUNT=$(/bin/echo "$TASKS_RESPONSE" | /bin/jq '[.[] | select(.status == "pending" or .status == "running")] | length')
log_message "[-] Found $TASK_COUNT pending or running tasks."
if [ "$TASK_COUNT" -ge 4 ]; then
    log_message "[!] Too many tasks currently running or pending ($TASK_COUNT). Skipping execution."
    /bin/echo "Too many Semaphore tasks currently in progress. Exiting without executing new task."
    exit 0
fi

MATCHING_TASK_COUNT=$(echo $TASKS_RESPONSE | jq --arg targethost "$TARGET_HOST" --argjson templateid "$TEMPLATE_ID" '[.[] | select(.template_id == $templateid) | select(.params.limit|index($targethost)) | select(.status|IN("running","waiting","pending","queued"))]|length')
if [[ $MATCHING_TASK_COUNT -gt 0 ]]; then
    log_message "Found $MATCHING_TASK_COUNT running or pending task(s) matching this template and host. Skipping."
    exit 0
fi

# Construct JSON payload with required and optional parameters
PAYLOAD="{\"template_id\": ${TEMPLATE_ID}, \"debug\": false, \"dry_run\": false, \"diff\": false, \"limit\": \"${TARGET_HOST}\", \"message\": \"Executed by Nagios Event Handler\"}"
log_message "[-] Final payload constructed: ${PAYLOAD}"

# Trigger the task in Semaphore
TRIGGER_RESPONSE=$(/bin/curl -k -s -XPOST \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json' \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -d "$PAYLOAD" \
     "$TRIGGER_TASK_URL")

if [ $? -ne 0 ]; then
    log_message "[x] Failed to trigger the task in Semaphore. Response: ${TRIGGER_RESPONSE}"
    exit 1
else
    log_message "[-] Task triggered in Semaphore successfully. Response: ${TRIGGER_RESPONSE}"
fi

# Delete the access token after use
DELETE_RESPONSE=$(/bin/curl -s -k -XDELETE \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json' \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     "$DELETE_TOKEN_URL/$ACCESS_TOKEN")

if [ $? -ne 0 ]; then
    log_message "[x] Failed to delete the access token. Response: $DELETE_RESPONSE"
else
    log_message "[-] Access token deleted successfully."
fi

# Clean up by removing the cookie file
/bin/rm -rf "${COOKIE_FILE}"
log_message "[-] Cookie file removed."

log_message "[-] Script execution completed."
