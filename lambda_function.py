from cryptography.fernet import Fernet
import urllib
import time
import sys
import json
import requests
import datetime
import pytz
import os
import datetime
import os.path
from oauth2client.service_account import ServiceAccountCredentials
from googleapiclient.discovery import build
import httplib2
import boto3
from botocore.exceptions import ClientError
import dateutil.parser
from googleapiclient.errors import HttpError
from urllib.parse import urlencode, quote_plus
from twilio.rest import Client
from bs4 import BeautifulSoup
import uuid
from urllib.parse import parse_qs
import re
import copy
import phonenumbers

google_calendar_service = None
ddb_client = None
s3_client = None
base_cancellation_url = 'https://DOMAIN_NAME/cancelevent'
base_redirect_url = 'https://DOMAIN_NAME/r?c='
webhook_url = 'https://DOMAIN_NAME/webhook'
calendly_api_key = None
twilio_client = None
fernet = None
default_country_code = None

def readable_datetime(dt):
    return dt.strftime('%d %b %I:%M %p %Z')

# We do not fail if formatting num fails. 
# When trying to send message with wrong num to Twilio, sending message will fail and
# make the Google Calendar event red.
def try_format_phone_number(num):
    try:
        num = num.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')
        phone_num = None
        if num.startswith('+'):
            phone_num = phonenumbers.parse(num, None)
        else:
            phone_num = phonenumbers.parse(num, default_country_code)
        num = phonenumbers.format_number(phone_num, phonenumbers.PhoneNumberFormat.E164)
    except Exception as e:
        print('Failed to format phone number: ' + num)
        print(str(e))
    return num

def extract_cancellation_link(desc):
    desc = BeautifulSoup(desc, features="html.parser").get_text('\n')
    desc = desc.replace('\n', ' ')
    ind = desc.lower().find('cancel:')
    if ind == -1:
        return None
    link_start_ind = ind + 7
    desc = desc[link_start_ind:].strip()
    desc = desc + ' '
    ind = desc.find(' ')
    if ind == -1:
        return None
    desc = desc[:ind]
    return desc.strip()

def extract_reschedule_link(desc):
    desc = BeautifulSoup(desc, features="html.parser").get_text('\n')
    desc = desc.replace('\n', ' ')
    ind = desc.lower().find('reschedule:')
    if ind == -1:
        return None
    link_start_ind = ind + 11
    desc = desc[link_start_ind:].strip()
    desc = desc + ' '
    ind = desc.find(' ')
    if ind == -1:
        return None
    desc = desc[:ind]
    return desc.strip()

def extract_utm_content(desc):
    desc = BeautifulSoup(desc, features="html.parser").get_text('\n')
    utm_content = None
    idx = desc.lower().find('utm content:')
    if idx != -1:
        idx = desc.find('"', idx)
        utm_content = desc[(idx + 1):(desc.find('"', idx + 1))]
        if utm_content != '':
            utm_content = fernet.decrypt(utm_content.encode()).decode()
            utm_content = json.loads(utm_content)
        else:
            utm_content = None
    return utm_content

def get_cmd_from_description(cmd, desc):
    cmd = cmd.lower()
    lines = desc.splitlines()
    for line in lines:
        if line.lower().startswith('*' + cmd):
            return line
    return None

def update_cmd_in_description(cmd, val, desc):
    lines = desc.splitlines(True)
    new_desc = ''
    cmd_found = False
    skip_next_newline = False
    for line in lines:
        if skip_next_newline:
            skip_next_newline = False
            if line.strip() == '':
                continue
        if not line.lower().startswith('*' + cmd.lower()):
            new_desc += line
            continue
        cmd_found = True
        if val != None:
            new_desc += '*' + cmd + ': ' + val + '\n'
        else:
            skip_next_newline = True
    if not cmd_found:
        new_desc = ''
        if val != None:
            new_desc = '*' + cmd + ': ' + val + '\n\n'
        new_desc += desc
    return new_desc.lstrip('\n').rstrip('\n')

def get_event_colors():
    global google_calendar_service

    # Fetch calendar and event global color palette.
    colors = None
    try:
        colors = google_calendar_service.colors().get().execute()
    except Exception as e:
        print(str(e))
        return None

    green_color_id = None
    red_color_id = None
    green_color_max = 0.0
    red_color_max = 0.0
    for color_key in colors['event'].keys():
        color_hex = colors['event'][color_key]['background'][1:]
        red_color = int('0x' + color_hex[1:3], 0)
        green_color = int('0x' + color_hex[3:5], 0)
        blue_color = int('0x' + color_hex[5:7], 0)
        # Plus 1 is done to avoid divide by 0 error
        total_hue = red_color + green_color + blue_color + 1.0
        if red_color/total_hue > red_color_max:
            red_color_id = color_key
            red_color_max = red_color/total_hue
        if green_color/total_hue > green_color_max:
            green_color_id = color_key
            green_color_max = green_color/total_hue
    return {'green': green_color_id, 'red': red_color_id}

def msg_sent_callback(status, event, colors, calendar_id, reason = None):
    if colors != None:
        event = google_calendar_service.events().get(calendarId=calendar_id, eventId=event['id']).execute()
        desc = BeautifulSoup(event['description'], features="html.parser").get_text('\n')
        event['colorId'] = colors['green'] if status else colors['red']
        desc = update_cmd_in_description('Failed to send message', reason, desc)
        event['description'] = desc
        google_calendar_service.events().update(calendarId=calendar_id, eventId=event['id'], body=event).execute()

def is_event_cancelled(event):
    return event['status'] == 'cancelled' or event['summary'].lower().startswith('canceled')

def update_sync_token(prev_sync_token, sync_token, sync_token_id):
    global ddb_client

    sync_token = '' if sync_token == None else sync_token
    prev_sync_token = '' if prev_sync_token == None else prev_sync_token
    expr_attr_names = {'#sync_token': 'sync_token', '#ttl': 'ttl'}
    expr_attr_values = {':sync_token': {'S': sync_token}, ':prev_sync_token': {'S': prev_sync_token}, ':ttl': {'N': str(int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)).timestamp()))}}
    update_expr = 'SET #sync_token = :sync_token, #ttl = :ttl'
    cond_expr = 'attribute_not_exists(#sync_token) or #sync_token = :prev_sync_token'    
    ddb_client.update_item(TableName='GoogleEventManager-Metadata', Key={'hk': {'S': 'list_events_sync_token'}, 'rk': {'S': sync_token_id}}, UpdateExpression=update_expr, ExpressionAttributeValues=expr_attr_values, ExpressionAttributeNames=expr_attr_names, ConditionExpression=cond_expr)

def get_sync_token(sync_token_id):
    global ddb_client

    resp = ddb_client.get_item(TableName='GoogleEventManager-Metadata', Key={'hk': {'S': 'list_events_sync_token'}, 'rk': {'S': sync_token_id}})
    sync_token = resp['Item']['sync_token']['S'] if 'Item' in resp else None
    return sync_token if sync_token != '' else None
 
def list_events(calendar_id, only_modified_events, atleast_n_days):
  global google_calendar_service
  service = google_calendar_service
  
  now = datetime.datetime.now(datetime.timezone.utc)
  # For sync token to work correctly, list params should stay the same.
  # By truncating datetime to just the date, sync token will stay valid upto a day
  # On the next day, query params will change and sync token will be reset. 
  now = now.replace(hour=0, minute=0, second=0, microsecond=0)
  start_datetime = (now - datetime.timedelta(days=1)).isoformat()
  end_datetime = (now + datetime.timedelta(days=(atleast_n_days + 1))).isoformat()
  page_token = None
  sync_token_id = str(start_datetime) + '-' + str(end_datetime)
  sync_token = get_sync_token(sync_token_id) if only_modified_events else None
  prev_sync_token = sync_token

  all_events = []
  while True:
    try:
        if sync_token == None:
            sync_events = service.events().list(calendarId=calendar_id, timeMin=start_datetime, timeMax=end_datetime, singleEvents=True, showDeleted=True, maxResults=9999, pageToken=page_token, syncToken=sync_token).execute()
        else:
            sync_events = service.events().list(calendarId=calendar_id, pageToken=page_token, syncToken=sync_token).execute()
    except HttpError as e:
        if e.resp.status == 410:
            print('Sync token invalidated. Aborting this run')
            return {'events': [], 'prev_sync_token': prev_sync_token, 'sync_token': None, 'sync_token_id': sync_token_id}
        raise e

    events = []
    if sync_token == None:
        events = sync_events['items']
    else:
        # Syncing events can return partial event properties; only the ones modified.
        # Fetch full event image.
        for sync_event in sync_events['items']:
            try:
                event = service.events().get(calendarId=calendar_id, eventId=sync_event['id']).execute()
                events.append(event)
            except HttpError as e:
                print(str(sync_event))
                raise e

    all_events = all_events + events
    page_token = sync_events.get('nextPageToken')
    sync_token = sync_events.get('nextSyncToken')
    if not page_token:
      break
  return {'events': all_events, 'prev_sync_token': prev_sync_token, 'sync_token': sync_token, 'sync_token_id': sync_token_id}

def init_google_calendar_service():
  service_account_json = None
  with open('google-event-manager-service-account.json', 'r') as creds_f:
    service_account_json = json.load(creds_f)
  google_scopes = ['https://www.googleapis.com/auth/calendar.events', 'https://www.googleapis.com/auth/calendar', 'https://www.googleapis.com/auth/calendar.settings.readonly']
  credentials = ServiceAccountCredentials.from_json_keyfile_dict(service_account_json, google_scopes)

  # Create an httplib2.Http object to handle our HTTP requests and authorize
  # it with the Credentials.
  http = httplib2.Http()
  http = credentials.authorize(http)
  return build('calendar', 'v3', http=http)

def lambda_handler(event, context):
    global google_calendar_service
    global ddb_client
    global s3_client
    global calendly_api_key
    global twilio_client
    global fernet
    global default_country_code

    # Authenticate and construct service.
    if 'CALENDLY_API_KEY' not in os.environ:
        raise Exception('Environment variable CALENDLY_API_KEY not set')
    calendly_api_key = os.environ['CALENDLY_API_KEY']
    
    if 'CALENDLY_SCHEDULING_URL' not in os.environ:
        raise Exception('Environment variable CALENDLY_SCHEDULING_URL not set')
    calendly_scheduling_url = os.environ['CALENDLY_SCHEDULING_URL']

    if 'CALENDAR_ID' not in os.environ:
        raise Exception('Environment variable CALENDAR_ID not set')
    calendar_id = os.environ['CALENDAR_ID']

    if 'AWS_IAM_ACCESS_KEY_ID' not in os.environ:
        raise Exception('Environment variable AWS_IAM_ACCESS_KEY_ID not set')
    aws_access_key_id = os.environ['AWS_IAM_ACCESS_KEY_ID']

    if 'AWS_IAM_ACCESS_KEY_SECRET' not in os.environ:
        raise Exception('Environment variable AWS_IAM_ACCESS_KEY_SECRET not set')
    aws_access_key_secret = os.environ['AWS_IAM_ACCESS_KEY_SECRET']

    if 'AWS_REGION' not in os.environ:
        raise Exception('Environment variable AWS_REGION not set')
    aws_region = os.environ['AWS_REGION']

    ddb_client = boto3.client('dynamodb', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_access_key_secret, region_name=aws_region)
    s3_client = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_access_key_secret, region_name=aws_region)

    if 'S3_BUCKET' not in os.environ:
        raise Exception('Environment variable S3_BUCKET not set')
    s3_bucket = os.environ['S3_BUCKET']
    # Authenticate and construct service.
    google_calendar_service = init_google_calendar_service()

    if 'TWILIO_PHONE_NUMBER' not in os.environ:
        raise Exception('Environment variable TWILIO_PHONE_NUMBER not set')
    twilio_num = os.environ['TWILIO_PHONE_NUMBER']

    if 'TWILIO_ACCOUNT_SID' not in os.environ:
        raise Exception('Environment variable TWILIO_ACCOUNT_SID not set')
    twilio_sid = os.environ['TWILIO_ACCOUNT_SID']

    if 'TWILIO_AUTH_TOKEN' not in os.environ:
        raise Exception('Environment variable TWILIO_AUTH_TOKEN not set')
    twilio_token = os.environ['TWILIO_AUTH_TOKEN']

    twilio_client = Client(twilio_sid, twilio_token)

    if 'ACTION' not in os.environ:
        raise Exception('Environment variable ACTION not set')
    action = os.environ['ACTION']

    if 'OPTIONAL_EMAIL_ADDRESS' not in os.environ:
        raise Exception('Environment variable OPTIONAL_EMAIL_ADDRESS not set')
    optional_email_address = os.environ['OPTIONAL_EMAIL_ADDRESS']

    if 'DOMAIN_NAME' not in os.environ:
        raise Exception('Environment variable DOMAIN_NAME not set')
    domain_name = os.environ['DOMAIN_NAME']

    if 'FERNET_KEY' not in os.environ:
        raise Exception('Environment variable FERNET_KEY not set')
    fernet_key = os.environ['FERNET_KEY']

    fernet = Fernet(fernet_key)

    if 'DEFAULT_COUNTRY_CODE' not in os.environ:
        raise Exception('Environment variable DEFAULT_COUNTRY_CODE not set')
    default_country_code = os.environ['DEFAULT_COUNTRY_CODE']

    if action == 'FETCH_EVENTS':
        try:
            watch_events(calendar_id, domain_name)
            print('Watching Google Calendar events now!')
        except Exception as e:
            print(str(e))
        ddb_events = fetch_modified_events(calendar_id)
        ddb_events = ddb_events + fetch_upcoming_events(calendar_id)
        return ddb_events
    elif action == 'POPULATE_EVENTS_DESCRIPTION':
        return populate_events_description(calendar_id, calendly_scheduling_url, optional_email_address, domain_name)
    elif action == 'POST_EVENT_CONFIRMATION':
        return cancel_event(calendar_id, event, domain_name)
    elif action == 'SEND_MSG':
        return send_messages(twilio_num, calendar_id, calendly_scheduling_url, domain_name, optional_email_address)
    elif action == 'RECEIVE_MSG':
        return receive_message(event)
    elif action == 'REDIRECT_SHROTENED_URL':
        return redirect_shortened_url(event)
    elif action == 'RECEIVE_MSG_STATUS':
        return msg_status_received(calendar_id, event)
    elif action == 'WEBHOOK':
        return safe_handle_webhook_payload(calendar_id, calendly_scheduling_url, optional_email_address, domain_name, twilio_num, event)
#START#####################

def track_for_msg(event):
    track_for_msg = False

    #Event not yet ready to be sent as message
    if 'description' not in event or event['description'].lower().find('resched') == -1:
        return track_for_msg

    #Event was created by host. The event is within next 24 hours. So track it for messaging
    now = datetime.datetime.now(datetime.timezone.utc)
    inform_until_datetime = now + datetime.timedelta(days=1)
    event_start_datetime = dateutil.parser.isoparse(event['start']['dateTime'])
    if event_start_datetime.timestamp() < inform_until_datetime.timestamp():
        track_for_msg = True

    #Event was created by calendly. User knows about it, track this event for messaging
    if 'description' in event and event['description'].lower().find('powered by calendly.com') != -1:
        track_for_msg = True

    #Host added a command to track event for sending messages.
    if 'description' in event and get_cmd_from_description('send', BeautifulSoup(event['description'], features="html.parser").get_text('\n')) != None:
        track_for_msg = True
    
    return track_for_msg

def mark_event_ignore_forever_for_msg(event_id):
    cond_expr = 'attribute_exists(id)'

    expr_attr_names = {'#ignore_for_msg': 'ignore_for_msg'}
    expr_attr_values = {':ignore_for_msg': {'S': 'True'}}
    update_expr = 'SET #ignore_for_msg = :ignore_for_msg'
    updated_ddb_item = None
    try:
        resp = ddb_client.update_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': event_id}}, UpdateExpression=update_expr, ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values, ConditionExpression=cond_expr, ReturnValues='ALL_NEW')
        updated_ddb_item = resp['Attributes']
    except ClientError as e:
        if e.response['Error']['Code'] !='ConditionalCheckFailedException':
            raise e
    return updated_ddb_item

def process_event(event, calendar_id, force_track_for_msg=False, force_ignore_forever_for_msg=False):
    utm_content = extract_utm_content(event['description']) if 'description' in event else None
    event_stored = None
    if utm_content != None:
        event_stored = store_rescheduled_event(utm_content['event_id'], event, calendar_id)
    else:
        event_stored = store_event(event, force_track_for_msg, force_ignore_forever_for_msg)

    # Try best effort to add WhatsApp link to the attendee WhatsApp number.
    if event_stored != None:
        try:
            to_num = try_format_phone_number(event['location']) if 'location' in event and event['location'] != '' else None
            desc = event['description'] if 'description' in event else ''
            desc = '' if desc == '' else BeautifulSoup(desc, features="html.parser").get_text('\n')
            new_desc = update_cmd_in_description('Attendee WhatsApp link', 'https://wa.me/' + to_num, desc)
            if to_num != None and new_desc != desc:
                google_calendar_service.events().patch(calendarId=calendar_id, eventId=event['id'], body={'description': new_desc}).execute()
        except Exception as e:
            print(str(e))

    return event_stored

def store_event(event, force_track_for_msg=False, force_ignore_forever_for_msg=False, latest_client_known_event=None):
    #TODO: IMP!!! Handle 'partial'

    global ddb_client

    #Only process events which have associated location(phone number)
    should_store = True
    if 'location' not in event or event['location'] == '':
        should_store = False
    else:
        event['location'] = try_format_phone_number(event['location'])

    #Do not store day long events
    if 'dateTime' not in event['start'] or 'dateTime' not in event['end']:
        should_store = False

    #Location was removed, remove the event from our table so its not processed
    if not should_store:
        expr_attr_names = {'#sequence_name': 'sequence', '#updated_epoch_name': 'updated_epoch'}
        expr_attr_vals = {
                ':sequence_val': {'N': str(event['sequence'])}, 
                ':updated_epoch_val': {'N': str(dateutil.parser.isoparse(event['updated']).timestamp()*1000)}
                }
        cond_expr = 'attribute_exists(id) and #sequence_name <= :sequence_val and #updated_epoch_name <= :updated_epoch_val'
        try:
            ddb_client.delete_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': event['id']}}, ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_vals, ConditionExpression=cond_expr)
        except ClientError as e:
            if e.response['Error']['Code'] !='ConditionalCheckFailedException':
                raise e
        return None

    #print('[INFO] Storing event with id ' + event['id'])

    update_expr = 'SET #sequence = :sequence'
    update_expr += ', #start_epoch = :start_epoch'
    update_expr += ', #end_epoch = :end_epoch'
    update_expr += ', #created_epoch = :created_epoch'
    update_expr += ', #updated_epoch = :updated_epoch'
    update_expr += ', #location = :location'
    update_expr += ', #event = :event'
    update_expr += ', #msg_not_sent = :msg_not_sent'
    update_expr += ', #ttl = :ttl'
    update_expr += ', #version = if_not_exists(#version, :version_zero) + :version_delta'
    
    expr_attr_names = {
            '#sequence': 'sequence',
            '#start_epoch': 'start_epoch',
            '#end_epoch': 'end_epoch',
            '#created_epoch': 'created_epoch',
            '#updated_epoch': 'updated_epoch',
            '#location': 'location',
            '#event': 'event',
            '#msg_not_sent': 'msg_not_sent',
            '#ttl': 'ttl',
            '#version': 'version'
            }

    expr_attr_values = {
            ':sequence': {'N': str(event['sequence'])},
            ':start_epoch': {'N': str(dateutil.parser.isoparse(event['start']['dateTime']).timestamp()*1000)},
            ':end_epoch': {'N': str(dateutil.parser.isoparse(event['end']['dateTime']).timestamp()*1000)},
            ':created_epoch': {'N': str(dateutil.parser.isoparse(event['created']).timestamp()*1000)},
            ':updated_epoch': {'N': str(dateutil.parser.isoparse(event['updated']).timestamp()*1000)},
            ':location': {'S': try_format_phone_number(event['location']) if 'location' in event else ''},
            ':event': {'S': json.dumps(event)},
            ':msg_not_sent': {'S': 'True'},
            ':ttl': {'N': str(int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).timestamp()))},
            ':version_delta': {'N': '1'},
            ':version_zero': {'N': '0'}
            }

    if latest_client_known_event != None:
        expr_attr_names['#latest_client_known_event'] = 'latest_client_known_event'
        expr_attr_values[':latest_client_known_event'] = {'S': json.dumps(latest_client_known_event)}
        update_expr += ', #latest_client_known_event = if_not_exists(#latest_client_known_event, :latest_client_known_event)'

    #Add 'description_missing' attr to item so that it can propagate to DDB index
    expr_attr_names['#description_missing'] = 'description_missing'
    #TODO: Is description missing logic is replicated in multiple places in code. Unify it.
    if 'description' not in event or event['description'].lower().find('resched') == -1:
        expr_attr_values[':description_missing'] = {'S': 'True'}
        update_expr += ', #description_missing = :description_missing'
    #Remove' description_missing' attr from item
    else:
        update_expr += ' REMOVE #description_missing'

    cond_expr = 'attribute_not_exists(id) or (#sequence <= :sequence and #updated_epoch < :updated_epoch)'

    updated_ddb_item = None
    try:
        resp = ddb_client.update_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': event['id']}}, UpdateExpression=update_expr, ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values, ConditionExpression=cond_expr, ReturnValues='ALL_NEW')
        updated_ddb_item = resp['Attributes']
    except ClientError as e:
        if e.response['Error']['Code'] !='ConditionalCheckFailedException':
            raise e

    # Update track_for_msg in a separate update call since track_for_msg can be updated even if Google canlendar event is not updated.
    expr_attr_names = {}
    expr_attr_values = {}
    update_expr = ''
    if force_track_for_msg or track_for_msg(event):
        expr_attr_names['#track_for_msg'] = 'track_for_msg'
        expr_attr_values[':track_for_msg'] = {'S': 'True'}
        update_expr = 'SET #track_for_msg = :track_for_msg'

        cond_expr = 'attribute_exists(id)'
        try:
            resp = ddb_client.update_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': event['id']}}, UpdateExpression=update_expr, ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values, ConditionExpression=cond_expr, ReturnValues='ALL_NEW')
            updated_ddb_item = resp['Attributes']
        except ClientError as e:
            if e.response['Error']['Code'] !='ConditionalCheckFailedException':
                raise e

    return updated_ddb_item

def fetch_modified_events(calendar_id):
    # List events which have been modified since the last time Google calendar was queried.
    resp = list_events(calendar_id, True, 91)
    stored_ddb_events = process_events(resp['events'], calendar_id)
    update_sync_token(resp['prev_sync_token'], resp['sync_token'], resp['sync_token_id'])
    return stored_ddb_events

def fetch_upcoming_events(calendar_id):
    resp = list_events(calendar_id, False, 1)
    return process_events(resp['events'], calendar_id)

def process_events(events, calendar_id):
    stored_ddb_events = []
    for event in events:
        try:
            ddb_event = process_event(event, calendar_id)
            # Some events are removed from DynamoDB table
            # Such events do not need to be populated
            if ddb_event != None:
                stored_ddb_events.append(ddb_event)
            # Webhook handles all the requests. This poller is for catch all. 
            # Poller does not need to be fast. Sleep 200ms. before store_event calls
            # to reduce request throughput to DynamoDB 
            time.sleep(0.1)
        except Exception as e:
            print('Exception while storing event id ' + event['id'])
            print(str(e))
            raise e
    return stored_ddb_events

#END#######################

#START#####################

def get_calendly_user():
    url = 'https://api.calendly.com/users/me'
    headers = {'Authorization': 'Bearer ' + calendly_api_key, 'Content-Type': 'application/json'}
    resp = requests.get(url, headers=headers)
    if resp == None or resp.status_code != 200 or 'resource' not in resp.json():
        raise Exception('Failed to get calendly user')
    return (resp.json())['resource']

def get_calendly_scheduled_event(event_uri):
    headers = {'Authorization': 'Bearer ' + calendly_api_key, 'Content-Type': 'application/json'}
    resp = requests.get(event_uri, headers=headers)
    if resp == None or resp.status_code != 200 or 'resource' not in resp.json():
        raise Exception('Failed to get calendly scheduled event')
    return (resp.json())['resource']

def get_calendly_scheduled_events(user_uri, min_start_datetime, max_start_datetime):
    min_start_time = min_start_datetime.astimezone(datetime.timezone.utc).isoformat()
    max_start_time = max_start_datetime.astimezone(datetime.timezone.utc).isoformat()
    base_url = 'https://api.calendly.com/scheduled_events'
    base_url = base_url + '?count=100&user=' + user_uri + '&min_start_time=' + min_start_time + '&max_start_time=' + max_start_time
    headers = {'Authorization': 'Bearer ' + calendly_api_key, 'Content-Type': 'application/json'}
    resp = requests.get(base_url, headers=headers)
    if resp == None or resp.status_code != 200 or 'collection' not in resp.json():
        raise Exception('Failed to get calendly event types')
    return (resp.json())['collection']

def get_calendly_event_types(user_uri):
    base_url = 'https://api.calendly.com/event_types'
    base_url = base_url + '?count=100&user=' + user_uri
    headers = {'Authorization': 'Bearer ' + calendly_api_key, 'Content-Type': 'application/json'}
    resp = requests.get(base_url, headers=headers)
    if resp == None or resp.status_code != 200 or 'collection' not in resp.json():
        raise Exception('Failed to get calendly event types')
    return (resp.json())['collection']

def calendly_scheduling_url_to_event_type_uri(scheduling_url):
    user = get_calendly_user()
    event_types = get_calendly_event_types(user['uri'])
    for e in event_types:
        if e['scheduling_url'].find(scheduling_url) != -1:
            return e['uri']
    return None

def generate_calendly_link(scheduling_url):
    event_uri = calendly_scheduling_url_to_event_type_uri(scheduling_url)
    if event_uri == None:
        raise Exception('Failed to find requested scheduling link in calendly organization')

    url = 'https://api.calendly.com/scheduling_links'
    body = {'max_event_count': 1, 'owner_type': 'EventType', 'owner': event_uri}
    headers = {'Authorization': 'Bearer ' + calendly_api_key, 'Content-Type': 'application/json'}
    resp = requests.post(url, headers=headers, data=json.dumps(body))
    if resp == None or resp.status_code != 201 or 'resource' not in resp.json():
        raise Exception('Failed to generate schedule once calendly link')
    return (resp.json())['resource']['booking_url']

#END#######################


#START#####################

def get_calendly_webhook_subscription():
    user = get_calendly_user()
    params = {
        'scope': 'user',
        'user': user['uri'],
        'organization': user['current_organization']
    }
    url = 'https://api.calendly.com/webhook_subscriptions?' + urlencode(params, quote_via=quote_plus)
    headers = {'Authorization': 'Bearer ' + calendly_api_key, 'Content-Type': 'application/json'}
    resp = requests.get(url, headers=headers)
    if resp != None and resp.status_code == 200 and 'collection' in resp.json():
        return resp.json()['collection'][0] if len(resp.json()['collection']) != 0 else None
    return None


def delete_calendly_webhook_subscription(webhook_uri):
    user = get_calendly_user()
    headers = {'Authorization': 'Bearer ' + calendly_api_key, 'Content-Type': 'application/json'}
    resp = requests.delete(webhook_uri, headers=headers)
    if resp != None and (resp.status_code == 204 or resp.status_code == 404):
        pass
    else:
        raise Exception('Failed to delete webhook. ' + str(resp))

def create_calendly_webhook_subscription(domain_name):
    global webhook_url

    # Delete disabled webhook subscription.
    # See: https://calendly.stoplight.io/docs/api-docs-v1/b3A6MTg3MDczOQ-create-a-webhook-subscription
    subscription = get_calendly_webhook_subscription()
    if subscription != None and subscription['state'] != 'active':
        print('Webhook subscription not active. Deleting it...')
        delete_calendly_webhook_subscription(subscription['uri'])
        print('Deleting webhook subscription succeeded.')
    elif subscription != None:
        print('An active Calendly webhook subscription already exists with URL: ' + subscription['callback_url'])
        return

    user = get_calendly_user()
    url = 'https://api.calendly.com/webhook_subscriptions'
    body = {'url': webhook_url.replace('DOMAIN_NAME', domain_name)}
    body['events'] = ['invitee.canceled', 'invitee.created']
    body['user'] = user['uri']
    body['organization'] = user['current_organization']
    body['scope'] = 'user'
    # TODO: Implement signing_key
    #body['signing_key'] = ''
    headers = {'Authorization': 'Bearer ' + calendly_api_key, 'Content-Type': 'application/json'}
    resp = requests.post(url, headers=headers, data=json.dumps(body))
    if resp != None and (resp.status_code == 201 or resp.status_code == 409):
        print('Created a Calendly webhook with URL: ' + body['url'])
        pass
    else:
        raise Exception('Failed to create webhook subscriptions. ' + str(resp) + '. ' + str(resp.json()))

#END#######################


#START#####################

def populate_event_description(ddb_event, calendar_id, calendly_scheduling_url, optional_email_address, domain_name):
    global google_calendar_service
    global base_cancellation_url
    global fernet

    event = json.loads(ddb_event['event']['S'])
    old_desc = event['description'] if 'description' in event else ''
    old_desc = old_desc + '\n\n'

    #Generate a cancellation link
    utm_content = {
            'event_id': ddb_event['id']['S'],
            'sequence': int(ddb_event['sequence']['N'])
            }
    params = {
            'utm_content': fernet.encrypt(json.dumps(utm_content).encode()).decode(),
            'show_cancel_dialog': 'true',
            'start_datetime': readable_datetime(dateutil.parser.isoparse(event['start']['dateTime']))
            }
    cancellation_url = base_cancellation_url.replace('DOMAIN_NAME', domain_name) + '?' + urlencode(params, quote_via=quote_plus)
    cancellation_url = get_shortened_url(cancellation_url, domain_name)
    #Cancellation is a special keyword. Its used in store_event for if/else
    new_desc = old_desc + 'Need to make changes to this event?'
    new_desc += '\nCancel: ' + cancellation_url

    #Generate a rescheduling link
    once_scheduling_link = generate_calendly_link(calendly_scheduling_url)
    params = {
            'email': optional_email_address,
            'location': ddb_event['location']['S'],
            'utm_content': fernet.encrypt(json.dumps(utm_content).encode()).decode()
            }
    once_scheduling_link += '?' + urlencode(params, quote_via=quote_plus)
    once_scheduling_link = get_shortened_url(once_scheduling_link, domain_name)

    new_desc = new_desc + '\n' + 'Reschedule: ' + once_scheduling_link
    new_desc = new_desc.lstrip('\n').rstrip('\n')

    try:
        event = google_calendar_service.events().get(calendarId=calendar_id, eventId=ddb_event['id']['S']).execute()
    except HttpError as e:
        if e.resp.status == 404:
            return
        raise e
    event['description'] = new_desc
    if event['sequence'] == int(ddb_event['sequence']['N']) and dateutil.parser.isoparse(event['updated']).timestamp()*1000 == int(ddb_event['updated_epoch']['N']):
        updated_event = google_calendar_service.events().update(calendarId=calendar_id, eventId=event['id'], body=event).execute()
        return process_event(updated_event, calendar_id)
    return None

def populate_events_description(calendar_id, calendly_scheduling_url, optional_email_address, domain_name) :
    global ddb_client
    
    resp = ddb_client.scan(TableName='GoogleEventManager-GoogleCalendarEvents', IndexName='GoogleEventManager-EventDescriptionMissingIndex')
    ddb_events = resp['Items']

    while 'LastEvaluatedKey' in resp:
        resp = ddb_client.scan(TableName='GoogleEventManager-GoogleCalendarEvents', IndexName='GoogleEventManager-EventDescriptionMissingIndex', ExclusiveStartKey=response['LastEvaluatedKey'])
        ddb_events.extend(response['Items'])

    for ddb_event in ddb_events:
        populate_event_description(ddb_event, calendar_id, calendly_scheduling_url, optional_email_address, domain_name)

#END#######################

#START#######################

def no_cancel_needed_response():
    html = '<html><head><link rel="shortcut icon" href="#"></head><body>'
    html += '<script>window.close();</script>'
    html += 'Appointment confirmed. You can close the window now.'
    html += '</body></html>'
    return {
        'statusCode': 200,
        'body': html,
        "headers": {'Content-Type': 'text/html'}
    }

def cancel_succeeded_response(cancel_for_reschedule):
    html = '<html><head><link rel="shortcut icon" href="#" class="CANCEL_SUCCEEDED"></head><body>'
    if cancel_for_reschedule:
        html += '<script>window.close();</script>'
    else:
        html += '<script>setTimeout("window.close()",3000);</script>'
        html += 'Cancellation succeeded.'
    html += '</body></html>'
    return {
        'statusCode': 200,
        'body': html,
        "headers": {'Content-Type': 'text/html'}
    }

def cancel_failed_response(cancel_for_reschedule):
    html = '<html><head><link rel="shortcut icon" href="#" class="CANCEL_FAILED"></head><body>'
    if cancel_for_reschedule:
        html += '<script>window.close();</script>'
    else:
        html += '<script>setTimeout("window.close()",3000);</script>'
        html += 'Cancellation failed. Please try again or contact the host.'
    html += '</body></html>'
    return {
        'statusCode': 200,
        'body': html,
        "headers": {'Content-Type': 'text/html'}
    }

def show_cancellation_dialog(readable_start_datetime, cancellation_url_params, domain_name):
    cancellation_url = base_cancellation_url.replace('DOMAIN_NAME', domain_name) + '?' + urlencode(cancellation_url_params, quote_via=quote_plus)
    with open('confirm-event-cancellation.html', 'r') as file:
        html = file.read()
    html = html.replace('{{start_datetime}}', readable_start_datetime)
    html = html.replace('{{cancellation_url}}', cancellation_url)
    return {
        'statusCode': 200,
        'body': html,
        "headers": {'Content-Type': 'text/html'}
    }

def cancel_event(calendar_id, lambda_event, domain_name):
    global google_calendar_service

    if 'User-Agent' in lambda_event['headers'] and lambda_event['headers']['User-Agent'].lower() == 'whatsapp':
        return cancel_failed_response(False)

    if 'queryStringParameters' not in lambda_event or 'utm_content' not in lambda_event['queryStringParameters']:
        print('queryStringParameters or queryStringParameters.utm_content missing in lambda_event')
        print(str(lambda_event))
        return cancel_failed_response(False)
    
    query_params = lambda_event['queryStringParameters']

    try:
        utm_content = fernet.decrypt(query_params['utm_content'].encode()).decode()
        params = json.loads(utm_content)
    except Exception as e:
        print('Failed to parse params.')
        print(str(lambda_event))
        print(str(e))
        return cancel_failed_response(False)

    if 'event_id' not in params or 'sequence' not in params:
        print('Params malformed')
        print(str(params))
        return cancel_failed_response(False)

    # Client clicked cancellation link. Show them a dialog. 
    # Same URL is invoked again when confirm cancellation button is clicked so we check whether show_cancel_dialog is set or not.
    # If it is set then show a confirm cancellation dialog else go ahead with the cancellation.
    if 'show_cancel_dialog' in query_params and query_params['show_cancel_dialog'] == 'true':
        new_query_params = copy.deepcopy(query_params)
        new_query_params.pop('show_cancel_dialog')
        new_query_params.pop('start_datetime')
        return show_cancellation_dialog(query_params['start_datetime'], new_query_params, domain_name)

    latest_client_known_event = None
    try:
        google_calendar_service.events().delete(calendarId=calendar_id, eventId=params['event_id']).execute()
    except HttpError as e:
        if e.resp.status != 410:
            print('Failed to cancel event_id: ' + params['event_id'])
            print(str(e))
            return cancel_failed_response(False)
    return cancel_succeeded_response(False)

#END#######################

#START#######################

def construct_event_sub_msg(event, domain_name):
    desc = event['description'] if 'description' in event else ''
    if desc == '':
        return desc
    cancel_link = get_shortened_url(extract_cancellation_link(desc), domain_name)
    reschedule_link = get_shortened_url(extract_reschedule_link(desc), domain_name)
    msg = 'Need to make changes to this event?\n'
    msg += 'Cancel: ' + cancel_link + '\n'
    msg += 'Reschedule: ' + reschedule_link
    return msg

def construct_event_msg(ddb_event, calendly_scheduling_url, domain_name, optional_email_address):
    event = json.loads(ddb_event['event']['S'])
    prev_event = json.loads(ddb_event['latest_client_known_event']['S']) if 'latest_client_known_event' in ddb_event else None
    
    # Phone number has changed. 
    # Treat this event as if no message has been sent to this user so far.
    # Setting previous event to None will result in the following logic 
    # to treat it as if we are sending msg to the user for the first time.
    if prev_event != None and try_format_phone_number(event['location']) != try_format_phone_number(prev_event['location']):
        prev_event = None    

    my_msg = ''
    start_datetime = readable_datetime(dateutil.parser.isoparse(event['start']['dateTime']))
    if (prev_event == None or not is_event_cancelled(prev_event)) and is_event_cancelled(event):
        my_msg = 'Your session scheduled for ' + start_datetime + ' has been cancelled.' 
        my_msg += '\n\n'
        params = {
            'email': optional_email_address
        }
        my_msg += 'You can schedule a new session by visiting: ' + calendly_scheduling_url + '?' + urlencode(params, quote_via=quote_plus)
    elif is_event_cancelled(event):
        # Both prev_event and event are cancelled. No need to send message for event.
        pass
    elif prev_event != None and prev_event['start']['dateTime'] != event['start']['dateTime']:
        # 'event' is a rescheduled event.
        prev_start_datetime = readable_datetime(dateutil.parser.isoparse(prev_event['start']['dateTime']))
        my_msg = 'Your session has been rescheduled to ' + start_datetime + '.'
        my_msg += ' Previous session scheduled for ' + prev_start_datetime + ' has been cancelled.' 
        sub_msg = construct_event_sub_msg(event, domain_name)
        my_msg += ('\n\n' if sub_msg != '' else '') + sub_msg
    elif prev_event == None:
        # This is a brand new event. Send a message to customer.
        my_msg = 'Your session has been scheduled for ' + start_datetime + '.'
        sub_msg = construct_event_sub_msg(event, domain_name)
        my_msg += ('\n\n' if sub_msg != '' else '') + sub_msg
    
    my_msg = None if my_msg == '' else my_msg

    return my_msg

def send_whatsapp_msg(from_no, to_no, msg):
    global twilio_client
    resp = twilio_client.messages.create(body=msg, from_='whatsapp:' + from_no, to='whatsapp:' + try_format_phone_number(to_no))
    return resp

def send_message(ddb_event, twilio_num, calendly_scheduling_url, colors, calendar_id, domain_name, optional_email_address):
    global ddb_client

    #Mark that the message was sent. Mark before sending so that we always send <= 1 msg. We never want to send same message again to a phone number.
    expr_attr_names = {'#msg_not_sent': 'msg_not_sent', '#id': 'id', '#latest_client_known_event': 'latest_client_known_event', '#version_sent': 'version_sent'}
    expr_attr_values = {':latest_client_known_event': ddb_event['event'], ':True': {'S': 'True'}, ':version_sent': ddb_event['version']}
    update_expr = 'SET #latest_client_known_event = :latest_client_known_event, #version_sent = :version_sent'
    update_expr += ' REMOVE #msg_not_sent'
    cond_expr = 'attribute_exists(#id) and #msg_not_sent = :True and (attribute_not_exists(#version_sent) or #version_sent < :version_sent)'
    try:
        resp = ddb_client.update_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': ddb_event['id']['S']}}, UpdateExpression=update_expr, ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values, ConditionExpression=cond_expr)
    except ClientError as e:
        print(str(e))
        raise e

    if 'ignore_for_msg' in ddb_event and ddb_event['ignore_for_msg']['S'] == 'True':
        return

    #Send the message
    msg = construct_event_msg(ddb_event, calendly_scheduling_url, domain_name, optional_email_address)
    # Nothing to send. Return.
    if msg == None:
        print('Nothing to send for event-id: ' + ddb_event['id']['S'])
        return

    err = None
    try:
        resp = send_whatsapp_msg(twilio_num, ddb_event['location']['S'], msg)
    except Exception as e:
        print('Failed to send message for event-id: ' + ddb_event['id']['S'])
        print(str(e))
        err = e

    print('Successfully sent a message for event-id: ' + ddb_event['id']['S'])
    
    if err != None:
        # For error messages like -
        # HTTP 400 error: Unable to create record: The 'To' number +16089606123a is not a valid phone number.
        err_msg = str(err)
        err_msg = err_msg[(err_msg.find(':') + 1):] if err_msg.find(':') != -1 else err_msg
        err_msg = err_msg.strip().lstrip('\n').rstrip('\n')
        err_msg = 'Unkown reason' if err_msg == '' else err_msg
        msg_sent_callback(False, json.loads(ddb_event['event']['S']), colors, calendar_id, reason = err_msg)
        return err

    #Track message id for changing color of event
    if resp != None and resp.sid != None:
        expr_attr_names = {'#msg_sid': 'msg_sid', '#id': 'id'}
        expr_attr_values = {':msg_sid': {'S': resp.sid}}
        update_expr = 'SET #msg_sid = :msg_sid'
        cond_expr = 'attribute_exists(#id)'
        try:
            ddb_client.update_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': ddb_event['id']['S']}}, UpdateExpression=update_expr, ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values, ConditionExpression=cond_expr)
        except ClientError as e:
            #Not raising error since tracking message id is best effort
            print(str(e))

def send_messages(twilio_num, calendar_id, calendly_scheduling_url, domain_name, optional_email_address):
    global ddb_client

    colors = get_event_colors()
    
    resp = ddb_client.scan(TableName='GoogleEventManager-GoogleCalendarEvents', IndexName='GoogleEventManager-EventsToMsg')
    ddb_events = resp['Items']

    while 'LastEvaluatedKey' in resp:
        resp = ddb_client.scan(TableName='GoogleEventManager-GoogleCalendarEvents', IndexName='GoogleEventManager-EventsToMsg', ExclusiveStartKey=response['LastEvaluatedKey'])
        ddb_events.extend(response['Items'])

    for ddb_event in ddb_events:
        try:
            send_message(ddb_event, twilio_num, calendly_scheduling_url, colors, calendar_id, domain_name, optional_email_address)
        except Exception as e:
            #Do not prevent one bad phone number prevent sending messages to all the following phone numbers
            print(str(e))
        time.sleep(2)

#END#######################

#START#######################

def construct_whatsapp_reply(to_num):
    global ddb_client

    expr_attr_names = {'#location': 'location'}
    expr_attr_values = {':location': {'S': to_num}}
    resp = ddb_client.query(TableName='GoogleEventManager-GoogleCalendarEvents', IndexName='GoogleEventManager-PhoneNumberIndex', KeyConditionExpression='#location = :location', ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values)
    ddb_events = resp['Items']

    while 'LastEvaluatedKey' in resp:
        resp = ddb_client.query(TableName='GoogleEventManager-GoogleCalendarEvents', IndexName='GoogleEventManager-PhoneNumberIndex', KeyConditionExpression='#location = :location', ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values, ExclusiveStartKey=response['LastEvaluatedKey'])
        ddb_events.extend(resp['Items'])

    now = datetime.datetime.now(datetime.timezone.utc)
    min_datetime = now - datetime.timedelta(hours=1)
    max_datetime = now + datetime.timedelta(days=30)
    reply = 'Your upcoming sessions in the next 30 days: \n'
    no_sessions = True
    session_num = 1
    for ddb_event in ddb_events:
        event = json.loads(ddb_event['event']['S'])
        start_datetime = dateutil.parser.isoparse(event['start']['dateTime'])
        if start_datetime < min_datetime or start_datetime > max_datetime:
            continue
        if is_event_cancelled(event):
            continue
        no_sessions = False
        reply += str(session_num) + '. ' + readable_datetime(start_datetime) + '\n'
        session_num += 1
    if no_sessions:
        reply = 'You do not have any session scheduled in the next 30 days.\n'
    return reply

def receive_message(lambda_event):
    to_num = urllib.parse.unquote(lambda_event['From'].lower())
    if not to_num.startswith('whatsapp:'):
        raise Exception('Unknown phone number: ' + lambda_event['From'])
    to_num = to_num[9:]
    content = construct_whatsapp_reply(to_num)
    return '<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response><Message><Body>' + content + '</Body></Message></Response>'

#END#######################

#START#######################

def redirect_code_to_shortened_url(code, domain_name):
    global base_redirect_url

    return base_redirect_url.replace('DOMAIN_NAME', domain_name) + code

def get_preexisting_shortened_url(redirect_url, domain_name):
    global ddb_client

    try:
        expr_attr_names = {'#redirect_url': 'redirect_url'}
        expr_attr_values = {':redirect_url': {'S': redirect_url}}
        resp = ddb_client.query(TableName='GoogleEventManager-RedirectCodeUrlMappings', IndexName='GoogleEventManager-UrlRedirectCodeMappings', KeyConditionExpression='#redirect_url = :redirect_url', ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values)
    except Exception as e:
        print(str(e))
        raise e

    if resp == None or 'Items' not in resp or len(resp['Items']) == 0:
        return None
    return redirect_code_to_shortened_url(resp['Items'][0]['code']['S'], domain_name)

def get_shortened_url(url, domain_name):
    global base_redirect_url

    if url.find(base_redirect_url.replace('DOMAIN_NAME', domain_name)) == 0:
        return url
    
    shortened_url = get_preexisting_shortened_url(url, domain_name)
    if shortened_url != None:
        return shortened_url

    code = uuid.uuid4().hex
    try:
        ttl = str(int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).timestamp()))
        ddb_client.put_item(TableName='GoogleEventManager-RedirectCodeUrlMappings', Item={'code': {'S': code}, 'redirect_url': {'S': url}, 'ttl': {'N': ttl}})
    except Exception as e:
        print(str(e))
        raise e
    return redirect_code_to_shortened_url(code, domain_name)

def bad_shortened_url_response():
    return {
    'statusCode': 400,
    'body': '<html><head/><body>Bad shortened url</body></html>',
    "headers": {'Content-Type': 'text/html'}
    }

def internal_server_error():
    return {
    'statusCode': 500,
    'body': '<html><head/><body>Internal Server Error</body></html>',
    "headers": {'Content-Type': 'text/html'}
    }

def redirect_shortened_url_response(redirect_url):
    return {
    'statusCode': 200,
    'body': '<html><head><title>Redirecting</title><meta http-equiv="refresh" content="0;URL=\'' + redirect_url + '\'"/></head><body><p>Redrecting you to <a href="' + redirect_url + '">' + redirect_url + '</a>.</p></body></html>',
    "headers": {'Content-Type': 'text/html'}
    }

def redirect_shortened_url(lambda_event):
    if 'queryStringParameters' not in lambda_event or 'c' not in lambda_event['queryStringParameters']:
        print('queryStringParameters or u missing in lambda_event')
        print(str(lambda_event))
        return bad_shortened_url_response()

    redirect_code = lambda_event['queryStringParameters']['c']

    try:
        resp = ddb_client.get_item(TableName='GoogleEventManager-RedirectCodeUrlMappings', Key={'code': {'S': redirect_code}})
    except Exception as e:
        print(str(e))
        return internal_server_error()

    if 'Item' not in resp:
        return bad_shortened_url_response()

    redirect_url = resp['Item']['redirect_url']['S'] 
    return redirect_shortened_url_response(redirect_url)


#END#######################

#START#######################

def msg_status_received(calendar_id, lambda_event):
    global ddb_client

    body = parse_qs(lambda_event['body'])
    try:
        expr_attr_names = {'#msg_sid': 'msg_sid'}
        expr_attr_values = {':msg_sid': {'S': body['MessageSid'][0]}}
        resp = ddb_client.query(TableName='GoogleEventManager-GoogleCalendarEvents', IndexName='GoogleEventManager-MessageDeliveryStatusIndex', KeyConditionExpression='#msg_sid = :msg_sid', ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values)
    except Exception as e:
        print(str(e))
        raise e
    
    if resp == None or 'Items' not in resp or len(resp['Items']) == 0:
        return {'statusCode': 200}

    ddb_event = resp['Items'][0]
    delivery_status = body['MessageStatus'][0]
    if delivery_status == 'sent' or delivery_status == 'delivered' or delivery_status == 'receiving' or delivery_status == 'received' or delivery_status == 'read':
        msg_sent_callback(True, json.loads(ddb_event['event']['S']), get_event_colors(), calendar_id)
    elif delivery_status == 'failed' or delivery_status == 'undelivered' or delivery_status == 'undelivered':
        reason = body['ErrorMessage'][0].strip() if 'ErrorMessage' in body and len(body['ErrorMessage']) > 0 else None
        reason = 'Unknown reason' if reason == '' else reason
        msg_sent_callback(False, json.loads(ddb_event['event']['S']), get_event_colors(), calendar_id, reason = reason)

#END#######################

#START#######################

def store_rescheduled_event(old_event_id, new_event, calendar_id):
    global google_calendar_service

    mark_event_ignore_forever_for_msg(old_event_id)
    
    try:
        google_calendar_service.events().delete(calendarId=calendar_id, eventId=old_event_id).execute()
    except HttpError as e:
        print(str(e))
        if e.resp.status != 410:
            print('Failed to cancel event_id: ' + old_event_id)
            print(str(e))
            raise e

    # Find the new event after rescheduling
    # New event might not meet within 24 hour window requirement for tracking for message.
    # So force track the event for msg since clealy client knows about the event since they rescheduled the event. 
    old_event = google_calendar_service.events().get(calendarId=calendar_id, eventId=old_event_id).execute()
    return store_event(new_event, force_track_for_msg=True, latest_client_known_event=old_event)

def cancel_old_event_after_reschedule(old_event_id, new_event_start_time, new_event_cancel_url, calendar_id):
    global google_calendar_service

    #TODO: IMP!!! How to ensure this is called before Google Calendar webhook is invoked for rescheduled event creation.
    
    mark_event_ignore_forever_for_msg(old_event_id)
    
    try:
        google_calendar_service.events().delete(calendarId=calendar_id, eventId=old_event_id).execute()
    except HttpError as e:
        print(str(e))
        if e.resp.status != 410:
            print('Failed to cancel event_id: ' + old_event_id)
            print(str(e))
            raise e

    # This block is all best effor since in worst case scenario we will end up sending 2 messages.
    # One for the deleted event and another for new event after rescheduling. 
    # Code below tries to make sure we only send one message i.e. for the new event after reschedule.
    try:
        new_event_start_datetime = dateutil.parser.isoparse(new_event_start_time)
        # Find the new event after rescheduling
        new_event_resp = google_calendar_service.events().list(calendarId=calendar_id, timeMin=new_event_start_datetime.isoformat(), timeMax=(new_event_start_datetime + datetime.timedelta(seconds=1)).isoformat(), singleEvents=True, showDeleted=True, maxResults=9999, pageToken=None).execute()
        new_event = None
        for e in new_event_resp['items']:
            if 'description' in e and e['description'].find(new_event_cancel_url) != -1:
                new_event = e
                break
        if new_event == None:
            print('Failed to find an active google calendar event at ' + str(new_event_start_time))
            # Returns false so calendly keeps posting the event to our webhook until Google calendar event is created.
            return False
        # New event might not meet within 24 hour window requirement for tracking for message.
        # So force track the event for msg since clealy client knows about the event since they rescheduled the event. 
        process_event(new_event, calendar_id, force_track_for_msg=True)
        old_event = google_calendar_service.events().get(calendarId=calendar_id, eventId=old_event_id).execute()
        expr_attr_names = {'#latest_client_known_event': 'latest_client_known_event'}
        expr_attr_values = {':latest_client_known_event': {'S': json.dumps(old_event)}}
        update_expr = 'SET #latest_client_known_event = :latest_client_known_event'
        # Calendly creates reschedule and cancellation links with the redirect params which were used to created the initial appointment.
        # As a result all following appointments will have the utm_source of deleted event. 
        # Only update new event with old event if new event does not already know about an event.
        cond_expr = 'attribute_not_exists(#latest_client_known_event)'
        try:
            ddb_client.update_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': new_event['id']}}, ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values, UpdateExpression=update_expr, ConditionExpression=cond_expr)
        except ClientError as e:
            if e.response['Error']['Code'] =='ConditionalCheckFailedException':
                # This is an expected scenario. New event has been rescheduled multiple times. 
                # No need to link it with the old event which created it in the first place.
                return True
    except Exception as e:
        print('Failed to mark old event or new event after rescheduling for tracking messages')
        print(str(e))
    return True

def safe_handle_webhook_payload(calendar_id, calendly_scheduling_url, optional_email_address, domain_name, twilio_num, lambda_event):
    user_agent = lambda_event['headers']['User-Agent'] if 'User-Agent' in lambda_event['headers'] else None

    try:
        if user_agent.find('APIs-Google') != -1:
            handle_google_calendar_webhook_payload(calendar_id, calendly_scheduling_url, optional_email_address, domain_name, twilio_num, lambda_event)
    except Exception as e:
        print(str(lambda_event))
        print(str(e))
    
    return {'statusCode': 200, 'body': '<html></html>', "headers": {'Content-Type': 'text/html'}}

def handle_google_calendar_webhook_payload(calendar_id, calendly_scheduling_url, optional_email_address, domain_name, twilio_num, lambda_event):
    stored_ddb_events = fetch_modified_events(calendar_id)

    populated_ddb_events = []
    for ddb_event in stored_ddb_events:        
        e = ddb_event
        if 'description_missing' in ddb_event and ddb_event['description_missing']['S'] == 'True':
            e = populate_event_description(ddb_event, calendar_id, calendly_scheduling_url, optional_email_address, domain_name)
        # e can be None if event was not populated.
        if e != None:
            populated_ddb_events.append(e)
    
    colors = get_event_colors()
    for ddb_event in populated_ddb_events:
        try:
            if 'track_for_msg' in ddb_event and ddb_event['track_for_msg']['S'] == 'True' and 'msg_not_sent' in ddb_event and ddb_event['msg_not_sent']['S'] == 'True':
                send_message(ddb_event, twilio_num, calendly_scheduling_url, colors, calendar_id, domain_name, optional_email_address)
        except Exception as e:
            #Do not prevent one bad phone number prevent sending messages to all the following phone numbers
            print(str(e))
        time.sleep(2)

def handle_calendly_webhook_payload(calendar_id, lambda_event):
    global fernet

    body = json.loads(lambda_event['body'])
    payload = body['payload']
    utm_content = payload['tracking']['utm_content']
    
    # This event was not created as a result of generated reschedule link. 
    # All reschedule links have utm_content attached to them.
    if body['event'] != 'invitee.created' or utm_content == None or utm_content.strip() == '':
        return {'statusCode': 200, 'body': '<html></html>', "headers": {'Content-Type': 'text/html'}}

    utm_content = fernet.decrypt(utm_content.encode()).decode()
    utm_content = json.loads(utm_content)
    event = get_calendly_scheduled_event(payload['event'])
    op_success = False
    try:
        op_success = cancel_old_event_after_reschedule(utm_content['event_id'], event['start_time'], payload['cancel_url'], calendar_id)
    except Exception as e:
        print(str(e))
    return {'statusCode': 200 if op_success else 500, 'body': '<html></html>', "headers": {'Content-Type': 'text/html'}}


#END#######################


#START#######################


def watch_events(calendar_id, domain_name):
  page_token = None
  body = {
    'payload': True,
    'address': webhook_url.replace('DOMAIN_NAME', domain_name),
    'id': 'id3',
    'type': 'web_hook'
  }

  now = datetime.datetime.now(datetime.timezone.utc)
  now = now.replace(hour=0, minute=0, second=0, microsecond=0)
  # If next Google watch event is created several hours later because of some error, 
  # start watching from 1 day ago to provide overlap for unwatched time.
  start_datetime = (now - datetime.timedelta(days=1)).isoformat()
  # Google watch event has a default ttl of 7 days. So watch for 90 days + 7 days instead of only 90 days.
  end_datetime = (now + datetime.timedelta(days=98)).isoformat()

  try:
    resp = google_calendar_service.events().watch(calendarId=calendar_id, timeMin=start_datetime, timeMax=end_datetime, singleEvents=True, showDeleted=True, maxResults=9999, pageToken=page_token, body=body).execute()
  except HttpError as e:
    if e.resp.status == 400 and str(e.content).find('channelIdNotUnique') != -1:
        print('Google Calendar events watch channel already exists')
        return
    else:
        print('Failed to watch for Google Calendar events')
        print(str(e))
        raise e

#END#######################
