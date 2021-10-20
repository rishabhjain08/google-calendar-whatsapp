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

google_calendar_service = None
ddb_client = None
s3_client = None
base_cancellation_url = 'https://DOMAIN_NAME/confirm'
base_redirect_url = 'https://DOMAIN_NAME/r'
calendly_api_key = None
twilio_client = None
fernet = None

def readable_datetime(dt):
    return dt.strftime('%d %b %I:%M %p %Z')

def format_phone_number(num):
    return num.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')

# Strip user commands and unwanted information from description before sending message.
# Commands are on a new line and the line always starts with *
def strip_description(desc):
    lines = desc.splitlines(True)
    new_desc = ''
    prev_stripped_line = None
    for line in lines:
        if line.startswith('*'):
            continue
        if line.lower().find('powered by calendly.com') != -1:
            continue
        if line.lower().find('please share anything that will help prepare for our meeting') != -1:
            continue
        #We dont want two new lines in succession in the description
        stripped_line = line.lstrip('\n').rstrip('\n').strip()
        if prev_stripped_line != None and prev_stripped_line == '' and stripped_line == '':
            continue
        prev_stripped_line = stripped_line
        
        new_desc += line
    return new_desc.lstrip('\n').rstrip('\n')

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
    for line in lines:
        if not line.lower().startswith('*' + cmd.lower()):
            new_desc += line
            continue
        cmd_found = True
        if val != None:
            new_desc += '*' + cmd + ': ' + val + '\n'
    if not cmd_found:
        new_desc = ''
        if val != None:
            new_desc = '*' + cmd + ': ' + val + '\n'
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

def set_event_color(status, event, colors, calendar_id, reason = None):
    if colors != None:
        event = google_calendar_service.events().get(calendarId=calendar_id, eventId=event['id']).execute()
        event['colorId'] = colors['green'] if status else colors['red']
        old_desc = BeautifulSoup(event['description'], features="html.parser").get_text('\n')
        new_desc = update_cmd_in_description('Failed to send message', reason, old_desc)
        event['description'] = new_desc
        updated_event = google_calendar_service.events().update(calendarId=calendar_id, eventId=event['id'], body=event).execute()

def list_events(calendar_id):
  now = datetime.datetime.now(datetime.timezone.utc)
  start_datetime = (now - datetime.timedelta(hours=1)).isoformat()
  end_datetime = (now + datetime.timedelta(days=90)).isoformat()
  page_token = None
  all_events = []
  while True:
    events = google_calendar_service.events().list(calendarId=calendar_id, timeMin=start_datetime, timeMax=end_datetime, singleEvents=True, showDeleted=True, maxResults=9999, pageToken=page_token).execute()
    all_events = all_events + events['items']
    page_token = events.get('nextPageToken')
    if not page_token:
      break
  return all_events

def init_google_calendar_service(s3_bucket):
  global s3_client
  
  resp = s3_client.get_object(Bucket=s3_bucket, Key='google-event-manager-service-account.json')
  service_account_json = json.loads(resp['Body'].read().decode('utf-8'))
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
    google_calendar_service = init_google_calendar_service(s3_bucket)

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

    if action == 'FETCH_EVENTS':
        return fetch_events(calendar_id)
    elif action == 'POPULATE_EVENTS_DESCRIPTION':
        return populate_events_description(calendar_id, calendly_scheduling_url, optional_email_address, domain_name)
    elif action == 'POST_EVENT_CONFIRMATION':
        return cancel_event(calendar_id, event)
    elif action == 'SEND_MSG':
        return send_messages(twilio_num, calendar_id, calendly_scheduling_url)
    elif action == 'RECEIVE_MSG':
        return receive_message(event)
    elif action == 'REDIRECT_SHROTENED_URL':
        return redirect_shortened_url(event)
    elif action == 'RECEIVE_MSG_STATUS':
        return msg_status_received(calendar_id, event)

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

def store_event(event, force_track_for_msg=False):
    global ddb_client

    #Only process events which have associated location(phone number)
    should_store = True
    if 'location' not in event or event['location'] == '':
        should_store = False

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
        return False

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
    
    expr_attr_names = {
            '#sequence': 'sequence',
            '#start_epoch': 'start_epoch',
            '#end_epoch': 'end_epoch',
            '#created_epoch': 'created_epoch',
            '#updated_epoch': 'updated_epoch',
            '#location': 'location',
            '#event': 'event',
            '#msg_not_sent': 'msg_not_sent',
            '#ttl': 'ttl'
            }

    expr_attr_values = {
            ':sequence': {'N': str(event['sequence'])},
            ':start_epoch': {'N': str(dateutil.parser.isoparse(event['start']['dateTime']).timestamp()*1000)},
            ':end_epoch': {'N': str(dateutil.parser.isoparse(event['end']['dateTime']).timestamp()*1000)},
            ':created_epoch': {'N': str(dateutil.parser.isoparse(event['created']).timestamp()*1000)},
            ':updated_epoch': {'N': str(dateutil.parser.isoparse(event['updated']).timestamp()*1000)},
            ':location': {'S': format_phone_number(event['location']) if 'location' in event else ''},
            ':event': {'S': json.dumps(event)},
            ':msg_not_sent': {'S': 'True'},
            ':ttl': {'N': str(int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).timestamp()))}
            }

    if force_track_for_msg or track_for_msg(event):
        expr_attr_names['#track_for_msg'] = 'track_for_msg'
        expr_attr_values[':track_for_msg'] = {'S': 'True'}
        update_expr += ', #track_for_msg = :track_for_msg'

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
    try:
        ddb_client.update_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': event['id']}}, UpdateExpression=update_expr, ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values, ConditionExpression=cond_expr)
    except ClientError as e:
        if e.response['Error']['Code'] !='ConditionalCheckFailedException':
            raise e

def fetch_events(calendar_id):
    global google_calendar_service
    #TODO: Use sync token to limit the amount of events fetched
    events = list_events(calendar_id)
    for event in events:
        store_event(event)

#END#######################

#START#####################

def get_calendly_user():
    url = 'https://api.calendly.com/users/me'
    headers = {'Authorization': 'Bearer ' + calendly_api_key, 'Content-Type': 'application/json'}
    resp = requests.get(url, headers=headers)
    if resp == None or resp.status_code != 200 or 'resource' not in resp.json():
        raise Exception('Failed to get calendly user')
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

def populate_event_description(ddb_event, calendar_id, calendly_scheduling_url, optional_email_address, domain_name):
    global google_calendar_service
    global base_cancellation_url
    global fernet

    event = json.loads(ddb_event['event']['S'])
    old_desc = (event['description'] + '\n') if 'description' in event else ''

    #Generate a cancellation link
    utm_content = {
            'event_id': ddb_event['id']['S'],
            'sequence': int(ddb_event['sequence']['N'])
            }
    params = {
            'utm_content': fernet.encrypt(json.dumps(utm_content).encode()).decode()
            }
    cancellation_url = base_cancellation_url.replace('DOMAIN_NAME', domain_name) + '?' + urlencode(params, quote_via=quote_plus)
    cancellation_url = get_redirect_url(cancellation_url, domain_name)
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
    once_scheduling_link = get_redirect_url(once_scheduling_link, domain_name)

    new_desc = new_desc + '\n' + 'Reschedule: ' + once_scheduling_link

    try:
        event = google_calendar_service.events().get(calendarId=calendar_id, eventId=ddb_event['id']['S']).execute()
    except HttpError as e:
        if e.resp.status == 404:
            return
        raise e
    event['description'] = new_desc
    if event['sequence'] == int(ddb_event['sequence']['N']) and dateutil.parser.isoparse(event['updated']).timestamp()*1000 == int(ddb_event['updated_epoch']['N']):
        updated_event = google_calendar_service.events().update(calendarId=calendar_id, eventId=event['id'], body=event).execute()
        store_event(updated_event)

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
    html = '<html><head><link rel="shortcut icon" href="#"></head><body>'
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
    html = '<html><head><link rel="shortcut icon" href="#"></head><body>'
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

def cancel_event(calendar_id, lambda_event):
    global google_calendar_service

    cancel_for_reschedule = False

    if 'User-Agent' in lambda_event['headers'] and lambda_event['headers']['User-Agent'].lower() == 'whatsapp':
        return cancel_failed_response(cancel_for_reschedule)

    if 'queryStringParameters' not in lambda_event:
        print('queryStringParameters missing in lambda_event')
        print(str(lambda_event))
        return cancel_failed_response(cancel_for_reschedule)
    
    cancel_for_reschedule = 'event_type_uuid' in lambda_event['queryStringParameters']

    # This is a brand new schedule request not a re-schedule request since we attach utm_content query parameter
    # to all the calendly reschedule links generated by this code.
    if 'queryStringParameters' not in lambda_event or 'utm_content' not in lambda_event['queryStringParameters']:
        return no_cancel_needed_response()

    try:
        utm_content = fernet.decrypt(lambda_event['queryStringParameters']['utm_content'].encode()).decode()
        params = json.loads(utm_content)
    except Exception as e:
        print('Failed to parse params.')
        print(str(lambda_event))
        print(str(e))
        return cancel_failed_response(cancel_for_reschedule)

    if 'event_id' not in params or 'sequence' not in params:
        print('Params malformed')
        print(str(params))
        return cancel_failed_response(cancel_for_reschedule)

    latest_client_known_event = None
    try:
        google_calendar_service.events().delete(calendarId=calendar_id, eventId=params['event_id']).execute()
    except HttpError as e:
        if e.resp.status != 410:
            print('Failed to cancel event_id: ' + params['event_id'])
            print(str(e))
            return cancel_failed_response(cancel_for_reschedule)

    # This block is all best effor since in worst case scenario we will end up sending 2 messages.
    # One for the deleted event and another for new event after rescheduling. 
    # Code below tries to make sure we only send one message i.e. for the new event after reschedule.
    try:
        # Update the newly re-scheduled event with the old event which was just deleted 
        # Event was deleted not rescheduled. Nothing to do.
        if not cancel_for_reschedule:
            return cancel_succeeded_response(cancel_for_reschedule)
        new_event_uuid = lambda_event['queryStringParameters']['event_type_uuid']
        new_event_start_datetime = dateutil.parser.isoparse(lambda_event['queryStringParameters']['event_start_time'])
        new_event_end_datetime = dateutil.parser.isoparse(lambda_event['queryStringParameters']['event_end_time'])
        #Find the new event after rescheduling
        new_event_resp = google_calendar_service.events().list(calendarId=calendar_id, timeMin=new_event_start_datetime.isoformat(), timeMax=(new_event_start_datetime + datetime.timedelta(seconds=1)).isoformat(), singleEvents=True, showDeleted=True, maxResults=9999, pageToken=None).execute()
        new_event = None
        for e in new_event_resp['items']:
            # New event was just scheduled. It cannot be in cancelled state.
            if e['status'] != 'cancelled':
                new_event = e
                break
        if new_event == None:
            raise Exception('Failed to find an active google calendar event at expected time')
        # New event might not meet within 24 hour window requirement for tracking for message.
        # So force track the event for msg since clealy client knows about the event since they rescheduled the event. 
        store_event(new_event, force_track_for_msg=True)
        # Calendly creates reschedule and cancellation links with the redirect params which were used to created the initial appointment.
        # As a result all following appointments will have the utm_source of deleted event. 
        # This event has been rescheduled multiple times. 
        # This is not the new event created right after previous one was deleted as a result of rescheduling,
        if new_event['sequence'] != 0:
            return cancel_succeeded_response(cancel_for_reschedule)
        old_event = google_calendar_service.events().get(calendarId=calendar_id, eventId=params['event_id']).execute()
        expr_attr_names = {'#latest_client_known_event': 'latest_client_known_event'}
        expr_attr_values = {':latest_client_known_event': {'S': json.dumps(old_event)}}
        update_expr = 'SET #latest_client_known_event = :latest_client_known_event'
        ddb_client.update_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': new_event['id']}}, ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values, UpdateExpression=update_expr)
        # Do not send message for the deleted event since we will send a message for the rescheduled event.
        # Store event in storage after deleting it from calendar so that we have the latest event image in storage 
        # before we update an attribute in storage. If we dont do it, the new attribute may be overwritten. 
        # Mark old event for not sending message only after we were able to mark new event for sending message.
        store_event(old_event)
        expr_attr_names = {'#msg_not_sent': 'msg_not_sent'}
        update_expr = 'REMOVE #msg_not_sent'
        ddb_client.update_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': params['event_id']}}, ExpressionAttributeNames=expr_attr_names, UpdateExpression=update_expr)
    except Exception as e:
        print('Failed to mark old event or new event after rescheduling for tracking messages')
        print(str(e))
        print(str(lambda_event))

    return cancel_succeeded_response(cancel_for_reschedule)

#END#######################

#START#######################

def construct_event_msg(ddb_event, calendly_scheduling_url):
    event = json.loads(ddb_event['event']['S'])
    prev_event = json.loads(ddb_event['latest_client_known_event']['S']) if 'latest_client_known_event' in ddb_event else None
    desc = strip_description(BeautifulSoup(event['description'], features="html.parser").get_text('\n')) if 'description' in event else ''
    my_msg = ''
    start_datetime = readable_datetime(dateutil.parser.isoparse(event['start']['dateTime']))
    # 'event' is a rescheduled event.
    if prev_event != None and prev_event['start']['dateTime'] != event['start']['dateTime']:
        prev_start_datetime = readable_datetime(dateutil.parser.isoparse(prev_event['start']['dateTime']))
        my_msg = 'Your session has been rescheduled to ' + start_datetime + '.'
        my_msg += ' Previous session scheduled for ' + prev_start_datetime + ' has been cancelled.' 
        my_msg += ('\n\n' if desc != '' else '') + desc
    # Session time has not changed since the last time client was informed. No need to send message for this event.
    elif prev_event != None and prev_event['location'] == event['location']:
        return None
    elif event['status'] == 'cancelled' or event['summary'].lower().startswith('canceled'):
        my_msg = 'Your session scheduled for ' + start_datetime + ' has been cancelled.' 
        my_msg += '\n\n'
        my_msg += 'You can schedule a new session by visiting: ' + calendly_scheduling_url
    # This is a brand new event. Send a message to customer.
    else:
        my_msg = 'Your session has been scheduled for ' + start_datetime + '.'
        my_msg += ('\n\n' if desc != '' else '') + desc

    return my_msg

def send_whatsapp_msg(from_no, to_no, msg):
    global twilio_client
    resp = twilio_client.messages.create(body=msg, from_='whatsapp:' + from_no, to='whatsapp:' + to_no)
    return resp

def send_message(ddb_event, twilio_num, calendly_scheduling_url, colors, calendar_id):
    global ddb_client

    #Mark that the message was sent. Mark before sending so that we always send <= 1 msg. We never want to send same message again to a phone number.
    expr_attr_names = {'#msg_not_sent': 'msg_not_sent', '#id': 'id', '#latest_client_known_event': 'latest_client_known_event'}
    expr_attr_values = {':latest_client_known_event': ddb_event['event']}
    update_expr = 'SET #latest_client_known_event = :latest_client_known_event'
    update_expr += ' REMOVE #msg_not_sent'
    cond_expr = 'attribute_exists(#id)'
    try:
        ddb_client.update_item(TableName='GoogleEventManager-GoogleCalendarEvents', Key={'id': {'S': ddb_event['id']['S']}}, UpdateExpression=update_expr, ExpressionAttributeNames=expr_attr_names, ExpressionAttributeValues=expr_attr_values, ConditionExpression=cond_expr)
    except ClientError as e:
        print(str(e))
        raise e

    #Send the message
    msg = construct_event_msg(ddb_event, calendly_scheduling_url)
    # Nothing to send. Return.
    if msg == None:
        return

    err = None
    try:
        resp = send_whatsapp_msg(twilio_num, ddb_event['location']['S'], msg)
    except Exception as e:
        print(str(e))
        err = e

    if err != None:
        # For error messages like -
        # HTTP 400 error: Unable to create record: The 'To' number +16089606123a is not a valid phone number.
        err_msg = str(err)
        err_msg = err_msg[(err_msg.find(':') + 1):] if err_msg.find(':') != -1 else err_msg
        err_msg = err_msg.strip().lstrip('\n').rstrip('\n')
        err_msg = 'Unkown reason' if err_msg == '' else err_msg
        set_event_color(False, json.loads(ddb_event['event']['S']), colors, calendar_id, reason = err_msg)
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

def send_messages(twilio_num, calendar_id, calendly_scheduling_url):
    global ddb_client

    colors = get_event_colors()
    
    resp = ddb_client.scan(TableName='GoogleEventManager-GoogleCalendarEvents', IndexName='GoogleEventManager-EventsToMsg')
    ddb_events = resp['Items']

    while 'LastEvaluatedKey' in resp:
        resp = ddb_client.scan(TableName='GoogleEventManager-GoogleCalendarEvents', IndexName='GoogleEventManager-EventsToMsg', ExclusiveStartKey=response['LastEvaluatedKey'])
        ddb_events.extend(response['Items'])

    for ddb_event in ddb_events:
        try:
            send_message(ddb_event, twilio_num, calendly_scheduling_url, colors, calendar_id)
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
        if event['status'] == 'cancelled' or event['summary'].lower().startswith('canceled'):
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

def get_redirect_url(url, domain_name):
    code = uuid.uuid4().hex
    redirect_url = base_redirect_url.replace('DOMAIN_NAME', domain_name) + '?c=' + code
    try:
        ttl = str(int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).timestamp()))
        ddb_client.put_item(TableName='GoogleEventManager-RedirectCodeUrlMappings', Item={'code': {'S': code}, 'redirect_url': {'S': url}, 'ttl': {'N': ttl}})
    except Exception as e:
        print(str(e))
        raise e
    return redirect_url

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
        set_event_color(True, json.loads(ddb_event['event']['S']), get_event_colors(), calendar_id)
    elif delivery_status == 'failed' or delivery_status == 'undelivered' or delivery_status == 'undelivered':
        reason = body['ErrorMessage'][0].strip() if 'ErrorMessage' in body and len(body['ErrorMessage']) > 0 else None
        reason = 'Unknown reason' if reason == '' else reason
        set_event_color(False, json.loads(ddb_event['event']['S']), get_event_colors(), calendar_id, reason = reason)

#END#######################