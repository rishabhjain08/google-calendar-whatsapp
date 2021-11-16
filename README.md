# google-calendar-whatsapp

## About

**TL;DR**

This project allows the host to schedule, reschedule and cancel all events from Google Calendar. Attendees are notified on Whatsapp when an event is scheduled, rescheduled or cancelled and allows the attendees to reschedule and cancel events by following the links in the Whatsapp message which updates the host's Google Calendar. 

Workflows supported by this project:
- Host creates event in Google Calendar, enters phone number in location field. Project sends Whatsapp message to the attendee.
- Attendee receives a Whatsapp message when host schedules an event. Whatsapp message contains reschedule event and cancel event links. 
- Reschedule link in Whatsapp message sent to the attendee redirects to calendly.com and allows attendee to reschedule the event on calendly.com. calendly.com is linked to host's Google Calendar so calendly.com only shows available slots to the attendee. When attendee reschedules the event, old event disappears from host's Google Calendar and newly rescheduled event shows up in host's Google Calendar. Also a reschedule Whatsapp message is sent to the attendee to confirm the reschedule.
- Cancel link in Whatsapp message sent to attendee when opened, cancels the event and removes the event host's Google Calendar. Also, a cancellation message is sent to the attendee to confirm the cancellation.
- Host can create events in their Google calendar and attendees can create events on calendly.com. When attendee creates an event on calendly.com, newly scheduled event shows up in host's Google Calendar and a 'event scheduled' Whatsapp message is sent to the attendee to confirm that the event is scheduled. The Whatsapp message contains reschedule event and cancel event links if attendee wants to modify the scheduled event.
- When host moves the event around in Google Calendar to change the event start time, a Whatsapp message is sent to the attendee to notify the attendee of the reschedule. Whatsapp message sent to the attendee contains a reschedule event and cancel event link if attendee wants to modify the rescheduled event.
- When host cancels the event in Google Calendar, an event cancelled Whatsapp message is sent to the attendee.
- Events turn green in host's Google Calendar when a Whatsapp message has been sent successfully to the attendee. Event turns red in host's Google Calendar when the project fails to send Whatsapp message to the attendee. Project also adds reason for failure to send Whatsapp message in the Google Calendar event description.
- Attendees can send a Whatsapp message to host's Whatsapp business number to list all the events scheduled in the next 30 days.

## Setup

### General setup
- [Generate](https://cryptography.io/en/latest/fernet/) a Fernet key. Note it down. This will be needed when setting up resources in AWS developer account for this project. This Fernet key is used to encrypt URL params so no-one can tamper with URL params. 

### Own a domain
- You will need a domain you own to setup this project. The domain name is used to create shortened cancellation and reschedule URLs to be sent in Whatsapp message to attendees. **If you do not have a domain** or you do not want to buy a domain, you can modify the project so that non-shortened URLs are sent to attendees.
- Note down your domain name. Let's say your domain name is MY_DOMAIN_NAME (eg. abc.com). This will be needed when setting Calendly account and setting up resources in AWS developer account for this project. 

### Twilio account setup
- Create a Twilio account if you dont already have one. This project uses Twilio APIs to send Whatsapp messages to attendees. 
- Note down [Account SID and Auth Token](https://www.twilio.com/blog/better-twilio-authentication-csharp-twilio-api-keys) after creating your Twilio account. This will be needed when setting up resources in AWS developer account for this project.
- Note down your Twilio [Whatsapp bussiness number](https://www.twilio.com/docs/whatsapp/api#using-twilio-phone-numbers-with-whatsapp) with which you want to send messages to attendees. This will be needed when setting up resources in AWS developer account for this project.
- [Request](https://www.twilio.com/whatsapp/request-access) Twilio to enable Twilio number for Whatsapp.
- Note that you can use [Twilio sandbox](https://www.twilio.com/docs/whatsapp/sandbox) to test this project while approval is in progress.

### Calendly account setup
- You will need a **Calendly Professional** account for this setup. This project needs calendly.com to redirect to a URL owned by you after attendee reschedule an event so that this project can cancel the event which was rescheduled.
- [Create](https://help.calendly.com/hc/en-us/articles/360043820134-Setting-up-your-first-event#setting-up-your-first-event-0-0) a one-on-one event type on calendly.com.
- Under event settings, configure the event location by changing *What event is this > Location* to **Phone call**. This is needed so that calendly.com prompts attendees to enter their phone number while scheduling appointments on calendly.com
- Under event settings, configure the confirmation page by changing *Confirmation Page > On confirmation* to **Redirect to an external site** and by changing *Confirmation Page > Redirect URL* to **https://MY_DOMAIN_NAME/confirm**.  
- Note down event's link. This will be needed when setting up resources in AWS developer account for this project.

### Google Calendar setup
- Create a project in [Google developer console](https://developers.google.com/workspace/guides/create-project) and enable Google Calendar API for the project.
- Create **Service Account** credentials for the project. Download the json for Service Account credentials temporarily on your local machine. **Note** that this json file is private and should not be made public. Let's say name of the json file on your local machine is MY_GOOGLE_SERVICE_ACCOUNT_CREDS.json
- Note the json file path down. This will be needed when setting up resources in AWS developer account for this project. 
- Note down the [email address](https://cloud.google.com/iam/docs/service-accounts#user-managed) corresponding to the Service Account you just created. It will look something like service-account-name@project-id.iam.gserviceaccount.com. Let's say the email address is MY_GOOGLE_SERVICE_ACCOUNT_EMAIL_ADDRESS. 
- We now need to go to out Google Calendar and [configure]((https://support.google.com/calendar/answer/37082?hl=en-GB)) it so that *MY_GOOGLE_SERVICE_ACCOUNT_EMAIL_ADDRESS* is allowed to access our Google Calendar. Under *Settings > Share with specific people* grant MY_GOOGLE_SERVICE_ACCOUNT_EMAIL_ADDRESS permission to *Make changes to events*.

### AWS developer account setup

Execute the following steps in **AWS region us-east-1 (IAD)**:
- Create a S3 bucket. Let's say you name it MY_S3_BUCKET.
- Upload MY_GOOGLE_SERVICE_ACCOUNT_CREDS.json from your local machine to MY_S3_BUCKET/google-event-manager-service-account.json. Delete MY_GOOGLE_SERVICE_ACCOUNT_CREDS.json from your local machine.
- Zip [lambda_function.py](lambda_function.py) which is located at project source code's root directory into google-event-manager-lambda-function.zip and upload it to MY_S3_BUCKET/google-event-manager-lambda-function.zip. To speed up initial setup, instead of zipping your own lambda-function.py you can use [pre-zipped lambda-function.py](https://github.com/rishabhjain08/google-event-manager/releases/download/Release/google-event-manager-lambda-function.zip) in Github Releases for this repo.
- Install all the python dependencies under a directory named **python** since AWS Lambda [requires](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path) python dependencies to be installed under **python** directory, then zipped and uploaded to create a Lambda layer. Upload the zip of **python** directory to MY_S3_BUCKET/google-event-manager-lambda-layer.zip. To speed up initial setup, instead of installing your own dependcies and zipping them you can use [pre-zipped python directory](https://github.com/rishabhjain08/google-event-manager/releases/download/Release/google-event-manager-lambda-layer.zip) in Github Releases for this repo.
- Create a [CloudFormation stack](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacks.html) using [template.yaml](template.yaml) located at project's source code's root directory. Note that [template.yaml](template.yaml) can be opened in [CloudFormation Designer](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/working-with-templates-cfn-designer.html).
- **Note that the stack will remain in status CREATE_IN_PROGRESS until AWS Certificate is validated. Go to AWS Certificate Manager to [validate the certificate](https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html)**.
- Get API Gateway invoke URL for API **GoogleEventManager-WhatsappMsgReceived** and assign it to Twilio *WHEN A MESSAGE COMES IN* [POST webhook URL](https://www.twilio.com/docs/messaging/guides/webhook-request#request-parameters). This will allow Twilio to POST attendee's messages to the assigned webhook URL.
- Get API Gateway invoke URL for API **GoogleEventManager-WhatsappMsgDeliveryStatus** and assign it to Twilio *STATUS CALLBACK URL* [POST webhook URL](https://www.twilio.com/docs/messaging/guides/webhook-request#status-callback-parameters). This will allow Twilio to POST message status to the assigned webhook URL.
- Add DNS record to your custom domain to route traffic to your domain name to API Gateway domain name. API Gateway domain name can be found under *Configurations* [here](https://console.aws.amazon.com/apigateway/main/publish/domain-names) 


## Limitations
- Currently AWS resources can only be created in us-east-1 since custom domain names are only supported in **us-east-1** and a CloudFormation stack cannot own cross-region AWS resources.
