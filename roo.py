import random
import string
import requests
import json
import time
import uuid
from random_word import RandomWords
import os.path
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import sys

def get_random_words():
    r = RandomWords()
    return r.get_random_word() + '_' + r.get_random_word() + '_' + r.get_random_word()

def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly','https://www.googleapis.com/auth/gmail.modify']

def readEmails(query):
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                # your creds file here. Please create json file as here https://cloud.google.com/docs/authentication/getting-started
                'rookeys.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q=query).execute()
        messages = results.get('messages',[]);
        if not messages:
            print('No new messages.')
        else:
            message_count = 0
            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                email_data = msg['payload']['headers']
                for values in email_data:
                    name = values['name']
                    if name == 'From':
                        from_name= values['value']
                        for part in msg['payload']['parts']:
                            try:
                                data = part['body']["data"]
                                byte_code = base64.urlsafe_b64decode(data)

                                text = byte_code.decode("utf-8")

                                myresult = text.split("please follow the link below:\r\n")[1].split("\r\nCopyright 2023 Deliveroo")[0]
                                #service.users().messages().delete(userId='me', id=message['id']).execute()
                                if 'please follow the link below:' in text:
                                    service.users().messages().trash(userId='me', id=message['id']).execute()
                                    return myresult


                                #print(msg)
                            except BaseException as error:
                                pass
    except Exception as error:
        print(f'An error occurred: {error}')

def getlink(email):

    get_magic_link(email)

    print("waiting for the magic link to arrive")
    time.sleep(12)

    query = f"from:noreply@t.deliveroo.com to:{email}"
    return readEmails(query)

def get_session_with_promo(session_base_url, voucher_code):

    for i in range(0,13):

        proxy_info = {
            'http': 'http://XaieaXO45f0Mj6sK:wifi;us;;;@rotating.proxyempire.io:9000',
            'https': 'http://XaieaXO45f0Mj6sK:wifi;us;;;@rotating.proxyempire.io:9000'
        }

        session = requests.Session()
        session.proxies = proxy_info
        
        r = session.get(session_base_url)
        
        if voucher_code in r.text:
            print('found session!')

            guid = r.text.split('"rooGuid":"')[1].split('","')[0]
            session_guid = r.text.split('"rooSessionGuid":"')[1].split('","')[0]

            return [session, guid, session_guid]
        else:
            print('did not find session, trying another...')
    return

def get_deliveroo_number(sms_man_token):
    deliveroo_code = '234'
    country_code = '100'

    r = requests.get(f"http://api.sms-man.com/control/get-number?token={sms_man_token}&country_id={country_code}&application_id={deliveroo_code}")
    print(r)
    print(r.text)
    return r.json()

def get_phone_no(sms_man_token):
    data = get_deliveroo_number(sms_man_token)
    return data['number'], data['request_id']

def reject_deliveroo_number(sms_man_token, request_id):
    r = requests.get(f"http://api.sms-man.com/control/set-status?token={sms_man_token}&request_id={request_id}&status=reject")

    return r.json()

def get_sms(sms_man_token, request_id):
    r = requests.get(f"http://api.sms-man.com/control/get-sms?token={sms_man_token}&request_id={request_id}")

    return r.json()

def send_code(session, number, guid, session_guid):
    headers = {
        "accept": "application/json, application/vnd.api+json",
        "accept-language": "en",
        "authorization": "",
        "content-type": "application/json",
        "x-roo-client": "consumer-web-app",
        "x-roo-client-referer": "https://deliveroo.co.uk/",
        "x-roo-country": "uk",
        "x-roo-external-device-id": "",
        "x-roo-guid": guid,
        "x-roo-sticky-guid": guid,
        "x-roo-session-guid": session_guid
    }

    data = {
        'verification_address': number,
        'verification_method': 'sms',
        'verification_trigger': 'account_creation'
    }

    url = "https://deliveroo.co.uk/send_verification_code"
    body = json.dumps(data)

    r = session.post(url, data=body, headers=headers)
    print("Sent code to number....")
    return r.json()

def verify_code(session, number, code, guid, session_guid):

    url = "https://deliveroo.co.uk/verify_code"

    headers = {
            "accept": "application/json, application/vnd.api+json",
            "accept-language": "en",
            "authorization": "",
            "content-type": "application/json",
            "x-roo-client": "consumer-web-app",
            "x-roo-client-referer": "https://deliveroo.co.uk/",
            "x-roo-country": "uk",
            "x-roo-external-device-id": "",
            "x-roo-guid": guid,
            "x-roo-sticky-guid": guid,
            "x-roo-session-guid": session_guid
        }


    body = {
        'verification_code': code,
        'verification_address': number,
        'verification_method': 'sms',
        'verification_trigger': 'account_creation'
    }

    r = session.post(url, headers=headers, data=json.dumps(body))

    return r.json()

def create_account(personal_info, session, number, secret, email, guid, session_guid):

    url = "https://api.uk.deliveroo.com/orderapp/v1/users"

    headers = {
        "accept": "application/json, application/vnd.api+json",
        "accept-language": "en",
        "authorization": "",
        "content-type": "application/json",
        "x-roo-client": "consumer-web-app",
        "x-roo-client-referer": "https://deliveroo.co.uk/",
        "x-roo-country": "uk",
        "x-roo-external-device-id": "",
        "x-roo-guid": guid,
        "x-roo-sticky-guid": guid,
        "x-roo-session-guid": session_guid
    }
    body = {
        'first_name': personal_info['first_name'],
        'last_name': personal_info['last_name'],
        'full_name': '',
        'preferred_name': '',
        'email': email,
        'password': 'SomeRooPW12345!',
        'client_type': 'web',
        'country': 'uk',
        'mobile': number,
        'verification_secret': secret

    }

    r = session.post(url, headers=headers, data=json.dumps(body))

    return r.json()

def add_address(address, session, number, user_id, bearer_token, guid, session_guid):

    url = f"https://api.uk.deliveroo.com/orderapp/v2/users/{user_id}/addresses?market=gb"

    headers = {
        "accept": "application/json, application/vnd.api+json",
        "accept-language": "en",
        "authorization": f"Bearer {bearer_token}",
        "content-type": "application/json",
        "x-roo-client": "consumer-web-app",
        "x-roo-client-referer": "https://deliveroo.co.uk/",
        "x-roo-country": "uk",
        "x-roo-external-device-id": "",
        "x-roo-guid": guid,
        "x-roo-sticky-guid": guid,
        "x-roo-session-guid": session_guid
    }



    body = {
        "street_address": address['street_address'],
        "city_town": address['city_town'],
        "post_code": address['post_code'],
        "apartment": address['apartment'],
        "phone": number,
        "coordinates": address['coordinates'],
        "country": "UK",
        "checkout_id": ""
    }

    r = session.post(url, headers=headers, data=json.dumps(body))

    return r.json()

def redeem_code(session, voucher, user_id, guid, session_guid, bearer_token):

    headers = {
        "accept": "application/json, application/vnd.api+json",
        "accept-language": "en",
        "authorization": f"Bearer {bearer_token}",
        "content-type": "application/json",
        "x-roo-client": "consumer-web-app",
        "x-roo-client-referer": "https://deliveroo.co.uk/",
        "x-roo-country": "uk",
        "x-roo-external-device-id": "",
        "x-roo-guid": guid,
        "x-roo-sticky-guid": guid,
        "x-roo-session-guid": session_guid
    }

    url = f'https://api.uk.deliveroo.com/orderapp/v1/users/{user_id}/vouchers'


    body = {
        'page': 'account',
        'redemption_code': voucher
    }

    r = session.post(url, headers=headers, data=json.dumps(body))

    print(r)

    print(r.text)

    return r.json()

def poll_number(sms_man_token, request_id):

    for i in range(0,20):
        poll_sms_response = get_sms(sms_man_token, request_id)
        if 'sms_code' in poll_sms_response:
            return poll_sms_response['sms_code']
        else:
            print("Still waiting for code...")
            time.sleep(0.8)

    #no sms found, try again
    reject_deliveroo_number(sms_man_token, request_id)
    print('rejected')

    return 'rejected'

def get_magic_link(email):
    url = "https://api.uk.deliveroo.com/orderapp/v1/login/generate_magic_link"
    body = {
        'email': email,
        'redirect_path': '/',
        'page_in_progress': 'login'
    }
    headers = {
        "accept": "application/json, application/vnd.api+json",
        "accept-language": "en",
        "authorization": "",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "pragma": "no-cache",
        "sec-ch-ua": "\"Google Chrome\";v=\"111\", \"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"111\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"macOS\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
        "x-roo-client": "consumer-web-app",
        "x-roo-client-referer": "https://deliveroo.co.uk/",
        "x-roo-country": "uk",
        "x-roo-external-device-id": "",
    }

    r = requests.post(url, data=json.dumps(body), headers=headers)

    return r

def generate_stripe_token(card_info):

    url = "https://api.stripe.com/v1/tokens"
    headers = {
        "accept": "application/json",
        "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
        "cache-control": "no-cache",
        "content-type": "application/x-www-form-urlencoded",
        "pragma": "no-cache",
        "sec-ch-ua": "\"Google Chrome\";v=\"111\", \"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"111\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"macOS\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site"
      }

    #guid = "6c30b562-25d7-4317-b430-7ab8fd75dd652aa600"
    guid = uuid.uuid4()
    #muid = "b2c7a226-c4b9-4a57-9723-cc824db04e2aa8862c"
    muid = uuid.uuid4()
    #sid = "94063575-32ea-463e-b71c-e3b5e13fb401489e83"
    sid = uuid.uuid4()

    pan = card_info['pan']
    cvc = card_info['cvc']
    exp_month = card_info['exp_month']
    exp_year = card_info['exp_year']
    zip_code = card_info['zip_code']

    body = f"card[number]={pan}&card[cvc]={cvc}&card[exp_month]={exp_month}&card[exp_year]={exp_year}&card[address_zip]={zip_code}&guid={guid}&muid={muid}&sid={sid}&payment_user_agent=stripe.js%2Fd982bef7e1%3B+stripe-js-v3%2Fd982bef7e1&time_on_page=516479&key=pk_live_Xon38nmuPwMk6T5SAfyPglmv&_stripe_version=2022-11-15"

    r = requests.post(url, headers=headers, data=body)

    return r.json()

def add_token(nonce, user_id, bearer_token, guid, session_guid):

    print("USER ID")
    print(user_id)
    print("######")

    print("GUID")
    print(guid)
    print("######")

    print("SESSION GUID")
    print(session_guid)
    print("######")

    proxy_info = {
        'http': 'http://XaieaXO45f0Mj6sK:wifi;us;;;@rotating.proxyempire.io:9000',
        'https': 'http://XaieaXO45f0Mj6sK:wifi;us;;;@rotating.proxyempire.io:9000'
    }

    session = requests.Session()
    session.proxies = proxy_info

    url = f"https://api.uk.deliveroo.com/orderapp/v1/users/{user_id}/payment-tokens"

    headers = {
            "accept": "application/json, application/vnd.api+json",
            "accept-language": "en",
            "authorization": f"Bearer {bearer_token}",
            "content-type": "application/json",
            "x-roo-client": "consumer-web-app",
            "x-roo-client-referer": "https://deliveroo.co.uk/",
            "x-roo-country": "uk",
            "x-roo-external-device-id": "",
            "x-roo-guid": guid,
            "x-roo-sticky-guid": guid,
            "x-roo-session-guid": session_guid
        }
    
    session.headers.update(headers)

    body = {
        "provider": "stripe",
        "nonce": str(nonce),
        "checkout_id": str(uuid.uuid4()),
    }

    r = session.post(url, headers=headers, data=json.dumps(body))

    print(r)
    print(r.text)

    return r.json()

def signup_plus_trail(payment_method_id, user_id, bearer_token, guid, session_guid):

    proxy_info = {
        'http': 'http://XaieaXO45f0Mj6sK:wifi;us;;;@rotating.proxyempire.io:9000',
        'https': 'http://XaieaXO45f0Mj6sK:wifi;us;;;@rotating.proxyempire.io:9000'
    }

    session = requests.Session()
    session.proxies = proxy_info

    url = f"https://api.uk.deliveroo.com/orderapp/v1/users/{user_id}/subscriptions"

    headers = {
        "accept": "application/json, application/vnd.api+json",
        "accept-language": "en",
        "authorization": f"Bearer {bearer_token}",
        "content-type": "application/json",
        "x-roo-client": "consumer-web-app",
        "x-roo-client-referer": "https://deliveroo.co.uk/",
        "x-roo-country": "uk",
        "x-roo-external-device-id": "",
        "x-roo-guid": guid,
        "x-roo-sticky-guid": guid,
        "x-roo-session-guid": session_guid
    }

    body = {
        "offer_uname": "uk_monthly_799_2022Q4_90dft",
        "payment_method_id": payment_method_id,
        "immediate_charge_ack": False
    }

    r = session.post(url, headers=headers, data=json.dumps(body))

    print("##PLUS##")
    print(r)
    print(r.text)

    return r.json()

def send_message_whatsapp(message, user_phone):

    url = f"http://68.183.40.173:3000/api/sendText?phone={user_phone}&text={message}&session=roo"

    payload={}
    headers = {
      'x-api-key': 'ed28cd74-d33b-495f-be42-d4faa9b463ee'
    }

    r = requests.request("GET", url, headers=headers, data=payload)

    return r.json()

def do_roo(sms_man_token, session_base_url, personal_info, card_info, address, voucher_code):

    proceed = False
    user_phone = personal_info["user_phone"]

    email_suffix = 'puppet.lol'

    number, request_id = get_phone_no(sms_man_token)
    email = get_random_words() + '@' + email_suffix
    print(f"generated the email id {email} for you")
    send_message_whatsapp(f"generated the email id {email} for you", user_phone)
    session_data = get_session_with_promo(session_base_url, voucher_code)
    session = session_data[0]
    guid = session_data[1]
    session_guid = session_data[2]
    print("Waiting for number to become active...")
    send_message_whatsapp("Waiting for number to become active...", user_phone)
    time.sleep(8)
    send_code(session, number, guid, session_guid)

    print("Sent code to phone number...")

    code = poll_number(sms_man_token, request_id)

    if code == 'rejected':

        print("phone number didn't work, trying again")
        send_message_whatsapp("phone number didn't work, trying again", user_phone)

        number, request_id = get_phone_no(sms_man_token)
        email = get_random_words() + '@' + email_suffix
        print(f"generated the email id {email} for you")
        send_message_whatsapp(f"generated the email id {email} for you", user_phone)
        session_data = get_session_with_promo(session_base_url, voucher_code)
        session = session_data[0]
        guid = session_data[1]
        session_guid = session_data[2]
        print("Waiting for number to become active...")
        time.sleep(8)
        send_code(session, number, guid, session_guid)

        print("Sent code to phone number...")

        code = poll_number(sms_man_token, request_id)

        if code == 'rejected':

            send_message_whatsapp("phone number didn't work, trying again", user_phone)
            number, request_id = get_phone_no(sms_man_token)
            email = get_random_words() + '@' + email_suffix
            print(f"generated the email id {email} for you")
            send_message_whatsapp(f"generated the email id {email} for you", user_phone)
            session_data = get_session_with_promo(session_base_url, voucher_code)
            session = session_data[0]
            guid = session_data[1]
            session_guid = session_data[2]
            print("Waiting for number to become active...")
            time.sleep(8)
            send_code(session, number, guid, session_guid)

            print("Sent code to phone number...")

            code = poll_number(sms_man_token, request_id)

            if code == 'rejected':
                proceed = False

            else:
                proceed = True

        else:
            proceed = True

    else:
        proceed = True

    if proceed == True:
        print("Succesfully got a code, proceeding")
        send_message_whatsapp("Succesfully got a code, proceeding", user_phone)
        #pass the verification code to deliveroo
        verify_code_response = verify_code(session, number, code, guid, session_guid)

        secret = verify_code_response['verification_secret']

        print("verified phone number")
        send_message_whatsapp("verified phone number", user_phone)

        #Create deliveroo account
        create_account_response = create_account(personal_info, session, number, secret, email, guid, session_guid)

        #Get auth token and user id
        user_id = create_account_response['id']
        bearer_token = create_account_response['consumer_auth_token']

        print("BEARER TOKEN")
        print(bearer_token)
        print("#####")

        print("generated account")
        send_message_whatsapp("generated account", user_phone)

        #Redeem voucher code
        redeem_code(session, voucher_code, user_id, guid, session_guid, bearer_token)

        print("redeemed voucher")

        #add address
        add_address(address, session, number, user_id, bearer_token, guid, session_guid)

        print("added address")

        #add the card
        #generate stripe token if none were provided
        if 'nonce' not in card_info:
            nonce = generate_stripe_token(card_info)['id']
        else:
            nonce = card_info['nonce']

        #add token to roo account
        payment_method_id = add_token(nonce, user_id, bearer_token, guid, session_guid)['id']
        print("added your disposable card to the account")
        send_message_whatsapp("added your disposable card to the account", user_phone)

        #signup for the deliveroo plus trail
        signup_plus_trail(payment_method_id, user_id, bearer_token, guid, session_guid)
        print("signed you up for the deliveroo plus trail")

        #generate magic link
        link = getlink(email)
        print(f"generated a magic link for account {email}")

        #send link to user via whatsapp
        send_message_whatsapp(link, user_phone)

        return email

    else:
        print("Had to stop after three unsuccesful attempts, please try again")

