from flask import Flask, request
from roo import do_roo, getlink

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello from Flask!'

@app.route('/login_account', methods=["POST"])
def login_roo():
    content = request.get_json(force=True)
    email = content['email']
    link = getlink(email)
    return {
        'link': link
    }


@app.route('/create_account', methods=["POST"])
def run_roo():

    content = request.get_json(force=True)

    session_base_url = content['session_base_url']
    sms_man_token = content['sms_man_token']
    personal_info = content['personal_info']
    card_info = content['card_info']
    address = content['address']
    voucher_code = content['voucher_code']
    redeem_voucher = content['redeem_voucher']
    print("triggered")

    print("CARD INFO")
    print(card_info)
    
    do_roo(sms_man_token, session_base_url, personal_info, card_info, address, voucher_code, redeem_voucher)

    return

if __name__ == '__main__':
    app.run()
