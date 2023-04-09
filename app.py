from flask import Flask, request
from roo import do_roo

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello from Flask!'

@app.route('/roo', methods=["POST"])
def run_roo():

    content = request.get_json(force=True)

    session_base_url = content['session_base_url']
    email_suffix = content['email_suffix']
    personal_info = content['personal_info']
    card_info = content['card_info']
    address = content['address']
    voucher_code = content['voucher_code']
    print("triggered")

    print("CARD INFO")
    print(card_info)

    #return (session_base_url, email_suffix, address)
    do_roo(session_base_url, email_suffix, personal_info, card_info, address, voucher_code)

    return

if __name__ == '__main__':
    app.run()