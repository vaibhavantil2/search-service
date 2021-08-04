from hashids import Hashids
import time

def proccess_payment_simulation(payment_method, card_hash):
    time.sleep(60)
    hashids = Hashids(alphabet='abcdefghijklmnopqrstuvwxyz1234567890', min_length=22)
    return hashids.encode(1)

def proccess_return_products(payment_method, prod_details):
    time.sleep(60)
    hashids = Hashids(alphabet=payment_method.id)
    return hashids.encode(1), prod_details.prod_id
