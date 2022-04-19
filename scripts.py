import json
from urllib.request import urlopen, Request
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Check field names for potential password identifiers (and some username identifiers)
def check_for_password_field(filename):
    # most common naming conventions for the password field in a database (and some username fields)
    potential_pass_fields = ['password','passwd','passwrd','pw','pass','pwrd','pword','pwd','passwords','passwds','pws','passwrds','pwords','pwds', 'username', 'uname', 'user', 'name', 'account', 'accountname']

    file = open(filename)
    data = json.load(file)

    results2 = []
    results = {}

    for index in range(0, len(data)):
        if 'type' in data[index]:
            if data[index]['type'] == 'table':
                # get current tablename
                tablename = data[index]['name']
        if 'data' in data[index]:
            # Found data in dictionary, check for a password field
            for password in potential_pass_fields:
                # No need to check every entry, all entries in one table will have the same fields.
                for key in data[index]['data'][0].keys():
                    if password == key.lower():
                        results[key] = tablename
                        results2.append(results.copy())
                        results.clear()
    return results2

# Check file for address fields
def check_for_address_field(filename, already_sensitive):
    
    file = open(filename)
    data = json.load(file)

    table = {}
    field = []
    field_names = []

    # get the field names inside of the json file
    for index in range(0, len(data)):
        if 'type' in data[index]:
            if data[index]['type'] == 'table':
                # get current tablename
                tablename = data[index]['name']
        if 'data' in data[index]:
            for key in data[index]['data'][0]:
                field.append(key)
            table[tablename] = field
            field_names.append(table.copy())
            table.clear()
            field = []

    # Field : Table
    is_address = {}
    results = []
    count_field = 0
    count_address = 0

    for index in range(0, len(field_names)):
        for table in field_names[index]:
            # table == current table
            for ind in range(0, len(data)):
                if 'data' in data[ind]:
                    if data[ind]['name'] == table:
                        for field in field_names[index][table]:
                            # field == id, Name, SSN -> from field_names

                            # If field was already detected dont check it
                            if not field in str(already_sensitive):
                                for index1 in range(0, len(data[ind]['data'])):
                                    # {"id":"4","passwrd":"Patric Steward","pass":"sedhdhs"}
                                    for key in data[ind]['data'][index1].keys():
                                        # key == id, Name, SSN -> from data

                                        if key == field:
                                            count_field += 1
                                            # check if it is an address
                                            check_address = data[ind]['data'][index1][key]
                                            if isinstance(check_address, str):
                                                check_address = check_address.replace(" ", "+")
                                                url = "https://www.google.com/search?q=" + check_address

                                                req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36'})
                                                webpage_bytes = urlopen(req).read()

                                                webpage_str = webpage_bytes.decode("utf8")
                                                keywords = ["address", "rent", "property"]
                                                count = 0
                                                for word in webpage_str.split():
                                                    if word in keywords:
                                                        count = count + 1
                                                # From testing 3 occurences is ideal. (Least amount of fake positives and fake negatives)
                                                if count >= 3:
                                                    count_address += 1

                            # calculate address field probability
                            if count_address != 0:
                                probability = (count_address / count_field) * 100
                            else:
                                probability = 0
                            # if more than 40% of values in column is address, then the field is an address field
                            if probability >= 40.0:
                                is_address[field] = table
                                results.append(is_address.copy())
                                is_address.clear()

                            count_field = 0
                            count_address = 0
    return results

# Checks if json file was exported from phpmyadmin (only supported json export)
def check_file(filename):
    file = open(filename)
    data = json.load(file)
    str_data = str(data)

    if 'PHPMyAdmin' in str_data:
        return True
    else:
        return False

# Estimate how long encryption would take
def calculate_encryption_time(data):
    def encrypt(data):
        byte_data = data.encode("utf-8")
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX)
        cipher.encrypt_and_digest(byte_data)

    data = str(data)
    start = time.time()
    encrypt(data)
    duration = time.time() - start
    return str(duration)

