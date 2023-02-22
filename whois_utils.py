import regex
import os
import subprocess
import json
DIR_PATH = os.path.dirname(os.path.realpath(__file__))
WHOIS_PATH = os.path.join(DIR_PATH,'dsource' ,  'whois.exe')
REGEX_IP = r'^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$'
REGEX_URL = r'^(https?://)?([\da-z.-]+).([a-z.]{2,6})([/\w .-])/?$'
REGEX_WHOIS_ENTRY = r'[a-zA-Z ]*: .*'

def remove_control_characters(dictionary):
    """Removes all control characters from a dictionary"""
    control_chars = ''.join(map(chr, range(0, 32))) + ''.join(map(chr, range(127, 160)))
    table = str.maketrans(dict.fromkeys(control_chars))
    cleaned_dict = {}
    for key, value in dictionary.items():
        if isinstance(value, dict):
            cleaned_dict[key] = remove_control_characters(value)
        elif isinstance(value, str):
            cleaned_dict[key] = value.translate(table)
        else:
            cleaned_dict[key] = value
    return cleaned_dict

def matches_whois(string: str):
    return regex.match(REGEX_WHOIS_ENTRY, string)

def dump_json(d_str: dict):
    cleaned_dict = remove_control_characters(d_str)
    dict_string = ""
    dict_string = json.dumps(cleaned_dict, sort_keys=True)
    return dict_string

def sanitize_input(input_str: str):
    # Regular expression to check if the input is a valid IP address or URL
    # Check if the input matches either the IP or URL regex
    if regex.match(REGEX_IP, input_str) or regex.match(REGEX_URL, input_str):
        return input_str
    else:
        raise ValueError("Input must be a valid IP address or URL")

def open_whois_pipe(name: str):
    result = subprocess.run([WHOIS_PATH,"-nobanner", name], capture_output=True, text=True)
    return result
    