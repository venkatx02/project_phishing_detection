from flask import Flask, render_template, request
import pickle
from urllib.parse import urlparse, urlsplit
import re
import urllib
import tldextract
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import time
import dns.resolver
import pandas as pd #importing pandas library - used for managing dataframe
import numpy as np #importing numpy - used for mathematical calculations
from sklearn.model_selection import train_test_split #used for splitting train and test data
from xgboost import XGBClassifier #importing XGBoost
#importing some performance metrics
from sklearn.metrics import confusion_matrix 
from sklearn.metrics import f1_score
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
#importing libraries for data visualization
import seaborn as sns
import matplotlib.pyplot as plt


app = Flask(__name__)
xgbModel = pickle.load(open("xgbModel.pkl", "rb"))


@app.route('/', methods=['GET'])
def main():
    return render_template('index.html')

@app.route('/', methods=['POST'])
def predict():
    url = request.form['urllink']

    def get_hostname(url):
        urlinfo = urllib.parse.urlsplit(url)
        return urlinfo.hostname
    def get_domain(url):
        return tldextract.extract(url).domain
    def get_path(url):
        urlinfo = urllib.parse.urlsplit(url)
        return urlinfo.path
    hostname = get_hostname(url)
    domain = get_domain(url)
    path = get_path(url)
    def url_length(url):
        return len(url) 
    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
            '[0-9a-fA-F]{7}', url)  # Ipv6
        if match:
            return 1
        else:
            return 0
    def count_dots(hostname):
        return hostname.count('.')
    def count_hyphens(url):
        return url.count('-')
    def count_at(url):
        return url.count('@')
    def count_slash(url):
        return url.count('/')
    def count_double_slash(url):
        list=[x.start(0) for x in re.finditer('//', url)]
        if list[len(list)-1]>6:
            return 1
        else:
            return 0
        return url.count('//')
    def count_http_token(url):
        return url.count('http')
    def ratio_digits(url):
        return len(re.sub("[^0-9]", "", url))/len(url)
    def prefix_suffix(url):
        if re.findall(r"https?://[^\-]+-[^\-]+/", url):
            return 1
        else:
            return 0 
    def shortening_service(url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                        'tr\.im|link\.zip\.net',
                        url)
        if match:
            return 1
        else:
            return 0
    try:
        reqs = requests.get(url)
        soup = BeautifulSoup(reqs.text, 'html.parser')
        count=0
    
        urls = []
        for link in soup.find_all('a'):
            count = count+1
        nb_hyperlinks = count
    except:
        nb_hyperlinks = 0
    try:
        response = requests.get(url)
        pagecontent = response.content
    except:
        pagecontent = ""
    def iframe(content):
        if content == "":
            return 1
        else:
            if re.findall(r"[<iframe>|<frameBorder>]", str(content)):
                return 0
            else:
                return 1
    def rightClick(content):
        if content == "":
            return 1
        else:
            if re.findall(r"event.button ?== ?2", str(content)):
                return 1
            else:
                return 0
    extracted_domain = tldextract.extract(url)
    soup = BeautifulSoup(pagecontent, 'html.parser', from_encoding='iso-8859-1')
    Text = soup.get_text()
    def domain_with_copyright(domain, content):
        try:
            m = re.search(u'(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})', content)
            _copyright = content[m.span()[0]-50:m.span()[0]+50]
            if domain.lower() in _copyright.lower():
                return 0
            else:
                return 1
        except:
            return 1
    def whois_registered_domain(domain):
        try:
            hostname = whois.whois(domain).domain_name
            if type(hostname) == list:
                for host in hostname:
                    if re.search(host.lower(), domain):
                        return 0
                return 1
            else:
                if re.search(hostname.lower(), domain):
                    return 0
                else:
                    return 1     
        except:
            return 1
    def domain_registration_length(domain):
        try:
            res = whois.whois(domain)
            expiration_date = res.expiration_date
            today = time.strftime('%Y-%m-%d')
            today = datetime.strptime(today, '%Y-%m-%d')
            # Some domains do not have expiration dates. The application should not raise an error if this is the case.
            if expiration_date:
                if type(expiration_date) == list:
                    expiration_date = min(expiration_date)
                return abs((expiration_date - today).days)
            else:
                return 0
        except:
            return -1
    URL = "https://endpoint.apivoid.com/domainage/v1/pay-as-you-go/?key=c1b80285225711816ec3ff48c7c43a58b970e0e3&host="+hostname
    r = requests.get(url = URL)
    data = r.json()
    try:
        domain_age = data['data']['domain_age_in_days']
    except:
        domain_age = -1
    def web_traffic(url):
            try:
                rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
            except:
                return 0
            return int(rank)
    domaincomsplit = urlparse(url).netloc
    domaincom = '.'.join(domaincomsplit.split('.')[-2:])
    def dns_record(domaincom):
        try:
            nameservers = dns.resolver.resolve(domaincom,'NS')
            if len(nameservers)>0:
                return 0
            else:
                return 1
        except:
            return 1
    def google_index(url):
        google = "https://www.google.com/search?q=site:" + url + "&hl=en"
        response = requests.get(google, cookies={"CONSENT": "YES+1"})
        soup = BeautifulSoup(response.content, "html.parser")
        not_indexed = re.compile("did not match any documents")
        if soup(text=not_indexed):
            return 1
        else:
            return 0
    URL = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D='+domaincom
    key = 's8wsc84cgcckckkscg4c04k48s4s8k08w0k0gokk'
    r = requests.get(url = URL, headers={'API-OPR':key})
    data = r.json()
    page_rank = data['response'][0]['page_rank_integer']


    feature_array = []
    feature_array.append(url_length(url))
    feature_array.append(having_ip_address(url))
    feature_array.append(count_dots(hostname))
    feature_array.append(count_hyphens(url))
    feature_array.append(count_at(url))
    feature_array.append(count_slash(url))
    feature_array.append(count_double_slash(url))
    feature_array.append(count_http_token(url))
    feature_array.append(ratio_digits(url))
    feature_array.append(prefix_suffix(url))
    feature_array.append(shortening_service(url))
    feature_array.append(nb_hyperlinks)
    feature_array.append(iframe(pagecontent))
    feature_array.append(rightClick(pagecontent))
    feature_array.append(domain_with_copyright(domain, Text))
    feature_array.append(whois_registered_domain(hostname))
    feature_array.append(domain_registration_length(hostname))
    feature_array.append(domain_age)
    feature_array.append(web_traffic(url))
    feature_array.append(dns_record(domaincom))
    feature_array.append(google_index(url))
    feature_array.append(page_rank)

    fa = [feature_array]
    feature_names = ['length_url', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_slash', 'nb_dslash', 'https_token', 'ratio_digits_url', 'prefix_suffix', 'shortening_service', 'nb_hyperlinks', 'iframe', 'right_clic', 'domain_with_copyright', 'whois_registered_domain', 'domain_registration_length', 'domain_age', 'web_traffic', 'dns_record', 'google_index', 'page_rank']
    feature_frame = pd.DataFrame(fa, columns= feature_names)
    pred = xgbModel.predict(feature_frame)

    if pred[0]==0:
        classification = "This URL is benign and safe to use!"
    if pred[0]==1:
        classification = "This URL is phishing and avoid using this site!"

    return render_template('index.html', prediction=classification, urllink=url)

if __name__ == '__main__':
    app.run(port=3000, debug=True)

