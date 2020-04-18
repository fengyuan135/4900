import sys,getopt,os

# Porcessing part import
import argparse
import errno, pathlib, re
import datetime, time
import json, requests, urllib.request
import sqlite3
import logging

# Format result csv part import
import argparse
import sys, os
import errno, pathlib, re
import datetime, time
import json, requests, urllib.request
import sqlite3
import logging
import csv
import hashlib
import urllib.request
import pycurl
import whois
from datetime import datetime
from bs4 import BeautifulSoup
import urllib.request
import re
import xlwt
import dns.resolver
from requests import get
from urllib.parse import urlparse
from shodan import Shodan

api = Shodan('td0ah1yDHDOuEKn6eovHziYCQHutaOA9')

def main(argv):
    web_list_path = ''
    current_path = os.path.abspath('.')
    try:
        opts, args = getopt.getopt(argv, 'f:')
    except getopt.GetoptError:
        print ('Error')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-f'):
            web_list_path = arg
    print("web_list_path = " + web_list_path)
    print("current_path = " + current_path)

    # Process web list and upload to urlscan api to get relative uuid list
    print("Processing web list and upload to urlscan api to get relative uuid list")
    urls_to_scan = [line.rstrip('\n') for line in open(web_list_path,encoding='utf-8-sig', errors='ignore')]

    uuidList= open(current_path + '/uuid.txt',"w")
    processing_number = 1
    
    for target_url in urls_to_scan:
        headers = {
            'Content-Type': 'application/json',
            'API-Key': 'f6ac1a5e-39f5-4937-9c44-6bd0bd88f8c2',
        }
        
        data = '{"url": "%s", "public": "on"}' % target_url 
        
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=data.encode('utf-8'))
        
        if (response.status_code != 200):
            print("Server didn't return an 'OK' response.  Content was: {!r}".format(response.content))
            continue
        else:
            print(response.json())
            ## end POST request
            print()
            print("Working on file number: " + str(processing_number))
            if response.json().get("uuid") is None:
                continue
            uuid = response.json().get("uuid")
            print("print uuid:")
            print(uuid)
            uuidList.write(uuid + "\n")
            processing_number = processing_number + 1
            
            time.sleep(2)
    uuidList.close()

    print("Complete uuid processing")
    print()
    print("Format result csv part")

    with open(current_path + '/dataset.csv', 'w') as csvfile:
        fieldnames = ['url','ip_address', 'Country','server', 'ptr','asn' , 'asnname','domain','malicious','ads_blocked',
        'totalLinks','urlScore','secureRequests','securePercentage','IPv6Percentage','certificate','favicon_hash_value',
        'protocol','dom','domain_age','contain_prefix','url_length','dot_number','validatity_period_time_stamp','is_redirect',
        'iframe_number','mailtos_number','a_tag_number',
        'domain_in_url','MX','NS','SOA','right_disable','hover_change_status_bar',
        'indexed_by_google','webpage_rank','a_tag_url_number_percentage','meta_link_percentage','contain_popup_window',
        'open_ports_number','referers','GET_request_percentage','POST_request_percentage','HEAD_request_percentage','PUT_request_percentage',
        'DELETE_request_percentage','CONNECT_request_percentage','OPTIONS_request_percentage','Phishing']
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        print('current_path = ' + current_path)
        print('open uuid list')
        uuids_to_scan = [line.rstrip('\n') for line in open(current_path + "/uuid.txt")]
        fileNum=1
        
        print('get information from urlscan')
        for target_uuid in uuids_to_scan:
            response = requests.get('https://urlscan.io/api/v1/result/' + target_uuid + '/')
            content= response.json()
            if (content.get("data") is None):
                continue
            
            request_info = content.get("data").get("requests")
            verdict_info = content.get("verdicts")
            list_info = content.get("lists")
            stats_info = content.get("stats")
            page_info = content.get("page")
            
            ### more specific data
            print('get more specific data')
            protocol_info = stats_info.get("protocolStats")
            
            ### data for summary
            print('get data for summary')
            page_domain = page_info.get("domain")
            page_ip = page_info.get("ip")
            if (page_ip is None):
                continue
            page_country = page_info.get("country")
            page_server = page_info.get("server")
            ptr= page_info.get('ptr')
            asn= page_info.get('asn')
            asnname = page_info.get('asnname')
            ads_blocked = stats_info.get("adBlocked")
            securePercentage = stats_info.get("securePercentage")
            secureRequests= stats_info.get("secureRequests")
            ipv6_percentage = stats_info.get("IPv6Percentage")
            totalLinks= stats_info.get("totalLinks")
            score=verdict_info.get("overall").get("score")
            
            if verdict_info.get("overall").get("malicious") == True:
                is_malicious = 1
            else:
                is_malicious = 0
            
            urls = page_info.get("url")
            certificate= list_info.get("certificates")
            certificates=None
            if(certificate is None):
                certificates= 0
            else:
                certificates=1
            
            domurl=  content.get("task").get("domURL")
            domContent =requests.get(domurl).text
            print("Working on file number: " + str(fileNum))
            
            
            #print(domContent)
            try:
                dom = hashlib.md5(domContent.encode()).hexdigest()
                print("Hash: " + dom)
                print(' ')
                page_protocol = protocol_info[0].get("protocol")
            except:
                page_protocol = 0
                
            #get favicon hash
            try:
                response1 = requests.get("https://www.google.com/s2/favicons?domain="+page_domain)
                favicon = response1.content
                favicon_hash_value = hashlib.md5(favicon).hexdigest()
            except:
                favicon_hash_value = 0
            print('favicon hash done')
            
            
            #get age of domain and validatity period
            try:
                domain = whois.query(page_domain)
                domain_age = (datetime.now() - domain.creation_date).total_seconds
                validatity_period = domain.__dict__.get("expiration_date")
                date_o = time.strptime(validatity_period, '%Y-%m-%d %H:%M:%S')
                validatity_period_time_stamp = int(time.mktime(date_o))
            except:
                domain_age = 0
                validatity_period_time_stamp = 0
            print('age calculated')
            
            #check if url contain prefix
            prefixes = ["http", "ftp", "news", "telnet", "gopher", "wais", "mailto", "file"]
            contain_prefix = False
            try:
                for prefix in prefixes:
                    if (urls.startswith(prefix)):
                        contain_prefix = 1
                        break
            except:
                contain_prefix = 0
            print('prefix done')
            
            
            #get url length and dot numbers
            try:
                url_length = len(urls)
            except:
                dot_number = 0
            
            try:
                dot_number = urls.count('.')
            except:
                dot_number = 0
                
            #get redirect times
            try:
                response = requests.get('https://urlscan.io/api/v1/result/' + target_uuid + '/')
                content= response.json()
                redirect_times = content.get("stats").get("domainStats")[0].get("redirects")
                if redirect_times > 0:
                    is_redirect = 1
                else:
                    is_redirect = 0
            except:
                is_redirect = 0
            print('redirect done')
            
            #get iframe and a tag numbers 
            try:
                req = urllib.request.Request(urls)
                webpage = urllib.request.urlopen(req)
                html = webpage.read()
                soup = BeautifulSoup(html, 'html.parser')
                iframe_number = (len(soup.find_all('iframe')))
                a_tag_number = (len(soup.find_all('a')))
                
                meta_link_number = (len(soup.find_all('meta')['href']))
                if (totalLinks != 0):
                    meta_link_percentage = meta_link_number / totalLinks
                else:
                    meta_link_percentage = 0
            except:
                iframe_number = 0
                a_tag_number = 0
                a_tag_url_number_percentage = 0
                meta_link_percentage = 0
            print('meta tage done')
            
            #get mailto numbers
            wb = xlwt.Workbook()
            ws = wb.add_sheet('Emails')
            ws.write(0,0,'Emails')
            emailList = []
            mailtos_number = 0
            try:
                getH = requests.get(urls)
                h = getH.content
                soup = BeautifulSoup(h,'html.parser')
                mailtos = soup.select('[href^=mailto]')
                for i in mailtos:
                    href = i['href']
                    try:
                        str1, str2 = href.split(':')
                    except ValueError:
                        break
                    emailList.append(str2)
                    mailtos_number = len(emailList)
            except:
                mailtos_number = 0
            print('mailto done')
            
            #check if domain is contained in url
            try:
                if page_domain in urls:
                    domain_in_url = 1
                else:
                    domain_in_url = 0
            except:
                domain_in_url = 0
            
            #check dns record(MX, NS, SOA,CNAME)
            try:
                MX = dns.resolver.query(page_domain, "MX")
            except:
                MX = 0
            try:
                NS = dns.resolver.query(page_domain, "NS")
            except:
                NS = 0
            try:
                SOA = dns.resolver.query(page_domain, "SOA")
            except:
                SOA = 0
            print('record part done')
            
            #check if right click disable, hover change status bar
            right_disable = 0
            hover_change_status_bar = 0
            contain_popup_window = 0
            try:
                r = requests.get(urls)
                txt = r.text
                with open (current_path + "/temple.txt","w") as f:
                    f.write(txt)
                    f.close()       #save page source code
                with open (current_path + "/temple.txt") as data:
                    if "event.button==2" in data.read():
                        right_disable = 1
                    if "onMouseover=" + '"window.status=' in data.read():
                        hover_change_status_bar = 1
                        data.close()    #search from the source code
                    if 'alert(' | 'toggle(' in data.read():
                        contain_popup_window = 1
            except:
                right_disable = 0
                hover_change_status_bar = 0
                contain_popup_window = 0
            print('right click and hover part done')
            
            #check if indexed by google
            indexed_by_google = 0
            try:
                request = requests.get(urls)
                if request.status_code == 200:
                    indexed_by_google = 1
                else:
                    indexed_by_google = 0
            except:
                indexed_by_google = 0
            print('indexed by google done')
            
            #get webpage_rank
            webpage_rank = 0
            try:
                domain = '{uri.netloc}'.format(uri=urlparse(urls))
                domain = domain.replace("www.", "")
                ENDPOINT = 'https://data.similarweb.com/api/v1/data?domain=' + domain
                resp = get(ENDPOINT)
                if resp.status_code == 200:
                    webpage_rank = resp.json()['GlobalRank']['Rank']
                else:
                    webpage_rank = 0  # web site not exist anymore
            except:
                webpage_rank = 0
            print('get rank')
            
            #get ports from shodan
            try:
                ipinfo = api.host(page_ip)
                open_ports_number = len(ipinfo['ports'])
            except:
                open_ports_number = 0
            print('get ports')
            
            #count referer and percentage of request url
            referers = []
            count_referers = 0
            total_request = 0
            
            GET_request = 0
            POST_request = 0
            HEAD_request = 0
            PUT_request = 0
            DELETE_request = 0
            CONNECT_request = 0
            OPTIONS_request = 0
            
            GET_request_percentage = 0
            POST_request_percentage = 0
            HEAD_request_percentage = 0
            PUT_request_percentage = 0
            DELETE_request_percentage = 0
            CONNECT_request_percentage = 0
            OPTIONS_request_percentage = 0
            
            try:
                for i in request_info:
                    if 'Referer' in i['request']['request']['headers']:
                        referers.append(i['request']['request']['headers']['Referer'])
                        count_referers = len(set(referers))
            except:
                count_referers = 0
            
            try:
                for i in request_info:
                    if 'method' in i['request']['request']:
                        total_request = total_request + 1
                        if i['request']['request']['method'] == 'GET':
                            GET_request = GET_request + 1
                        if i['request']['request']['method'] == 'POST':
                            POST_request = POST_request + 1
                        if i['request']['request']['method'] == 'HEAD':
                            HEAD_request = HEAD_request + 1
                        if i['request']['request']['method'] == 'PUT':
                            PUT_request = PUT_request + 1
                        if i['request']['request']['method'] == 'DELETE':
                            DELETE_request = DELETE_request + 1
                        if i['request']['request']['method'] == 'CONNECT':
                            CONNECT_request = CONNECT_request + 1
                        if i['request']['request']['method'] == 'OPTIONS':
                            OPTIONS_request = OPTIONS_request + 1
            except:
                GET_request = 0
                POST_request = 0
                HEAD_request = 0
                PUT_request = 0
                DELETE_request = 0
                CONNECT_request = 0
                OPTIONS_request = 0
            
            if (total_request != 0):
                GET_request_percentage = GET_request / total_request
                POST_request_percentage = POST_request / total_request
                HEAD_request_percentage = HEAD_request / total_request
                PUT_request_percentage = PUT_request / total_request
                DELETE_request_percentage = DELETE_request / total_request
                CONNECT_request_percentage = CONNECT_request / total_request
                OPTIONS_request_percentage = OPTIONS_request / total_request
            else:
                GET_request_percentage = 0
                POST_request_percentage = 0
                HEAD_request_percentage = 0
                PUT_request_percentage = 0
                DELETE_request_percentage = 0
                CONNECT_request_percentage = 0
                OPTIONS_request_percentage = 0
            print('get request percentage')
            
            #output to the csv
            writer.writerow({'url':urls,'ip_address':page_ip, 'Country': page_country,'server': page_server,
            'ptr':ptr ,'asn': asn , 'asnname': asnname,'domain': page_domain,'malicious': is_malicious,
            'ads_blocked':ads_blocked,'totalLinks':totalLinks,'urlScore':score,'secureRequests':secureRequests,
            'securePercentage':securePercentage,'IPv6Percentage':ipv6_percentage,'certificate':certificates,
            'favicon_hash_value':favicon_hash_value,'protocol':page_protocol,'dom':dom,'domain_age':domain_age,
            'contain_prefix':contain_prefix,'url_length':url_length,'dot_number':dot_number,
            'validatity_period_time_stamp':validatity_period_time_stamp,'is_redirect':is_redirect,
            'iframe_number':iframe_number,'mailtos_number':mailtos_number,'a_tag_number':a_tag_number,
            'domain_in_url':domain_in_url,'MX':MX,
            'NS':NS,'SOA':SOA,'right_disable':right_disable,'hover_change_status_bar':hover_change_status_bar,
            'indexed_by_google':indexed_by_google,'webpage_rank':webpage_rank,
            'a_tag_url_number_percentage':a_tag_url_number_percentage,'meta_link_percentage':meta_link_percentage, 
            'contain_popup_window':contain_popup_window,'open_ports_number':open_ports_number,
            'referers':count_referers,'GET_request_percentage':GET_request_percentage,
            'POST_request_percentage':POST_request_percentage,'HEAD_request_percentage':HEAD_request_percentage,
            'PUT_request_percentage':PUT_request_percentage,'DELETE_request_percentage':DELETE_request_percentage,
            'CONNECT_request_percentage':CONNECT_request_percentage,'OPTIONS_request_percentage':OPTIONS_request_percentage,'Phishing':1})
            fileNum=fileNum+1
        print("csv formatted")
    
    print('Deleting temple txt caused by program')
    os.remove(current_path + '/temple.txt')
    os.remove(current_path + '/uuid.txt')


        



if __name__ == '__main__':
    main(sys.argv[1:])

 
