NS
================
'ns' is a nslookup alternative with the ability to resolve multiple hosts, domains or URLs in one convenient command.

I use nslookup multiple times a day and find the one liner nslookup command to be very limiting.
I regularly wish nslookup would resolve more than one host at one time, accept URLs and have the 
ability to direct the query to an alternative DNS server fom the convenience of the nslookup one liner.

I developed 'ns' specifically to address these short comings with windows users in mind.


NS features
---------------

* Resolves multiple inputs simultaneously in one convenient CLI command
* Profiles input as plain hostname, FQDN or IP address
* Performs A or PTR resolution dependent on input profile, followed by CNAME lookup
* Converts URIs or URLs to FQDN or IP address then performs DNS resolution
* User can define DNS server to query
* All features are all accessible from the convenience of a one liner
* Py2exe setup script provided with source code


Create Win32 EXE from source using py2exe
-----------------------------------------
1. Install ns python dependencies
2. Change into source dir 
3. Create exe file using supplied py2exe script
...See [py2exe website for tutorial](http://www.py2exe.org/index.cgi/Tutorial)
4. Copy dist\ns.exe to location in window's system path


```
pip install -r requirements.txt
cd ns
python setup_ns_py2exe.py py2exe
cp dist\ns.exe <windows\system\path>
```


Usage
-----
`
 ns {hostname} | {IP address} | {URL/URI} [ -s {server IP} | -t {1-10) | -l {5,10,20,30,60} | -h | -d | --version ]
`

Argument  | Type   | Format        | Default                    | Description
----------|--------|---------------|----------------------------|--------------------
hostname | string | {hostname} | No default value | hostname to query, accepts multiple strings
ip address | string | x.x.x.x | No default value | ip address to query, accepts multiple strings
URL/URI | string | http://domain.name.com/xxxx | No default value | URL / URI to query, accepts multiple strings
-s | string | -s [x.x.x.x] | blank | Specific DNS server, alternative to OS detected DNS server
-t | integer | -t {1-10 sec} | 2 | Timeout for each DNS query
-l | integer | -l {5, 10, 20, 30, 60 sec} | 5 | Timeout if multiple DNS servers are queried
-h | switch | -h | disabled | Prints help to console   
-d | switch | -d | disabled | Enables debug output to console
--version | --version | disabled | Displays version


Examples
--------
Query IP address, FQDN, URL and local hostname using OS's DNS server
```
ns 8.8.8.8 google.com.au http://github.com myrouter
```

Query multiple FQDN using google DNS server
```
ns google.com.au -s
```

Query multiple FQDN using specific google DNS server
```
ns google.com.au -s 8.8.4.4
```

Query multiple local hostnames
```
ns hostname1 hostname2 hostname3 hostname4
```