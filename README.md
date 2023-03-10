# whoisjson
Json object wrapper for Mark Russinovich's Windows System Internals Whois Lookup 
```
dist/whoisjson.exe MD5 checksum 7b98172837a215e9495c4dab5de1d427
```
compile your own with
```
pyinstaller --onefile --name whoisjson whois.py whois_utils.py --add-binary "dsource/whois.exe;dsource" --hidden-import regex
```

### Takes Domain Names Returns JSON output Example whoisjson.exe google.ca returns 
```
{"admin_city": "Toronto",
"admin_country": "CA",
"admin_email": "dns-admin@google.com",
"admin_name": "Rajiv Prasad",
"admin_organization": "Google Canada Corporation",
"admin_phone": "+1.4162146034",
"admin_postal_code": "M5H2G4",
"admin_street": "12-111 Richmond St W",
"creation_date": "2000-10-04T02:21:23Z",
"dnssec": "unsigned",
"domain_name": "google.ca",
"domain_status": "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
"name_server": "ns2.google.com",
"registrant_city": "Toronto",
"registrant_country": "CA",
"registrant_email": "dns-admin@google.com",
"registrant_name": "Google Canada Corporation",
"registrant_organization": "Google Canada Corporation",
"registrant_phone": "+1.4162146034",
"registrant_postal_code": "M5H2G4",
"registrant_street": "12-111 Richmond St. W",
"registrar": "MarkMonitor International Canada Ltd.",
"registrar_abuse_contact_email": "abusecomplaints@markmonitor.com",
"registrar_abuse_contact_phone": "+1.2083895740",
"registrar_iana_id": "not applicable",
"registrar_url": "Markmonitor.com",
"registrar_whois_server": "whois.ca.fury.ca",
"registry_admin_id": "105817359-CIRA",
"registry_domain_id": "D73081-CIRA",
"registry_expiry_date": "2023-04-28T04:00:00Z",
"registry_registrant_id": "106113561-CIRA",
"registry_tech_id": "105817359-CIRA",
"tech_city": "Toronto",
"tech_country": "CA",
"tech_email": "dns-admin@google.com",
"tech_name": "Rajiv Prasad",
"tech_organization": "Google Canada Corporation",
"tech_phone": "+1.4162146034",
"tech_postal_code": "M5H2G4",
"tech_street": "12-111 Richmond St W",
"updated_date": "2022-09-01T20:23:52Z",
"url_of_the_icann_whois_inaccuracy_complaint_form": "https://www.icann.org/wicf/",
"whois_server": "whois.ca.fury.ca"}```
