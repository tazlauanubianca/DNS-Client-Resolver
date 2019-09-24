# DNS Client

A C program allowing interogation of a DNS server using the RFC 1035 and RFC 1034 protocols.

The DNS client implemented is a C / C ++ program that works as a resolver DNS, using queries for extract information from DNS servers. The program will receive an argument from the command line as a domain name or IP address and it will display a series of information about it. To obtain the needed information, UDP and TCP are used and messages were constructed in the following structure:

```
+---------------------+
|
	Header
|
+---------------------+
|
	Question
|
+---------------------+
|
	Answer
|
+---------------------+
|
	Authority
|
+---------------------+
|
	Additional
|
+---------------------+
	-> the question for the name server
	-> RRs answering the question
	-> RRs pointing toward an authority
	-> RRs holding additional information
```

The client supports the following types of queries:
* A (Host Address)
* MX (Mail Exchange)
* NS (Authoritative Name Server)
* CNAME (the canonical name for an alias)
* SOA (Start Of a zone of Authority)
* TXT (Text strings)
* PTR (Domain Name Pointer)

Example of usage:
* `./dnsclient google.com A`
* `./dnsclient 141.85.37.5 PTR`
