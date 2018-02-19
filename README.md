# DNSresolver
A custom DNS Resolver written in Java, that lets you resolve 'A', 'MX', 'NS' type queries and produces an output similar
to the 'dig' tool. The resolver first contacts the root servers, gets a response for the top level domains and continues
resolving until it reaches the Authoratative NS for the query zone which hosts the DNS data for the request.

### To run:
```
Ensure you have dnsjava downloaded and set in class path (If using Eclipse)
Download source: http://www.dnsjava.org/download/

git clone https://github.com/bhaveshgoyal/DNSresolver.git
cd DNSresolver/
make

For DNSResolver without DNSSEC:
chmod +x ./resolver
./resolver <Host-name> [Type: A | MX | NS]


For DNSResolver with DNSSEC: (Ignore Any Warnings)
chmod +x ./resolversec
./resolversec <Host-name> [Type: A | MX | NS]
```

Note: The order of arguments is important and if the second arguments if not specified, the resolver automatically gives a response to 'A' type resolution
request. Careful approach has been followed at each step of resolution to retry request to ongoing server if no response is seen. If the server doesn't seem
to be responsding after two tries, the resolver makes the query to the next server in the current iteration. The resolver makes sure to keep resolving until
it founds the answer section in its response. This makes sure that the queries such as 'google.co.jp' are completely resolved too which need an extra step of
resolution baring the single pass of iterative resolution. If the resolution encounteres a CNAME at any point, it doesn't stop at that moment and in turn tries
to resolve the CNAME in an iterative fashion until a valid type record requested is found.

----------------------------------
**A Note on DNSSEC implementation:**

As stated, the program makes use of dnsjava to Resolve single iterative queries and validate the same.

When started, the program first performs some prelim checks to verify the arguments to the module. It then starts by iterating over the list of root servers to resolve the input query. The query is appended with '.' to make it an absoulte domain name for resolution. The module then fetches an Iterative Resolver enabled with DNSSEC OK (DO) flag and communicates over TCP to make sure large packets as in case of (dnssec-tools.org) are also put together when fragmented over wire. If the query fails, the program retries with the same server before moving on to the next server in the current iteration. At each step of resolution, the program first updates the current level of resolution servers and then starts verification of DNSSEC records. During the verification, the program aquires an iterator to the signature of the current RRSet in process. If no signatures are found in any of the RRSets, this would mean that the response server didn't have DNSSEC enabled. When a signature is found, the program proceeds to validate the same, by making a DNSKEY type query to the signer and matching the public keys of the response and the one returned through DNSKEY query. This is done by matching the key tag corresponding to the public keys. Note, at this point it might be possible that the server may have selfsigned its public key, thus an additional check is performed to find any such self signed records and verify the same using inbuilt DNSSEC.verify module for the same. If no such self-signed signature is found, the program proceeds with two cases. If a keytag wasn't matched in the first place that means that the record couldn't be verified. Else, the program tries to verify the footprint against the current response in consideration. If the above proceeds successfully, the program then validates the DS record between the parent and child zones, to establish a chain of trust. This is done by making a 'DS' type query to the record signer in consideration and in turn validating its signature recursively with the DS Record Set fetched. This is done all the way up till the program encounters the signer as root, which is known to be trusted or could be hardcoded with a trust anchor otherwise. When the entire recursive call completes, the record is said to be verified.

*Note:* The program measures the query time completely between the moment it contacts the first root server for the response to the point till it resolves a final resolution.

----------------------------
**Testing Environment**

```
Java specifications:
java 9.0.1
Java(TM) SE Runtime Environment (build 9.0.1+11)

Dependencies: 
dnsjava-2.1.8 (stable)

OS specifications:
-Darwin 17.0.0 x86_64
(macOS High Sierra)

VPN Client:
Tunnelblick

OVPN config ISP:
vpn181181245.opengw.net
Config File Type: TCP/UDP supported
```

**Sample Program Output:**
```
bagl ❯❯❯ ./resolver google.com A
javac -cp "./src/*:lib/dnsjava-2.1.8.jar" src/resolver.java -d ./bin
java -cp "bin/:lib/dnsjava-2.1.8.jar" resolver google.com A

QUESTION SECTION:
google.com.     0   IN  A

ANSWER SECTION:
google.com.     300 IN  A   172.217.27.78

Query Time: 1833 msec
WHEN: Mon Feb 19 16:48:09 2018
MSG SIZE rcvd: 44


bagl ❯❯❯ ./resolver google.com MX
javac -cp "./src/*:lib/dnsjava-2.1.8.jar" src/resolver.java -d ./bin
java -cp "bin/:lib/dnsjava-2.1.8.jar" resolver google.com MX

QUESTION SECTION:
google.com.     0   IN  MX

ANSWER SECTION:
google.com.     600 IN  MX  10 aspmx.l.google.com.
google.com.     600 IN  MX  40 alt3.aspmx.l.google.com.
google.com.     600 IN  MX  50 alt4.aspmx.l.google.com.
google.com.     600 IN  MX  30 alt2.aspmx.l.google.com.
google.com.     600 IN  MX  20 alt1.aspmx.l.google.com.

Query Time: 994 msec
WHEN: Mon Feb 19 16:48:17 2018
MSG SIZE rcvd: 356


bagl ❯❯❯ ./resolver google.com NS
javac -cp "./src/*:lib/dnsjava-2.1.8.jar" src/resolver.java -d ./bin
java -cp "bin/:lib/dnsjava-2.1.8.jar" resolver google.com NS

QUESTION SECTION:
google.com.     0   IN  NS

ANSWER SECTION:
google.com.     345600  IN  NS  ns4.google.com.
google.com.     345600  IN  NS  ns3.google.com.
google.com.     345600  IN  NS  ns2.google.com.
google.com.     345600  IN  NS  ns1.google.com.

Query Time: 1604 msec
WHEN: Mon Feb 19 16:48:23 2018
MSG SIZE rcvd: 276

-----------------
*DNSSEC Enabled:*

bagl ❯❯❯ ./resolversec paypal.com A
javac -cp "./src/*:lib/dnsjava-2.1.8.jar" src/resolversec.java -d ./bin
Note: src/resolversec.java uses unchecked or unsafe operations.
Note: Recompile with -Xlint:unchecked for details.
java -cp "bin/:lib/dnsjava-2.1.8.jar" resolversec paypal.com A
Zone SIGNER: paypal.com.
DNS Footprint Found: 11811
Self-signed DNSKEY Verified for: paypal.com.
DS SIGNER: paypal.com.
Validating Parent-Child DS Records...
Zone SIGNER: com.
DNS Footprint Found: 46967
DS SIGNER: com.
Validating Parent-Child DS Records...
Zone SIGNER: .
DNS Footprint Found: 41824
DS SIGNER: .

DNSSEC: SUCCESS. Record Verified

DNSSEC: SUCCESS. Record Verified

QUESTION SECTION:
paypal.com.     0   IN  A

ANSWER SECTION:
paypal.com.     79  IN  A   64.4.250.32
paypal.com.     79  IN  A   64.4.250.33

Query Time: 38385 msec
WHEN: Mon Feb 19 18:20:42 2018
MSG SIZE rcvd: 241


bagl ❯❯❯ ./resolversec dnssec-failed.org A
javac -cp "./src/*:lib/dnsjava-2.1.8.jar" src/resolversec.java -d ./bin
Note: src/resolversec.java uses unchecked or unsafe operations.
Note: Recompile with -Xlint:unchecked for details.
java -cp "bin/:lib/dnsjava-2.1.8.jar" resolversec dnssec-failed.org A

DNSSEC: Error Verifying Records for: dnssec-failed.org

QUESTION SECTION:
dnssec-failed.org.  0   IN  A

ANSWER SECTION:
dnssec-failed.org.  7200    IN  A   69.252.80.75

Query Time: 8285 msec
WHEN: Mon Feb 19 18:23:46 2018
MSG SIZE rcvd: 51


bagl ❯❯❯ ./resolversec bhaveshgoyal.xyz A
javac -cp "./src/*:lib/dnsjava-2.1.8.jar" src/resolversec.java -d ./bin
Note: src/resolversec.java uses unchecked or unsafe operations.
Note: Recompile with -Xlint:unchecked for details.
java -cp "bin/:lib/dnsjava-2.1.8.jar" resolversec bhaveshgoyal.xyz A

DNSSEC: DNSSEC not supported

QUESTION SECTION:
bhaveshgoyal.xyz.   0   IN  A

ANSWER SECTION:
bhaveshgoyal.xyz.   299 IN  A   52.76.213.87

Query Time: 5989 msec
WHEN: Mon Feb 19 18:24:04 2018
MSG SIZE rcvd: 61
```
