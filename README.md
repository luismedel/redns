# redns

A simple, regex-ready and scriptable authoritative DNS server for toying, testing and red teaming.

**Features:**
* Almost fully compatible with standard BIND zone files as defined in [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035).
* Regex based dynamic record matching.
+ Dynamic responses using Lua scripts (ala PowerDNS) thanks to the awesome [MoonSharp Lua interpreter](https://github.com/moonsharp-devs/moonsharp).
* Easily extensible. Currently supports A, AAAA, CNAME, NS, MX, TXT, PTR, SOA and NULL records.
* Easy to deploy.

**Anti-features 🙂:**
* No zone transfers.
* No DNSSEC.
* No recursive queries.

**To-do:**
- [ ] More robust networking code.
- [ ] Add domain compression to responses.
- [ ] Upgrade Lua engine to a recent version of MoonSharp.

## License

Written by Luis Medel, Percibe Information Security.

Copyright (c) 2021, [Percibe S.L.](https://percibe.net)
All rights reserved.

This program is released under a 3-clause BSD license. For more detail see the LICENSE.md file.

## Usage

```console

redns [options]

Where options can be:

 --zone <path>                 Loads zone from file (defaults to ./zone.conf)
                               (can be used multiple times)

 --no-reverse-zone             Don't add a reverse zone.

 --bind <proto>:<addr>:<port>  Listens at the specified endpoint, where:
                                    <proto>  udp|tcp.
                                    <addr>   local address to bind to.
                                    <port>   local port to bind to.
                               (can be used multiple times)

 --log <path>                  Send logs to file.
 --no-console                  Disables console output.
 --loglevel <level>            debug|info|warn|error|all (defaults to debug).

 --help                        Prints this screen and exit.

Call redns without arguments to start the default server.

```

### Example

```console

  redns --zone .\zone.conf \
        --bind udp:0.0.0.0:53 \
        --bind tcp:0.0.0.0:53 \
        --loglevel debug

```

## Zone files

redns tries to be fully compatible with standard BIND zone files. Nevertheless, some syntax changes were neccesary to add suport for regex defined records and Lua scripts.

### Standard zones

You can feed redns with any standard zone file. For example:

```zone
$ORIGIN example.com.	; Designates the start of this zone file

$TTL 3600		; Default expiration time (in seconds) of all RRs
			; without their own TTL value

example.com.    IN  SOA     ns.example.com. admin.example.com. ( 2020091025
                                                                 7200
                                                                 3600
                                                                 1209600
                                                                 3600 )

@		IN  NS      ns			; A nameserver for example.com
@		IN  NS      ns2			; Another nameserver

ns              IN  A       192.0.2.2		; IPv4 for ns.example.com
ns2             IN  A       192.0.2.3		; IPv4 for ns2.example.com

example.com.    IN  A       192.0.2.1       	; IPv4 address for example.com
@               IN  AAAA    2001:db8:10::1  	; IPv6 address for example.com

www             IN  CNAME   example.com.	; An alias for example.com
wwwtest         IN  CNAME   www			; Another alias for www.example.com

mail            IN  A       192.0.2.3		; IPv4 address for mail.example.com
mail2           IN  A       192.0.2.4		; IPv4 address for mail2.example.com
mail3           IN  A       192.0.2.5		; IPv4 address for mail3.example.com
```

### Non-standard zones 🧙🏼‍♂️

This is where the magic of redns happens.

#### Dynamic record matching

redns supports regex based dynamic record matching. Simply define your record as usual, but using a regex pattern.

The next record matches any query starting with 'info' followed by digits (ie: info1.example.com, info999.example.com, info123456.example.com, info314159.example.com, etc.)

```zone
/^info\d+/      IN  A       192.0.2.6
```

> Note you can use any special char and anchor in your regex. Simply be aware that at runtime this:
>
>```regex
>/^info\d+/
>```
>will be expanded using the zone origin. So, anchors like $ (end of text) won't be valid.
>
>In our example: 
>```regex
>/^info\d+\.example\.com/
>```

#### Dynamic record responses using Lua scripts

You can return a custom response using Lua scripts. We use a (in our humble opinion) saner syntax than [PowerDNS'](https://powerdns.com) one. This syntax allows to add several scripting engines to the server (ie: <?js, <?shell, etc.):

Let's return an boring IPv4 for an A record.

```zone
subdomain       IN  A       <?lua
                                return "192.168.2.7"
                            ?>
```

You can return more than one value, if allowed by the record type.
```zone
subdomain       IN  NS      <?lua
                                return "192.0.2.2", "192.0.2.3"
                            ?>
```

If the record type expects more than one value (like in MX records, for example) you can use a table. Only remember to use the same order you would use in a zone file:
```zone
example.com.    IN  MX      <?lua
				-- MX => priority, hostname
                                return { 10, "mail.example.com." }
                            ?>
```

A more complete MX output for example.com could be this:
```zone
example.com.    IN  MX      <?lua
                                return { 10, "mail.example.com." },
                                       { 20, "mail2.example.com." },
                                       { 30, "mai3.example.com." }
                            ?>
```

You can alter the response type within Lua (not all DNS clients support this, though). For example, lets change from A to TXT:

```zone
subdomain2      IN  A       <?lua
                                responseType = "TXT"
                                return "I'm was an A record, but I switched to TXT!"
                            ?>
```
> FYI, there are 4 globals available for Lua scripts to use:
>```console
> remoteAddress:	Client address (read only string) (e.g.: "192.168.2.4")
> remotePort:		Remote port (read only int)
> requestName:		Request (read only string) (e.g.: "mail.example.com")
> responseType:		Response type (read/write string) ("A", "AAAA", "NS", "MX", etc.)
> 	 		Setted by default to the apporpiate response type in each call.
> ```

#### Best of both worlds
Of course, you can combine both, dynamic matching and Lua scripting:

```zone
/^text\d+/      IN  TXT     <?lua
				return "Custom TXT for " ..
						remoteAddress .. ":" ..
						remotePort
                            ?>
```

Another one. Set a catch-all record and do whatever you want with the data:

```zone
/^.+/        IN  TXT        <?lua  
                                local path = "/tmp/" .. remoteAddress .. ".txt"
                                local file = io.open (path, "a")
                                file:write (requestName)
                                file:close ()

                                return "Your request was saved to disk"
                            ?>
```
