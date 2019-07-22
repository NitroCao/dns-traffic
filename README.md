# Dns-Traffic
Log all DNS query records in your computer.

## To-Do
- [ ] Implement a simple WebUI
- [ ] Support more databases

## Requirement
You may need install libpcap (On UNIX/Linux) or winpcap (On Windows). 
## Output Mode
* standard output
* json format file. The filename is just like this: `PREFIX-2019-07-22`
* MongoDB. Database name, collection name and database timeout can be modified through `dbName`, `dbCollection` 
and `dbTimeout` variable in `main.go`.

## Usage
```
dns-traffic run -h
NAME:
   dns-traffic run - Run dns-traffic

USAGE:
   dns-traffic run [command options] [arguments...]

OPTIONS:
   --interface value, -i value  Specify network interface
   --snapshot value, -s value   Specify the length as bytes of snapshot (default: 1600)
   --promiscuous, -p            Enable promiscuous mode for interface
   --timeout value, -t value    Specify the timeout as seconds (default: 30)
   --output PREFIX, -o PREFIX   Dump data as json file named with prefix PREFIX and timestamp
   --mongo value, -m value      Specify MongoDB URI
   --stdout, -d                 Print data in stdout
```
If both `--output` and `--mongo` are specified, it will use `--output` only.  
If no output mode is specified, it will output to standard output by default.  
A typical usage is like this:
```
dns-traffic run -i en0 -o output.json
```
or:
```
dns-traffic run -i en0 -m 'mongodb://admin@adminpasswd:127.0.0.1:27017'
```

## third-party libraries used
* gopacket (https://github.com/google/gopacket)
* cli (https://github.com/urfave/cli)
* mongo (https://github.com/mongodb/mongo-go-driver)

## LICENSE
GPLv3