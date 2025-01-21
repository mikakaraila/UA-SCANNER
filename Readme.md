**UA SCANNER**
==============

UA Scanner will check OPC UA Server endpoints and report unsecure ones to file: *scan_results.json*
- Depreaceated
- Anonymous access should be prevented
- Check and report that server & client has "same" current time
- Report server product information:
  - ProductName
  - ProductUri
  - ManufacturerName
  - SoftwareVersion
  - BuildDate
  - BuildNumber
  - CurrentSessionCount
  - CumulatedSessionCount
  - CurrentSubscriptionCount
- For each nodeId:
  - Report access rights
  - Report permissions (plain text format)
- Check & report diagnostics counters:
  - Warning if not zero: 
    - RejectedRequestCount
    - RejectedSessionCount
    - SessionAbortCount
    - SessionTimeoutCount
  - Error if not zero:
    - SecurityRejectedRequestCount
    - SecurityRejectedSessionCount
- Syslog and Graylog2 are also used to notify critical secury issues

# Build
-------

	npm install
	npm run build
	npm run win-compile_x64
    npm run linux-compile_x64
    npm run pretest
	npm run certificate

# Usage:
--------
Command line options:
| option | Value, example | description |
| ----------- | ----------- | --------- |
| --endpoint | opc.tcp://H7Q8Q13.mshome.net:53530/OPCUA/SimulationServer |
| --securityMode | None or Sign or SignAndEncrypt |
| --securityPolicy| Basic512 or Basic25Sha etc. | Depends on server |
| --username| *username* | Username |
| --password| *password* | Secret password|
| --node| nodeId | Used for the monitoring value changes|
| --root| nodeId | NodeId for crawl or History|
| --timeout| number | Use as seconds for timeout|
| --debug| | Generate extra debug output |
| --History| | Read raw history from given --node nodeId|
| --help| | Show usage/help|
| --version| | Shows version number|
| --crawl| | Browse address space, uses ns=0;i=85 if --root not used|
| --discovery| |
| --grayloghost| hostname | Default localhost |
| --graylogport| number | Overrides default|
| --sysloghost| hostname | Default localhost |
| --syslogport| number | Overrides default|
| --syslogtcp | **false** or true | default is false (udp used normally)|

## Debug:
---------
node -r ts-node/register bin\ua_scanner.ts -e opc.tcp://H7Q8Q13.mshome.net:53530/OPCUA/SimulationServer -c 

## Windows:
-----------
ua_scanner.exe -e opc.tcp://H7Q8Q13.mshome.net:53530/OPCUA/SimulationServer -c
