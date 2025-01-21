#!/usr/bin/env ts-node
/* eslint-disable complexity */
/* eslint-disable max-statements */
// tslint:disable:no-logger
/*
MIT License

Copyright (c) 2024  Valmet Automation - Finland (https://www.valmet.com)

Copyright (c) 2024 Mika Karaila, mika.karaila@valmet.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
//
// This application is part of CTAC project.
// Purpose: Scanner / monitoring application for the end user OPC UA Server security.
// Example: TypeScript based application that will test server security.
// Execute: node -r ts-node/register bin\ua_scanner.ts -e opc.tcp://H7Q8Q13.mshome.net:53530/OPCUA/SimulationServer -c
//
// For the Valmet DNA OPC UA Server:
// node -r ts-node/register bin\ua_scanner.ts -e opc.tcp://localhost:62544 -u username -p password -r ns=1;s=DNA -c --securityMode Sign --securityPolicy Basic256Sha256
//

import * as fs from "fs";
import * as path from "path";
import * as util from "util";
import { types } from "util";
import yargs from "yargs";
import { red, green, yellow, magenta, cyan } from "chalk";
import {
    ApplicationType,
    accessLevelFlagToString,
    permissionFlagToString,
    assert,
    AttributeIds,
    hexDump,
    ClientMonitoredItem,
    ClientSession,
    ClientSubscription,
    coerceMessageSecurityMode,
    coerceNodeId,
    coerceSecurityPolicy,
    DataValue,
    findServersOnNetwork,
    makeNodeId,
    MessageSecurityMode,
    NodeId,
    OPCUAClient,
    OPCUAClientOptions,
    SecurityPolicy,
    UAString,
    UserIdentityInfo,
    UserTokenType,
    VariableIds,
    RolePermissionType,
    WellKnownRoles,
    StatusCodes
} from "node-opcua";
import { Certificate, toPem } from "node-opcua-crypto";
import {  NodeCrawler } from "node-opcua-client-crawler";
import { readCertificate, exploreCertificate } from "node-opcua-crypto";
import { subjectToString } from "node-opcua-server-configuration";
// import winston from "winston/lib/winston/config";

// tslint:disable:no-var-requires
const Table = require("easy-table");
const treeify = require("treeify");

// TODO Add syslog || graylog2 clients for performing needed external alarming
// Syslog:      https://www.npmjs.com/package/syslog-client
// Graylog2:    https://www.npmjs.com/package/graylog2
//
// Best solution is to use winston and then syslog or graylog2 transport
//
// Testing:
// KIWI syslog server (free) for Windows: https://www.solarwinds.com/free-tools/kiwi-free-syslog-server

const winston = require('winston');
const os = require("os");
const syslog = require("syslog-client");
require('winston-syslog').Syslog;
require('winston-daily-rotate-file');
const WinstonGraylog2 = require('winston-graylog2');
let logger: any;

function initLogs(grayloghost: string, graylogport:number, sysloghost:string, syslogport: number, syslogtcp: boolean) {
    let options4graylog = {
    name: 'Graylog',
    level: 'error', // verbose, info, debug, warning NOT reported, only error, alert & emergency log entries
    silent: false,
    handleExceptions: false,
    graylog: {
        servers: [{host: 'localhost', port: 12201}, 
                  // {host: 'remote.host', port: 12201}
                ],
        hostname: os.hostname(),
        facility: 'OPC UA Monitoring',
        bufferSize: 1400 // Max MTU size do not exceed
    },
    staticMeta: {env: 'staging'}
    };

    // Add remote graylog server into the Graylog options
    if (grayloghost.length>0 && graylogport>0) {
        options4graylog.graylog.servers.push({host: grayloghost, port: graylogport});
        console.debug(yellow("Using graylog servers: ") + cyan(JSON.stringify(options4graylog.graylog.servers)));
    }
    else {
        console.debug(yellow("Using default grayloghost: ") + cyan("localhost") + yellow(" and port: ") + cyan("12201"));
    }
    let transport = syslog.Transport.Udp; // Default
    if (syslogtcp === true) {
        transport = syslog.Transport.Tcp;
        console.debug(yellow("Using ") + cyan("TCP") + yellow(" transport for syslog"));
    }
    else {
        console.debug(yellow("Using default transport ") + cyan("UDP") + yellow(" for syslog"));
    }
    let options4syslog = {
    syslogHostname: os.hostname(),
    level: "error",
    appName: "UA Scanner",
    transport: transport,
    port: 514,
    // facility: "system" // user-level messages or 3 == system daemons
    };
    if (sysloghost != "None" && sysloghost.length>4) {
        options4syslog.syslogHostname = sysloghost;
        console.debug(yellow("Using syslog hostname: ") + cyan(sysloghost));
    }
    else {
        console.debug(yellow("Using default syslog hostname: ") + cyan(os.hostname()));
    }
    if (syslogport>0) {
        options4syslog.port = syslogport;
        console.debug(yellow("Using given syslog port: ") + cyan(syslogport));
    }
    else {
        console.debug(yellow("Using default syslog port: ") + cyan("514"));
    }
    // Store logs to own subfolder
    if (!fs.existsSync("./logs")) {
        fs.mkdirSync("./logs");
    }
    logger = winston.createLogger({
    // level: 'info',
    levels: winston.config.syslog.levels,
    format: winston.format.json(),
    // defaultMeta: { service: 'user-service' },
    // defaultMeta: { service: 'OPC UA Monitoring'},
    transports: [
        //
        // - Write all logs with importance level of `error` or less to `error.log`
        // - Write all logs with importance level of `info` or less to `combined.log`
        //
        // new winston.transports.File({   filename: 'error.log', level: 'error' }), // TODO remove, just for testing
        // new winston.transports.File({   filename: 'all.log' }),              // TODO remove, just for testing
        new winston.transports.DailyRotateFile({
            level: 'info',
            auditFile: path.join("./logs", 'UA-Scanner-audit.json'),
            filename: path.join("./logs", 'UA-Scanner-%DATE%.log'),
            datePattern: 'YYYY-MM-DD-HH',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '14d'
        }),
        // Next line defined that info and warning levels are not reported to syslog
        new winston.transports.Syslog(options4syslog),
        new WinstonGraylog2(options4graylog)
    ],
    });

    //
    // If we're not in production then log to the `logger` with the format:
    // `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
    //
    if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
    }));
    }
}

function getTick() {
    return Date.now();
}

let theSubscription: ClientSubscription | null;
let the_session: ClientSession;
let client: OPCUAClient;
let timeout = 30000;
let doDebug = false;
let userName: string;
let password: string;
let monitored_node: NodeId;
let root_node: NodeId;

// Collect scan results to own JSON object
let scanResults:any = { 
    "Namespaces": [{}],
    "Endpoints": [{}],
    "NodeIds": [{}]
};

async function listNamespaces() {
    // -----------------------------------------------------------------------------------------------------------
    //   NAMESPACE
    //   display namespace array
    // -----------------------------------------------------------------------------------------------------------
    const server_NamespaceArray_Id = makeNodeId(VariableIds.Server_NamespaceArray); // ns=0;i=2006
    const namespaceArray = await the_session.readNamespaceArray();
    for (const namespace of namespaceArray) {
        const index = await the_session.getNamespaceIndex(namespace.toString())
        const key = "Namespaces";
        scanResults[key].push({"id": + index, "namespace": namespace});
    }
}

function checkServerCertificate(filename: string) {
  // Certificate info to fields/variables:
  // Status,ValidFrom,ValidTo,Organization,OrganizationUnit,Locality,State,Country,AppUri,DomainName,IP,Filename
  let Organization:string = "-";
  let OrganizationUnit:string = "-";
  let Locality:string = "-";
  let State:string = "-";
  let Country:string = "-";
  const certificate = readCertificate(filename);
  const certificate_info = exploreCertificate(certificate);
  const Version = certificate_info.tbsCertificate.version.toString();
  const Issuer = certificate_info.tbsCertificate.issuer.commonName;
  let Uri = "";
  let DnsName = "";
  if (certificate_info.tbsCertificate && 
      certificate_info.tbsCertificate.extensions && 
      certificate_info.tbsCertificate.extensions.subjectAltName) {
    if (certificate_info.tbsCertificate.extensions.subjectAltName.uniformResourceIdentifier) {
      Uri = certificate_info.tbsCertificate.extensions.subjectAltName.uniformResourceIdentifier;
    }
    if (certificate_info.tbsCertificate.extensions.subjectAltName.dNSName) {
      DnsName = certificate_info.tbsCertificate.extensions.subjectAltName.dNSName;
    }
  }
  let expirationLimit = 365 * 24 * 60 * 60 * 1000;  // TODO Configurable, Default expiration limit is 1 year
  const ValidFrom = certificate_info.tbsCertificate.validity.notBefore;
  // Check that certificate is already valid
  if (ValidFrom.getTime() > new Date().getTime()) {
    logger.alert(red("Certificate is not yet valid: ") + cyan(ValidFrom));
  }
  const ValidTo = certificate_info.tbsCertificate.validity.notAfter;
  // Check when certificate will be invalid
  if (ValidTo.getTime() - expirationLimit < new Date().getTime()) {
    logger.alert(red("Certificate will be invalid after: ") + cyan(ValidTo));
  }
  const existingSubject = subjectToString(certificate_info.tbsCertificate.subject);
  logger.info(yellow(" Subject                   : ") + cyan(JSON.stringify(existingSubject)));
  logger.info(yellow(" Version                   : ") + cyan(Version));
  logger.info(yellow(" Issuer                    : ") + cyan(Issuer));
  logger.info(yellow(" UniformResourceIdentifier : ") + cyan(Uri));
  logger.info(yellow(" DNS name                  : ") + cyan(DnsName));
  logger.info(yellow(" Valid from                : ") + cyan(ValidFrom));
  logger.info(yellow(" Valid to                  : ") + cyan(ValidTo));
  if (certificate_info.tbsCertificate.subject.countryName) {
      Country = certificate_info.tbsCertificate.subject.countryName.toString();
  }
  logger.info(yellow(" Country                   : ") + cyan(Country));
  if (certificate_info.tbsCertificate.subject.localityName) {
      Locality = certificate_info.tbsCertificate.subject.localityName;
  }
  logger.info(yellow(" Locality                  : ") + cyan(Locality));
  if (certificate_info.tbsCertificate.subject.stateOrProvinceName) {
      State = certificate_info.tbsCertificate.subject.stateOrProvinceName;
  }
  logger.info(yellow(" State                     : ") + cyan(State));
  if (certificate_info.tbsCertificate.subject.organizationName) {
    Organization = certificate_info.tbsCertificate.subject.organizationName;
  }
  logger.info(yellow(" Organization name         : ") + cyan(Organization));
  if (certificate_info.tbsCertificate.subject.organizationUnitName) {
      OrganizationUnit = certificate_info.tbsCertificate.subject.organizationUnitName;
  }
  logger.info(yellow(" Organization unit         : ") + cyan(OrganizationUnit));
  let CommonName = "-";
  if (certificate_info.tbsCertificate.subject.commonName) {
      CommonName = certificate_info.tbsCertificate.subject.commonName;
  }
  logger.info(yellow(" Common name               : ") + cyan(CommonName));
  const Algorithm = certificate_info.tbsCertificate.subjectPublicKeyInfo.algorithm;
  // const Org = certificate_info.tbsCertificate.subject.organizationName!;
  const KeyLen = certificate_info.tbsCertificate.subjectPublicKeyInfo.keyLength;
  logger.info(yellow(" Key length                : ") + cyan(KeyLen)); // TODO Min length??
  const signature = certificate_info.signatureAlgorithm.identifier;
  logger.info(yellow(" Signature                 : ") + cyan(signature));
  // If not self signed then these will be available
  let Serial = "SelfSigned";
  if (certificate_info.tbsCertificate.extensions && 
      certificate_info.tbsCertificate.extensions.authorityKeyIdentifier && 
      certificate_info.tbsCertificate.extensions.authorityKeyIdentifier.serial) {
    Serial = certificate_info.tbsCertificate.extensions.authorityKeyIdentifier.serial;
  }
  let KeyIdentifier = "";
  if (certificate_info.tbsCertificate.extensions && 
    certificate_info.tbsCertificate.extensions.authorityKeyIdentifier && 
    certificate_info.tbsCertificate.extensions.authorityKeyIdentifier.keyIdentifier) {
    KeyIdentifier = certificate_info.tbsCertificate.extensions.authorityKeyIdentifier.keyIdentifier;
  }
  logger.info(yellow(" Key identifier            : ") + cyan(KeyIdentifier));
  logger.info(yellow(" Filename                  : ") + cyan(filename));
  // String variable that can be shown in DNA diagnostics
  let description = "Version: " + certificate_info.tbsCertificate.version + " issuer: " + certificate_info.tbsCertificate.issuer.commonName;
  description = description + " From: " + certificate_info.tbsCertificate.validity.notBefore + " To: " + certificate_info.tbsCertificate.validity.notBefore;
  logger.info(yellow(" Description               : ") + cyan(description));
  // console.log(JSON.stringify(table));
}

async function scanServer(serverName: UAString, endpointUrl: UAString, securityMode: MessageSecurityMode, securityPolicy: SecurityPolicy, doCrawling: boolean) {
    
    const optionsInitial: OPCUAClientOptions = {
        securityMode,
        securityPolicy,
        endpointMustExist: false,
        keepSessionAlive: true,
        connectionStrategy: {
            initialDelay: 2000,
            maxDelay: 10 * 1000,
            maxRetry: 10
        },
        // discoveryUrl
    };

    client = OPCUAClient.create(optionsInitial);

    client.on("backoff", (retry: number, delay: number) => {
        logger.info(yellow("backoff  attempt #"), cyan(retry), yellow(" retrying in "), cyan(delay / 1000.0), yellow(" seconds"));
    });
    if (doDebug) {
        logger.info(yellow("connecting to "), cyan(endpointUrl));
        logger.info(yellow("    strategy: "), cyan(JSON.stringify(client.connectionStrategy)));
    }
    try {
        await client.connect(endpointUrl!.toString());
    } catch (err) {
        logger.error("Cannot connect: " + endpointUrl);
        if (types.isNativeError(err)) {
            logger.error(err.message);
        }
        return;
    }

    const endpoints = await client.getEndpoints();

    if (doDebug) {
        fs.writeFileSync("endpoints.log", JSON.stringify(endpoints, null, " "));
        logger.info(treeify.asTree(endpoints, true));
    }

    const table = new Table();

    let serverCertificate: Certificate | undefined;

    let i = 0;
    for (const endpoint of endpoints) {
        table.cell("Endpoint", endpoint.endpointUrl + "");
        table.cell("Application URI", endpoint.server.applicationUri);
        table.cell("Product URI", endpoint.server.productUri);
        table.cell("Application Name", endpoint.server.applicationName.text);
        table.cell("Security Mode", MessageSecurityMode[endpoint.securityMode].toString());
        if (MessageSecurityMode[endpoint.securityMode].toString() === "None") {
            // TODO Add to report
            logger.alert(red("Unsecure endpoint: ") + cyan(endpointUrl) + yellow(" unsecure SecurityMode: ") + cyan(MessageSecurityMode[endpoint.securityMode].toString()));
            if (endpointUrl) {
                scanResults["Endpoints"].push({"EndpointUrl": + endpointUrl, "UnsecureSecurityMode": MessageSecurityMode[endpoint.securityMode].toString()});
            }
        }
        table.cell("securityPolicyUri", endpoint.securityPolicyUri);
        // Deprecreated TODO Check and update latest old ones
        if (endpoint.securityPolicyUri === "http://opcfoundation.org/UA/SecurityPolicy#Basic256" ||
            endpoint.securityPolicyUri === "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15") {
            logger.alert(red("Unsecure endpoint: ") + cyan(endpointUrl) + yellow(" deprecated SecurityPolicy: ") + cyan(endpoint.securityPolicyUri));
            if (endpointUrl) {
                scanResults["Endpoints"].push({"EndpointUrl": + endpointUrl, "DeprecatedSecurityPolicy": endpoint.securityPolicyUri});
            }
        }
        table.cell("Type", ApplicationType[endpoint.server.applicationType]);
        table.cell("certificate", "..." /*endpoint.serverCertificate*/);
        endpoint.server.discoveryUrls = endpoint.server.discoveryUrls || [];
        table.cell("discoveryUrls", endpoint.server.discoveryUrls.join(" - "));
        serverCertificate = endpoint.serverCertificate;

        // Store each server certificate locally
        const certificate_filename = path.join(__dirname, "server_certificate" + i + ".pem"); // TODO Own temp folder or something else
        if (serverCertificate) {
            fs.writeFileSync(certificate_filename, toPem(serverCertificate, "CERTIFICATE"));
            checkServerCertificate(certificate_filename);
        }
        table.newRow();
        i++;
    }
    // TODO Add to report!!!
    for (const endpoint of endpoints) {
        if (doDebug) {
            logger.info(
                yellow("Security Mode: "), cyan(MessageSecurityMode[endpoint.securityMode].toString()),
                yellow(" Policy: "), cyan(endpoint.securityPolicyUri)
            );
        }
        const table2 = new Table();
        for (const token of endpoint.userIdentityTokens!) {
            table2.cell("Policy", token.policyId);
            table2.cell("TokenType", token.tokenType.toString());
            // Check that anonymous Policy is not available
            if (token.tokenType === 0) {
                logger.alert(red("Unsecure endpoint: ") + cyan(endpointUrl) + yellow(" Unsecure TokenType: ") + cyan(token.tokenType.toString()) + yellow(" (Anonymous)"));
            }
            table2.cell("IssuedTokenType", token.issuedTokenType);
            table2.cell("IssuerEndpointUrl", token.issuerEndpointUrl);
            table2.cell("SecurityPolicyUri", token.securityPolicyUri);
            table2.newRow();
        }
        if (doDebug) logger.info(cyan(table2.toString()));
    }
    await client.disconnect();

    // reconnect using the correct end point URL now
    if (doDebug) {
        logger.info(cyan("Server Certificate :"));
        logger.info(yellow(hexDump(serverCertificate!))); // TODO read metadata from the certificate
    }
    
    const adjustedEndpointUrl = client.endpointUrl;
    const options = {
        securityMode,
        securityPolicy,
        // we specify here server certificate
        serverCertificate,
        defaultSecureTokenLifetime: 40000,
        endpointMustExist: false,
        connectionStrategy: {
            initialDelay: 2000,
            maxDelay: 10 * 1000,
            maxRetry: 10
        }
    };
    logger.info(yellow("Security mode: "), cyan(MessageSecurityMode[options.securityMode].toString()));
    logger.info(yellow("Security policy: "), cyan(options.securityPolicy.toString()));
    
    client = OPCUAClient.create(options);
    await client.connect(adjustedEndpointUrl);
    let userIdentity: UserIdentityInfo = { type: UserTokenType.Anonymous }; // anonymous
    if (userName && password) {
        logger.info(yellow("Username: "), cyan(userName));
        userIdentity = {
            type: UserTokenType.UserName,
            password: password as string,
            userName: userName as string
        };
    }
    else {
        logger.alert(red("Server should not have Anonymous access!"));
    }
    the_session = await client.createSession(userIdentity);
    client.on("connection_reestablished", () => {
        logger.info(yellow("!!!!!!!!!!!!!!!!!!!!!!!!  ") + green("CONNECTION RE-ESTABLISHED") +  yellow("  !!!!!!!!!!!!!!!"));
    });
    logger.info(yellow("sessionId: "), cyan(the_session.sessionId.toString()));
    client.on("backoff", (retry: number, delay: number) => {
        logger.info(yellow("backoff  attempt #"), cyan(retry), yellow(" retrying in "), cyan(delay / 1000.0), yellow(" seconds"));
    });
    client.on("start_reconnection", () => {
        logger.info(yellow("!!!!!!!!!!!!!!!!!!!!!!!!  ") + green("Starting Reconnection") + yellow("      !!!!!!!!!!!!!!!"));
    });
    // Stress test DOS limit Sessions
    // await dDosTest(client, userIdentity);
    // TODO Read max operation limits and other max values
    await listNamespaces();

    // -----------------------------------------------------------------------------------------------------------
    //   Node Crawling TODO access rights & permissions => long list of variables & roles
    // -----------------------------------------------------------------------------------------------------------
    let t1: number;
    let t2: number;

    function print_stat() {
        t2 = Date.now();
        const str = util.format(
            "R= %d W= %d T=%d t= %d",
            client.bytesRead,
            client.bytesWritten,
            client.transactionsPerformed,
            t2 - t1
        );
        logger.info(yellow.bold(str));
    }

    if (doCrawling) {
        assert(the_session !== null && typeof the_session === "object");
        const crawler = new NodeCrawler(the_session);

        let t5 = Date.now();
        client.on("send_request", () => {
            t1 = Date.now();
        });
        if (doDebug) {
            client.on("receive_response", print_stat);
        }
        t5 = Date.now();
        // xx crawler.on("browsed", function (element) {
        // xx     logger.info("->",(new Date()).getTime()-t,element.browseName.name,element.nodeId.toString());
        // xx });
        let nodeId: NodeId;
        if (root_node) {
            nodeId = root_node;
        }
        else {
            nodeId = coerceNodeId("ns=0;i=85"); // "ObjectsFolder"
        }
        logger.info(yellow("Now crawling object folder, please wait..."));

        const obj = await crawler.read(nodeId);
        if (doDebug) {
            logger.info(yellow(" Time        = "), cyan(new Date().getTime() - t5));
            logger.info(yellow(" read        = "), cyan(crawler.readCounter));
            logger.info(yellow(" browse      = "), cyan(crawler.browseCounter));
            logger.info(yellow(" browseNext  = "), cyan(crawler.browseNextCounter));
            logger.info(yellow(" transaction = "), cyan(crawler.transactionCounter));
        }
        if (false) {
            // todo : treeify.asTree performance is *very* slow on large object, replace with better implementation
            // xx logger.info(treeify.asTree(obj, true));
            treeify.asLines(obj, true, true, (line: string) => {
                logger.info(line);
            });
        }
        /*
            * Anonymous            The Role has very limited access for use when a Session has anonymous credentials.
            * AuthenticatedUser    The Role has limited access for use when a Session has valid non-anonymous credentials
            *                      but has not been explicitly granted access to a Role.
            * Observer             The Role is allowed to browse, read live data, read historical data/events or subscribe to data/events.
            * Operator             The Role is allowed to browse, read live data, read historical data/events or subscribe to data/events.
            *                      In addition, the Session is allowed to write some live data and call some Methods.
            * Engineer             The Role is allowed to browse, read/write configuration data, read historical data/events,
            *                      call Methods or subscribe to data/events.
            * Supervisor           The Role is allowed to browse, read live data, read historical data/events, call Methods or
            *                      subscribe to data/events.
            * ConfigureAdmin       The Role is allowed to change the non-security related config
            * SecurityAdmin	    The Role is allowed to change security related settings.
        */
        logger.info(yellow("Username: ") + cyan(userName));
        treeify.asLines(obj, true, true, async (line: string) => {
            if (line.indexOf("nodeId:") > 0) {
                const node:string = line.substring(line.indexOf("nodeId:")+8);
                // logger.info("NodeId: " + node);
                const perm = await the_session.read({nodeId: node, attributeId: AttributeIds.RolePermissions});
                // logger.info("RolePermission: " + perm.value.value);
                /*
                export const allPermissions =
                PermissionFlag.Browse |
                PermissionFlag.Browse |
                PermissionFlag.ReadRolePermissions |
                PermissionFlag.WriteAttribute |
                PermissionFlag.WriteRolePermissions |
                PermissionFlag.WriteHistorizing |
                PermissionFlag.Read |
                PermissionFlag.Write |
                PermissionFlag.ReadHistory |
                PermissionFlag.InsertHistory |
                PermissionFlag.ModifyHistory |
                PermissionFlag.DeleteHistory |
                PermissionFlag.ReceiveEvents |
                PermissionFlag.Call |
                PermissionFlag.AddReference |
                PermissionFlag.RemoveReference |
                PermissionFlag.DeleteNode |
                PermissionFlag.AddNode;
                */
                const access = await the_session.read({nodeId: node, attributeId: AttributeIds.AccessLevel});
                /* AccessLevelFlag {
                    CurrentRead = 1,
                    CurrentWrite = 2,
                    HistoryRead = 4,
                    HistoryWrite = 8,
                    SemanticChange = 16,
                    StatusWrite = 32,
                    TimestampWrite = 64,
                    NONE = 2048,
                    None = 2048
                }
                */
                let elem:RolePermissionType;
                logger.info(yellow.bold("NodeId: ") + cyan(node));
                logger.info(yellow(" AccessRights: ") + cyan(accessLevelFlagToString(access.value.value)));
                scanResults["NodeIds"].push({"NodeId": node, "AccessRights": accessLevelFlagToString(access.value.value)});
                logger.info(yellow(" Permissions: "));
                if (perm && perm.value && perm.value.value) {
                    for (let e = 0; e < perm.value.value.length; e++) {
                        elem = perm.value!.value[e];
                        // WellKnownRoles, see https://reference.opcfoundation.org/Core/Part3/v105/docs/4.9.2
                        let role="";
                        if (elem.roleId.toString() === "ns=0;i=15644") {
                            role = "Anonymous";
                        }
                        if (elem.roleId.toString() === "ns=0;i=15656") {
                            role="AuthenticatedUser";
                        }
                        if (elem.roleId.toString() === "ns=0;i=15680") {
                            role="Operator";
                        }
                        if (elem.roleId.toString() === "ns=0;i=16036") {
                            role="Engineer";
                        }
                        if (elem.roleId.toString() === "ns=0;i=15716") {
                            role="ConfigureAdmin";
                        }
                        if (elem.roleId.toString() === "ns=0;i=15704") {
                            role="SecurityAdmin";
                        }
                        if (elem.roleId.toString() === "ns=0;i=15692") {
                            role="Supervisor";
                        }
                        let flag = elem.permissions as number;
                        logger.info(yellow("  Role: ") + cyan(role));
                        logger.info(yellow("  Perm: ") + cyan(permissionFlagToString(flag)));
                        scanResults["NodeIds"].push({"NodeId": node, "AccessRights": accessLevelFlagToString(access.value.value),
                                                     "Role": role, "Permissions": permissionFlagToString(flag)});
                    }
                }
            }
        });
        crawler.dispose();
    }
    client.removeListener("receive_response", print_stat);

    // ----------------------------------------------------------------------------------
    // create subscription
    // ----------------------------------------------------------------------------------
    const parameters = {
        maxNotificationsPerPublish: 10,
        priority: 10,
        publishingEnabled: true,
        requestedLifetimeCount: 1000,
        requestedMaxKeepAliveCount: 12,
        requestedPublishingInterval: 2000
    };

    theSubscription = await the_session.createSubscription2(parameters);
    let t = getTick();
    if (doDebug) {
        logger.info(yellow("started subscription: "), cyan(theSubscription!.subscriptionId)); // TODO Test max amount
        logger.info(yellow("revised parameters: "));
        logger.info(
            yellow("  revised maxKeepAliveCount:  "), cyan(theSubscription!.maxKeepAliveCount),
            yellow("   ( requested: "), cyan(parameters.requestedMaxKeepAliveCount) + yellow(")")
        );
        logger.info(
            yellow("  revised lifetimeCount:      "), cyan(theSubscription!.lifetimeCount),
            yellow(" ( requested: "), cyan(parameters.requestedLifetimeCount) + yellow(")")
        );
        logger.info(
            yellow("  revised publishingInterval: "), cyan(theSubscription!.publishingInterval),
            yellow(" ( requested: "), cyan(parameters.requestedPublishingInterval) + yellow(")")
        );
    }
    theSubscription
        .on("internal_error", (err: Error) => {
            logger.error("Received internal error: " + err.message);
        })
        .on("keepalive", () => {
            const t4 = getTick();
            const span = t4 - t;
            t = t4;
            logger.info(yellow("keepalive "),
                cyan(span / 1000),
                yellow("sec"),
                yellow(" pending request on server = "),
                cyan((theSubscription as any).getPublishEngine().nbPendingPublishRequests)
            );
        })
        .on("terminated", () => {
            /* */
        });
    
    try {
        const results1 = await theSubscription.getMonitoredItems();
    } catch (err) {
        if (types.isNativeError(err)) {
            logger.error("Server doesn't seems to implement getMonitoredItems method: " + err.message);
        }
    }

    // TODO Stress test subscription amount and monitoredItems amount, perhaps NOT good idea to run in production environment

    // ---------------------------------------------------------------
    //  monitor a variable node value
    // ---------------------------------------------------------------
    logger.info(yellow("Monitoring node: "), cyan(monitored_node.toString()));
    const monitoredItem = ClientMonitoredItem.create(
        theSubscription,
        {
            attributeId: AttributeIds.Value,
            nodeId: monitored_node
        },
        {
            discardOldest: true,
            queueSize: 10000,
            samplingInterval: 1000
            // xx filter:  { parameterTypeId: "ns=0;i=0",  encodingMask: 0 },
        }
    );
    monitoredItem.on("initialized", () => {
        // logger.info(yellow("monitoredItem initialized"));
    });
    monitoredItem.on("changed", (dataValue1: DataValue) => {
        if (doDebug) {
            logger.info(cyan(monitoredItem.itemToMonitor.nodeId.toString()), yellow(" value has changed to ") + cyan(dataValue1.value.toString()));
        }
        // TODO After simulated network break value should update ADD CHECK HERE!!!
    });
    monitoredItem.on("err", (err_message: string) => {
        logger.error(monitoredItem.itemToMonitor.nodeId.toString() + " error: " + err_message);
    });

    const results = await theSubscription.getMonitoredItems();
    logger.info(yellow("Timeout timer:  "), cyan(timeout));
    if (timeout > 0) {
        // simulate a connection break at t =timeout/2
        // new Promise((resolve) => {
        setTimeout(() => {
            logger.info(green("-------------------------------------------------------------------- "));
            logger.info(green("--                        ")+red("SIMULATE CONNECTION BREAK") + green("               -- "));
            logger.info(green("-------------------------------------------------------------------- "));
            const socket = (client as any)._secureChannel._transport._socket;
            socket.end();
            socket.emit("error", new Error("ECONNRESET"));
        }, timeout / 2.0);
        // });

        await new Promise<void>((resolve) => {
            setTimeout(async () => {
                // logger.debug(yellow("time out => shutting down "));
                if (!theSubscription) {
                    return resolve();
                }
                if (theSubscription) {
                    const s = theSubscription;
                    theSubscription = null;
                    await s.terminate();
                    await the_session.close();
                    await client.disconnect();
                    logger.info(green("Done"));
                    logger.info(yellow("Scan results: ") + cyan(JSON.stringify(scanResults)));
                    fs.writeFileSync("scan_results.json", JSON.stringify(scanResults));
                    // TODO Save with serverName into the JSON file
                    // process.exit(0);
                    return resolve();
                }
            }, timeout);
        });
    }
    await the_session.close();
    await client.disconnect();
    logger.info(green("Scan server(s) done successfully!!"));
}

async function sleep(delayInMilliseconds: number): Promise<void> {
    return new Promise((resolve) => {
        setTimeout(resolve, delayInMilliseconds);
    });
}

async function watchDog() {
    if (the_session && !the_session.isReconnecting) {
        await the_session.read({nodeId: "ns=0;i=2258;", attributeId: AttributeIds.Value});
    }
}

// NOTE: Do not run in production environment
async function dDosTest(client: OPCUAClient, userIdentity: UserIdentityInfo) {
    logger.info(yellow("Starting DDOS test"));
    const id = setInterval(watchDog, 10000); // This will keep main session alive
    // Read first: 
    // current session count    ns=0;i=2277
    // cumulated session count  ns=0;i=2278
    // Create sessions until fails
    // Wait session timeout and see if sessions released
    let current = await the_session.read({nodeId: "ns=0;i=2277;", attributeId: AttributeIds.Value});
    let cumulated = await the_session.read({nodeId: "ns=0;i=2278;", attributeId: AttributeIds.Value});
    const start = current.value.value; // Number of sessions at start of test
    logger.info(yellow("Session timeout: ") + cyan(the_session.timeout) + yellow(" current: ") + cyan(current.value.value) + yellow("/") + cyan(cumulated.value.value));
    let maxSessions = [];
    for (let s = 0; s < 50; s++) {
        try {
            maxSessions[s] = await client.createSession(userIdentity);
        }
        catch (err:any) {
            logger.error(err.message + " on session: #" + s);
            current = await the_session.read({nodeId: "ns=0;i=2277;", attributeId: AttributeIds.Value});
            cumulated = await the_session.read({nodeId: "ns=0;i=2278;", attributeId: AttributeIds.Value});
            logger.info(yellow("Session timeout: ") + cyan(the_session.timeout) + yellow(" current: ") + cyan(current.value.value) + yellow("/") + cyan(cumulated.value.value));
            break;
        }
    }
    await sleep(the_session.timeout + 2000);
    for (let s = 0; s < maxSessions.length; s++) {
        try {
            logger.info(yellow("Closing session: ") + cyan(maxSessions[s].sessionId) + " / " + cyan(s));
            maxSessions[s].close();
        }
        catch (err:any) {
            logger.error("Max sessions, error: " + err.message);
        }
    }
    // Check that the_session is still alive
    current = await the_session.read({nodeId: "ns=0;i=2277;", attributeId: AttributeIds.Value});
    cumulated = await the_session.read({nodeId: "ns=0;i=2278;", attributeId: AttributeIds.Value});
    logger.info(yellow("Ending DDOS test"));
    logger.info(yellow("Session timeout: ") + cyan(the_session.timeout) + yellow(" current: ") + cyan(current.value.value) + yellow(" / cumulated:") + cyan(cumulated.value.value));
    // If start amount is same as current then all sessions cleaned correctly
    if (start - current.value.value === 0) {
        logger.debug(green("DDOS cleanup status: ") + cyan(start) + yellow(" - ") + cyan(current.value.value) + yellow(" = ") + cyan(start - current.value.value));
    }
    else {
        logger.error("DDOS cleanup status: " + start + " - " + current.value.value.toString() + " = " + (start - current.value.value));
    }
    clearInterval(id);
}

async function infoVariable(session: ClientSession, name: string, node: string) {
    const result = await session.read({nodeId: node, attributeId: AttributeIds.Value});
    if (result && result.statusCode == StatusCodes.Good) {
        logger.info(yellow("variable: ") + cyan(name) + yellow(" value: ") + cyan(result.value.value.toString()));
    }
}

async function warnVariableNotZero(session: ClientSession, name: string, node: string) {
    const result = await session.read({nodeId: node, attributeId: AttributeIds.Value});
    if (result && result.statusCode == StatusCodes.Good && result.value.value > 0) {
        logger.alert(red("Variable: ") + cyan(name) + yellow(" > 0, current value: ") + cyan(result.value.value.toString()));
    }
}

async function errorVariableNotZero(session: ClientSession, name: string, node: string) {
    const result = await session.read({nodeId: node, attributeId: AttributeIds.Value});
    if (result && result.statusCode == StatusCodes.Good && result.value.value > 0) {
        logger.alert(red("Variable: ") + cyan(name) + yellow(" != 0, current value: ") + cyan(result.value.value.toString()));
    }
}

async function checkServerCurrentTimeToClientTime(session: ClientSession) {
    const node = "ns=0;i=2258"; // Server current time
    const result = await session.read({nodeId: node, attributeId: AttributeIds.Value});
    const ct = new Date();;
    if (result && result.statusCode == StatusCodes.Good) {
        const diffInMs = Math.abs(ct.getTime() - result.value.value.getTime());
        logger.info(yellow("Server current time - client current time, delta: ") + cyan(diffInMs) + yellow(" ms"));
        // TODO Limit to configuration, for test purpose too small limit
        if (diffInMs > 500) {
            logger.alert(red("Server/client time is not synchronized with NTP, current time different is too much: ") + cyan(diffInMs) + yellow(" ms"));
        }
    }
}

// TODO periodic checks:
//
// Security settings: No anonymous access (other certificate etc. will be scanned only on start)
// Certificate validity: end date, report, WARN if will expire in 1 month, ERROR if will expire in 1 week
// Diagnostics error counters to be checked with given period (default 1 hour)
// Other diagnostics counters close to max limit (10% or 1-2 resource units free)
// 

async function periodic_tests(endpoint: string, security_Mode: string, security_Policy: string, interval: number) {
    const securityMode = coerceMessageSecurityMode(security_Mode!);
    if (securityMode === MessageSecurityMode.Invalid) {
        throw new Error("Invalid Security mode");
    }
    const securityPolicy = coerceSecurityPolicy(security_Policy!);
    if (securityPolicy === SecurityPolicy.Invalid) {
        throw new Error("Invalid securityPolicy");
    }
    const options = {
        securityMode,
        securityPolicy,
        // we specify here server certificate
        // serverCertificate,
        defaultSecureTokenLifetime: 40000,
        endpointMustExist: false,
        connectionStrategy: {
            initialDelay: 2000,
            maxDelay: 10 * 1000,
            maxRetry: 10
        }
    };
    logger.info(yellow("Security mode: "), cyan(MessageSecurityMode[options.securityMode].toString()));
    logger.info(yellow("Security policy: "), cyan(options.securityPolicy.toString()));
    client = OPCUAClient.create(options);
    await client.connect(endpoint);
    // Use global: userName and password 
    // Check that there is no Anonymous access
    let userIdentity: UserIdentityInfo = { type: UserTokenType.Anonymous }; // anonymous
    if (userName && password) {
        logger.info(yellow("Username: "), cyan(userName));
        userIdentity = {
            type: UserTokenType.UserName,
            password: password as string,
            userName: userName as string
        };
    }
    else {
        logger.alert(red("Server should not have Anonymous access!"));
    }
    const session = await client.createSession(userIdentity);
    client.on("connection_reestablished", () => {
        logger.info(yellow("!!!!!!!!!!!!!!!!!!!!!!!!  ") + green("CONNECTION RE-ESTABLISHED") +  yellow("  !!!!!!!!!!!!!!!"));
    });
    logger.info(yellow("sessionId: "), cyan(session.sessionId.toString()));
    client.on("backoff", (retry: number, delay: number) => {
        logger.info(yellow("backoff  attempt #"), cyan(retry), yellow(" retrying in "), cyan(delay / 1000.0), yellow(" seconds"));
    });
    client.on("start_reconnection", () => {
        logger.info(yellow("!!!!!!!!!!!!!!!!!!!!!!!!  ") + green("Starting Reconnection") + yellow("      !!!!!!!!!!!!!!!"));
    });

    // NTP Check server current time and client local OS time
    await checkServerCurrentTimeToClientTime(session);
    // Certificate validity

    // Diagnostics:
    // ServerStatus to report / log

	await infoVariable(session, "ProductName", "ns=0;i=2261");
	await infoVariable(session, "ProductUri", "ns=0;i=2262")
    await infoVariable(session, "ManufacturerName", "ns=0;i=2263")
	await infoVariable(session, "SoftwareVersion", "ns=0;i=2264")
	await infoVariable(session, "BuildDate", "ns=0;i=2266")
	await infoVariable(session, "BuildNumber", "ns=0;i=2265")

	await infoVariable(session, "CurrentSessionCount", "ns=0;i=2277")
	await infoVariable(session, "CumulatedSessionCount", "ns=0;i=2278")
	await infoVariable(session, "CurrentSubscriptionCount", "ns=0;i=2285")
	//  Read again after some time variables above to check if increased
	// NOTE ActualSessionTimeout will limit this, think if we should use keepalive or session subscription with current time
		
	// Read rejected counters that will make warning
	await warnVariableNotZero(session, "RejectedRequestCount", "ns=0;i=2288")
	await warnVariableNotZero(session, "RejectedSessionCount", "ns=0;i=3705")
	await warnVariableNotZero(session, "SessionAbortCount", "ns=0;i=2282")
	await warnVariableNotZero(session, "SessionTimeoutCount", "ns=0;i=2281")

    // Read rejected counters that will make error
	await errorVariableNotZero(session, "SecurityRejectedRequestCount", "ns=0;i=2287")
	await errorVariableNotZero(session, "SecurityRejectedSessionCount", "ns=0;i=2279")

    // Close session and disconnect client
    await session.close();
    await client.disconnect();

    // Run again after interval
    setTimeout(periodic_tests, interval, endpoint, security_Mode, security_Policy, interval);
}

async function main() {
    // ts-node bin/ua_scanner.ts
    // ts-node bin/ua_scanner.ts --endpoint  opc.tcp://localhost:53530/OPCUA/SimulationServer --node "ns=5;s=Sinusoid1"
    const argv = await yargs(process.argv)
        .wrap(132)
        .usage(yellow("Usage: $0 -d --endpoint <endpointUrl> [--securityMode (None|SignAndEncrypt|Sign)] [--securityPolicy (None|Basic256|Basic128Rsa15)] --node <node_id_to_monitor> --crawl"))
        .option("endpoint", {
            alias: "e",
            // demandOption: true, // Use discovery server to find servers if not defined
            // TODO test more if given then => no discovery
            describe: yellow("the end point to connect to like opc.tcp://localhost:4840")
        })
        .option("securityMode", {
            alias: "s",
            default: "None",
            describe: yellow("the security mode ( None | Sign | SignAndEncrypt )")
        })
        .option("securityPolicy", {
            alias: "P",
            default: "None",
            describe: yellow("the policy mode : (" + Object.keys(SecurityPolicy).join(" - ") + ")")
        })
        .option("username", {
            alias: "u",
            describe: yellow("specify the user name of a UserNameIdentityToken")
        })
        .option("password", {
            alias: "p",
            describe: yellow("specify the password of a UserNameIdentityToken")
        })
        .option("node", {
            alias: "n",
            describe: yellow("the nodeId of the value to monitor")
        })
        .option("root", {
            alias: "r",
            describe: yellow("the nodeId of the root nodeId to crawl (browse)")
        })
        .option("timeout", {
            alias: "t",
            describe: yellow("the timeout of the session in second =>  (-1 for infinity)")
        })
        .option("debug", {
            alias: "d",
            boolean: true,
            describe: yellow("display more verbose debug information")
        })
        .option("History", {
            alias: "H",
            describe: yellow("make an historical read")
        })
        .option("help", {
            alias: "h",
            describe: yellow("help; show usage")
        })
        .option("version", {
            alias: "v",
            describe: yellow("show version")
        })
        .option("crawl", {
            alias: "c",
            boolean: false,
            describe: yellow("Crawl; browse through address space")
        })
        .option("discovery", {
            alias: "D",
            describe: yellow("Specify the endpoint uri of discovery server (by default same as server endpoint uri)")
        })
        .option("grayloghost", {
            alias: "g",
            describe: yellow("Add server hostname to graylog servers")
        })
        .option("graylogport", {
            alias: "G",
            describe: yellow("Add server port to graylog servers")
        })
        .option("sysloghost", {
            alias: "s",
            describe: yellow("Use hostname for syslog server")
        })
        .option("syslogport", {
            alias: "S",
            describe: yellow("Use port for syslog server")
        })
        .option("syslogtcp", {
            alias: "T",
            boolean: false,
            describe: yellow("Use TCP for syslog (default UDP)")
        })
        .example(yellow("ua_scanner ") + red("-e") + cyan(" opc.tcp://localhost:53530/OPCUA/SimulationServer") + red(" -c"), yellow("Simple use with endpoint and crawl"))
        .example(yellow("ua_scanner ") + red("-e") + cyan(" opc.tcp://localhost:53530/OPCUA/SimulationServer") + red(" -c -g") + cyan(" remotehost ") +red("-G") + cyan(" 12201"), yellow("Graylog parameters"))
        .example(yellow("ua_scanner ") + red("-e") + cyan(" opc.tcp://localhost:53530/OPCUA/SimulationServer") + red(" -c -s") + cyan(" remotehost ") +red("-S") + cyan(" 514"), yellow("Syslog parameters"))
        .example(yellow("ua_scanner ") + red("--endpoint") + cyan(" opc.tcp://localhost:49230") +  red(" -P=") + cyan("Basic256Rsa256 ") + red("-s=") + cyan("Sign "), yellow("Use security policy and mode"))
        .example(yellow("ua_scanner ") + red("-e") + cyan(" opc.tcp://localhost:49230") + red(" -P=") + cyan("Basic256Sha256") + red(" -s=") + cyan("Sign ") 
            + red("-u") + cyan(" JoeDoe ") + red("-p") + cyan(" P@338@rd"), yellow("Give username and password"))
        .example(yellow("ua_scanner ") + red("--endpoint") + cyan(" opc.tcp://localhost:49230") +red(" -n=") + cyan('"ns=0;i=2258"'), yellow("Monitor nodeId")).argv;

    let grayloghost:any = argv.grayloghost || "";
    let graylogport:any = argv.graylogport || 0;
    let sysloghost:any = argv.sysloghost || "";
    let syslogport:any = argv.syslogport || 0;
    let syslogtcp:any = argv.syslogtcp || false;

    if (argv.help) {
        yargs.showHelp();
        process.exit(0);
    }
    initLogs(grayloghost, graylogport, sysloghost, syslogport, syslogtcp);

    const securityMode = coerceMessageSecurityMode(argv.securityMode!);
    if (securityMode === MessageSecurityMode.Invalid) {
        throw new Error("Invalid Security mode");
    }
    const securityPolicy = coerceSecurityPolicy(argv.securityPolicy!);
    if (securityPolicy === SecurityPolicy.Invalid) {
        throw new Error("Invalid securityPolicy");
    }
    if (argv.userName) {
        userName = argv.userName.toString();
    }
    if (argv.password) {
        password = argv.password.toString();
    }
    if (argv.root) {
        root_node = coerceNodeId(argv.root.toString());
    }

    timeout = (argv.timeout as number) * 1000 || 60000; // Must be long enough to get updates after connection break
    monitored_node = coerceNodeId((argv.node as string) || makeNodeId(VariableIds.Server_ServerStatus_CurrentTime));

    logger.info(yellow("securityMode:    "), cyan(securityMode.toString()));
    logger.info(yellow("securityPolicy:  "), cyan(securityPolicy.toString()));
    logger.info(yellow("timeout:         "), cyan(timeout ? timeout : " Infinity "));
    logger.info(yellow("monitoring node: "), cyan(monitored_node));

    const endpointUrl = argv.endpoint as string;

    const capabilities = argv.capabilities || "LDS";
    const discoveryUrl: string = argv.discovery as string || "opc.tcp://localhost:4840";
    const doCrawling = !!argv.crawl;
    const doHistory = !!argv.history;
    doDebug = !!argv.debug;

    if (endpointUrl) {
        await scanServer("Server1", endpointUrl, securityMode, securityPolicy, doCrawling);
    }
    else {
        // Use given or default discoveryUrl to scan servers on network
        findServersOnNetwork(discoveryUrl, async function (err, servers) {
            if(err) {
                logger.error(err.message);
                yargs.showHelp();
                process.exit(0);
            }
            if (servers) {
                logger.info(yellow("Servers on network (registered to discovery): "));
                for (const s of servers) {
                    for (const c of s.serverCapabilities!) {
                        if (c === "LDS") {
                            logger.info(green("Discovery server: ") + cyan(s.serverName) + " " + cyan(s.discoveryUrl)); // SKIP
                        }
                        else {
                            logger.info(green("Server found: ") + cyan(s.serverName) + " " + cyan(s.discoveryUrl)); // SCAN => if no endpoint given
                            await scanServer(s.serverName, s.discoveryUrl, securityMode, securityPolicy, doCrawling);
                        }
                    }
                }
            }
            else {
                logger.info(yellow("Use option -D to give discoveryServerUrl or -e to give endpoint!"));
                yargs.showHelp();
                process.exit(0);
            }
        });
    }
    const interval = 60 * 1000; // 1 min for testing, TODO default 60 * 60 * 1000 == 1 hour
    setTimeout(periodic_tests, interval, endpointUrl, securityMode, securityPolicy, interval);

    while (true) {
        await sleep(1000);
    }
}

process.once("SIGINT", async () => {
    logger.warning(yellow("User interruption (Ctrl-c)..."));

    if (theSubscription) {
        logger.warning(yellow("Received client interruption from user"));
        logger.warning(yellow("Shutting down..."));
        const subscription = theSubscription;
        theSubscription = null;

        await subscription.terminate();
    }
    await the_session.close();
    await client.disconnect();
    process.exit(0);
});

main();