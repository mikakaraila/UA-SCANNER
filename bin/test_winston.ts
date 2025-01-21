const winston = require('winston');
const os = require("os");
const syslog = require("syslog-client");
require('winston-syslog').Syslog;
const WinstonGraylog2 = require('winston-graylog2');
const options4graylog = {
  name: 'Graylog',
  level: 'debug',
  silent: false,
  handleExceptions: false,
  graylog: {
    servers: [{host: 'localhost', port: 12201}, {host: 'remote.host', port: 12201}],
    hostname: os.hostname(),
    facility: 'OPC UA Monitoring',
    bufferSize: 1400
  },
  staticMeta: {env: 'staging'}
};

var options = {
  syslogHostname: os.hostname(),
  transport: syslog.Transport.Udp,
  port: 514
};

const logger = winston.createLogger({
  // level: 'info',
  levels: winston.config.syslog.levels,
  format: winston.format.json(),
  // defaultMeta: { service: 'user-service' },
  defaultMeta: { service: 'OPC UA Monitoring' },
  transports: [
    //
    // - Write all logs with importance level of `error` or less to `error.log`
    // - Write all logs with importance level of `info` or less to `combined.log`
    //
    new winston.transports.File({   filename: 'error.log', level: 'error' }),
    new winston.transports.File({   filename: 'combined.log' }),
    // Next line defined that info and warning levels are not reported to syslog
    new winston.transports.Syslog({ syslogHostname: os.hostname(), level: "error", transport: syslog.Transport.Udp, port: 514}),
    new WinstonGraylog2(options4graylog)
  ],
});

//
// If we're not in production then log to the `console` with the format:
// `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
//

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}


/*
logger
  .clear()          // Remove all transports
  .add(console)     // Add console transport
  add(files)       // Add file transport
  .remove(console); // Remove console transport
*/
var options2 = {
  facility: syslog.Facility.Alert,
  severity: syslog.Severity.Critical,
  priority: syslog.Severity.Critical
};
logger.info("Info - Test");
logger.debug("Debug - test");
logger.warning("Warn - Test");
logger.error("Error - Test");
logger.crit("Critical - Test!");
logger.alert("Alert - Test!!");
logger.emerg("Emergency - Test!!!");

