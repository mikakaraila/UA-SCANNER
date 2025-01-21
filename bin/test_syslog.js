var os = require("os");
var syslog = require("syslog-client");
var chalk = require("chalk");
// var client = syslog.createClient("127.0.0.1");

// Default options
var options = {
  syslogHostname: os.hostname(),
  transport: syslog.Transport.Udp,
  port: 514
};

var client = syslog.createClient("127.0.0.1", options);

var options = {
  facility: syslog.Facility.Alert,
  severity: syslog.Severity.Critical
};

var message = "Something is wrong!";

client.log(message, options, function(error) {
  if (error) {
      console.error(chalk.red(error));
  } else {
      console.log(chalk.green("sent message successfully"));
  }
});
