var zephyr = require('./zephyr');

var cls = process.argv[2];
var inst = process.argv[3];

function subscribe() {
  console.log('Subscribing to %s %s', cls, inst);
  zephyr.subscribeTo([ [ cls, inst, '*' ] ], function(err) {
    if (err) {
      console.error('Could not subscribe', err);
      return;
    }
    console.log('Subscribed to %s %s', cls, inst);

    process.stdin.on('data', function(message) {
      var notice = zephyr.sendNotice({
        port: 1,
        class: cls,
        instance: inst,
        body: [
	  'badass rockstar zephyr',
	  message
        ]
      }, zephyr.ZAUTH, function(err) {
        if (err) {
	  console.error('Failed to send notice', err);
	  return;
        }
        console.log('got HMACK');
      }).on('servack', function(err, msg) {
        if (err) {
	  console.error('got SERVNAK', err);
	  return;
        }
        console.log('got SERVACK', msg);
      });
      console.log('uid', notice.uid);
    });
    process.stdin.setEncoding('utf8');
    process.stdin.resume();
  });
}

zephyr.initialize();
if (process.argv[4]) {
  zephyr.loadSession(new Buffer(process.argv[4], 'base64'));
  setTimeout(subscribe, 5000);
} else {
  zephyr.openPort();
  subscribe();
}

zephyr.on("notice", function(msg) {
  if (msg.kind == zephyr.HMACK) {
    console.log("HMACK : %s / %s / %s [%s]",
		msg.class, msg.instance, msg.sender, msg.opcode);
  } else if (msg.kind == zephyr.SERVACK) {
    console.log("SERVACK : %s / %s / %s [%s] %s",
		msg.class, msg.instance, msg.sender, msg.opcode,
		msg.body[0]);
  } else if (msg.kind == zephyr.SERVNAK) {
    console.log("SERVNAK : %s / %s / %s [%s] %s",
		msg.class, msg.instance, msg.sender, msg.opcode,
		msg.body[0]);
  } else {
    console.log("%s / %s / %s %s [%s] (%s)\n%s",
		msg.class, msg.instance, msg.sender,
		(msg.checkedAuth == zephyr.ZAUTH_YES) ?
		"AUTHENTIC" : "UNAUTHENTIC",
		msg.opcode, msg.body[0], msg.body[1]);
  }
});

setInterval(function() {
  console.log('Session state', zephyr.dumpSession().toString('base64'));
}, 2000);
