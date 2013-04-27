var zephyr = require('./zephyr');

var cls = process.argv[2];
var inst = process.argv[3];

zephyr.openPort();

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

zephyr.subscribeTo([ [ cls, inst, '*' ] ], function(err) {
  if (err) {
    console.dir(err);
    return;
  }
  console.log('Subscribed to %s %s', cls, inst);

  process.stdin.on('data', function(message) {
    zephyr.sendNotice({
      class: cls,
      instance: inst,
      body: [
	'badass rockstar zephyr',
	message
      ]
    }, zephyr.ZAUTH, function(err) {
      if (err) {
	console.dir(err);
	return;
      }
      console.log('got HMACK');
    }).on('servack', function(err, msg) {
      if (err) {
	console.dir('got SERVNAK', err);
	return;
      }
      console.log('got SERVACK', msg);
    });
  });
  process.stdin.setEncoding('utf8');
  process.stdin.resume();
});
