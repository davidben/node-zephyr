var events = require('events');
var util = require('util');

var Q = require('q');

var internal = require('./build/Release/zephyr');

var zephyr = new events.EventEmitter();

zephyr.ZAUTH_FAILED = -1;
zephyr.ZAUTH_YES = 1;
zephyr.ZAUTH_NO = 0;

zephyr.UNSAFE = 0;
zephyr.UNACKED = 1;
zephyr.ACKED = 2;
zephyr.HMACK = 3;
zephyr.HMCTL = 4;
zephyr.SERVACK = 5;
zephyr.SERVNAK = 6;
zephyr.CLIENTACK = 7;
zephyr.STAT = 8;

zephyr.ZSRVACK_SENT = 'SENT';
zephyr.ZSRVACK_NOTSENT = 'LOST';
zephyr.ZSRVACK_FAIL = 'FAIL';

zephyr.ZEPHYR_CTL_CLASS = 'ZEPHYR_CTL';
zephyr.ZEPHYR_CTL_CLIENT = 'CLIENT';

zephyr.CLIENT_SUBSCRIBE = 'SUBSCRIBE';
zephyr.CLIENT_SUBSCRIBE_NODEFS = 'SUBSCRIBE_NODEFS';
zephyr.CLIENT_UNSUBSCRIBE = 'UNSUBSCRIBE';
zephyr.CLIENT_CANCELSUB = 'CLEARSUB';
zephyr.CLIENT_GIMMESUBS = 'GIMME';
zephyr.CLIENT_GIMMEDEFS = 'GIMMEDEFS';
zephyr.CLIENT_FLUSHSUBS = 'FLUSHSUBS';

var ZSRVACK_PRIORITY = { }
ZSRVACK_PRIORITY[zephyr.ZSRVACK_SENT] = 0;
ZSRVACK_PRIORITY[zephyr.ZSRVACK_NOTSENT] = 1;
ZSRVACK_PRIORITY[zephyr.ZSRVACK_FAIL] = 2;

zephyr.openPort = internal.openPort;

// TODO: Make these properties with a getter?
zephyr.getSender = internal.getSender;
zephyr.getRealm = internal.getRealm;

var hmackTable = { };
var servackTable = { };

function OutgoingNotice() {
  events.EventEmitter.call(this);
}
OutgoingNotice.prototype = Object.create(events.EventEmitter.prototype);

zephyr.sendNotice = function(msg, onHmack) {
  var ev = new OutgoingNotice();
  if (onHmack)
    ev.once('hmack', onHmack);

  try {
    var uids = internal.sendNotice(msg);
  } catch (err) {
    // FIXME: Maybe this should just be synchronous? Reporting the
    // error twice is silly, but if you fail this early, you fail
    // both.
    process.nextTick(function() {
      ev.emit('hmack', err);
      ev.emit('servack', err);
    });
    return ev;
  }

  // Set up a bunch of deferreds for ACKs.
  var keys = uids.map(function(uid) { return uid.toString('base64'); });

  // HMACK
  // XXX: libzephyr gets confused with fragmentation code and HMACKs
  // and doesn't expect ZSendPacket to not block. This requires a fix
  // in libzephyr.
  Q.all(keys.map(function(key) {
    hmackTable[key] = Q.defer();
    return hmackTable[key].promise;
  })).then(function() {
    ev.emit('hmack', null);
  }, function(err) {
    // I don't think this ever happens. Meh.
    ev.emit('hmack', err);
  }).done();

  // SERVACK
  // libzephyr also drops non-initial SERVACKs on the floor. This
  // would be worth tweaking but, for now, only report on the initial
  // one.
/*
  Q.all(keys.map(function(key) {
    servackTable[key] = Q.defer();
    return servackTable[key].promise;
  })).then(function(msgs) {
    // Collapse messages into a single one. Use the most sad result.
    var collapsed, pri = -1;
    msgs.forEach(function(msg) {
      if (ZSRVACK_PRIORITY[msg] > pri) {
	collapsed = msg;
	pri = ZSRVACK_PRIORITY[msg];
      }
    });
    ev.emit('servack', null, collapsed);
*/
  servackTable[keys[0]] = Q.defer();
  Q.all([servackTable[keys[0]].promise]).then(function(msg) {
    ev.emit('servack', null, msg);
  }, function(err) {
    ev.emit('servack', err);
  }).done();

  return ev;
};

function zephyrCtl(opcode, subs, cb) {
  // Instead of using ZSubscribeTo, manually assemble using our
  // existing asynchronous sendNotice.

  // TODO(davidben): Manually fragment the subs list if it's too
  // long. ZSubscribeTo calls Z_FormatHeader, which is internal.
  //
  // TODO(davidben): Key management.

  var body = [];
  for (var i = 0; i < subs.length; i++) {
    var sub = subs[i];
    var zClass = sub[0], zInst = sub[1], zRecip = sub[2];
    body.push(zClass);
    body.push(zInst);
    if (zRecip != null && zRecip[0] === '*')
      zRecip = zRecip.substring(1);
    if (zRecip == null || (zRecip !== '' && zRecip[0] !== '@'))
      zRecip = zephyr.getSender();
    body.push(zRecip);
  }
  // ZFormatNoticeList sticks an extra NUL at the end.
  body.push('');

  var notice = {
    class: zephyr.ZEPHYR_CTL_CLASS,
    instance: zephyr.ZEPHYR_CTL_CLIENT,
    opcode: opcode,
    recipient: '',
    format: '',
    body: body,
  };

  zephyr.sendNotice(notice).once('servack', cb);
}

zephyr.subscribeTo = function(subs, cb) {
  zephyrCtl(zephyr.CLIENT_SUBSCRIBE, subs, cb);
};

zephyr.subscribeToSansDefaults = function(subs, cb) {
  zephyrCtl(zephyr.CLIENT_SUBSCRIBE_NODEFS, subs, cb);
};

zephyr.unsubscribeTo = function(subs, cb) {
  zephyrCtl(zephyr.CLIENT_UNSUBSCRIBE, subs, cb);
};

zephyr.cancelSubscriptions = function(cb) {
  zephyrCtl(zephyr.CLIENT_CANCELSUB, [], cb);
};

internal.setNoticeCallback(function(err, notice) {
  if (err) {
    zephyr.emit("error", err);
  } else {
    var key;
    if (notice.kind === zephyr.HMACK) {
      key = notice.uid.toString('base64');
      if (hmackTable[key])
	hmackTable[key].resolve(null);
      delete hmackTable[key];
    } else if (notice.kind === zephyr.SERVACK) {
      key = notice.uid.toString('base64');
      if (servackTable[key])
	servackTable[key].resolve(notice.body[0]);
      delete servackTable[key];
    } else if (notice.kind === zephyr.SERVNAK) {
      key = notice.uid.toString('base64');
      if (servackTable[key])
	servackTable[key].reject(new Error(notice.body[0]));
      delete servackTable[key];
    }

    zephyr.emit("notice", notice);
  }
});

module.exports = zephyr;
