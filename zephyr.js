var events = require('events');
var util = require('util');

var Q = require('q');

var internal = require('./build/Release/zephyr');

var zephyr = new events.EventEmitter();

zephyr.ZAUTH_FAILED = -1;
zephyr.ZAUTH_YES = 1;
zephyr.ZAUTH_NO = 0;

zephyr.ZAUTH = 'ZAUTH';
zephyr.ZNOAUTH = 'ZNOAUTH';

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

var Z_FRAGFUDGE = 13;
var Z_MAXPKTLEN = 1024;

zephyr.openPort = internal.openPort;

// TODO: Make these properties with a getter?
zephyr.getSender = internal.getSender;
zephyr.getRealm = internal.getRealm;

var hmackTable = { };
var servackTable = { };

function OutgoingNotice(hmack, servack) {
  events.EventEmitter.call(this);

  Q.nodeify(hmack, this.emit.bind(this, 'hmack'));
  Q.nodeify(servack, this.emit.bind(this, 'servack'));
}
OutgoingNotice.prototype = Object.create(events.EventEmitter.prototype);

function internalSendNotice(msg, certRoutine) {
  try {
    var uids = internal.sendNotice(msg, certRoutine);
  } catch (err) {
    // FIXME: Maybe this should just be synchronous? Reporting the
    // error twice is silly, but if you fail this early, you fail
    // both.
    return {
      hmack: Q.reject(err),
      servack: Q.reject(err),
    };
  }

  // Set up a bunch of deferreds for ACKs.
  var keys = uids.map(function(uid) { return uid.toString('base64'); });

  // HMACK
  // XXX: libzephyr gets confused with fragmentation code and HMACKs
  // and doesn't expect ZSendPacket to not block. This requires a fix
  // in libzephyr.
  var hmack = Q.all(keys.map(function(key) {
    hmackTable[key] = Q.defer();
    return hmackTable[key].promise;
  }));

  // SERVACK
  // libzephyr also drops non-initial SERVACKs on the floor. This
  // would be worth tweaking but, for now, only report on the initial
  // one.
  servackTable[keys[0]] = Q.defer();
  var servack = Q.all([servackTable[keys[0]].promise]);

  return {
    hmack: hmack,
    servack: servack,
  };
};

zephyr.sendNotice = function(msg, certRoutine, onHmack) {
  var acks = internalSendNotice(msg, certRoutine);
  var ev = new OutgoingNotice(acks.hmack, acks.servack);
  if (onHmack)
    ev.once('hmack', onHmack);
  return ev;
};

function zephyrCtl(opcode, subs, cb) {
  // Normalize recipients.
  subs = subs.map(function(sub) {
    var zClass = sub[0], zInst = sub[1], zRecip = sub[2];
    if (zRecip != null && zRecip[0] === '*')
      zRecip = zRecip.substring(1);
    if (zRecip == null || (zRecip !== '' && zRecip[0] !== '@'))
      zRecip = zephyr.getSender();
    return [zClass, zInst, zRecip];
  });

  try {
    var uids = internal.subscriptions(subs, opcode);
  } catch (err) {
    process.nextTick(function() {
      cb(err);
    });
    return;
  }

  Q.nodeify(Q.all(uids.map(function(uid) {
    var key = uid.toString('base64');
    servackTable[key] = Q.defer();
    return servackTable[key].promise;
  })), cb);
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

zephyr.formatNotice = internal.formatNotice;

internal.setNoticeCallback(function(err, notice) {
  if (err) {
    zephyr.emit("error", err);
    return;
  }

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
});

module.exports = zephyr;
