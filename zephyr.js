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

zephyr.initialize = internal.initialize;
zephyr.openPort = internal.openPort;

zephyr.dumpSession = internal.dumpSession;
zephyr.loadSession = internal.loadSession;

// TODO: Make these properties with a getter?
zephyr.getSender = internal.getSender;
zephyr.getRealm = internal.getRealm;

zephyr.downcase = internal.downcase;

var hmackTable = { };
var servackTable = { };

function OutgoingNotice(uid, hmack, servack) {
  events.EventEmitter.call(this);

  this.uid = uid;
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

  return waitOnUids(uids);
}

function waitOnUids(uids) {
  // TODO(davidben): Have all of these time out appropriately, and
  // whatnot. Also if an HMACK times out, there's no hope for the
  // SERVACK, so punt it too.

  // HMACK
  // XXX: libzephyr gets confused with fragmentation code and HMACKs
  // and doesn't expect ZSendPacket to not block. This requires a fix
  // in libzephyr.
  var hmack = Q.all(uids[0].map(function(uid) {
    hmackTable[uid] = Q.defer();
    return hmackTable[uid].promise;
  }));

  // SERVACK
  var servack = Q.all(uids[1].map(function(uid) {
    servackTable[uid] = Q.defer();
    return servackTable[uid].promise;
  }));

  return {
    // This assumes that the send_function is called by ZSrvSendPacket
    // in the right order. A pretty safe assumption. If it ever
    // breaks, we can return a third thing easily enough.
    uid: uids[0][0],
    hmack: hmack,
    servack: servack,
  };
};

zephyr.sendNotice = function(msg, certRoutine, onHmack) {
  var acks = internalSendNotice(msg, certRoutine);
  var ev = new OutgoingNotice(acks.uid, acks.hmack, acks.servack);
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

  Q.nodeify(waitOnUids(uids).servack, cb);
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

  var uid;
  if (notice.kind === zephyr.HMACK) {
    uid = notice.uid;
    if (hmackTable[uid])
      hmackTable[uid].resolve(null);
    delete hmackTable[uid];
  } else if (notice.kind === zephyr.SERVACK) {
    uid = notice.uid;
    if (servackTable[uid])
      servackTable[uid].resolve(notice.body[0]);
    delete servackTable[uid];
  } else if (notice.kind === zephyr.SERVNAK) {
    uid = notice.uid;
    if (servackTable[uid])
      servackTable[uid].reject(new Error(notice.body[0]));
    delete servackTable[uid];
  }

  zephyr.emit("notice", notice);
});

module.exports = zephyr;
