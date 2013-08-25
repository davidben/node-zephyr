var dgram = require('dgram');
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
zephyr.getDestAddr = internal.getDestAddr;

zephyr.downcase = internal.downcase;

function OutgoingNotice(uid, packets, hmack, servack) {
  events.EventEmitter.call(this);

  this.uid = uid;
  this.packets = packets;
  Q.nodeify(hmack, this.emit.bind(this, 'hmack'));
  Q.nodeify(servack, this.emit.bind(this, 'servack'));
}
OutgoingNotice.prototype = Object.create(events.EventEmitter.prototype);

function internalSendNotice(msg, certRoutine) {
  try {
    var packets = internal.sendNotice(msg, certRoutine);
  } catch (err) {
    // FIXME: Maybe this should just be synchronous? Reporting the
    // error twice is silly, but if you fail this early, you fail
    // both.
    return {
      hmack: Q.reject(err),
      servack: Q.reject(err),
    };
  }

  return sendPackets(packets);
}

var sock;

var HM_TIMEOUT = 10 * 1000;  // From zephyr.h
var SERV_TIMEOUT = 60 * 1000;  // From Z_ReadWait.

function TimeoutError() {
  Error.captureStackTrace(this, TimeoutError);
}
util.inherits(TimeoutError, Error);
TimeoutError.prototype.toString = function() {
  return "Timeout";
};

function AckTable(timeout) {
  this.timeout_ = timeout;

  this.oldTable_ = {};
  this.oldTableCount_ = 0;
  this.newTable_ = {};
  this.newTableCount_ = 0;

  this.interval_ = null;
}
AckTable.prototype.rotateTables_ = function() {
  if (this.oldTableCount_ != 0)
    throw "Rotating with non-zero oldTableCount_!";
  this.oldTable_ = this.newTable_;
  this.oldTableCount_ = this.newTableCount_;
  this.newTable_ = {};
  this.newTableCount_ = 0;
};
AckTable.prototype.tick_ = function() {
  // Expire oldTable_.
  for (var key in this.oldTable_) {
    this.oldTable_[key].reject(new TimeoutError());
  }
  this.oldTableCount_ = 0;
  this.rotateTables_();

  if (this.oldTableCount_ == 0) {
    clearInterval(this.interval_);
    this.interval_ = null;
  }
};
AckTable.prototype.addUid = function(uid) {
  if (uid in this.newTable_) {
    // This shouldn't happen...
    return Q.reject("Repeat UID!");
  }
  var deferred = Q.defer();
  this.newTable_[uid] = deferred;
  this.newTableCount_++;
  if (this.interval_ == null) {
    this.rotateTables_();
    this.interval_ = setInterval(this.tick_.bind(this), this.timeout_);
  }
  return deferred.promise;
};
AckTable.prototype.resolve = function(uid, value) {
  if (uid in this.newTable_) {
    this.newTable_[uid].resolve(value);
    delete this.newTable_[uid];
    this.newTableCount_--;
  } else if (uid in this.oldTable_) {
    this.oldTable_[uid].resolve(value);
    delete this.oldTable_[uid];
    this.oldTableCount_--;
  }
};
AckTable.prototype.reject = function(uid, err) {
  if (uid in this.newTable_) {
    this.newTable_[uid].reject(err);
    delete this.newTable_[uid];
    this.newTableCount_--;
  } else if (uid in this.oldTable_) {
    this.oldTable_[uid].reject(err);
    delete this.oldTable_[uid];
    this.oldTableCount_--;
  }
};

var hmackTable = new AckTable(HM_TIMEOUT);
var servackTable = new AckTable(SERV_TIMEOUT);

function ensureSocketInitialized() {
  // Lazily initialize the sending packet. Meh.
  if (!sock) {
    // We create our own socket to send on and listen for ACKs on
    // that. Otherwise we have to deal with libzephyr blocking on
    // everything, including a sendto.
    sock = dgram.createSocket('udp4');
    sock.on('message', function(msg, rinfo) {
      try {
        var notice = zephyr.parseNotice(msg);
      } catch (err) {
        console.error('Received bad packet on outgoing socket', err);
        return;
      }

      var uid;
      if (notice.kind === zephyr.HMACK) {
        uid = notice.uid;
        hmackTable.resolve(uid, null);
      } else if (notice.kind === zephyr.SERVACK) {
        uid = notice.uid;
        servackTable.resolve(uid, notice.body[0]);
      } else if (notice.kind === zephyr.SERVNAK) {
        uid = notice.uid;
        servackTable.reject(uid, new Error(notice.body[0]));
      }
    });
  }
}

function sendPacket(pkt) {
  ensureSocketInitialized();

  var waitHmack = false, waitServack = false;
  if (pkt.kind === zephyr.UNACKED) {
    waitHmack = true;
  } else if (pkt.kind === zephyr.ACKED) {
    waitHmack = true;
    waitServack = true;
  }

  // Send the packet.
  var uid = pkt.uid;
  var dest = zephyr.getDestAddr();
  Q.ninvoke(
    sock, 'send',
    pkt.buffer, 0, pkt.buffer.length,
    dest.port, dest.host
  ).then(function() {
    if (!waitHmack)
      hmackTable.resolve(uid);
    if (!waitServack)
      servackTable.resolve(uid);
  }, function(err) {
    hmackTable.reject(uid, err);
    servackTable.reject(uid, err);
  }).done();

  return {
    hmack: hmackTable.addUid(pkt.uid),
    servack: servackTable.addUid(pkt.uid)
  };
}

// Okay, this is dumb. rmem_default and rmem_max are 229376 which
// gives a bit over 200 packets in the buffer. Use 25 as a
// suuuper-conservative estimate. There seems to be more going on.
//
// For more fun, go all the way to servack before sendin another.
var MAX_PACKETS_IN_FLIGHT = 25;

function sendPackets(packets) {
  // This assumes that the send_function is called by ZSrvSendPacket
  // in the right order. A pretty safe assumption. If it ever breaks,
  // we can return a third thing easily enough.
  var uid = packets.length ? packets[0].uid : null;
  var hmack = Q.defer();
  var servack = Q.defer();

  var outgoing = new OutgoingNotice(uid, packets.length,
                                    hmack.promise, servack.promise);

  var servackResult = null;

  packets = packets.slice(0);  // Make a copy...
  var hmacksPending = 0, servacksPending = 0;
  var i = 0, aborted = false;
  function loop() {
    if (!aborted) {
      while (servacksPending < MAX_PACKETS_IN_FLIGHT && i < packets.length) {
        // Send out a packet.
        var acks = sendPacket(packets[i]);
        packets[i] = null;  // Meh. Release the buffer when we can.
        hmacksPending++; servacksPending++; i++;

        acks.hmack.then(function() {
          hmacksPending--;
          outgoing.emit('hmackprogress', i - hmacksPending);
          loop();
        }, function(err) {
          // Ack! Reject everything.
          if (Q.isPending(hmack.promise))
            hmack.reject(err);
          if (Q.isPending(servacksPending))
            servack.reject(err)
          aborted = true;
        }).done();

        acks.servack.then(function(ret) {
          servacksPending--;
          outgoing.emit('servackprogress', i - servacksPending);
          servackResult = ret;
          loop();
        }, function(err) {
          if (Q.isPending(servacksPending))
            servack.reject(err)
          aborted = true;
        }).done();
      }
    }

    // End condition.
    if (i >= packets.length) {
      if (hmacksPending == 0 && Q.isPending(hmack.promise)) {
        hmack.resolve();
      }
      if (servacksPending == 0 && Q.isPending(servack.promise)) {
        servack.resolve(servackResult);
      }
    }
  }

  loop();

  return outgoing;
};

zephyr.sendNotice = function(msg, certRoutine, onHmack) {
  var ev = internalSendNotice(msg, certRoutine);
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
    var packets = internal.subscriptions(subs, opcode);
  } catch (err) {
    process.nextTick(function() {
      cb(err);
    });
    return;
  }

  var ev = sendPackets(packets);
  if (cb)
    ev.once('servack', cb);
  return ev;
}

zephyr.subscribeTo = function(subs, cb) {
  return zephyrCtl(zephyr.CLIENT_SUBSCRIBE, subs, cb);
};

zephyr.subscribeToSansDefaults = function(subs, cb) {
  return zephyrCtl(zephyr.CLIENT_SUBSCRIBE_NODEFS, subs, cb);
};

zephyr.unsubscribeTo = function(subs, cb) {
  return zephyrCtl(zephyr.CLIENT_UNSUBSCRIBE, subs, cb);
};

zephyr.cancelSubscriptions = function(cb) {
  return zephyrCtl(zephyr.CLIENT_CANCELSUB, [], cb);
};

zephyr.formatNotice = internal.formatNotice;

zephyr.parseNotice = function(buf) {
  // Okay, what the hell, zephyr? Why does ZParseNotice not check that
  // the buffer has enough size of the ZVERSIONHDR. This is not
  // something for the caller to do.
  if (buf.length < 4)
    throw "Packet too short";
  return internal.parseNotice(buf);
};

internal.setNoticeCallback(function(err, notice) {
  if (err) {
    console.error('Zephyr packet error', err);
    return;
  }
  zephyr.emit('notice', notice);
});

module.exports = zephyr;
