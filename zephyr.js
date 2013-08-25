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
var hmackTable = { };
var servackTable = { };

var HM_TIMEOUT = 10 * 1000;  // From zephyr.h
var SERV_TIMEOUT = 60 * 1000;  // From Z_ReadWait.

function TimeoutError() {
  Error.captureStackTrace(this, TimeoutError);
}
util.inherits(TimeoutError, Error);
TimeoutError.prototype.toString = function() {
  return "Timeout";
};

function AckTimer(table, timeout) {
  this.table_ = table;
  this.timeout_ = timeout;

  this.oldBuf_ = [];
  this.newBuf_ = [];

  this.interval_ = null;
}
AckTimer.prototype.tick_ = function() {
  // Expire oldBuf_.
  for (var i = 0; i < this.oldBuf_.length; i++) {
    var uid = this.oldBuf_[i][0], deferred = this.oldBuf_[i][1];
    if (this.table_[uid] === deferred) {
      deferred.reject(new TimeoutError());
      delete this.table_[uid];
    }
  }
  // Cycle buffers.
  this.oldBuf_ = this.newBuf_;
  this.newBuf_ = [];

  if (this.oldBuf_.length == 0) {
    clearInterval(this.interval_);
    this.interval_ = null;
  }
};
AckTimer.prototype.addUid = function(uid) {
  var deferred = this.table_[uid];
  // It's... conceivable we raced with the ACK in installing the
  // timeout since we wait until the packet is sent to install the
  // timeout.
  if (!deferred)
    return;
  this.newBuf_.push([uid, deferred]);
  if (this.interval_ == null) {
    this.oldBuf_ = this.newBuf_;
    this.newBuf_ = [];
    this.interval_ = setInterval(this.tick_.bind(this), this.timeout_);
  }
};

var hmackTimer = new AckTimer(hmackTable, HM_TIMEOUT);
var servackTimer = new AckTimer(servackTable, SERV_TIMEOUT);

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
    });
  }
}

function sendPacket(pkt) {
  ensureSocketInitialized();

  var hmack, servack;
  var waitHmack = true, waitServack = true;
  if (pkt.kind === zephyr.UNACKED) {
    hmack = (hmackTable[pkt.uid] = Q.defer());
    servack = Q.defer(); waitServack = false;
  } else if (pkt.kind === zephyr.ACKED) {
    hmack = (hmackTable[pkt.uid] = Q.defer());
    servack = (servackTable[pkt.uid] = Q.defer());
  } else {
    hmack = Q.defer(); waitHmack = false;
    servack = Q.defer(); waitServack = false;
  }

  // Send the packet.
  var uid = pkt.uid;
  var dest = zephyr.getDestAddr();
  Q.ninvoke(
    sock, 'send',
    pkt.buffer, 0, pkt.buffer.length,
    dest.port, dest.host
  ).then(function() {
    if (!waitHmack) {
      hmack.resolve();
    } else {
      hmackTimer.addUid(uid);
    }

    if (!waitServack) {
      servack.resolve();
    } else {
      servackTimer.addUid(uid);
    }
  }, function(err) {
    // We failed to send. Reject hmack and servack.
    hmack.reject(err);
    servack.reject(err);
    if (waitHmack)
      delete hmackTable[pkt.uid];
    if (waitServack)
      delete servackTable[pkt.uid];
  }).done();

  return {
    hmack: hmack.promise,
    servack: servack.promise
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
