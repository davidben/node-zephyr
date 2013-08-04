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

function OutgoingNotice(uid, hmack, servack) {
  events.EventEmitter.call(this);

  this.uid = uid;
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
function sendPackets(packets) {
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

  // To avoid the kernel dropping packets, send the packets one at a
  // time, waiting for HMACKs between each.
  var sendAndHmack = packets.reduce(function(soFar, pkt) {
    var kind = pkt.kind;
    var uid = pkt.uid;
    var buffer = pkt.buffer;
    return soFar.then(function() {
      var dest = zephyr.getDestAddr();
      var ret = Q.ninvoke(sock, 'send',
                          buffer, 0, buffer.length,
                          dest.port, dest.host);
      // Make sure the buffer is not held by the next closure. Silly
      // stuff with how V8 implements closures.
      buffer = null;
      return ret;
    }).then(function() {
      if (kind === zephyr.UNACKED || kind === zephyr.UNSAFE) {
        hmackTable[uid] = Q.defer();
        return hmackTable[uid].promise;
      }
      return Q();
    });
  }, Q());

  // TODO(davidben): Have all of these time out appropriately, and
  // whatnot. Also if an HMACK times out, there's no hope for the
  // SERVACK, so punt it too.

  // SERVACK
  var servack = Q.all(packets.filter(function(pkt) {
    return pkt.kind == zephyr.ACKED;
  }).map(function(pkt) {
    servackTable[pkt.uid] = Q.defer();
    return servackTable[pkt.uid].promise;
  })).then(function(ret) {
    // Just return the first fragment's result I guess...
    return ret[0];
  });

  return {
    // This assumes that the send_function is called by ZSrvSendPacket
    // in the right order. A pretty safe assumption. If it ever
    // breaks, we can return a third thing easily enough.
    uid: packets[0].uid,
    hmack: sendAndHmack,
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
    var packets = internal.subscriptions(subs, opcode);
  } catch (err) {
    process.nextTick(function() {
      cb(err);
    });
    return;
  }

  Q.nodeify(sendPackets(packets).servack, cb);
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
