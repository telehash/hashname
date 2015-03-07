var base32 = require('rfc-3548-b32');
var siphash = require('siphash');
var crypto = require('crypto');

// rollup uses only intermediate buffers, data must be validated first
function rollup(imbuff)
{
  var roll = new Buffer(0);
  Object.keys(imbuff).sort().forEach(function(id){
    roll = crypto.createHash("sha256").update(Buffer.concat([roll,new Buffer(id, 'hex')])).digest();
    roll = crypto.createHash("sha256").update(Buffer.concat([roll,imbuff[id]])).digest();
  });
  return roll;
}

// simple wrapper to consistently handle buffer<=>base32
exports.base32 = {
  encode:function(){
    return base32.encode.apply(this,arguments).toLowerCase().split('=').join('');
  },
  decode:function(buf){
    if(Buffer.isBuffer(buf)) return buf;
    try{
      buf = base32.decode.apply(this,arguments);
    }catch(E){
      console.log("ERRR",E)
      buf = new Buffer(0);
    }
    return buf;
  }
}

// wrapper of easier to use siphash interface
exports.siphash = function(key, value){
  if(!key || !value) return false;
  if(exports.isHashname(key)) key = base32.decode(key).slice(0,16);
  // convert to siphash key array format
  if(Buffer.isBuffer(key) && key.length == 16)
  {
    var key2 = [];
    key2[0] = key.readUInt32BE(0);
    key2[1] = key.readUInt32BE(4);
    key2[2] = key.readUInt32BE(8);
    key2[3] = key.readUInt32BE(12);
    key = key2;
  }
  if(key.length != 4) return false;
  if(Buffer.isBuffer(value)) value = value.toString('binary');
  var hash = siphash.hash(key,value);
  var digest = new Buffer(8);
  digest.writeUInt32BE(hash.h,0);
  digest.writeUInt32BE(hash.l,4);
  digest.key = key; // for reference
  return digest;
};

// generate hashname from keys json, vals are either base32 keys or key binary Buffer's
exports.fromKeys = function(keys, intermediates)
{
  if(typeof keys != 'object') return false;
  if(!Object.keys(keys).length) return false;
  var imbuff = {};
  
  // first generate intermediates from given keys
  exports.ids(keys).forEach(function(id){
    var keybuf = (Buffer.isBuffer(keys[id])) ? keys[id] : exports.base32.decode(keys[id]);
    imbuff[id] = crypto.createHash("sha256").update(keybuf).digest();
  });

  // require only valid keys to be passed in
  if(Object.keys(imbuff).length != Object.keys(keys).length) return false;

  // fill in any given intermediates too
  if(typeof intermediates == 'object') exports.ids(intermediates).forEach(function(id){
    if(imbuff[id]) return; // skip existing keys
    imbuff[id] = (Buffer.isBuffer(intermediates[id])) ? intermediates[id] : exports.base32.decode(intermediates[id]);
  });

  return exports.base32.encode(rollup(imbuff));
}

// just parse a hashname into a 32byte buffer
exports.buffer = function(hn)
{
  if(typeof hn != 'string') return false;
  var buf = exports.base32.decode(hn);
  if(buf.length != 32) return false;
  return buf;
}

// returns sorted validated ids from {id:"...",id:"..."} or [id,id]
exports.ids = function(keys, intermediates)
{
  if(typeof keys == 'object' && !Array.isArray(keys))
  {
    keys = Object.keys(keys);
  }
  if(!Array.isArray(keys)) return [];
  // validate them
  var ret = [];
  keys.forEach(function(id){
    // normalize 'cs1a' keys
    if(id.length == 4 && id.substr(0,2) == 'cs') id = id.substr(2);
    if(exports.isID(id)) ret.push(id);
  });
  
  // merge in any intermediates
  if(intermediates) exports.ids(intermediates).forEach(function(id){
    if(ret.indexOf(id) == -1) ret.push(id);
  });

  // sort them
  return ret.sort().reverse();
}

// just a convenience
exports.match = function(keys1, keys2, im1, im2)
{
  var ids1 = exports.ids(keys1, im1);
  var ids2 = exports.ids(keys2, im2);
  for(var i = 0; ids1[i]; i++)
  {
    if(ids2.indexOf(ids1[i]) >= 0) return ids1[i];
  }
  return false;
}

// return the buffer of the given key
exports.key = function(id, keys)
{
  if(typeof keys != 'object') return false;
  if(Buffer.isBuffer(keys[id])) return keys[id];
  if(typeof keys[id] != 'string') return false;
  return exports.base32.decode(keys[id]);
}

// return the intermediates (base32)
exports.intermediates = function(keys)
{
  if(typeof keys != 'object') return false;
  var ret = {};
  exports.ids(keys).forEach(function(id){
    var buf = Buffer.isBuffer(keys[id]) ? keys[id] : exports.base32.decode(keys[id]);
    ret[id] = exports.base32.encode(crypto.createHash("sha256").update(buf).digest());
  });
  return ret;
}

exports.isHashname = function(hn)
{
  if(typeof hn != 'string') return false;
  if(hn.length != 52) return false;
  if(exports.base32.decode(hn).length == 32) return true;
  return false;
}

exports.isID = function(id)
{
  if(Buffer.isBuffer(id) && id.length == 1) return true;
  if(typeof id != 'string') return false;
  if(id.length != 2) return false;
  var buf = new Buffer(id,'hex');
  if(buf && buf.toString('hex') == id) return true;
  return false;
}