var base32 = require('base32');
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

// always returns a buffer
function b32buff(str)
{
  return new Buffer(base32.decode(str),'binary');
}

// simple wrapper to consistently handle buffer<=>base32
exports.base32 = {
  encode:base32.encode,
  decode:b32buff
}

// generate hashname from keys json, vals are either base32 keys or key binary Buffer's
exports.fromKeys = function(json)
{
  if(typeof json != 'object') return false;
  if(!Object.keys(json).length) return false;
  var imbuff = {};
  Object.keys(json).forEach(function(id){
    var keybuf = (Buffer.isBuffer(json[id])) ? json[id] : b32buff(json[id]);
    imbuff[id] = crypto.createHash("sha256").update(keybuf).digest();
  });
  // validate ids
  if(!exports.ids(imbuff).length) return false;
  return base32.encode(rollup(imbuff));
}

// generate from a given key, and other intermediate json
exports.fromKey = function(id, key, json)
{
  if(typeof id != 'string') return false;
  if(!Buffer.isBuffer(key)) return false;
  if(typeof json != 'object') return false;
  var imbuff = {};
  Object.keys(json).forEach(function(id){
    imbuff[id] = (Buffer.isBuffer(json[id])) ? json[id] : b32buff(json[id]);
  });
  imbuff[id] = crypto.createHash("sha256").update(key).digest();
  // validate ids
  if(!exports.ids(imbuff).length) return false;
  return base32.encode(rollup(imbuff));
}

// just parse a hashname into a 32byte buffer
exports.buffer = function(hn)
{
  if(typeof hn != 'string') return false;
  var buf = b32buff(hn);
  if(buf.length != 32) return false;
  return buf;
}

// returns sorted validated ids from {id:"...",id:"..."} or [id,id]
exports.ids = function(keys)
{
  if(typeof keys == 'object' && !Array.isArray(keys))
  {
    keys = Object.keys(keys);
  }
  if(!Array.isArray(keys)) return [];
  // sort them
  var keys = keys.sort().reverse();
  for(var i = 0; keys[i]; i++)
  {
    if(typeof keys[i] != 'string' || keys[i].length != 2 || (new Buffer(keys[i],'hex')).length != 1) return [];
  }
  if(!keys.length) return [];
  return keys;
}

// just a convenience
exports.match = function(keys1, keys2)
{
  var ids1 = exports.ids(keys1);
  var ids2 = exports.ids(keys2);
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
  if(typeof keys[id] != 'string') return false;
  return b32buff(keys[id]);
}

exports.compact = function(skip, keys)
{
  var key = exports.key(skip, keys);
  if(!key) return false;
  var ret = {};
  Object.keys(keys).forEach(function(id){
    if(id == skip) return;
    ret[id] = base32.encode(crypto.createHash("sha256").update(b32buff(keys[id])).digest());
  });
  return ret;
}

