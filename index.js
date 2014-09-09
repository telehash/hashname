var base32 = require('rfc-3548-b32');
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
  decode:function(){
    var buf;
    try{
      buf = base32.decode.apply(this,arguments);
    }catch(E){
      console.log("ERRR",E)
      buf = new Buffer(0);
    }
    return buf;
  }
}

// generate hashname from keys json, vals are either base32 keys or key binary Buffer's
exports.fromKeys = function(json)
{
  if(typeof json != 'object') return false;
  if(!Object.keys(json).length) return false;
  var imbuff = {};
  Object.keys(json).forEach(function(id){
    var keybuf = (Buffer.isBuffer(json[id])) ? json[id] : exports.base32.decode(json[id]);
    imbuff[id] = crypto.createHash("sha256").update(keybuf).digest();
  });
  // validate ids
  if(!exports.ids(imbuff).length) return false;
  return exports.base32.encode(rollup(imbuff));
}

// generate from a given key (1a), and other intermediate json ({1a:true,2a:"..."})
exports.fromPacket = function(packet)
{
  if(!Buffer.isBuffer(packet.body)) return false;
  if(typeof packet.json != 'object') return false;
  var imbuff = {};
  Object.keys(packet.json).forEach(function(id){
    if(packet.json[id] === true)
    {
      imbuff[id] = crypto.createHash("sha256").update(packet.body).digest();
    }else{
      imbuff[id] = (Buffer.isBuffer(packet.json[id])) ? packet.json[id] : exports.base32.decode(packet.json[id]);
    }
  });
  // validate ids
  if(!exports.ids(imbuff).length) return false;
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
  return exports.base32.decode(keys[id]);
}

exports.intermediate = function(keys)
{
  var ret = {};
  Object.keys(keys).forEach(function(id){
    ret[id] = exports.base32.encode(crypto.createHash("sha256").update(exports.base32.decode(keys[id])).digest());
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