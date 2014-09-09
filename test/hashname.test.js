var expect = require('chai').expect;
var hashname = require('../index.js');


describe('hashname', function(){

  it('should generate from two keys', function(){
    var keys = {
      "3a":"tydfjkhd5vzt006t4nz5g5ztxmukk35whtr661ty3r8x80y46rv0",
      "1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun"
    };
    expect(hashname.fromKeys(keys)).to.be.equal('anptpctxorixfzzj6dwwncwz3vzeessbhuokkfsdlx2upxw4qocq');
  })

  it('should generate from one key', function(){
    var keys = {
      "1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun"
    };
    expect(hashname.fromKeys(keys)).to.be.equal('4zkizbvt5aufpy3tdcmot4qpubkcmmepcgwwv5otgjr3vxpfp3pa');
  })

  it('fails w/ no keys', function(){
    expect(hashname.fromKeys({})).to.be.equal(false);
  })

  it('fails w/ bad id', function(){
    expect(hashname.fromKeys({"bad":"8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun"})).to.be.equal(false);
  })

  it('returns buffer', function(){
    expect(hashname.buffer('4w0fh69ad6d1xhncwwd1020tqnhqm4y5zbdmtqdk7d3v36qk6wbg')).to.be.a('object');
  })

  it('returns intermediate', function(){
    var keys = {
      "3a":"tydfjkhd5vzt006t4nz5g5ztxmukk35whtr661ty3r8x80y46rv0",
      "1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun"
    };
    var json = hashname.intermediate(keys);
    expect(json).to.be.a('object');
    expect(json["1a"].length).to.be.equal(52);
  });

  it('returns key buffer', function(){
    var keys = {
      "3a":"tydfjkhd5vzt006t4nz5g5ztxmukk35whtr661ty3r8x80y46rv0",
      "1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun"
    };
    var buf = hashname.key("3a",keys);
    expect(buf).to.be.a('object');
    expect(buf.toString('hex')).to.be.equal('9e0654a8e3ed737fffd3e373d37733bb28a56fb63ce3effe78dcff7fff1cf46f');
  });
  
  it('generates from compact', function(){
    var json = { '1a': 'kbr7mf0fgz04fd0tjtntxpx4pk9ht4qryk647mvy9gn39upu7zcg', '3a':true };
    var key = new Buffer('cf9af94e2d2eff9000d9257e5817f9ed35398cbc8e7063073e1e11d403c43636','hex');
    expect(hashname.fromPacket({json:json,body:key})).to.be.equal('wuvp6is3ae6oa7fzmt6uuyysmnabst43fp2wastwv53oxtkdfuma');
  });

  it('returns sorted ids', function(){
    expect(hashname.ids(['1a','2a']).toString()).to.be.equal(['2a','1a'].toString());
  });

  it('finds best id', function(){
    expect(hashname.match(['1a','2a','44'],['1a','2a','55'])).to.be.equal('2a');
  });

  it('exposes base32 utility', function(){
    expect(hashname.base32).to.be.an('object');
    expect(hashname.base32.encode(new Buffer('foo'))).to.be.equal('mzxw6');
    expect(hashname.base32.decode('mzxw6').toString()).to.be.equal('foo');
  });

  it('verifies hashname', function(){
    expect(hashname.isHashname('anptpctxorixfzzj6dwwncwz3vzeessbhuokkfsdlx2upxw4qocq')).to.be.true;
    expect(hashname.isHashname({})).to.be.false;
    expect(hashname.isHashname('anptpctxorixfzzj6dwwncwz3vzeessbhuokkfsdlx2upxw4qoc')).to.be.false;
  });


})