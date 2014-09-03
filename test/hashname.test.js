var expect = require('chai').expect;
var hashname = require('../index.js');


describe('hashname', function(){

  it('should generate from two keys', function(){
    var keys = {
      "3a":"tydfjkhd5vzt006t4nz5g5ztxmukk35whtr661ty3r8x80y46rv0",
      "1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun"
    };
    expect(hashname.fromKeys(keys)).to.be.equal('5ccn9gcxnj9nd7hp1m3v5pjwcu5hq80bt366bzh1ebhf9zqaxu2g');
  })

  it('should generate from one key', function(){
    var keys = {
      "1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun"
    };
    expect(hashname.fromKeys(keys)).to.be.equal('5bx4502uhjcp6xymjpzp6ku9ehh29j3zw9vr6u6rh26btu75cw4g');
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

  it('returns compact', function(){
    var keys = {
      "3a":"tydfjkhd5vzt006t4nz5g5ztxmukk35whtr661ty3r8x80y46rv0",
      "1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun"
    };
    var json = hashname.compact("3a",keys);
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
    expect(buf.toString('hex')).to.be.equal('cf9af94e2d2eff9000d9257e5817f9ed35398cbc8e7063073e1e11d403c43636');
  });
  
  it('generates from compact', function(){
    var json = { '1a': 'kbr7mf0fgz04fd0tjtntxpx4pk9ht4qryk647mvy9gn39upu7zcg' };
    var key = new Buffer('cf9af94e2d2eff9000d9257e5817f9ed35398cbc8e7063073e1e11d403c43636','hex');
    expect(hashname.fromKey('3a',key,json)).to.be.equal('5ccn9gcxnj9nd7hp1m3v5pjwcu5hq80bt366bzh1ebhf9zqaxu2g');
  });

  it('returns sorted ids', function(){
    expect(hashname.ids(['1a','2a']).toString()).to.be.equal(['2a','1a'].toString());
  });

  it('finds best id', function(){
    expect(hashname.match(['1a','2a','44'],['1a','2a','55'])).to.be.equal('2a');
  });

  it('exposes base32 utility', function(){
    expect(hashname.base32).to.be.an('object');
    expect(hashname.base32.encode(new Buffer('foo'))).to.be.equal('ctqpy');
    expect(hashname.base32.decode('ctqpy').toString()).to.be.equal('foo');
  });

  it('verifies hashname', function(){
    expect(hashname.isHashname('5ccn9gcxnj9nd7hp1m3v5pjwcu5hq80bt366bzh1ebhf9zqaxu2g')).to.be.true;
    expect(hashname.isHashname({})).to.be.false;
    expect(hashname.isHashname('5ccn9gcxnj9nd7hp1m3v5pjwcu5hq80bt366bzh1ebhf9zqaxu2')).to.be.false;
    // TODO fix base32 to have a strict mode
//    expect(hashname.isHashname('lccn9gcxnj9nd7hp1m3v5pjwcu5hq80bt366bzh1ebhf9zqaxu2g')).to.be.false;
  });


})