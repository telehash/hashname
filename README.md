# Hashname - A fingerprint for multiple public keys (in pure javascript)

This module will generate and parse [hashnames](https://github.com/telehash/telehash.org/tree/v3/v3/hashname), base32 encoded consistent fingerprint strings from one or more public keys.

Install: `npm install hashname`

Primary usage:

```js
var hashname = require('hashname');
var keys = {
  "3a":"tydfjkhd5vzt006t4nz5g5ztxmukk35whtr661ty3r8x80y46rv0",
  "1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun"
};
var hn = hashname.fromKeys(keys));
// hn will be '5ccn9gcxnj9nd7hp1m3v5pjwcu5hq80bt366bzh1ebhf9zqaxu2g'
```

There's also other utility/convenience methods, see the examples in the [tests](test/).