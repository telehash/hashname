# Hashname - A fingerprint for multiple public keys (in pure javascript)

This module will generate and parse [hashnames](https://github.com/telehash/telehash.org/tree/v3/v3/hashname), base32 encoded fingerprint strings from one or more public keys.

Install: `npm install hashname`

Usage:

```js
var hashname = require('hashname');
var keys = {
}
console.log(hashname.keys(keys));
// prints ''
```

