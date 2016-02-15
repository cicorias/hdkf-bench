'use strict';

var Benchmark = require('benchmark');
var crypto = require('crypto');
var HKDF = require('./hkdf');

var suite = new Benchmark.Suite();

var prePubKey = crypto.createECDH('secp256k1').generateKeys();
var preRandomBytes = crypto.randomBytes(8);
var preSxy = crypto.createECDH('secp256k1');

var preSxyGenKeys = crypto.createECDH('secp256k1');
preSxyGenKeys.generateKeys();

var preSxySecret = crypto.createECDH('secp256k1');
preSxySecret.generateKeys();
var preSecret = preSxySecret.computeSecret(prePubKey);

// add tests
suite.add('HKDF test full', function() {
  var pubKey = crypto.createECDH('secp256k1').generateKeys();
  var expirationBuffer = crypto.randomBytes(8);
  var sxy = crypto.createECDH('secp256k1');
  sxy.generateKeys();
  sxy = sxy.computeSecret(pubKey);
  HKDF('sha256', sxy, expirationBuffer).derive('', 32);
})

.add('HKDF prePubKey test 2', function() {
  var pubKey = prePubKey;
  var expirationBuffer = crypto.randomBytes(8);
  var sxy = crypto.createECDH('secp256k1');
  sxy.generateKeys();
  sxy = sxy.computeSecret(pubKey);
  HKDF('sha256', sxy, expirationBuffer).derive('', 32);
})

.add('HKDF preRandomBytes', function() {
  var pubKey = prePubKey;//crypto.createECDH('secp256k1').generateKeys();
  var expirationBuffer = preRandomBytes;// crypto.randomBytes(8);
  var sxy = crypto.createECDH('secp256k1');
  sxy.generateKeys();
  sxy = sxy.computeSecret(pubKey);
  HKDF('sha256', sxy, expirationBuffer).derive('', 32);
})

.add('HKDF preSxy', function() {
  var pubKey = prePubKey;//crypto.createECDH('secp256k1').generateKeys();
  var expirationBuffer = preRandomBytes;// crypto.randomBytes(8);
  var sxy = preSxy;// crypto.createECDH('secp256k1');
  sxy.generateKeys();
  sxy = sxy.computeSecret(pubKey);
  HKDF('sha256', sxy, expirationBuffer).derive('', 32);
})

.add('HKDF preGenKeys', function() {
  var pubKey = prePubKey;//crypto.createECDH('secp256k1').generateKeys();
  var expirationBuffer = preRandomBytes;// crypto.randomBytes(8);
  var sxy = preSxyGenKeys.computeSecret(pubKey);
  HKDF('sha256', sxy, expirationBuffer).derive('', 32);
})


.add('HKDF preSecret', function() {
  var expirationBuffer = preRandomBytes;// crypto.randomBytes(8);
  var sxy = preSecret;// preSxyGenKeys.computeSecret(pubKey);
  HKDF('sha256', sxy, expirationBuffer).derive('', 32);
})


// add listeners
.on('cycle', function(event) {
  console.log(String(event.target));
})
.on('complete', function() {
  console.log('Fastest is ' + this.filter('fastest').map('name'));
})
// run async
.run({ 'async': true });