'use strict';
/* global describe it */

const assert = require('assert');
const asn1 = require('..');

const Buffer = require('buffer').Buffer;

describe('asn1.js DER decoder', function() {
  it('should propagate implicit tag', function() {
    const B = asn1.define('B', function() {
      this.seq().obj(
        this.key('b').octstr()
      );
    });

    const A = asn1.define('Bug', function() {
      this.seq().obj(
        this.key('a').implicit(0).use(B)
      );
    });

    const out = A.decode(new Buffer('300720050403313233', 'hex'), 'der');
    assert.equal(out.a.b.toString(), '123');
  });

  it('should decode optional tag to undefined key', function() {
    const A = asn1.define('A', function() {
      this.seq().obj(
        this.key('key').bool(),
        this.optional().key('opt').bool()
      );
    });
    const out = A.decode(new Buffer('30030101ff', 'hex'), 'der');
    assert.deepEqual(out, { 'key': true });
  });

  it('should decode optional tag to default value', function() {
    const A = asn1.define('A', function() {
      this.seq().obj(
        this.key('key').bool(),
        this.optional().key('opt').octstr().def('default')
      );
    });
    const out = A.decode(new Buffer('30030101ff', 'hex'), 'der');
    assert.deepEqual(out, { 'key': true, 'opt': 'default' });
  });

  function test(name, model, inputHex, expected) {
    it(name, function() {
      const M = asn1.define('Model', model);
      const decoded = M.decode(new Buffer(inputHex,'hex'), 'der');
      assert.deepEqual(decoded, expected);
    });
  }

  function testIsNaN(name, model, inputHex, expected) {
    it(name, function() {
      var M = asn1.define('Model', model);
      var decoded = M.decode(new Buffer(inputHex,'hex'), 'der');
      assert.equal(isNaN(decoded), isNaN(expected));
    });
  }

  function testBN(name, model, inputHex, expected) {
    it(name, function() {
      var M = asn1.define('Model', model);
      var decoded = M.decode(new Buffer(inputHex,'hex'), 'der');
      assert.deepEqual(decoded.toString(), expected.toString());
    });
  } 

  test('should decode choice', function() {
    this.choice({
      apple: this.bool(),
    });
  }, '0101ff', { 'type': 'apple', 'value': true });

  it('should decode optional and use', function() {
    const B = asn1.define('B', function() {
      this.int();
    });

    const A = asn1.define('A', function() {
      this.optional().use(B);
    });

    const out = A.decode(new Buffer('020101', 'hex'), 'der');
    assert.equal(out.toString(10), '1');
  });

  test('should decode indefinite length', function() {
    this.seq().obj(
      this.key('key').bool()
    );
  }, '30800101ff0000', { 'key': true });

  test('should decode real zero', function() {
    this.real();
  }, '0900', 0);

  testIsNaN('should decode real NaN', function() {
    this.real();
  }, '090142', NaN);

  test('should decode real Infinity', function() {
    this.real();
  }, '090140', Infinity);

  test('should decode real -Infinity', function() {
    this.real();
  }, '090141', -Infinity);

  test('should decode real 1 (nr3)', function() {
    this.real();
  }, '090603312e452b30', 1);

  test('should decode real 1.2 (nr3)', function() {
    this.real();
  }, '090703312e32452b30', 1.2);

  test('should decode real 1.2 (nr2)', function() {
    this.real();
  }, '090402312e32', 1.2);

  test('should decode real 1 (nr1)', function() {
    this.real();
  }, '09020131', 1);

  test('should decode objDesc', function() {
    this.objDesc();
  }, '0703323830', '280');

  test('should decode octstr', function() {
    this.octstr();
  }, '0403323830', new Buffer('280'));

  test('should decode octstr with size', function() {
    this.octstr(3);
  }, '0403323830', new Buffer('280'));

  test('should decode octstr with size in interval', function() {
    this.octstr(3,7);
  }, '04053238303130', new Buffer('28010'));

  testBN('should decode int in interval', function() {
    this.int(10,90);
  }, '02010a', new asn1.bignum(10));

  testBN('should decode int in interval', function() {
    this.int(10,90);
  }, '0203989680', new asn1.bignum(10000000));

  test('should decode bmpstr', function() {
    this.bmpstr();
  }, '1e26004300650072007400690066006900630061' +
     '0074006500540065006d0070006c006100740065', 'CertificateTemplate');

  test('should decode bmpstr with cyrillic chars', function() {
    this.bmpstr();
  }, '1e0c041f04400438043204350442', 'Привет');

  test('should properly decode objid with dots', function() {
    this.objid({
      '1.2.398.3.10.1.1.1.2.2': 'yes'
    });
  }, '060a2a830e030a0101010202', 'yes');

  it('should decode encapsulated models', function() {
    const B = asn1.define('B', function() {
      this.seq().obj(
        this.key('nested').int()
      );
    });
    const A = asn1.define('A', function() {
      this.octstr().contains(B);
    });

    const out = A.decode(new Buffer('04053003020105', 'hex'), 'der');
    assert.equal(out.nested.toString(10), '5');
  });

  test('should decode IA5 string', function() {
    this.ia5str();
  }, '160C646F6720616E6420626F6E65', 'dog and bone');

  test('should decode printable string', function() {
    this.printstr();
  }, '1310427261686D7320616E64204C69737A74', 'Brahms and Liszt');

  test('should decode T61 string', function() {
    this.t61str();
  }, '140C4F6C69766572205477697374', 'Oliver Twist');

  test('should decode ISO646 string', function() {
    this.iso646str();
  }, '1A0B7365707469632074616E6B', 'septic tank');

  test('should decode utctime to utc ms', function() {
    this.utctime();
  }, '170D3136313030313035303030305A', '1475298000000');

  it('should decode optional seqof', function() {
    const B = asn1.define('B', function() {
      this.seq().obj(
        this.key('num').int()
      );
    });
    const A = asn1.define('A', function() {
      this.seq().obj(
        this.key('test1').seqof(B),
        this.key('test2').optional().seqof(B)
      );
    });

    let out = A.decode(new Buffer(
      '3018300A30030201013003020102300A30030201033003020104', 'hex'), 'der');
    assert.equal(out.test1[0].num.toString(10), 1);
    assert.equal(out.test1[1].num.toString(10), 2);
    assert.equal(out.test2[0].num.toString(10), 3);
    assert.equal(out.test2[1].num.toString(10), 4);

    out = A.decode(new Buffer('300C300A30030201013003020102', 'hex'), 'der');
    assert.equal(out.test1[0].num.toString(10), 1);
    assert.equal(out.test1[1].num.toString(10), 2);
    assert.equal(out.test2, undefined);
  });

  it('should not require decoder param', function() {
     const M = asn1.define('Model', function() {
       this.choice({
         apple: this.bool(),
       });
     });
     // Note no decoder specified, defaults to 'der'
     const decoded = M.decode(new Buffer('0101ff', 'hex'));
     assert.deepEqual(decoded, { 'type': 'apple', 'value': true });
  });
});
