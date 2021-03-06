'use strict';
/* global describe it */

const assert = require('assert');
const asn1 = require('..');
const BN = require('bn.js');

const Buffer = require('buffer').Buffer;

describe('asn1.js DER encoder', function() {
  /*
   * Explicit value shold be wrapped with A0 | EXPLICIT tag
   * this adds two more bytes to resulting buffer.
   * */
  it('should code explicit tag as 0xA2', function() {
    const E = asn1.define('E', function() {
      this.explicit(2).octstr()
    });

    const encoded = E.encode('X', 'der');

    // <Explicit tag> <wrapped len> <str tag> <len> <payload>
    assert.equal(encoded.toString('hex'), 'a203040158');
    assert.equal(encoded.length, 5);
  })

  function test(name, model_definition, model_value, der_expected) {
    it(name, function() {
      let Model, derActual;
      Model = asn1.define('Model', model_definition);
      derActual = Model.encode(model_value, 'der');
      assert.deepEqual(derActual, new Buffer(der_expected,'hex'));
    });
  }

  test('should encode real zero', function() {
    this.real();
  }, 0, '0900');

  test('should encode real Infinity', function() {
    this.real();
  }, Infinity, '090140');

  test('should encode real -Infinity', function() {
    this.real();
  }, -Infinity, '090141');

  test('should encode real NaN', function() {
    this.real();
  }, NaN, '090142');

  test('should encode real number 1', function() {
    this.real();
  }, 1, '09020131');

  test('should encode real number 2578', function() {
    this.real();
  }, 2578, '09050132353738');

  test('should encode real number float 1.2 to 1.2E+0', function() {
    this.real();
  }, 1.2, '090703312e32452b30');

  test('should encode real number float 1.45343434 to 1.45343434E+0', function() {
    this.real();
  }, 1.45343434, '090e03312e3435333433343334452b30');

  test('should encode real number float 1453434.34 to 1.45343434E+6', function() {
    this.real();
  }, 1453434.34, '090e03312e3435333433343334452b36');

  test('should encode real number float 0.00000000004 to 0.4E-11', function() {
    this.real();
  }, 0.00000000004, '090703342e452d3131');

  test('should encode objDesc', function() {
    this.objDesc();
  }, '280', '0703323830');

  test('should encode octstr', function() {
    this.octstr();
  }, new Buffer('280'), '0403323830');

  test('should encode octstr with size', function() {
    this.octstr(3);
  }, new Buffer('280'), '0403323830');

  test('should encode octstr with size in interval', function() {
    this.octstr(3,7);
  }, new Buffer('28010'), '04053238303130');

  test('should encode int in interval 1', function() {
    this.int(0, 65535);
  }, 10, '02010a');

  test('should encode int in interval 2', function() {
    this.int(100, 65535);
  }, 3000, '02020bb8');

   test('should encode int in interval 3', function() {
    this.int(100, 65535);
  }, 30000000000000, '02061b48eb57e000');

  test('should encode choice', function() {
    this.choice({
      apple: this.bool()
    });
  }, { type: 'apple', value: true }, '0101ff');

  test('should encode implicit seqof', function() {
    const Int = asn1.define('Int', function() {
      this.int();
    });
    this.implicit(0).seqof(Int);
  }, [ 1 ], 'A003020101' );

  test('should encode explicit seqof', function() {
    const Int = asn1.define('Int', function() {
      this.int();
    });
    this.explicit(0).seqof(Int);
  }, [ 1 ], 'A0053003020101' );

  test('should encode BN(128) properly', function() {
    this.int();
  }, new BN(128), '02020080');

  test('should encode int 128 properly', function() {
    this.int();
  }, 128, '02020080');

  test('should encode 0x8011 properly', function() {
    this.int();
  }, 0x8011, '0203008011');

  test('should omit default value in DER', function() {
    this.seq().obj(
      this.key('required').def(false).bool(),
      this.key('value').int()
    );
  }, {required: false, value: 1}, '3003020101');

  it('should encode optional and use', function() {
    const B = asn1.define('B', function() {
      this.int();
    });

    const A = asn1.define('A', function() {
      this.optional().use(B);
    });

    const out = A.encode(1, 'der');
    assert.equal(out.toString('hex'), '020101');
  });

  test('should properly encode objid with dots', function() {
    this.objid({
      '1.2.398.3.10.1.1.1.2.2': 'yes'
    });
  }, 'yes', '060a2a830e030a0101010202');

  test('should properly encode objid as array of strings', function() {
    this.objid();
  }, '1.2.398.3.10.1.1.1.2.2'.split('.'), '060a2a830e030a0101010202');

  test('should properly encode bmpstr', function() {
    this.bmpstr();
  }, 'CertificateTemplate', '1e26004300650072007400690066006900630061' +
                            '0074006500540065006d0070006c006100740065');

  test('should properly encode bmpstr with cyrillic chars', function() {
    this.bmpstr();
  }, 'Привет', '1e0c041f04400438043204350442');

  it('should encode encapsulated models', function() {
    const B = asn1.define('B', function() {
      this.seq().obj(
        this.key('nested').int()
      );
    });
    const A = asn1.define('A', function() {
      this.octstr().contains(B);
    });

    const out = A.encode({ nested: 5 }, 'der')
    assert.equal(out.toString('hex'), '04053003020105');
  });

  test('should properly encode IA5 string', function() {
    this.ia5str();
  }, 'dog and bone', '160C646F6720616E6420626F6E65');

  test('should properly encode printable string', function() {
    this.printstr();
  }, 'Brahms and Liszt', '1310427261686D7320616E64204C69737A74');

  test('should properly encode T61 string', function() {
    this.t61str();
  }, 'Oliver Twist', '140C4F6C69766572205477697374');

  test('should properly encode ISO646 string', function() {
    this.iso646str();
  }, 'septic tank', '1A0B7365707469632074616E6B');

  it('should not require encoder param', function() {
     const M = asn1.define('Model', function() {
       this.choice({
         apple: this.bool()
       });
     });
     // Note no encoder specified, defaults to 'der'
     const encoded = M.encode({ 'type': 'apple', 'value': true });
     assert.deepEqual(encoded, new Buffer('0101ff', 'hex'));
  });

  test('should properly encode utctime', function () {
    this.utctime();
  }, '2016-10-01 05:00:00 UTC', '170D3136313030313035303030305A');

  it('should throw error on empty date', function () {
    const M = asn1.define('1', function () {
      this.utctime();
    })
    
    const encode = function () {
      M.encode('')
    };
    //encode();
    assert.throws(encode, Error, "Error thrown");

  });

  it('should throw error on empty date', function () {
    let time = asn1.define('time', function () {
      this.utctime()
    });

    let range = asn1.define('AbonentService', function () {
      this.seq().obj(        
        this.key('begin_time').use(time),
        this.key('end_time').use(time)
      );
    });

    let q = range.encode({begin_time: '2010-10-10 12:00:00 UTC', end_time: '2010-10-10 12:00:00 UTC'}, 'der');
    
    assert.equal(q.toString('hex'), '301e170d3130313031303132303030305a170d3130313031303132303030305a');

    const encodeError = function () {
      let q = range.encode({begin_time: '2010-10-10 12:00:00 UTC'}, 'der');
    };
    //encodeError();
    assert.throws(encodeError, Error, "Error thrown");

  });

});

