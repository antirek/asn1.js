var assert = require('assert');
var asn1 = require('..');
var bn = asn1.bignum;
var fixtures = require('./fixtures');
var jsonEqual = fixtures.jsonEqual;

var Buffer = require('buffer').Buffer;

describe('asn1.js models', function() {

  describe('plain use', function() {
    it('should encode submodel', function() {
      var SubModel = asn1.define('SubModel', function() {
        this.seq().obj(
          this.key('b').octstr()
        );
      });
      var Model = asn1.define('Model', function() {
        this.seq().obj(
          this.key('a').int(),
          this.key('sub').use(SubModel)
        );
      });

      var data = {a: new bn(1), sub: {b: new Buffer("XXX")}};
      var wire = Model.encode(data, 'der');
      assert.equal(wire.toString('hex'), '300a02010130050403585858');
      var back = Model.decode(wire, 'der');
      jsonEqual(back, data);
    });

    it('should honour implicit tag from parent', function() {
      var SubModel = asn1.define('SubModel', function() {
        this.seq().obj(
          this.key('x').octstr()
        )
      });
      var Model = asn1.define('Model', function() {
        this.seq().obj(
          this.key('a').int(),
          this.key('sub').use(SubModel).implicit(0)
        );
      });

      var data = {a: new bn(1), sub: {x: new Buffer("123")}};
      var wire = Model.encode(data, 'der');
      assert.equal(wire.toString('hex'), '300a020101a0050403313233');
      var back = Model.decode(wire, 'der');
      jsonEqual(back, data);
    });

    it('should honour explicit tag from parent', function() {
      var SubModel = asn1.define('SubModel', function() {
        this.seq().obj(
          this.key('x').octstr()
        )
      });
      var Model = asn1.define('Model', function() {
        this.seq().obj(
          this.key('a').int(),
          this.key('sub').use(SubModel).explicit(0)
        );
      });

      var data = {a: new bn(1), sub: {x: new Buffer("123")}};
      var wire = Model.encode(data, 'der');
      assert.equal(wire.toString('hex'), '300c020101a00730050403313233');
      var back = Model.decode(wire, 'der');
      jsonEqual(back, data);

    });

    it('should get model with function call', function() {
      var SubModel = asn1.define('SubModel', function() {
        this.seq().obj(
          this.key('x').octstr()
        )
      });
      var Model = asn1.define('Model', function() {
        this.seq().obj(
          this.key('a').int(),
          this.key('sub').use(function(obj) {
              assert.equal(obj.a, 1);
              return SubModel;
          })
        );
      });

      var data = {a: new bn(1), sub: {x: new Buffer("123")}};
      var wire = Model.encode(data, 'der');
      assert.equal(wire.toString('hex'), '300a02010130050403313233');
      var back = Model.decode(wire, 'der');
      jsonEqual(back, data);

    });

    it('should support recursive submodels', function() {
      var PlainSubModel = asn1.define('PlainSubModel', function() {
        this.int();
      });
      var RecursiveModel = asn1.define('RecursiveModel', function() {
        this.seq().obj(
          this.key('plain').bool(),
          this.key('content').use(function(obj) {
            if(obj.plain) {
              return PlainSubModel;
            } else {
              return RecursiveModel;
            }
          })
        );
      });

      var data = {
        'plain': false,
        'content': {
          'plain': true,
          'content': new bn(1)
        }
      };
      var wire = RecursiveModel.encode(data, 'der');
      assert.equal(wire.toString('hex'), '300b01010030060101ff020101');
      var back = RecursiveModel.decode(wire, 'der');
      jsonEqual(back, data);
    });

  });

  describe('switch use', function() {
    it('should encode/decode', function() {
      var Model1Data = asn1.define('Model1Data', function () {
          this.utf8str();
      });
      
      var Model2Data = asn1.define('Model2Data', function () {
          this.int();
      });

      var Model = asn1.define('Model', function () {
          this.obj(
              this.key('id').int(),
              this.key('type').numstr(),
              this.key('data').switch('type', {
                  '12': Model1Data,
                  '15': Model2Data
              })
          )
      });

      /*
      var data1 = {id: 1, type: '12', data: 'lopata'};
      var res1 = Model.encode(data1, 'der');
      console.log(res1);

      var data2 = {id: 1, type: '15', data: 10};
      var res2 = Model.encode(data2, 'der');
      console.log(res2);

      var message = '300100';
      var value1 = Model.decode(message, 'der');
      console.log(value1);
      */

    });

  });

});

