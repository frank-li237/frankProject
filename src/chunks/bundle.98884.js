System.register([], function(_export, _context) { return { execute: function () {
System.register("chunks:///_virtual/aes.js", ['./rollupPluginModLoBabelHelpers.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, BlockCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      BlockCipher = module.BlockCipher;
    }],
    execute: function () {
      // Lookup tables
      var _SBOX = [];
      var INV_SBOX = [];
      var _SUB_MIX_0 = [];
      var _SUB_MIX_1 = [];
      var _SUB_MIX_2 = [];
      var _SUB_MIX_3 = [];
      var INV_SUB_MIX_0 = [];
      var INV_SUB_MIX_1 = [];
      var INV_SUB_MIX_2 = [];
      var INV_SUB_MIX_3 = [];

      // Compute lookup tables

      // Compute double table
      var d = [];
      for (var i = 0; i < 256; i += 1) {
        if (i < 128) {
          d[i] = i << 1;
        } else {
          d[i] = i << 1 ^ 0x11b;
        }
      }

      // Walk GF(2^8)
      var x = 0;
      var xi = 0;
      for (var _i = 0; _i < 256; _i += 1) {
        // Compute sbox
        var sx = xi ^ xi << 1 ^ xi << 2 ^ xi << 3 ^ xi << 4;
        sx = sx >>> 8 ^ sx & 0xff ^ 0x63;
        _SBOX[x] = sx;
        INV_SBOX[sx] = x;

        // Compute multiplication
        var x2 = d[x];
        var x4 = d[x2];
        var x8 = d[x4];

        // Compute sub bytes, mix columns tables
        var t = d[sx] * 0x101 ^ sx * 0x1010100;
        _SUB_MIX_0[x] = t << 24 | t >>> 8;
        _SUB_MIX_1[x] = t << 16 | t >>> 16;
        _SUB_MIX_2[x] = t << 8 | t >>> 24;
        _SUB_MIX_3[x] = t;

        // Compute inv sub bytes, inv mix columns tables
        t = x8 * 0x1010101 ^ x4 * 0x10001 ^ x2 * 0x101 ^ x * 0x1010100;
        INV_SUB_MIX_0[sx] = t << 24 | t >>> 8;
        INV_SUB_MIX_1[sx] = t << 16 | t >>> 16;
        INV_SUB_MIX_2[sx] = t << 8 | t >>> 24;
        INV_SUB_MIX_3[sx] = t;

        // Compute next counter
        if (!x) {
          xi = 1;
          x = xi;
        } else {
          x = x2 ^ d[d[d[x8 ^ x2]]];
          xi ^= d[d[xi]];
        }
      }

      // Precomputed Rcon lookup
      var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

      /**
       * AES block cipher algorithm.
       */
      var AESAlgo = exports('AESAlgo', /*#__PURE__*/function (_BlockCipher) {
        _inheritsLoose(AESAlgo, _BlockCipher);
        function AESAlgo() {
          return _BlockCipher.apply(this, arguments) || this;
        }
        var _proto = AESAlgo.prototype;
        _proto._doReset = function _doReset() {
          var t;

          // Skip reset of nRounds has been set before and key did not change
          if (this._nRounds && this._keyPriorReset === this._key) {
            return;
          }

          // Shortcuts
          this._keyPriorReset = this._key;
          var key = this._keyPriorReset;
          var keyWords = key.words;
          var keySize = key.sigBytes / 4;

          // Compute number of rounds
          this._nRounds = keySize + 6;
          var nRounds = this._nRounds;

          // Compute number of key schedule rows
          var ksRows = (nRounds + 1) * 4;

          // Compute key schedule
          this._keySchedule = [];
          var keySchedule = this._keySchedule;
          for (var ksRow = 0; ksRow < ksRows; ksRow += 1) {
            if (ksRow < keySize) {
              keySchedule[ksRow] = keyWords[ksRow];
            } else {
              t = keySchedule[ksRow - 1];
              if (!(ksRow % keySize)) {
                // Rot word
                t = t << 8 | t >>> 24;

                // Sub word
                t = _SBOX[t >>> 24] << 24 | _SBOX[t >>> 16 & 0xff] << 16 | _SBOX[t >>> 8 & 0xff] << 8 | _SBOX[t & 0xff];

                // Mix Rcon
                t ^= RCON[ksRow / keySize | 0] << 24;
              } else if (keySize > 6 && ksRow % keySize === 4) {
                // Sub word
                t = _SBOX[t >>> 24] << 24 | _SBOX[t >>> 16 & 0xff] << 16 | _SBOX[t >>> 8 & 0xff] << 8 | _SBOX[t & 0xff];
              }
              keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
            }
          }

          // Compute inv key schedule
          this._invKeySchedule = [];
          var invKeySchedule = this._invKeySchedule;
          for (var invKsRow = 0; invKsRow < ksRows; invKsRow += 1) {
            var _ksRow = ksRows - invKsRow;
            if (invKsRow % 4) {
              t = keySchedule[_ksRow];
            } else {
              t = keySchedule[_ksRow - 4];
            }
            if (invKsRow < 4 || _ksRow <= 4) {
              invKeySchedule[invKsRow] = t;
            } else {
              invKeySchedule[invKsRow] = INV_SUB_MIX_0[_SBOX[t >>> 24]] ^ INV_SUB_MIX_1[_SBOX[t >>> 16 & 0xff]] ^ INV_SUB_MIX_2[_SBOX[t >>> 8 & 0xff]] ^ INV_SUB_MIX_3[_SBOX[t & 0xff]];
            }
          }
        };
        _proto.encryptBlock = function encryptBlock(M, offset) {
          this._doCryptBlock(M, offset, this._keySchedule, _SUB_MIX_0, _SUB_MIX_1, _SUB_MIX_2, _SUB_MIX_3, _SBOX);
        };
        _proto.decryptBlock = function decryptBlock(M, offset) {
          var _M = M;

          // Swap 2nd and 4th rows
          var t = _M[offset + 1];
          _M[offset + 1] = _M[offset + 3];
          _M[offset + 3] = t;
          this._doCryptBlock(_M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

          // Inv swap 2nd and 4th rows
          t = _M[offset + 1];
          _M[offset + 1] = _M[offset + 3];
          _M[offset + 3] = t;
        };
        _proto._doCryptBlock = function _doCryptBlock(M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
          var _M = M;

          // Shortcut
          var nRounds = this._nRounds;

          // Get input, add round key
          var s0 = _M[offset] ^ keySchedule[0];
          var s1 = _M[offset + 1] ^ keySchedule[1];
          var s2 = _M[offset + 2] ^ keySchedule[2];
          var s3 = _M[offset + 3] ^ keySchedule[3];

          // Key schedule row counter
          var ksRow = 4;

          // Rounds
          for (var round = 1; round < nRounds; round += 1) {
            // Shift rows, sub bytes, mix columns, add round key
            var _t = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[s1 >>> 16 & 0xff] ^ SUB_MIX_2[s2 >>> 8 & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;
            var _t2 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[s2 >>> 16 & 0xff] ^ SUB_MIX_2[s3 >>> 8 & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;
            var _t3 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[s3 >>> 16 & 0xff] ^ SUB_MIX_2[s0 >>> 8 & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;
            var _t4 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[s0 >>> 16 & 0xff] ^ SUB_MIX_2[s1 >>> 8 & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;

            // Update state
            s0 = _t;
            s1 = _t2;
            s2 = _t3;
            s3 = _t4;
          }

          // Shift rows, sub bytes, add round key
          var t0 = (SBOX[s0 >>> 24] << 24 | SBOX[s1 >>> 16 & 0xff] << 16 | SBOX[s2 >>> 8 & 0xff] << 8 | SBOX[s3 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;
          var t1 = (SBOX[s1 >>> 24] << 24 | SBOX[s2 >>> 16 & 0xff] << 16 | SBOX[s3 >>> 8 & 0xff] << 8 | SBOX[s0 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;
          var t2 = (SBOX[s2 >>> 24] << 24 | SBOX[s3 >>> 16 & 0xff] << 16 | SBOX[s0 >>> 8 & 0xff] << 8 | SBOX[s1 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;
          var t3 = (SBOX[s3 >>> 24] << 24 | SBOX[s0 >>> 16 & 0xff] << 16 | SBOX[s1 >>> 8 & 0xff] << 8 | SBOX[s2 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;

          // Set output
          _M[offset] = t0;
          _M[offset + 1] = t1;
          _M[offset + 2] = t2;
          _M[offset + 3] = t3;
        };
        return AESAlgo;
      }(BlockCipher));
      AESAlgo.keySize = 256 / 32;

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
       */
      var AES = exports('AES', BlockCipher._createHelper(AESAlgo));
    }
  };
});

System.register("chunks:///_virtual/blowfish.js", ['./rollupPluginModLoBabelHelpers.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, BlockCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      BlockCipher = module.BlockCipher;
    }],
    execute: function () {
      var N = 16;

      //Origin pbox and sbox, derived from PI
      var ORIG_P = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B];
      var ORIG_S = [[0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5, 0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E, 0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60, 0xE65525F3, 0xAA55AB94, 0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993, 0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C, 0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193, 0x61D809CC, 0xFB21A991, 0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1, 0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5, 0x0F6D6FF3, 0x83F44239, 0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A, 0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4, 0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176, 0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706, 0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B, 0x075372C9, 0x80991B7B, 0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4, 0x5E5C9EC2, 0x196A2463, 0x68FB6FAF, 0x3E6C53B5, 0x1339B2EB, 0x3B52EC6F, 0x6DFC511F, 0x9B30952C, 0xCC814544, 0xAF5EBD09, 0xBEE3D004, 0xDE334AFD, 0x660F2807, 0x192E4BB3, 0xC0CBA857, 0x45C8740F, 0xD20B5F39, 0xB9D3FBDB, 0x5579C0BD, 0x1A60320A, 0xD6A100C6, 0x402C7279, 0x679F25FE, 0xFB1FA3CC, 0x8EA5E9F8, 0xDB3222F8, 0x3C7516DF, 0xFD616B15, 0x2F501EC8, 0xAD0552AB, 0x323DB5FA, 0xFD238760, 0x53317B48, 0x3E00DF82, 0x9E5C57BB, 0xCA6F8CA0, 0x1A87562E, 0xDF1769DB, 0xD542A8F6, 0x287EFFC3, 0xAC6732C6, 0x8C4F5573, 0x695B27B0, 0xBBCA58C8, 0xE1FFA35D, 0xB8F011A0, 0x10FA3D98, 0xFD2183B8, 0x4AFCB56C, 0x2DD1D35B, 0x9A53E479, 0xB6F84565, 0xD28E49BC, 0x4BFB9790, 0xE1DDF2DA, 0xA4CB7E33, 0x62FB1341, 0xCEE4C6E8, 0xEF20CADA, 0x36774C01, 0xD07E9EFE, 0x2BF11FB4, 0x95DBDA4D, 0xAE909198, 0xEAAD8E71, 0x6B93D5A0, 0xD08ED1D0, 0xAFC725E0, 0x8E3C5B2F, 0x8E7594B7, 0x8FF6E2FB, 0xF2122B64, 0x8888B812, 0x900DF01C, 0x4FAD5EA0, 0x688FC31C, 0xD1CFF191, 0xB3A8C1AD, 0x2F2F2218, 0xBE0E1777, 0xEA752DFE, 0x8B021FA1, 0xE5A0CC0F, 0xB56F74E8, 0x18ACF3D6, 0xCE89E299, 0xB4A84FE0, 0xFD13E0B7, 0x7CC43B81, 0xD2ADA8D9, 0x165FA266, 0x80957705, 0x93CC7314, 0x211A1477, 0xE6AD2065, 0x77B5FA86, 0xC75442F5, 0xFB9D35CF, 0xEBCDAF0C, 0x7B3E89A0, 0xD6411BD3, 0xAE1E7E49, 0x00250E2D, 0x2071B35E, 0x226800BB, 0x57B8E0AF, 0x2464369B, 0xF009B91E, 0x5563911D, 0x59DFA6AA, 0x78C14389, 0xD95A537F, 0x207D5BA2, 0x02E5B9C5, 0x83260376, 0x6295CFA9, 0x11C81968, 0x4E734A41, 0xB3472DCA, 0x7B14A94A, 0x1B510052, 0x9A532915, 0xD60F573F, 0xBC9BC6E4, 0x2B60A476, 0x81E67400, 0x08BA6FB5, 0x571BE91F, 0xF296EC6B, 0x2A0DD915, 0xB6636521, 0xE7B9F9B6, 0xFF34052E, 0xC5855664, 0x53B02D5D, 0xA99F8FA1, 0x08BA4799, 0x6E85076A], [0x4B7A70E9, 0xB5B32944, 0xDB75092E, 0xC4192623, 0xAD6EA6B0, 0x49A7DF7D, 0x9CEE60B8, 0x8FEDB266, 0xECAA8C71, 0x699A17FF, 0x5664526C, 0xC2B19EE1, 0x193602A5, 0x75094C29, 0xA0591340, 0xE4183A3E, 0x3F54989A, 0x5B429D65, 0x6B8FE4D6, 0x99F73FD6, 0xA1D29C07, 0xEFE830F5, 0x4D2D38E6, 0xF0255DC1, 0x4CDD2086, 0x8470EB26, 0x6382E9C6, 0x021ECC5E, 0x09686B3F, 0x3EBAEFC9, 0x3C971814, 0x6B6A70A1, 0x687F3584, 0x52A0E286, 0xB79C5305, 0xAA500737, 0x3E07841C, 0x7FDEAE5C, 0x8E7D44EC, 0x5716F2B8, 0xB03ADA37, 0xF0500C0D, 0xF01C1F04, 0x0200B3FF, 0xAE0CF51A, 0x3CB574B2, 0x25837A58, 0xDC0921BD, 0xD19113F9, 0x7CA92FF6, 0x94324773, 0x22F54701, 0x3AE5E581, 0x37C2DADC, 0xC8B57634, 0x9AF3DDA7, 0xA9446146, 0x0FD0030E, 0xECC8C73E, 0xA4751E41, 0xE238CD99, 0x3BEA0E2F, 0x3280BBA1, 0x183EB331, 0x4E548B38, 0x4F6DB908, 0x6F420D03, 0xF60A04BF, 0x2CB81290, 0x24977C79, 0x5679B072, 0xBCAF89AF, 0xDE9A771F, 0xD9930810, 0xB38BAE12, 0xDCCF3F2E, 0x5512721F, 0x2E6B7124, 0x501ADDE6, 0x9F84CD87, 0x7A584718, 0x7408DA17, 0xBC9F9ABC, 0xE94B7D8C, 0xEC7AEC3A, 0xDB851DFA, 0x63094366, 0xC464C3D2, 0xEF1C1847, 0x3215D908, 0xDD433B37, 0x24C2BA16, 0x12A14D43, 0x2A65C451, 0x50940002, 0x133AE4DD, 0x71DFF89E, 0x10314E55, 0x81AC77D6, 0x5F11199B, 0x043556F1, 0xD7A3C76B, 0x3C11183B, 0x5924A509, 0xF28FE6ED, 0x97F1FBFA, 0x9EBABF2C, 0x1E153C6E, 0x86E34570, 0xEAE96FB1, 0x860E5E0A, 0x5A3E2AB3, 0x771FE71C, 0x4E3D06FA, 0x2965DCB9, 0x99E71D0F, 0x803E89D6, 0x5266C825, 0x2E4CC978, 0x9C10B36A, 0xC6150EBA, 0x94E2EA78, 0xA5FC3C53, 0x1E0A2DF4, 0xF2F74EA7, 0x361D2B3D, 0x1939260F, 0x19C27960, 0x5223A708, 0xF71312B6, 0xEBADFE6E, 0xEAC31F66, 0xE3BC4595, 0xA67BC883, 0xB17F37D1, 0x018CFF28, 0xC332DDEF, 0xBE6C5AA5, 0x65582185, 0x68AB9802, 0xEECEA50F, 0xDB2F953B, 0x2AEF7DAD, 0x5B6E2F84, 0x1521B628, 0x29076170, 0xECDD4775, 0x619F1510, 0x13CCA830, 0xEB61BD96, 0x0334FE1E, 0xAA0363CF, 0xB5735C90, 0x4C70A239, 0xD59E9E0B, 0xCBAADE14, 0xEECC86BC, 0x60622CA7, 0x9CAB5CAB, 0xB2F3846E, 0x648B1EAF, 0x19BDF0CA, 0xA02369B9, 0x655ABB50, 0x40685A32, 0x3C2AB4B3, 0x319EE9D5, 0xC021B8F7, 0x9B540B19, 0x875FA099, 0x95F7997E, 0x623D7DA8, 0xF837889A, 0x97E32D77, 0x11ED935F, 0x16681281, 0x0E358829, 0xC7E61FD6, 0x96DEDFA1, 0x7858BA99, 0x57F584A5, 0x1B227263, 0x9B83C3FF, 0x1AC24696, 0xCDB30AEB, 0x532E3054, 0x8FD948E4, 0x6DBC3128, 0x58EBF2EF, 0x34C6FFEA, 0xFE28ED61, 0xEE7C3C73, 0x5D4A14D9, 0xE864B7E3, 0x42105D14, 0x203E13E0, 0x45EEE2B6, 0xA3AAABEA, 0xDB6C4F15, 0xFACB4FD0, 0xC742F442, 0xEF6ABBB5, 0x654F3B1D, 0x41CD2105, 0xD81E799E, 0x86854DC7, 0xE44B476A, 0x3D816250, 0xCF62A1F2, 0x5B8D2646, 0xFC8883A0, 0xC1C7B6A3, 0x7F1524C3, 0x69CB7492, 0x47848A0B, 0x5692B285, 0x095BBF00, 0xAD19489D, 0x1462B174, 0x23820E00, 0x58428D2A, 0x0C55F5EA, 0x1DADF43E, 0x233F7061, 0x3372F092, 0x8D937E41, 0xD65FECF1, 0x6C223BDB, 0x7CDE3759, 0xCBEE7460, 0x4085F2A7, 0xCE77326E, 0xA6078084, 0x19F8509E, 0xE8EFD855, 0x61D99735, 0xA969A7AA, 0xC50C06C2, 0x5A04ABFC, 0x800BCADC, 0x9E447A2E, 0xC3453484, 0xFDD56705, 0x0E1E9EC9, 0xDB73DBD3, 0x105588CD, 0x675FDA79, 0xE3674340, 0xC5C43465, 0x713E38D8, 0x3D28F89E, 0xF16DFF20, 0x153E21E7, 0x8FB03D4A, 0xE6E39F2B, 0xDB83ADF7], [0xE93D5A68, 0x948140F7, 0xF64C261C, 0x94692934, 0x411520F7, 0x7602D4F7, 0xBCF46B2E, 0xD4A20068, 0xD4082471, 0x3320F46A, 0x43B7D4B7, 0x500061AF, 0x1E39F62E, 0x97244546, 0x14214F74, 0xBF8B8840, 0x4D95FC1D, 0x96B591AF, 0x70F4DDD3, 0x66A02F45, 0xBFBC09EC, 0x03BD9785, 0x7FAC6DD0, 0x31CB8504, 0x96EB27B3, 0x55FD3941, 0xDA2547E6, 0xABCA0A9A, 0x28507825, 0x530429F4, 0x0A2C86DA, 0xE9B66DFB, 0x68DC1462, 0xD7486900, 0x680EC0A4, 0x27A18DEE, 0x4F3FFEA2, 0xE887AD8C, 0xB58CE006, 0x7AF4D6B6, 0xAACE1E7C, 0xD3375FEC, 0xCE78A399, 0x406B2A42, 0x20FE9E35, 0xD9F385B9, 0xEE39D7AB, 0x3B124E8B, 0x1DC9FAF7, 0x4B6D1856, 0x26A36631, 0xEAE397B2, 0x3A6EFA74, 0xDD5B4332, 0x6841E7F7, 0xCA7820FB, 0xFB0AF54E, 0xD8FEB397, 0x454056AC, 0xBA489527, 0x55533A3A, 0x20838D87, 0xFE6BA9B7, 0xD096954B, 0x55A867BC, 0xA1159A58, 0xCCA92963, 0x99E1DB33, 0xA62A4A56, 0x3F3125F9, 0x5EF47E1C, 0x9029317C, 0xFDF8E802, 0x04272F70, 0x80BB155C, 0x05282CE3, 0x95C11548, 0xE4C66D22, 0x48C1133F, 0xC70F86DC, 0x07F9C9EE, 0x41041F0F, 0x404779A4, 0x5D886E17, 0x325F51EB, 0xD59BC0D1, 0xF2BCC18F, 0x41113564, 0x257B7834, 0x602A9C60, 0xDFF8E8A3, 0x1F636C1B, 0x0E12B4C2, 0x02E1329E, 0xAF664FD1, 0xCAD18115, 0x6B2395E0, 0x333E92E1, 0x3B240B62, 0xEEBEB922, 0x85B2A20E, 0xE6BA0D99, 0xDE720C8C, 0x2DA2F728, 0xD0127845, 0x95B794FD, 0x647D0862, 0xE7CCF5F0, 0x5449A36F, 0x877D48FA, 0xC39DFD27, 0xF33E8D1E, 0x0A476341, 0x992EFF74, 0x3A6F6EAB, 0xF4F8FD37, 0xA812DC60, 0xA1EBDDF8, 0x991BE14C, 0xDB6E6B0D, 0xC67B5510, 0x6D672C37, 0x2765D43B, 0xDCD0E804, 0xF1290DC7, 0xCC00FFA3, 0xB5390F92, 0x690FED0B, 0x667B9FFB, 0xCEDB7D9C, 0xA091CF0B, 0xD9155EA3, 0xBB132F88, 0x515BAD24, 0x7B9479BF, 0x763BD6EB, 0x37392EB3, 0xCC115979, 0x8026E297, 0xF42E312D, 0x6842ADA7, 0xC66A2B3B, 0x12754CCC, 0x782EF11C, 0x6A124237, 0xB79251E7, 0x06A1BBE6, 0x4BFB6350, 0x1A6B1018, 0x11CAEDFA, 0x3D25BDD8, 0xE2E1C3C9, 0x44421659, 0x0A121386, 0xD90CEC6E, 0xD5ABEA2A, 0x64AF674E, 0xDA86A85F, 0xBEBFE988, 0x64E4C3FE, 0x9DBC8057, 0xF0F7C086, 0x60787BF8, 0x6003604D, 0xD1FD8346, 0xF6381FB0, 0x7745AE04, 0xD736FCCC, 0x83426B33, 0xF01EAB71, 0xB0804187, 0x3C005E5F, 0x77A057BE, 0xBDE8AE24, 0x55464299, 0xBF582E61, 0x4E58F48F, 0xF2DDFDA2, 0xF474EF38, 0x8789BDC2, 0x5366F9C3, 0xC8B38E74, 0xB475F255, 0x46FCD9B9, 0x7AEB2661, 0x8B1DDF84, 0x846A0E79, 0x915F95E2, 0x466E598E, 0x20B45770, 0x8CD55591, 0xC902DE4C, 0xB90BACE1, 0xBB8205D0, 0x11A86248, 0x7574A99E, 0xB77F19B6, 0xE0A9DC09, 0x662D09A1, 0xC4324633, 0xE85A1F02, 0x09F0BE8C, 0x4A99A025, 0x1D6EFE10, 0x1AB93D1D, 0x0BA5A4DF, 0xA186F20F, 0x2868F169, 0xDCB7DA83, 0x573906FE, 0xA1E2CE9B, 0x4FCD7F52, 0x50115E01, 0xA70683FA, 0xA002B5C4, 0x0DE6D027, 0x9AF88C27, 0x773F8641, 0xC3604C06, 0x61A806B5, 0xF0177A28, 0xC0F586E0, 0x006058AA, 0x30DC7D62, 0x11E69ED7, 0x2338EA63, 0x53C2DD94, 0xC2C21634, 0xBBCBEE56, 0x90BCB6DE, 0xEBFC7DA1, 0xCE591D76, 0x6F05E409, 0x4B7C0188, 0x39720A3D, 0x7C927C24, 0x86E3725F, 0x724D9DB9, 0x1AC15BB4, 0xD39EB8FC, 0xED545578, 0x08FCA5B5, 0xD83D7CD3, 0x4DAD0FC4, 0x1E50EF5E, 0xB161E6F8, 0xA28514D9, 0x6C51133C, 0x6FD5C7E7, 0x56E14EC4, 0x362ABFCE, 0xDDC6C837, 0xD79A3234, 0x92638212, 0x670EFA8E, 0x406000E0], [0x3A39CE37, 0xD3FAF5CF, 0xABC27737, 0x5AC52D1B, 0x5CB0679E, 0x4FA33742, 0xD3822740, 0x99BC9BBE, 0xD5118E9D, 0xBF0F7315, 0xD62D1C7E, 0xC700C47B, 0xB78C1B6B, 0x21A19045, 0xB26EB1BE, 0x6A366EB4, 0x5748AB2F, 0xBC946E79, 0xC6A376D2, 0x6549C2C8, 0x530FF8EE, 0x468DDE7D, 0xD5730A1D, 0x4CD04DC6, 0x2939BBDB, 0xA9BA4650, 0xAC9526E8, 0xBE5EE304, 0xA1FAD5F0, 0x6A2D519A, 0x63EF8CE2, 0x9A86EE22, 0xC089C2B8, 0x43242EF6, 0xA51E03AA, 0x9CF2D0A4, 0x83C061BA, 0x9BE96A4D, 0x8FE51550, 0xBA645BD6, 0x2826A2F9, 0xA73A3AE1, 0x4BA99586, 0xEF5562E9, 0xC72FEFD3, 0xF752F7DA, 0x3F046F69, 0x77FA0A59, 0x80E4A915, 0x87B08601, 0x9B09E6AD, 0x3B3EE593, 0xE990FD5A, 0x9E34D797, 0x2CF0B7D9, 0x022B8B51, 0x96D5AC3A, 0x017DA67D, 0xD1CF3ED6, 0x7C7D2D28, 0x1F9F25CF, 0xADF2B89B, 0x5AD6B472, 0x5A88F54C, 0xE029AC71, 0xE019A5E6, 0x47B0ACFD, 0xED93FA9B, 0xE8D3C48D, 0x283B57CC, 0xF8D56629, 0x79132E28, 0x785F0191, 0xED756055, 0xF7960E44, 0xE3D35E8C, 0x15056DD4, 0x88F46DBA, 0x03A16125, 0x0564F0BD, 0xC3EB9E15, 0x3C9057A2, 0x97271AEC, 0xA93A072A, 0x1B3F6D9B, 0x1E6321F5, 0xF59C66FB, 0x26DCF319, 0x7533D928, 0xB155FDF5, 0x03563482, 0x8ABA3CBB, 0x28517711, 0xC20AD9F8, 0xABCC5167, 0xCCAD925F, 0x4DE81751, 0x3830DC8E, 0x379D5862, 0x9320F991, 0xEA7A90C2, 0xFB3E7BCE, 0x5121CE64, 0x774FBE32, 0xA8B6E37E, 0xC3293D46, 0x48DE5369, 0x6413E680, 0xA2AE0810, 0xDD6DB224, 0x69852DFD, 0x09072166, 0xB39A460A, 0x6445C0DD, 0x586CDECF, 0x1C20C8AE, 0x5BBEF7DD, 0x1B588D40, 0xCCD2017F, 0x6BB4E3BB, 0xDDA26A7E, 0x3A59FF45, 0x3E350A44, 0xBCB4CDD5, 0x72EACEA8, 0xFA6484BB, 0x8D6612AE, 0xBF3C6F47, 0xD29BE463, 0x542F5D9E, 0xAEC2771B, 0xF64E6370, 0x740E0D8D, 0xE75B1357, 0xF8721671, 0xAF537D5D, 0x4040CB08, 0x4EB4E2CC, 0x34D2466A, 0x0115AF84, 0xE1B00428, 0x95983A1D, 0x06B89FB4, 0xCE6EA048, 0x6F3F3B82, 0x3520AB82, 0x011A1D4B, 0x277227F8, 0x611560B1, 0xE7933FDC, 0xBB3A792B, 0x344525BD, 0xA08839E1, 0x51CE794B, 0x2F32C9B7, 0xA01FBAC9, 0xE01CC87E, 0xBCC7D1F6, 0xCF0111C3, 0xA1E8AAC7, 0x1A908749, 0xD44FBD9A, 0xD0DADECB, 0xD50ADA38, 0x0339C32A, 0xC6913667, 0x8DF9317C, 0xE0B12B4F, 0xF79E59B7, 0x43F5BB3A, 0xF2D519FF, 0x27D9459C, 0xBF97222C, 0x15E6FC2A, 0x0F91FC71, 0x9B941525, 0xFAE59361, 0xCEB69CEB, 0xC2A86459, 0x12BAA8D1, 0xB6C1075E, 0xE3056A0C, 0x10D25065, 0xCB03A442, 0xE0EC6E0E, 0x1698DB3B, 0x4C98A0BE, 0x3278E964, 0x9F1F9532, 0xE0D392DF, 0xD3A0342B, 0x8971F21E, 0x1B0A7441, 0x4BA3348C, 0xC5BE7120, 0xC37632D8, 0xDF359F8D, 0x9B992F2E, 0xE60B6F47, 0x0FE3F11D, 0xE54CDA54, 0x1EDAD891, 0xCE6279CF, 0xCD3E7E6F, 0x1618B166, 0xFD2C1D05, 0x848FD2C5, 0xF6FB2299, 0xF523F357, 0xA6327623, 0x93A83531, 0x56CCCD02, 0xACF08162, 0x5A75EBB5, 0x6E163697, 0x88D273CC, 0xDE966292, 0x81B949D0, 0x4C50901B, 0x71C65614, 0xE6C6C7BD, 0x327A140A, 0x45E1D006, 0xC3F27B9A, 0xC9AA53FD, 0x62A80F00, 0xBB25BFE2, 0x35BDD2F6, 0x71126905, 0xB2040222, 0xB6CBCF7C, 0xCD769C2B, 0x53113EC0, 0x1640E3D3, 0x38ABBD60, 0x2547ADF0, 0xBA38209C, 0xF746CE76, 0x77AFA1C5, 0x20756060, 0x85CBFE4E, 0x8AE88DD8, 0x7AAAF9B0, 0x4CF9AA7E, 0x1948C25C, 0x02FB8A8C, 0x01C36AE4, 0xD6EBE1F9, 0x90D4F869, 0xA65CDEA0, 0x3F09252D, 0xC208E69F, 0xB74E6132, 0xCE77E25B, 0x578FDFE3, 0x3AC372E6]];
      var blowfishCtx = {
        pbox: [],
        sbox: []
      };
      function f(ctx, x) {
        var a = x >> 24 & 0xFF;
        var b = x >> 16 & 0xFF;
        var c = x >> 8 & 0xFF;
        var d = x & 0xFF;
        var y = ctx.sbox[0][a] + ctx.sbox[1][b];
        y = y ^ ctx.sbox[2][c];
        y = y + ctx.sbox[3][d];
        return y;
      }
      function blowfishEncrypt(ctx, left, right) {
        var Xl = left;
        var Xr = right;
        var temp;
        for (var i = 0; i < N; ++i) {
          Xl = Xl ^ ctx.pbox[i];
          Xr = f(ctx, Xl) ^ Xr;
          temp = Xl;
          Xl = Xr;
          Xr = temp;
        }
        temp = Xl;
        Xl = Xr;
        Xr = temp;
        Xr = Xr ^ ctx.pbox[N];
        Xl = Xl ^ ctx.pbox[N + 1];
        return {
          left: Xl,
          right: Xr
        };
      }
      function blowfishDecrypt(ctx, left, right) {
        var Xl = left;
        var Xr = right;
        var temp;
        for (var i = N + 1; i > 1; --i) {
          Xl = Xl ^ ctx.pbox[i];
          Xr = f(ctx, Xl) ^ Xr;
          temp = Xl;
          Xl = Xr;
          Xr = temp;
        }
        temp = Xl;
        Xl = Xr;
        Xr = temp;
        Xr = Xr ^ ctx.pbox[1];
        Xl = Xl ^ ctx.pbox[0];
        return {
          left: Xl,
          right: Xr
        };
      }

      /**
      * Initialization ctx's pbox and sbox.
      *
      * @param {Object} ctx The object has pbox and sbox.
      * @param {Array} key An array of 32-bit words.
      * @param {int} keysize The length of the key.
      *
      * @example
      *
      *     blowfishInit(BLOWFISH_CTX, key, 128/32);
      */
      function blowfishInit(ctx, key, keysize) {
        for (var Row = 0; Row < 4; Row++) {
          ctx.sbox[Row] = [];
          for (var Col = 0; Col < 256; Col++) {
            ctx.sbox[Row][Col] = ORIG_S[Row][Col];
          }
        }
        var keyIndex = 0;
        for (var index = 0; index < N + 2; index++) {
          ctx.pbox[index] = ORIG_P[index] ^ key[keyIndex];
          keyIndex++;
          if (keyIndex >= keysize) {
            keyIndex = 0;
          }
        }
        var data1 = 0;
        var data2 = 0;
        var res = 0;
        for (var i = 0; i < N + 2; i += 2) {
          res = blowfishEncrypt(ctx, data1, data2);
          data1 = res.left;
          data2 = res.right;
          ctx.pbox[i] = data1;
          ctx.pbox[i + 1] = data2;
        }
        for (var _i = 0; _i < 4; _i++) {
          for (var j = 0; j < 256; j += 2) {
            res = blowfishEncrypt(ctx, data1, data2);
            data1 = res.left;
            data2 = res.right;
            ctx.sbox[_i][j] = data1;
            ctx.sbox[_i][j + 1] = data2;
          }
        }
        return true;
      }

      /**
       * Blowfish block cipher algorithm.
       */
      var BlowfishAlgo = exports('BlowfishAlgo', /*#__PURE__*/function (_BlockCipher) {
        _inheritsLoose(BlowfishAlgo, _BlockCipher);
        function BlowfishAlgo(xformMode, key, cfg) {
          var _this;
          _this = _BlockCipher.call(this, xformMode, key, cfg) || this;

          // blickSize is an instance field and should set in constructor.
          _this.blockSize = 64 / 32;
          return _this;
        }
        var _proto = BlowfishAlgo.prototype;
        _proto._doReset = function _doReset() {
          // Skip reset of nRounds has been set before and key did not change
          if (this._keyPriorReset === this._key) {
            return;
          }

          // Shortcuts
          var key = this._keyPriorReset = this._key;
          var keyWords = key.words;
          var keySize = key.sigBytes / 4;

          //Initialization pbox and sbox
          blowfishInit(blowfishCtx, keyWords, keySize);
        };
        _proto.encryptBlock = function encryptBlock(M, offset) {
          var res = blowfishEncrypt(blowfishCtx, M[offset], M[offset + 1]);
          M[offset] = res.left;
          M[offset + 1] = res.right;
        };
        _proto.decryptBlock = function decryptBlock(M, offset) {
          var res = blowfishDecrypt(blowfishCtx, M[offset], M[offset + 1]);
          M[offset] = res.left;
          M[offset + 1] = res.right;
        };
        return BlowfishAlgo;
      }(BlockCipher));
      BlowfishAlgo.keySize = 128 / 32;
      BlowfishAlgo.ivSize = 64 / 32;
      // blickSize is an instance field and should set in constructor.

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.Blowfish.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.Blowfish.decrypt(ciphertext, key, cfg);
       */
      var Blowfish = exports('Blowfish', BlockCipher._createHelper(BlowfishAlgo));
    }
  };
});

System.register("chunks:///_virtual/cipher-core.js", ['./rollupPluginModLoBabelHelpers.js', './core.js', './enc-base64.js', './evpkdf.js'], function (exports) {
  var _inheritsLoose, Base, BufferedBlockAlgorithm, WordArray, Base64, EvpKDFAlgo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      Base = module.Base;
      BufferedBlockAlgorithm = module.BufferedBlockAlgorithm;
      WordArray = module.WordArray;
    }, function (module) {
      Base64 = module.Base64;
    }, function (module) {
      EvpKDFAlgo = module.EvpKDFAlgo;
    }],
    execute: function () {
      /**
       * Abstract base cipher template.
       *
       * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
       * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
       * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
       * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
       */
      var Cipher = exports('Cipher', /*#__PURE__*/function (_BufferedBlockAlgorit) {
        _inheritsLoose(Cipher, _BufferedBlockAlgorit);
        /**
         * Initializes a newly created cipher.
         *
         * @param {number} xformMode Either the encryption or decryption transormation mode constant.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @example
         *
         *     const cipher = CryptoJS.algo.AES.create(
         *       CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray }
         *     );
         */
        function Cipher(xformMode, key, cfg) {
          var _this;
          _this = _BufferedBlockAlgorit.call(this) || this;

          /**
           * Configuration options.
           *
           * @property {WordArray} iv The IV to use for this operation.
           */
          _this.cfg = Object.assign(new Base(), cfg);

          // Store transform mode and key
          _this._xformMode = xformMode;
          _this._key = key;

          // Set initial values
          _this.reset();
          return _this;
        }

        /**
         * Creates this cipher in encryption mode.
         *
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {Cipher} A cipher instance.
         *
         * @static
         *
         * @example
         *
         *     const cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
         */
        Cipher.createEncryptor = function createEncryptor(key, cfg) {
          return this.create(this._ENC_XFORM_MODE, key, cfg);
        }

        /**
         * Creates this cipher in decryption mode.
         *
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {Cipher} A cipher instance.
         *
         * @static
         *
         * @example
         *
         *     const cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
         */;
        Cipher.createDecryptor = function createDecryptor(key, cfg) {
          return this.create(this._DEC_XFORM_MODE, key, cfg);
        }

        /**
         * Creates shortcut functions to a cipher's object interface.
         *
         * @param {Cipher} cipher The cipher to create a helper for.
         *
         * @return {Object} An object with encrypt and decrypt shortcut functions.
         *
         * @static
         *
         * @example
         *
         *     const AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
         */;
        Cipher._createHelper = function _createHelper(SubCipher) {
          var selectCipherStrategy = function selectCipherStrategy(key) {
            if (typeof key === 'string') {
              return PasswordBasedCipher;
            }
            return SerializableCipher;
          };
          return {
            encrypt: function encrypt(message, key, cfg) {
              return selectCipherStrategy(key).encrypt(SubCipher, message, key, cfg);
            },
            decrypt: function decrypt(ciphertext, key, cfg) {
              return selectCipherStrategy(key).decrypt(SubCipher, ciphertext, key, cfg);
            }
          };
        }

        /**
         * Resets this cipher to its initial state.
         *
         * @example
         *
         *     cipher.reset();
         */;
        var _proto = Cipher.prototype;
        _proto.reset = function reset() {
          // Reset data buffer
          _BufferedBlockAlgorit.prototype.reset.call(this);

          // Perform concrete-cipher logic
          this._doReset();
        }

        /**
         * Adds data to be encrypted or decrypted.
         *
         * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
         *
         * @return {WordArray} The data after processing.
         *
         * @example
         *
         *     const encrypted = cipher.process('data');
         *     const encrypted = cipher.process(wordArray);
         */;
        _proto.process = function process(dataUpdate) {
          // Append
          this._append(dataUpdate);

          // Process available blocks
          return this._process();
        }

        /**
         * Finalizes the encryption or decryption process.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
         *
         * @return {WordArray} The data after final processing.
         *
         * @example
         *
         *     const encrypted = cipher.finalize();
         *     const encrypted = cipher.finalize('data');
         *     const encrypted = cipher.finalize(wordArray);
         */;
        _proto.finalize = function finalize(dataUpdate) {
          // Final data update
          if (dataUpdate) {
            this._append(dataUpdate);
          }

          // Perform concrete-cipher logic
          var finalProcessedData = this._doFinalize();
          return finalProcessedData;
        };
        return Cipher;
      }(BufferedBlockAlgorithm));
      Cipher._ENC_XFORM_MODE = 1;
      Cipher._DEC_XFORM_MODE = 2;
      Cipher.keySize = 128 / 32;
      Cipher.ivSize = 128 / 32;

      /**
       * Abstract base stream cipher template.
       *
       * @property {number} blockSize
       *
       *     The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
       */
      var StreamCipher = exports('StreamCipher', /*#__PURE__*/function (_Cipher) {
        _inheritsLoose(StreamCipher, _Cipher);
        function StreamCipher() {
          var _this2;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this2 = _Cipher.call.apply(_Cipher, [this].concat(args)) || this;
          _this2.blockSize = 1;
          return _this2;
        }
        var _proto2 = StreamCipher.prototype;
        _proto2._doFinalize = function _doFinalize() {
          // Process partial blocks
          var finalProcessedBlocks = this._process(!!'flush');
          return finalProcessedBlocks;
        };
        return StreamCipher;
      }(Cipher));

      /**
       * Abstract base block cipher mode template.
       */
      var BlockCipherMode = exports('BlockCipherMode', /*#__PURE__*/function (_Base) {
        _inheritsLoose(BlockCipherMode, _Base);
        /**
         * Initializes a newly created mode.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @example
         *
         *     const mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
         */
        function BlockCipherMode(cipher, iv) {
          var _this3;
          _this3 = _Base.call(this) || this;
          _this3._cipher = cipher;
          _this3._iv = iv;
          return _this3;
        }

        /**
         * Creates this mode for encryption.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @static
         *
         * @example
         *
         *     const mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
         */
        BlockCipherMode.createEncryptor = function createEncryptor(cipher, iv) {
          return this.Encryptor.create(cipher, iv);
        }

        /**
         * Creates this mode for decryption.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @static
         *
         * @example
         *
         *     const mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
         */;
        BlockCipherMode.createDecryptor = function createDecryptor(cipher, iv) {
          return this.Decryptor.create(cipher, iv);
        };
        return BlockCipherMode;
      }(Base));
      function xorBlock(words, offset, blockSize) {
        var _words = words;
        var block;

        // Shortcut
        var iv = this._iv;

        // Choose mixing block
        if (iv) {
          block = iv;

          // Remove IV for subsequent blocks
          this._iv = undefined;
        } else {
          block = this._prevBlock;
        }

        // XOR blocks
        for (var i = 0; i < blockSize; i += 1) {
          _words[offset + i] ^= block[i];
        }
      }

      /**
       * Cipher Block Chaining mode.
       */

      /**
       * Abstract base CBC mode.
       */
      var CBC = exports('CBC', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(CBC, _BlockCipherMode);
        function CBC() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return CBC;
      }(BlockCipherMode));
      /**
       * CBC encryptor.
       */
      CBC.Encryptor = /*#__PURE__*/function (_CBC) {
        _inheritsLoose(_class, _CBC);
        function _class() {
          return _CBC.apply(this, arguments) || this;
        }
        var _proto3 = _class.prototype;
        /**
         * Processes the data block at offset.
         *
         * @param {Array} words The data words to operate on.
         * @param {number} offset The offset where the block starts.
         *
         * @example
         *
         *     mode.processBlock(data.words, offset);
         */
        _proto3.processBlock = function processBlock(words, offset) {
          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;

          // XOR and encrypt
          xorBlock.call(this, words, offset, blockSize);
          cipher.encryptBlock(words, offset);

          // Remember this block to use with next block
          this._prevBlock = words.slice(offset, offset + blockSize);
        };
        return _class;
      }(CBC);
      /**
       * CBC decryptor.
       */
      CBC.Decryptor = /*#__PURE__*/function (_CBC2) {
        _inheritsLoose(_class2, _CBC2);
        function _class2() {
          return _CBC2.apply(this, arguments) || this;
        }
        var _proto4 = _class2.prototype;
        /**
         * Processes the data block at offset.
         *
         * @param {Array} words The data words to operate on.
         * @param {number} offset The offset where the block starts.
         *
         * @example
         *
         *     mode.processBlock(data.words, offset);
         */
        _proto4.processBlock = function processBlock(words, offset) {
          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;

          // Remember this block to use with next block
          var thisBlock = words.slice(offset, offset + blockSize);

          // Decrypt and XOR
          cipher.decryptBlock(words, offset);
          xorBlock.call(this, words, offset, blockSize);

          // This block becomes the previous block
          this._prevBlock = thisBlock;
        };
        return _class2;
      }(CBC);

      /**
       * PKCS #5/7 padding strategy.
       */
      var Pkcs7 = exports('Pkcs7', {
        /**
         * Pads data using the algorithm defined in PKCS #5/7.
         *
         * @param {WordArray} data The data to pad.
         * @param {number} blockSize The multiple that the data should be padded to.
         *
         * @static
         *
         * @example
         *
         *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
         */
        pad: function pad(data, blockSize) {
          // Shortcut
          var blockSizeBytes = blockSize * 4;

          // Count padding bytes
          var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

          // Create padding word
          var paddingWord = nPaddingBytes << 24 | nPaddingBytes << 16 | nPaddingBytes << 8 | nPaddingBytes;

          // Create padding
          var paddingWords = [];
          for (var i = 0; i < nPaddingBytes; i += 4) {
            paddingWords.push(paddingWord);
          }
          var padding = WordArray.create(paddingWords, nPaddingBytes);

          // Add padding
          data.concat(padding);
        },
        /**
         * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
         *
         * @param {WordArray} data The data to unpad.
         *
         * @static
         *
         * @example
         *
         *     CryptoJS.pad.Pkcs7.unpad(wordArray);
         */
        unpad: function unpad(data) {
          var _data = data;

          // Get number of padding bytes from last byte
          var nPaddingBytes = _data.words[_data.sigBytes - 1 >>> 2] & 0xff;

          // Remove padding
          _data.sigBytes -= nPaddingBytes;
        }
      });

      /**
       * Abstract base block cipher template.
       *
       * @property {number} blockSize
       *
       *    The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
       */
      var BlockCipher = exports('BlockCipher', /*#__PURE__*/function (_Cipher2) {
        _inheritsLoose(BlockCipher, _Cipher2);
        function BlockCipher(xformMode, key, cfg) {
          var _this4;
          /**
           * Configuration options.
           *
           * @property {Mode} mode The block mode to use. Default: CBC
           * @property {Padding} padding The padding strategy to use. Default: Pkcs7
           */
          _this4 = _Cipher2.call(this, xformMode, key, Object.assign({
            mode: CBC,
            padding: Pkcs7
          }, cfg)) || this;
          _this4.blockSize = 128 / 32;
          return _this4;
        }
        var _proto5 = BlockCipher.prototype;
        _proto5.reset = function reset() {
          var modeCreator;

          // Reset cipher
          _Cipher2.prototype.reset.call(this);

          // Shortcuts
          var cfg = this.cfg;
          var iv = cfg.iv,
            mode = cfg.mode;

          // Reset block mode
          if (this._xformMode === this.constructor._ENC_XFORM_MODE) {
            modeCreator = mode.createEncryptor;
          } else /* if (this._xformMode == this._DEC_XFORM_MODE) */{
              modeCreator = mode.createDecryptor;
              // Keep at least one block in the buffer for unpadding
              this._minBufferSize = 1;
            }
          this._mode = modeCreator.call(mode, this, iv && iv.words);
          this._mode.__creator = modeCreator;
        };
        _proto5._doProcessBlock = function _doProcessBlock(words, offset) {
          this._mode.processBlock(words, offset);
        };
        _proto5._doFinalize = function _doFinalize() {
          var finalProcessedBlocks;

          // Shortcut
          var padding = this.cfg.padding;

          // Finalize
          if (this._xformMode === this.constructor._ENC_XFORM_MODE) {
            // Pad data
            padding.pad(this._data, this.blockSize);

            // Process final blocks
            finalProcessedBlocks = this._process(!!'flush');
          } else /* if (this._xformMode == this._DEC_XFORM_MODE) */{
              // Process final blocks
              finalProcessedBlocks = this._process(!!'flush');

              // Unpad data
              padding.unpad(finalProcessedBlocks);
            }
          return finalProcessedBlocks;
        };
        return BlockCipher;
      }(Cipher));

      /**
       * A collection of cipher parameters.
       *
       * @property {WordArray} ciphertext The raw ciphertext.
       * @property {WordArray} key The key to this ciphertext.
       * @property {WordArray} iv The IV used in the ciphering operation.
       * @property {WordArray} salt The salt used with a key derivation function.
       * @property {Cipher} algorithm The cipher algorithm.
       * @property {Mode} mode The block mode used in the ciphering operation.
       * @property {Padding} padding The padding scheme used in the ciphering operation.
       * @property {number} blockSize The block size of the cipher.
       * @property {Format} formatter
       *    The default formatting strategy to convert this cipher params object to a string.
       */
      var CipherParams = exports('CipherParams', /*#__PURE__*/function (_Base2) {
        _inheritsLoose(CipherParams, _Base2);
        /**
         * Initializes a newly created cipher params object.
         *
         * @param {Object} cipherParams An object with any of the possible cipher parameters.
         *
         * @example
         *
         *     var cipherParams = CryptoJS.lib.CipherParams.create({
         *         ciphertext: ciphertextWordArray,
         *         key: keyWordArray,
         *         iv: ivWordArray,
         *         salt: saltWordArray,
         *         algorithm: CryptoJS.algo.AES,
         *         mode: CryptoJS.mode.CBC,
         *         padding: CryptoJS.pad.PKCS7,
         *         blockSize: 4,
         *         formatter: CryptoJS.format.OpenSSL
         *     });
         */
        function CipherParams(cipherParams) {
          var _this5;
          _this5 = _Base2.call(this) || this;
          _this5.mixIn(cipherParams);
          return _this5;
        }

        /**
         * Converts this cipher params object to a string.
         *
         * @param {Format} formatter (Optional) The formatting strategy to use.
         *
         * @return {string} The stringified cipher params.
         *
         * @throws Error If neither the formatter nor the default formatter is set.
         *
         * @example
         *
         *     var string = cipherParams + '';
         *     var string = cipherParams.toString();
         *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
         */
        var _proto6 = CipherParams.prototype;
        _proto6.toString = function toString(formatter) {
          return (formatter || this.formatter).stringify(this);
        };
        return CipherParams;
      }(Base));

      /**
       * OpenSSL formatting strategy.
       */
      var OpenSSLFormatter = exports('OpenSSLFormatter', {
        /**
         * Converts a cipher params object to an OpenSSL-compatible string.
         *
         * @param {CipherParams} cipherParams The cipher params object.
         *
         * @return {string} The OpenSSL-compatible string.
         *
         * @static
         *
         * @example
         *
         *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
         */
        stringify: function stringify(cipherParams) {
          var wordArray;

          // Shortcuts
          var ciphertext = cipherParams.ciphertext,
            salt = cipherParams.salt;

          // Format
          if (salt) {
            wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
          } else {
            wordArray = ciphertext;
          }
          return wordArray.toString(Base64);
        },
        /**
         * Converts an OpenSSL-compatible string to a cipher params object.
         *
         * @param {string} openSSLStr The OpenSSL-compatible string.
         *
         * @return {CipherParams} The cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
         */
        parse: function parse(openSSLStr) {
          var salt;

          // Parse base64
          var ciphertext = Base64.parse(openSSLStr);

          // Shortcut
          var ciphertextWords = ciphertext.words;

          // Test for salt
          if (ciphertextWords[0] === 0x53616c74 && ciphertextWords[1] === 0x65645f5f) {
            // Extract salt
            salt = WordArray.create(ciphertextWords.slice(2, 4));

            // Remove salt from ciphertext
            ciphertextWords.splice(0, 4);
            ciphertext.sigBytes -= 16;
          }
          return CipherParams.create({
            ciphertext: ciphertext,
            salt: salt
          });
        }
      });

      /**
       * A cipher wrapper that returns ciphertext as a serializable cipher params object.
       */
      var SerializableCipher = exports('SerializableCipher', /*#__PURE__*/function (_Base3) {
        _inheritsLoose(SerializableCipher, _Base3);
        function SerializableCipher() {
          return _Base3.apply(this, arguments) || this;
        }
        /**
         * Encrypts a message.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {WordArray|string} message The message to encrypt.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {CipherParams} A cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       .encrypt(CryptoJS.algo.AES, message, key);
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       .encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       .encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
         */
        SerializableCipher.encrypt = function encrypt(cipher, message, key, cfg) {
          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Encrypt
          var encryptor = cipher.createEncryptor(key, _cfg);
          var ciphertext = encryptor.finalize(message);

          // Shortcut
          var cipherCfg = encryptor.cfg;

          // Create and return serializable cipher params
          return CipherParams.create({
            ciphertext: ciphertext,
            key: key,
            iv: cipherCfg.iv,
            algorithm: cipher,
            mode: cipherCfg.mode,
            padding: cipherCfg.padding,
            blockSize: encryptor.blockSize,
            formatter: _cfg.format
          });
        }

        /**
         * Decrypts serialized ciphertext.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {WordArray} The plaintext.
         *
         * @static
         *
         * @example
         *
         *     var plaintext = CryptoJS.lib.SerializableCipher
         *       .decrypt(CryptoJS.algo.AES, formattedCiphertext, key,
         *         { iv: iv, format: CryptoJS.format.OpenSSL });
         *     var plaintext = CryptoJS.lib.SerializableCipher
         *       .decrypt(CryptoJS.algo.AES, ciphertextParams, key,
         *         { iv: iv, format: CryptoJS.format.OpenSSL });
         */;
        SerializableCipher.decrypt = function decrypt(cipher, ciphertext, key, cfg) {
          var _ciphertext = ciphertext;

          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Convert string to CipherParams
          _ciphertext = this._parse(_ciphertext, _cfg.format);

          // Decrypt
          var plaintext = cipher.createDecryptor(key, _cfg).finalize(_ciphertext.ciphertext);
          return plaintext;
        }

        /**
         * Converts serialized ciphertext to CipherParams,
         * else assumed CipherParams already and returns ciphertext unchanged.
         *
         * @param {CipherParams|string} ciphertext The ciphertext.
         * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
         *
         * @return {CipherParams} The unserialized ciphertext.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       ._parse(ciphertextStringOrParams, format);
         */;
        SerializableCipher._parse = function _parse(ciphertext, format) {
          if (typeof ciphertext === 'string') {
            return format.parse(ciphertext, this);
          }
          return ciphertext;
        };
        return SerializableCipher;
      }(Base));
      /**
       * Configuration options.
       *
       * @property {Formatter} format
       *
       *    The formatting strategy to convert cipher param objects to and from a string.
       *    Default: OpenSSL
       */
      SerializableCipher.cfg = Object.assign(new Base(), {
        format: OpenSSLFormatter
      });

      /**
       * OpenSSL key derivation function.
       */
      var OpenSSLKdf = exports('OpenSSLKdf', {
        /**
         * Derives a key and IV from a password.
         *
         * @param {string} password The password to derive from.
         * @param {number} keySize The size in words of the key to generate.
         * @param {number} ivSize The size in words of the IV to generate.
         * @param {WordArray|string} salt
         *     (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
         *
         * @return {CipherParams} A cipher params object with the key, IV, and salt.
         *
         * @static
         *
         * @example
         *
         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
         */
        execute: function execute(password, keySize, ivSize, salt, hasher) {
          var _salt = salt;

          // Generate random salt
          if (!_salt) {
            _salt = WordArray.random(64 / 8);
          }

          // Derive key and IV
          var key;
          if (!hasher) {
            key = EvpKDFAlgo.create({
              keySize: keySize + ivSize
            }).compute(password, _salt);
          } else {
            key = EvpKDFAlgo.create({
              keySize: keySize + ivSize,
              hasher: hasher
            }).compute(password, _salt);
          }

          // Separate key and IV
          var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
          key.sigBytes = keySize * 4;

          // Return params
          return CipherParams.create({
            key: key,
            iv: iv,
            salt: _salt
          });
        }
      });

      /**
       * A serializable cipher wrapper that derives the key from a password,
       * and returns ciphertext as a serializable cipher params object.
       */
      var PasswordBasedCipher = exports('PasswordBasedCipher', /*#__PURE__*/function (_SerializableCipher) {
        _inheritsLoose(PasswordBasedCipher, _SerializableCipher);
        function PasswordBasedCipher() {
          return _SerializableCipher.apply(this, arguments) || this;
        }
        /**
         * Encrypts a message using a password.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {WordArray|string} message The message to encrypt.
         * @param {string} password The password.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {CipherParams} A cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher
         *       .encrypt(CryptoJS.algo.AES, message, 'password');
         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher
         *       .encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
         */
        PasswordBasedCipher.encrypt = function encrypt(cipher, message, password, cfg) {
          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Derive key and other params
          var derivedParams = _cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, _cfg.salt, _cfg.hasher);

          // Add IV to config
          _cfg.iv = derivedParams.iv;

          // Encrypt
          var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, _cfg);

          // Mix in derived params
          ciphertext.mixIn(derivedParams);
          return ciphertext;
        }

        /**
         * Decrypts serialized ciphertext using a password.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
         * @param {string} password The password.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {WordArray} The plaintext.
         *
         * @static
         *
         * @example
         *
         *     var plaintext = CryptoJS.lib.PasswordBasedCipher
         *       .decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password',
         *         { format: CryptoJS.format.OpenSSL });
         *     var plaintext = CryptoJS.lib.PasswordBasedCipher
         *       .decrypt(CryptoJS.algo.AES, ciphertextParams, 'password',
         *         { format: CryptoJS.format.OpenSSL });
         */;
        PasswordBasedCipher.decrypt = function decrypt(cipher, ciphertext, password, cfg) {
          var _ciphertext = ciphertext;

          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Convert string to CipherParams
          _ciphertext = this._parse(_ciphertext, _cfg.format);

          // Derive key and other params
          var derivedParams = _cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, _ciphertext.salt, _cfg.hasher);

          // Add IV to config
          _cfg.iv = derivedParams.iv;

          // Decrypt
          var plaintext = SerializableCipher.decrypt.call(this, cipher, _ciphertext, derivedParams.key, _cfg);
          return plaintext;
        };
        return PasswordBasedCipher;
      }(SerializableCipher));
      /**
       * Configuration options.
       *
       * @property {KDF} kdf
       *     The key derivation function to use to generate a key and IV from a password.
       *     Default: OpenSSL
       */
      PasswordBasedCipher.cfg = Object.assign(SerializableCipher.cfg, {
        kdf: OpenSSLKdf
      });
    }
  };
});

System.register("chunks:///_virtual/cjs-loader.mjs", [], function (exports) {
  return {
    execute: function () {
      var CjsLoader = /*#__PURE__*/function () {
        function CjsLoader() {
          this._registry = {};
          this._moduleCache = {};
        }

        /**
         * Defines a CommonJS module.
         * @param id Module ID.
         * @param factory The factory.
         * @param resolveMap An object or a function returning object which records the module specifier resolve result.
         * The later is called as "deferred resolve map" and would be invocated right before CommonJS code execution.
         */
        var _proto = CjsLoader.prototype;
        _proto.define = function define(id, factory, resolveMap) {
          this._registry[id] = {
            factory: factory,
            resolveMap: resolveMap
          };
        }

        /**
         * Requires a CommonJS module.
         * @param id Module ID.
         * @returns The module's `module.exports`.
         */;
        _proto.require = function require(id) {
          return this._require(id);
        };
        _proto.throwInvalidWrapper = function throwInvalidWrapper(requestTarget, from) {
          throw new Error("Module '" + requestTarget + "' imported from '" + from + "' is expected be an ESM-wrapped CommonJS module but it doesn't.");
        };
        _proto._require = function _require(id, parent) {
          var cachedModule = this._moduleCache[id];
          if (cachedModule) {
            return cachedModule.exports;
          }
          var module = {
            id: id,
            exports: {}
          };
          this._moduleCache[id] = module;
          this._tryModuleLoad(module, id);
          return module.exports;
        };
        _proto._resolve = function _resolve(specifier, parent) {
          return this._resolveFromInfos(specifier, parent) || this._throwUnresolved(specifier, parent);
        };
        _proto._resolveFromInfos = function _resolveFromInfos(specifier, parent) {
          var _cjsInfos$parent$reso, _cjsInfos$parent;
          if (specifier in cjsInfos) {
            return specifier;
          }
          if (!parent) {
            return;
          }
          return (_cjsInfos$parent$reso = (_cjsInfos$parent = cjsInfos[parent]) == null ? void 0 : _cjsInfos$parent.resolveCache[specifier]) != null ? _cjsInfos$parent$reso : undefined;
        };
        _proto._tryModuleLoad = function _tryModuleLoad(module, id) {
          var threw = true;
          try {
            this._load(module, id);
            threw = false;
          } finally {
            if (threw) {
              delete this._moduleCache[id];
            }
          }
        };
        _proto._load = function _load(module, id) {
          var _this$_loadWrapper = this._loadWrapper(id),
            factory = _this$_loadWrapper.factory,
            resolveMap = _this$_loadWrapper.resolveMap;
          var vendorRequire = this._createRequire(module);
          var require = resolveMap ? this._createRequireWithResolveMap(typeof resolveMap === 'function' ? resolveMap() : resolveMap, vendorRequire) : vendorRequire;
          factory(module.exports, require, module);
        };
        _proto._loadWrapper = function _loadWrapper(id) {
          if (id in this._registry) {
            return this._registry[id];
          } else {
            return this._loadHostProvidedModules(id);
          }
        };
        _proto._loadHostProvidedModules = function _loadHostProvidedModules(id) {
          return {
            factory: function factory(_exports, _require, module) {
              if (typeof require === 'undefined') {
                throw new Error("Current environment does not provide a require() for requiring '" + id + "'.");
              }
              try {
                module.exports = require(id);
              } catch (err) {
                throw new Error("Exception thrown when calling host defined require('" + id + "').", {
                  cause: err
                });
              }
            }
          };
        };
        _proto._createRequire = function _createRequire(module) {
          var _this = this;
          return function (specifier) {
            return _this._require(specifier, module);
          };
        };
        _proto._createRequireWithResolveMap = function _createRequireWithResolveMap(requireMap, originalRequire) {
          return function (specifier) {
            var resolved = requireMap[specifier];
            if (resolved) {
              return originalRequire(resolved);
            } else {
              throw new Error('Unresolved specifier ' + specifier);
            }
          };
        };
        _proto._throwUnresolved = function _throwUnresolved(specifier, parentUrl) {
          throw new Error("Unable to resolve " + specifier + " from " + parent + ".");
        };
        return CjsLoader;
      }();
      var loader = exports('default', new CjsLoader());
    }
  };
});

System.register("chunks:///_virtual/core.js", ['./rollupPluginModLoBabelHelpers.js'], function (exports) {
  var _inheritsLoose, _construct;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _construct = module.construct;
    }],
    execute: function () {
      var _ref, _ref2, _ref3, _ref4, _ref5;
      /* eslint-disable no-use-before-define */

      var crypto = ((_ref = typeof globalThis != 'undefined' ? globalThis : void 0) == null ? void 0 : _ref.crypto) || ((_ref2 = typeof global != 'undefined' ? global : void 0) == null ? void 0 : _ref2.crypto) || ((_ref3 = typeof window != 'undefined' ? window : void 0) == null ? void 0 : _ref3.crypto) || ((_ref4 = typeof self != 'undefined' ? self : void 0) == null ? void 0 : _ref4.crypto) || ((_ref5 = typeof frames != 'undefined' ? frames : void 0) == null || (_ref5 = _ref5[0]) == null ? void 0 : _ref5.crypto);
      var randomWordArray;
      if (crypto) {
        randomWordArray = function randomWordArray(nBytes) {
          var words = [];
          for (var i = 0; i < nBytes; i += 4) {
            words.push(crypto.getRandomValues(new Uint32Array(1))[0]);
          }
          return new WordArray(words, nBytes);
        };
      } else {
        // Because there is no global crypto property in this context, cryptographically unsafe Math.random() is used.

        randomWordArray = function randomWordArray(nBytes) {
          var words = [];
          var r = function r(m_w) {
            var _m_w = m_w;
            var _m_z = 0x3ade68b1;
            var mask = 0xffffffff;
            return function () {
              _m_z = 0x9069 * (_m_z & 0xFFFF) + (_m_z >> 0x10) & mask;
              _m_w = 0x4650 * (_m_w & 0xFFFF) + (_m_w >> 0x10) & mask;
              var result = (_m_z << 0x10) + _m_w & mask;
              result /= 0x100000000;
              result += 0.5;
              return result * (Math.random() > 0.5 ? 1 : -1);
            };
          };
          for (var i = 0, rcache; i < nBytes; i += 4) {
            var _r = r((rcache || Math.random()) * 0x100000000);
            rcache = _r() * 0x3ade67b7;
            words.push(_r() * 0x100000000 | 0);
          }
          return new WordArray(words, nBytes);
        };
      }

      /**
       * Base class for inheritance.
       */
      var Base = exports('Base', /*#__PURE__*/function () {
        function Base() {}
        /**
         * Extends this object and runs the init method.
         * Arguments to create() will be passed to init().
         *
         * @return {Object} The new object.
         *
         * @static
         *
         * @example
         *
         *     var instance = MyType.create();
         */
        Base.create = function create() {
          for (var _len = arguments.length, args = new Array(_len), _key2 = 0; _key2 < _len; _key2++) {
            args[_key2] = arguments[_key2];
          }
          return _construct(this, args);
        }

        /**
         * Copies properties into this object.
         *
         * @param {Object} properties The properties to mix in.
         *
         * @example
         *
         *     MyType.mixIn({
         *         field: 'value'
         *     });
         */;
        var _proto = Base.prototype;
        _proto.mixIn = function mixIn(properties) {
          return Object.assign(this, properties);
        }

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = instance.clone();
         */;
        _proto.clone = function clone() {
          var clone = new this.constructor();
          Object.assign(clone, this);
          return clone;
        };
        return Base;
      }());

      /**
       * An array of 32-bit words.
       *
       * @property {Array} words The array of 32-bit words.
       * @property {number} sigBytes The number of significant bytes in this word array.
       */
      var WordArray = exports('WordArray', /*#__PURE__*/function (_Base) {
        _inheritsLoose(WordArray, _Base);
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of 32-bit words.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.create();
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
         */
        function WordArray(words, sigBytes) {
          var _this;
          if (words === void 0) {
            words = [];
          }
          if (sigBytes === void 0) {
            sigBytes = words.length * 4;
          }
          _this = _Base.call(this) || this;
          var typedArray = words;
          // Convert buffers to uint8
          if (typedArray instanceof ArrayBuffer) {
            typedArray = new Uint8Array(typedArray);
          }

          // Convert other array views to uint8
          if (typedArray instanceof Int8Array || typedArray instanceof Uint8ClampedArray || typedArray instanceof Int16Array || typedArray instanceof Uint16Array || typedArray instanceof Int32Array || typedArray instanceof Uint32Array || typedArray instanceof Float32Array || typedArray instanceof Float64Array) {
            typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
          }

          // Handle Uint8Array
          if (typedArray instanceof Uint8Array) {
            // Shortcut
            var typedArrayByteLength = typedArray.byteLength;

            // Extract bytes
            var _words = [];
            for (var i = 0; i < typedArrayByteLength; i += 1) {
              _words[i >>> 2] |= typedArray[i] << 24 - i % 4 * 8;
            }

            // Initialize this word array
            _this.words = _words;
            _this.sigBytes = typedArrayByteLength;
          } else {
            // Else call normal init
            _this.words = words;
            _this.sigBytes = sigBytes;
          }
          return _this;
        }

        /**
         * Creates a word array filled with random bytes.
         *
         * @param {number} nBytes The number of random bytes to generate.
         *
         * @return {WordArray} The random word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.random(16);
         */
        var _proto2 = WordArray.prototype;
        /**
         * Converts this word array to a string.
         *
         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
         *
         * @return {string} The stringified word array.
         *
         * @example
         *
         *     var string = wordArray + '';
         *     var string = wordArray.toString();
         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
         */
        _proto2.toString = function toString(encoder) {
          if (encoder === void 0) {
            encoder = Hex;
          }
          return encoder.stringify(this);
        }

        /**
         * Concatenates a word array to this word array.
         *
         * @param {WordArray} wordArray The word array to append.
         *
         * @return {WordArray} This word array.
         *
         * @example
         *
         *     wordArray1.concat(wordArray2);
         */;
        _proto2.concat = function concat(wordArray) {
          // Shortcuts
          var thisWords = this.words;
          var thatWords = wordArray.words;
          var thisSigBytes = this.sigBytes;
          var thatSigBytes = wordArray.sigBytes;

          // Clamp excess bits
          this.clamp();

          // Concat
          if (thisSigBytes % 4) {
            // Copy one byte at a time
            for (var i = 0; i < thatSigBytes; i += 1) {
              var thatByte = thatWords[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
              thisWords[thisSigBytes + i >>> 2] |= thatByte << 24 - (thisSigBytes + i) % 4 * 8;
            }
          } else {
            // Copy one word at a time
            for (var _i = 0; _i < thatSigBytes; _i += 4) {
              thisWords[thisSigBytes + _i >>> 2] = thatWords[_i >>> 2];
            }
          }
          this.sigBytes += thatSigBytes;

          // Chainable
          return this;
        }

        /**
         * Removes insignificant bits.
         *
         * @example
         *
         *     wordArray.clamp();
         */;
        _proto2.clamp = function clamp() {
          // Shortcuts
          var words = this.words,
            sigBytes = this.sigBytes;

          // Clamp
          words[sigBytes >>> 2] &= 0xffffffff << 32 - sigBytes % 4 * 8;
          words.length = Math.ceil(sigBytes / 4);
        }

        /**
         * Creates a copy of this word array.
         *
         * @return {WordArray} The clone.
         *
         * @example
         *
         *     var clone = wordArray.clone();
         */;
        _proto2.clone = function clone() {
          var clone = _Base.prototype.clone.call(this);
          clone.words = this.words.slice(0);
          return clone;
        };
        return WordArray;
      }(Base));

      /**
       * Hex encoding strategy.
       */
      WordArray.random = randomWordArray;
      var Hex = exports('Hex', {
        /**
         * Converts a word array to a hex string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The hex string.
         *
         * @static
         *
         * @example
         *
         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;

          // Convert
          var hexChars = [];
          for (var i = 0; i < sigBytes; i += 1) {
            var bite = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            hexChars.push((bite >>> 4).toString(16));
            hexChars.push((bite & 0x0f).toString(16));
          }
          return hexChars.join('');
        },
        /**
         * Converts a hex string to a word array.
         *
         * @param {string} hexStr The hex string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
         */
        parse: function parse(hexStr) {
          // Shortcut
          var hexStrLength = hexStr.length;

          // Convert
          var words = [];
          for (var i = 0; i < hexStrLength; i += 2) {
            words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << 24 - i % 8 * 4;
          }
          return new WordArray(words, hexStrLength / 2);
        }
      });

      /**
       * Latin1 encoding strategy.
       */
      var Latin1 = exports('Latin1', {
        /**
         * Converts a word array to a Latin1 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Latin1 string.
         *
         * @static
         *
         * @example
         *
         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;

          // Convert
          var latin1Chars = [];
          for (var i = 0; i < sigBytes; i += 1) {
            var bite = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            latin1Chars.push(String.fromCharCode(bite));
          }
          return latin1Chars.join('');
        },
        /**
         * Converts a Latin1 string to a word array.
         *
         * @param {string} latin1Str The Latin1 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
         */
        parse: function parse(latin1Str) {
          // Shortcut
          var latin1StrLength = latin1Str.length;

          // Convert
          var words = [];
          for (var i = 0; i < latin1StrLength; i += 1) {
            words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << 24 - i % 4 * 8;
          }
          return new WordArray(words, latin1StrLength);
        }
      });

      /**
       * UTF-8 encoding strategy.
       */
      var Utf8 = exports('Utf8', {
        /**
         * Converts a word array to a UTF-8 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-8 string.
         *
         * @static
         *
         * @example
         *
         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          try {
            return decodeURIComponent(escape(Latin1.stringify(wordArray)));
          } catch (e) {
            throw new Error('Malformed UTF-8 data');
          }
        },
        /**
         * Converts a UTF-8 string to a word array.
         *
         * @param {string} utf8Str The UTF-8 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
         */
        parse: function parse(utf8Str) {
          return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
        }
      });

      /**
       * Abstract buffered block algorithm template.
       *
       * The property blockSize must be implemented in a concrete subtype.
       *
       * @property {number} _minBufferSize
       *
       *     The number of blocks that should be kept unprocessed in the buffer. Default: 0
       */
      var BufferedBlockAlgorithm = exports('BufferedBlockAlgorithm', /*#__PURE__*/function (_Base2) {
        _inheritsLoose(BufferedBlockAlgorithm, _Base2);
        function BufferedBlockAlgorithm() {
          var _this2;
          _this2 = _Base2.call(this) || this;
          _this2._minBufferSize = 0;
          return _this2;
        }

        /**
         * Resets this block algorithm's data buffer to its initial state.
         *
         * @example
         *
         *     bufferedBlockAlgorithm.reset();
         */
        var _proto3 = BufferedBlockAlgorithm.prototype;
        _proto3.reset = function reset() {
          // Initial values
          this._data = new WordArray();
          this._nDataBytes = 0;
        }

        /**
         * Adds new data to this block algorithm's buffer.
         *
         * @param {WordArray|string} data
         *
         *     The data to append. Strings are converted to a WordArray using UTF-8.
         *
         * @example
         *
         *     bufferedBlockAlgorithm._append('data');
         *     bufferedBlockAlgorithm._append(wordArray);
         */;
        _proto3._append = function _append(data) {
          var m_data = data;

          // Convert string to WordArray, else assume WordArray already
          if (typeof m_data === 'string') {
            m_data = Utf8.parse(m_data);
          }

          // Append
          this._data.concat(m_data);
          this._nDataBytes += m_data.sigBytes;
        }

        /**
         * Processes available data blocks.
         *
         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
         *
         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
         *
         * @return {WordArray} The processed data.
         *
         * @example
         *
         *     var processedData = bufferedBlockAlgorithm._process();
         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
         */;
        _proto3._process = function _process(doFlush) {
          var processedWords;

          // Shortcuts
          var data = this._data,
            blockSize = this.blockSize;
          var dataWords = data.words;
          var dataSigBytes = data.sigBytes;
          var blockSizeBytes = blockSize * 4;

          // Count blocks ready
          var nBlocksReady = dataSigBytes / blockSizeBytes;
          if (doFlush) {
            // Round up to include partial blocks
            nBlocksReady = Math.ceil(nBlocksReady);
          } else {
            // Round down to include only full blocks,
            // less the number of blocks that must remain in the buffer
            nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
          }

          // Count words ready
          var nWordsReady = nBlocksReady * blockSize;

          // Count bytes ready
          var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

          // Process blocks
          if (nWordsReady) {
            for (var offset = 0; offset < nWordsReady; offset += blockSize) {
              // Perform concrete-algorithm logic
              this._doProcessBlock(dataWords, offset);
            }

            // Remove processed words
            processedWords = dataWords.splice(0, nWordsReady);
            data.sigBytes -= nBytesReady;
          }

          // Return processed words
          return new WordArray(processedWords, nBytesReady);
        }

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = bufferedBlockAlgorithm.clone();
         */;
        _proto3.clone = function clone() {
          var clone = _Base2.prototype.clone.call(this);
          clone._data = this._data.clone();
          return clone;
        };
        return BufferedBlockAlgorithm;
      }(Base));

      /**
       * Abstract hasher template.
       *
       * @property {number} blockSize
       *
       *     The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
       */
      var Hasher = exports('Hasher', /*#__PURE__*/function (_BufferedBlockAlgorit) {
        _inheritsLoose(Hasher, _BufferedBlockAlgorit);
        function Hasher(cfg) {
          var _this3;
          _this3 = _BufferedBlockAlgorit.call(this) || this;
          _this3.blockSize = 512 / 32;

          /**
           * Configuration options.
           */
          _this3.cfg = Object.assign(new Base(), cfg);

          // Set initial values
          _this3.reset();
          return _this3;
        }

        /**
         * Creates a shortcut function to a hasher's object interface.
         *
         * @param {Hasher} SubHasher The hasher to create a helper for.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
         */
        Hasher._createHelper = function _createHelper(SubHasher) {
          return function (message, cfg) {
            return new SubHasher(cfg).finalize(message);
          };
        }

        /**
         * Creates a shortcut function to the HMAC's object interface.
         *
         * @param {Hasher} SubHasher The hasher to use in this HMAC helper.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
         */;
        Hasher._createHmacHelper = function _createHmacHelper(SubHasher) {
          return function (message, key) {
            return new HMAC(SubHasher, key).finalize(message);
          };
        }

        /**
         * Resets this hasher to its initial state.
         *
         * @example
         *
         *     hasher.reset();
         */;
        var _proto4 = Hasher.prototype;
        _proto4.reset = function reset() {
          // Reset data buffer
          _BufferedBlockAlgorit.prototype.reset.call(this);

          // Perform concrete-hasher logic
          this._doReset();
        }

        /**
         * Updates this hasher with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {Hasher} This hasher.
         *
         * @example
         *
         *     hasher.update('message');
         *     hasher.update(wordArray);
         */;
        _proto4.update = function update(messageUpdate) {
          // Append
          this._append(messageUpdate);

          // Update the hash
          this._process();

          // Chainable
          return this;
        }

        /**
         * Finalizes the hash computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The hash.
         *
         * @example
         *
         *     var hash = hasher.finalize();
         *     var hash = hasher.finalize('message');
         *     var hash = hasher.finalize(wordArray);
         */;
        _proto4.finalize = function finalize(messageUpdate) {
          // Final message update
          if (messageUpdate) {
            this._append(messageUpdate);
          }

          // Perform concrete-hasher logic
          var hash = this._doFinalize();
          return hash;
        };
        return Hasher;
      }(BufferedBlockAlgorithm));

      /**
       * HMAC algorithm.
       */
      var HMAC = exports('HMAC', /*#__PURE__*/function (_Base3) {
        _inheritsLoose(HMAC, _Base3);
        /**
         * Initializes a newly created HMAC.
         *
         * @param {Hasher} SubHasher The hash algorithm to use.
         * @param {WordArray|string} key The secret key.
         *
         * @example
         *
         *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
         */
        function HMAC(SubHasher, key) {
          var _this4;
          _this4 = _Base3.call(this) || this;
          var hasher = new SubHasher();
          _this4._hasher = hasher;

          // Convert string to WordArray, else assume WordArray already
          var _key = key;
          if (typeof _key === 'string') {
            _key = Utf8.parse(_key);
          }

          // Shortcuts
          var hasherBlockSize = hasher.blockSize;
          var hasherBlockSizeBytes = hasherBlockSize * 4;

          // Allow arbitrary length keys
          if (_key.sigBytes > hasherBlockSizeBytes) {
            _key = hasher.finalize(key);
          }

          // Clamp excess bits
          _key.clamp();

          // Clone key for inner and outer pads
          var oKey = _key.clone();
          _this4._oKey = oKey;
          var iKey = _key.clone();
          _this4._iKey = iKey;

          // Shortcuts
          var oKeyWords = oKey.words;
          var iKeyWords = iKey.words;

          // XOR keys with pad constants
          for (var i = 0; i < hasherBlockSize; i += 1) {
            oKeyWords[i] ^= 0x5c5c5c5c;
            iKeyWords[i] ^= 0x36363636;
          }
          oKey.sigBytes = hasherBlockSizeBytes;
          iKey.sigBytes = hasherBlockSizeBytes;

          // Set initial values
          _this4.reset();
          return _this4;
        }

        /**
         * Resets this HMAC to its initial state.
         *
         * @example
         *
         *     hmacHasher.reset();
         */
        var _proto5 = HMAC.prototype;
        _proto5.reset = function reset() {
          // Shortcut
          var hasher = this._hasher;

          // Reset
          hasher.reset();
          hasher.update(this._iKey);
        }

        /**
         * Updates this HMAC with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {HMAC} This HMAC instance.
         *
         * @example
         *
         *     hmacHasher.update('message');
         *     hmacHasher.update(wordArray);
         */;
        _proto5.update = function update(messageUpdate) {
          this._hasher.update(messageUpdate);

          // Chainable
          return this;
        }

        /**
         * Finalizes the HMAC computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The HMAC.
         *
         * @example
         *
         *     var hmac = hmacHasher.finalize();
         *     var hmac = hmacHasher.finalize('message');
         *     var hmac = hmacHasher.finalize(wordArray);
         */;
        _proto5.finalize = function finalize(messageUpdate) {
          // Shortcut
          var hasher = this._hasher;

          // Compute HMAC
          var innerHash = hasher.finalize(messageUpdate);
          hasher.reset();
          var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));
          return hmac;
        };
        return HMAC;
      }(Base));
    }
  };
});

System.register("chunks:///_virtual/enc-base64.js", ['./core.js'], function (exports) {
  var WordArray;
  return {
    setters: [function (module) {
      WordArray = module.WordArray;
    }],
    execute: function () {
      var parseLoop = exports('parseLoop', function parseLoop(base64Str, base64StrLength, reverseMap) {
        var words = [];
        var nBytes = 0;
        for (var i = 0; i < base64StrLength; i += 1) {
          if (i % 4) {
            var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << i % 4 * 2;
            var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> 6 - i % 4 * 2;
            var bitsCombined = bits1 | bits2;
            words[nBytes >>> 2] |= bitsCombined << 24 - nBytes % 4 * 8;
            nBytes += 1;
          }
        }
        return WordArray.create(words, nBytes);
      });

      /**
       * Base64 encoding strategy.
       */
      var Base64 = exports('Base64', {
        /**
         * Converts a word array to a Base64 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Base64 string.
         *
         * @static
         *
         * @example
         *
         *     const base64String = CryptoJS.enc.Base64.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;
          var map = this._map;

          // Clamp excess bits
          wordArray.clamp();

          // Convert
          var base64Chars = [];
          for (var i = 0; i < sigBytes; i += 3) {
            var byte1 = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            var byte2 = words[i + 1 >>> 2] >>> 24 - (i + 1) % 4 * 8 & 0xff;
            var byte3 = words[i + 2 >>> 2] >>> 24 - (i + 2) % 4 * 8 & 0xff;
            var triplet = byte1 << 16 | byte2 << 8 | byte3;
            for (var j = 0; j < 4 && i + j * 0.75 < sigBytes; j += 1) {
              base64Chars.push(map.charAt(triplet >>> 6 * (3 - j) & 0x3f));
            }
          }

          // Add padding
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            while (base64Chars.length % 4) {
              base64Chars.push(paddingChar);
            }
          }
          return base64Chars.join('');
        },
        /**
         * Converts a Base64 string to a word array.
         *
         * @param {string} base64Str The Base64 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     const wordArray = CryptoJS.enc.Base64.parse(base64String);
         */
        parse: function parse(base64Str) {
          // Shortcuts
          var base64StrLength = base64Str.length;
          var map = this._map;
          var reverseMap = this._reverseMap;
          if (!reverseMap) {
            this._reverseMap = [];
            reverseMap = this._reverseMap;
            for (var j = 0; j < map.length; j += 1) {
              reverseMap[map.charCodeAt(j)] = j;
            }
          }

          // Ignore padding
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            var paddingIndex = base64Str.indexOf(paddingChar);
            if (paddingIndex !== -1) {
              base64StrLength = paddingIndex;
            }
          }

          // Convert
          return parseLoop(base64Str, base64StrLength, reverseMap);
        },
        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
      });
    }
  };
});

System.register("chunks:///_virtual/enc-base64url.js", ['./enc-base64.js'], function (exports) {
  var parseLoop;
  return {
    setters: [function (module) {
      parseLoop = module.parseLoop;
    }],
    execute: function () {
      /**
       * Base64url encoding strategy.
       */
      var Base64url = exports('Base64url', {
        /**
         * Converts a word array to a Base64url string.
         *
         * @param {WordArray} wordArray The word array.
         * 
         * @param {boolean} urlSafe Whether to use url safe.
         *
         * @return {string} The Base64url string.
         *
         * @static
         *
         * @example
         *
         *     const base64String = CryptoJS.enc.Base64.stringify(wordArray);
         */
        stringify: function stringify(wordArray, urlSafe) {
          if (urlSafe === void 0) {
            urlSafe = true;
          }
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;
          var map = urlSafe ? this._safeMap : this._map;

          // Clamp excess bits
          wordArray.clamp();

          // Convert
          var base64Chars = [];
          for (var i = 0; i < sigBytes; i += 3) {
            var byte1 = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            var byte2 = words[i + 1 >>> 2] >>> 24 - (i + 1) % 4 * 8 & 0xff;
            var byte3 = words[i + 2 >>> 2] >>> 24 - (i + 2) % 4 * 8 & 0xff;
            var triplet = byte1 << 16 | byte2 << 8 | byte3;
            for (var j = 0; j < 4 && i + j * 0.75 < sigBytes; j += 1) {
              base64Chars.push(map.charAt(triplet >>> 6 * (3 - j) & 0x3f));
            }
          }

          // Add padding
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            while (base64Chars.length % 4) {
              base64Chars.push(paddingChar);
            }
          }
          return base64Chars.join('');
        },
        /**
         * Converts a Base64url string to a word array.
         *
         * @param {string} base64Str The Base64url string.
         * 
         * @param {boolean} urlSafe Whether to use url safe.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     const wordArray = CryptoJS.enc.Base64.parse(base64String);
         */
        parse: function parse(base64Str, urlSafe) {
          if (urlSafe === void 0) {
            urlSafe = true;
          }
          // Shortcuts
          var base64StrLength = base64Str.length;
          var map = urlSafe ? this._safeMap : this._map;
          var reverseMap = this._reverseMap;
          if (!reverseMap) {
            this._reverseMap = [];
            reverseMap = this._reverseMap;
            for (var j = 0; j < map.length; j += 1) {
              reverseMap[map.charCodeAt(j)] = j;
            }
          }

          // Ignore padding
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            var paddingIndex = base64Str.indexOf(paddingChar);
            if (paddingIndex !== -1) {
              base64StrLength = paddingIndex;
            }
          }

          // Convert
          return parseLoop(base64Str, base64StrLength, reverseMap);
        },
        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
        _safeMap: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
      });
    }
  };
});

System.register("chunks:///_virtual/enc-utf16.js", ['./core.js'], function (exports) {
  var WordArray;
  return {
    setters: [function (module) {
      WordArray = module.WordArray;
    }],
    execute: function () {
      var swapEndian = function swapEndian(word) {
        return word << 8 & 0xff00ff00 | word >>> 8 & 0x00ff00ff;
      };

      /**
       * UTF-16 BE encoding strategy.
       */
      var Utf16BE = exports('Utf16BE', {
        /**
         * Converts a word array to a UTF-16 BE string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-16 BE string.
         *
         * @static
         *
         * @example
         *
         *     const utf16String = CryptoJS.enc.Utf16.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;

          // Convert
          var utf16Chars = [];
          for (var i = 0; i < sigBytes; i += 2) {
            var codePoint = words[i >>> 2] >>> 16 - i % 4 * 8 & 0xffff;
            utf16Chars.push(String.fromCharCode(codePoint));
          }
          return utf16Chars.join('');
        },
        /**
         * Converts a UTF-16 BE string to a word array.
         *
         * @param {string} utf16Str The UTF-16 BE string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     const wordArray = CryptoJS.enc.Utf16.parse(utf16String);
         */
        parse: function parse(utf16Str) {
          // Shortcut
          var utf16StrLength = utf16Str.length;

          // Convert
          var words = [];
          for (var i = 0; i < utf16StrLength; i += 1) {
            words[i >>> 1] |= utf16Str.charCodeAt(i) << 16 - i % 2 * 16;
          }
          return WordArray.create(words, utf16StrLength * 2);
        }
      });
      var Utf16 = exports('Utf16', Utf16BE);

      /**
       * UTF-16 LE encoding strategy.
       */
      var Utf16LE = exports('Utf16LE', {
        /**
         * Converts a word array to a UTF-16 LE string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-16 LE string.
         *
         * @static
         *
         * @example
         *
         *     const utf16Str = CryptoJS.enc.Utf16LE.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;

          // Convert
          var utf16Chars = [];
          for (var i = 0; i < sigBytes; i += 2) {
            var codePoint = swapEndian(words[i >>> 2] >>> 16 - i % 4 * 8 & 0xffff);
            utf16Chars.push(String.fromCharCode(codePoint));
          }
          return utf16Chars.join('');
        },
        /**
         * Converts a UTF-16 LE string to a word array.
         *
         * @param {string} utf16Str The UTF-16 LE string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     const wordArray = CryptoJS.enc.Utf16LE.parse(utf16Str);
         */
        parse: function parse(utf16Str) {
          // Shortcut
          var utf16StrLength = utf16Str.length;

          // Convert
          var words = [];
          for (var i = 0; i < utf16StrLength; i += 1) {
            words[i >>> 1] |= swapEndian(utf16Str.charCodeAt(i) << 16 - i % 2 * 16);
          }
          return WordArray.create(words, utf16StrLength * 2);
        }
      });
    }
  };
});

System.register("chunks:///_virtual/env", [], function (exports) {
  return {
    execute: function () {
      var DEV = exports('DEV', false);
    }
  };
});

System.register("chunks:///_virtual/evpkdf.js", ['./rollupPluginModLoBabelHelpers.js', './core.js', './md5.js'], function (exports) {
  var _inheritsLoose, Base, WordArray, MD5Algo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      Base = module.Base;
      WordArray = module.WordArray;
    }, function (module) {
      MD5Algo = module.MD5Algo;
    }],
    execute: function () {
      /**
       * This key derivation function is meant to conform with EVP_BytesToKey.
       * www.openssl.org/docs/crypto/EVP_BytesToKey.html
       */
      var EvpKDFAlgo = exports('EvpKDFAlgo', /*#__PURE__*/function (_Base) {
        _inheritsLoose(EvpKDFAlgo, _Base);
        /**
         * Initializes a newly created key derivation function.
         *
         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
         *
         * @example
         *
         *     const kdf = CryptoJS.algo.EvpKDF.create();
         *     const kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
         *     const kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
         */
        function EvpKDFAlgo(cfg) {
          var _this;
          _this = _Base.call(this) || this;

          /**
           * Configuration options.
           *
           * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
           * @property {Hasher} hasher The hash algorithm to use. Default: MD5
           * @property {number} iterations The number of iterations to perform. Default: 1
           */
          _this.cfg = Object.assign(new Base(), {
            keySize: 128 / 32,
            hasher: MD5Algo,
            iterations: 1
          }, cfg);
          return _this;
        }

        /**
         * Derives a key from a password.
         *
         * @param {WordArray|string} password The password.
         * @param {WordArray|string} salt A salt.
         *
         * @return {WordArray} The derived key.
         *
         * @example
         *
         *     const key = kdf.compute(password, salt);
         */
        var _proto = EvpKDFAlgo.prototype;
        _proto.compute = function compute(password, salt) {
          var block;

          // Shortcut
          var cfg = this.cfg;

          // Init hasher
          var hasher = cfg.hasher.create();

          // Initial values
          var derivedKey = WordArray.create();

          // Shortcuts
          var derivedKeyWords = derivedKey.words;
          var keySize = cfg.keySize,
            iterations = cfg.iterations;

          // Generate key
          while (derivedKeyWords.length < keySize) {
            if (block) {
              hasher.update(block);
            }
            block = hasher.update(password).finalize(salt);
            hasher.reset();

            // Iterations
            for (var i = 1; i < iterations; i += 1) {
              block = hasher.finalize(block);
              hasher.reset();
            }
            derivedKey.concat(block);
          }
          derivedKey.sigBytes = keySize * 4;
          return derivedKey;
        };
        return EvpKDFAlgo;
      }(Base));

      /**
       * Derives a key from a password.
       *
       * @param {WordArray|string} password The password.
       * @param {WordArray|string} salt A salt.
       * @param {Object} cfg (Optional) The configuration options to use for this computation.
       *
       * @return {WordArray} The derived key.
       *
       * @static
       *
       * @example
       *
       *     var key = CryptoJS.EvpKDF(password, salt);
       *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8 });
       *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
       */
      var EvpKDF = exports('EvpKDF', function EvpKDF(password, salt, cfg) {
        return EvpKDFAlgo.create(cfg).compute(password, salt);
      });
    }
  };
});

System.register("chunks:///_virtual/format-hex.js", ['./cipher-core.js', './core.js'], function (exports) {
  var CipherParams, Hex;
  return {
    setters: [function (module) {
      CipherParams = module.CipherParams;
    }, function (module) {
      Hex = module.Hex;
    }],
    execute: function () {
      var HexFormatter = exports('HexFormatter', {
        /**
         * Converts the ciphertext of a cipher params object to a hexadecimally encoded string.
         *
         * @param {CipherParams} cipherParams The cipher params object.
         *
         * @return {string} The hexadecimally encoded string.
         *
         * @static
         *
         * @example
         *
         *     var hexString = CryptoJS.format.Hex.stringify(cipherParams);
         */
        stringify: function stringify(cipherParams) {
          return cipherParams.ciphertext.toString(Hex);
        },
        /**
         * Converts a hexadecimally encoded ciphertext string to a cipher params object.
         *
         * @param {string} input The hexadecimally encoded string.
         *
         * @return {CipherParams} The cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var cipherParams = CryptoJS.format.Hex.parse(hexString);
         */
        parse: function parse(input) {
          var ciphertext = Hex.parse(input);
          return CipherParams.create({
            ciphertext: ciphertext
          });
        }
      });
    }
  };
});

System.register("chunks:///_virtual/index-minimal.js", ['./cjs-loader.mjs', './writer.js', './writer_buffer.js', './reader.js', './reader_buffer.js', './minimal2.js', './rpc.js', './roots.js'], function (exports, module) {
  var loader, __cjsMetaURL$1, __cjsMetaURL$2, __cjsMetaURL$3, __cjsMetaURL$4, __cjsMetaURL$5, __cjsMetaURL$6, __cjsMetaURL$7;
  return {
    setters: [function (module) {
      loader = module.default;
    }, function (module) {
      __cjsMetaURL$1 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$2 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$3 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$4 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$5 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$6 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$7 = module.__cjsMetaURL;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        var protobuf = exports;

        /**
         * Build type, one of `"full"`, `"light"` or `"minimal"`.
         * @name build
         * @type {string}
         * @const
         */
        protobuf.build = "minimal";

        // Serialization
        protobuf.Writer = require("./writer");
        protobuf.BufferWriter = require("./writer_buffer");
        protobuf.Reader = require("./reader");
        protobuf.BufferReader = require("./reader_buffer");

        // Utility
        protobuf.util = require("./util/minimal");
        protobuf.rpc = require("./rpc");
        protobuf.roots = require("./roots");
        protobuf.configure = configure;

        /* istanbul ignore next */
        /**
         * Reconfigures the library according to the environment.
         * @returns {undefined}
         */
        function configure() {
          protobuf.util._configure();
          protobuf.Writer._configure(protobuf.BufferWriter);
          protobuf.Reader._configure(protobuf.BufferReader);
        }

        // Set up buffer utility according to the environment
        configure();

        // #endregion ORIGINAL CODE

        module.exports;
      }, function () {
        return {
          './writer': __cjsMetaURL$1,
          './writer_buffer': __cjsMetaURL$2,
          './reader': __cjsMetaURL$3,
          './reader_buffer': __cjsMetaURL$4,
          './util/minimal': __cjsMetaURL$5,
          './rpc': __cjsMetaURL$6,
          './roots': __cjsMetaURL$7
        };
      });
    }
  };
});

System.register("chunks:///_virtual/index.js", ['./rollupPluginModLoBabelHelpers.js'], function (exports) {
  var _extends, _asyncToGenerator, _inheritsLoose, _assertThisInitialized, _wrapNativeSuper, _createClass, _regeneratorRuntime;
  return {
    setters: [function (module) {
      _extends = module.extends;
      _asyncToGenerator = module.asyncToGenerator;
      _inheritsLoose = module.inheritsLoose;
      _assertThisInitialized = module.assertThisInitialized;
      _wrapNativeSuper = module.wrapNativeSuper;
      _createClass = module.createClass;
      _regeneratorRuntime = module.regeneratorRuntime;
    }],
    execute: function () {
      exports({
        captureSameReq: ge,
        compareVersions: ot,
        createPostEvent: pt,
        createSafeURL: q,
        isIframe: _e,
        isPageReload: ke,
        isRGB: Q,
        isRGBShort: ht,
        isTMA: Cs,
        json: g,
        on: w,
        parseLaunchParams: X,
        postEvent: A,
        request: d,
        retrieveLaunchParams: vt,
        searchParams: K,
        serializeLaunchParams: yt,
        serializeThemeParams: Ie,
        supports: v,
        targetOrigin: ct,
        toRGB: me,
        withTimeout: be
      });
      var We = Object.defineProperty;
      var Ue = function Ue(s, e, t) {
        return e in s ? We(s, e, {
          enumerable: !0,
          configurable: !0,
          writable: !0,
          value: t
        }) : s[e] = t;
      };
      var c = function c(s, e, t) {
        return Ue(s, typeof e != "symbol" ? e + "" : e, t), t;
      };
      function oe(s, e) {
        var t;
        var n = function n() {
          t !== void 0 && e && e(t), t = void 0;
        };
        return [function () {
          return t === void 0 ? t = s(n) : t;
        }, n];
      }
      var Oe = /*#__PURE__*/function () {
        function Oe(e, t) {
          if (t === void 0) {
            t = {};
          }
          this.scope = e, this.options = t;
        }
        /**
         * Prints message into a console in case, logger is currently enabled.
         * @param level - log level.
         * @param args - arguments.
         */
        var _proto = Oe.prototype;
        _proto.print = function print(e) {
          var _console;
          var n = /* @__PURE__ */new Date(),
            r = Intl.DateTimeFormat("en-GB", {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              fractionalSecondDigits: 3,
              timeZone: "UTC"
            }).format(n),
            _this$options = this.options,
            i = _this$options.textColor,
            o = _this$options.bgColor,
            a = "font-weight: bold;padding: 0 5px;border-radius:5px";
          for (var _len = arguments.length, t = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
            t[_key - 1] = arguments[_key];
          }
          (_console = console)[e].apply(_console, ["%c" + r + "%c / %c" + this.scope, a + ";background-color: lightblue;color:black", "", a + ";" + (i ? "color:" + i + ";" : "") + (o ? "background-color:" + o : "")].concat(t));
        }
        /**
         * Prints error message into a console.
         * @param args
         */;
        _proto.error = function error() {
          for (var _len2 = arguments.length, e = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
            e[_key2] = arguments[_key2];
          }
          this.print.apply(this, ["error"].concat(e));
        }
        /**
         * Prints log message into a console.
         * @param args
         */;
        _proto.log = function log() {
          for (var _len3 = arguments.length, e = new Array(_len3), _key3 = 0; _key3 < _len3; _key3++) {
            e[_key3] = arguments[_key3];
          }
          this.print.apply(this, ["log"].concat(e));
        };
        return Oe;
      }();
      var F = new Oe("SDK", {
        bgColor: "forestgreen",
        textColor: "white"
      });
      var R = exports('EventEmitter', /*#__PURE__*/function () {
        function R() {
          c(this, "listeners", /* @__PURE__ */new Map());
          c(this, "listenersCount", 0);
          c(this, "subscribeListeners", []);
        }
        /**
         * Removes all event listeners.
         */
        var _proto2 = R.prototype;
        _proto2.clear = function clear() {
          this.listeners.clear(), this.subscribeListeners = [];
        }
        /**
         * Returns count of bound listeners.
         */;
        _proto2.emit = function emit(e) {
          var _this = this;
          for (var _len4 = arguments.length, t = new Array(_len4 > 1 ? _len4 - 1 : 0), _key4 = 1; _key4 < _len4; _key4++) {
            t[_key4 - 1] = arguments[_key4];
          }
          this.subscribeListeners.forEach(function (r) {
            return r({
              event: e,
              args: t
            });
          }), (this.listeners.get(e) || []).forEach(function (_ref2) {
            var r = _ref2[0],
              i = _ref2[1];
            r.apply(void 0, t), i && _this.off(e, r);
          });
        }
        /**
         * Adds new event listener.
         * @param event - event name.
         * @param listener - event listener.
         * @param once - should listener be called only once.
         * @returns Function to remove bound event listener.
         */;
        _proto2.on = function on(e, t, n) {
          var _this2 = this;
          var r = this.listeners.get(e);
          return r || this.listeners.set(e, r = []), r.push([t, n]), this.listenersCount += 1, function () {
            return _this2.off(e, t);
          };
        }
        /**
         * Removes event listener. In case, specified listener was bound several times, it removes
         * only a single one.
         * @param event - event name.
         * @param listener - event listener.
         */;
        _proto2.off = function off(e, t) {
          var n = this.listeners.get(e) || [];
          for (var r = 0; r < n.length; r += 1) if (t === n[r][0]) {
            n.splice(r, 1), this.listenersCount -= 1;
            return;
          }
        }
        /**
         * Adds a new event listener for all events.
         * @param listener - event listener.
         * @returns Function to remove event listener.
         */;
        _proto2.subscribe = function subscribe(e) {
          var _this3 = this;
          return this.subscribeListeners.push(e), function () {
            return _this3.unsubscribe(e);
          };
        }
        /**
         * Removes global event listener. In case, specified listener was bound several times, it removes
         * only a single one.
         * @param listener - event listener.
         */;
        _proto2.unsubscribe = function unsubscribe(e) {
          for (var t = 0; t < this.subscribeListeners.length; t += 1) if (this.subscribeListeners[t] === e) {
            this.subscribeListeners.splice(t, 1);
            return;
          }
        };
        _createClass(R, [{
          key: "count",
          get: function get() {
            return this.listenersCount + this.subscribeListeners.length;
          }
        }]);
        return R;
      }());
      function G(s, e, t) {
        return window.addEventListener(s, e, t), function () {
          return window.removeEventListener(s, e, t);
        };
      }
      function J() {
        var e = !1;
        for (var _len5 = arguments.length, s = new Array(_len5), _key5 = 0; _key5 < _len5; _key5++) {
          s[_key5] = arguments[_key5];
        }
        var t = s.flat(1);
        return [function (n) {
          return !e && t.push(n);
        }, function () {
          e || (e = !0, t.forEach(function (n) {
            return n();
          }));
        }, e];
      }
      var V = exports('SDKError', /*#__PURE__*/function (_Error) {
        _inheritsLoose(V, _Error);
        function V(e, t, n) {
          var _this4;
          _this4 = _Error.call(this, t, {
            cause: n
          }) || this, _this4.type = e, Object.setPrototypeOf(_assertThisInitialized(_this4), V.prototype);
          return _this4;
        }
        return V;
      }( /*#__PURE__*/_wrapNativeSuper(Error)));
      function f(s, e, t) {
        return new V(s, e, t);
      }
      var je = exports('ERR_METHOD_UNSUPPORTED', "ERR_METHOD_UNSUPPORTED"),
        ze = exports('ERR_METHOD_PARAMETER_UNSUPPORTED', "ERR_METHOD_PARAMETER_UNSUPPORTED"),
        Fe = exports('ERR_UNKNOWN_ENV', "ERR_UNKNOWN_ENV"),
        Qe = exports('ERR_TIMED_OUT', "ERR_TIMED_OUT"),
        Ye = exports('ERR_UNEXPECTED_TYPE', "ERR_UNEXPECTED_TYPE"),
        ce = exports('ERR_PARSE', "ERR_PARSE");
      function E() {
        return f(Ye, "Value has unexpected type");
      }
      var D = /*#__PURE__*/function () {
        function D(e, t, n) {
          this.parser = e, this.isOptional = t, this.type = n;
        }
        /**
         * Attempts to parse passed value
         * @param value - value to parse.
         * @throws {SDKError} ERR_PARSE
         * @see ERR_PARSE
         */
        var _proto3 = D.prototype;
        _proto3.parse = function parse(e) {
          if (!(this.isOptional && e === void 0)) try {
            return this.parser(e);
          } catch (t) {
            throw f(ce, "Unable to parse value" + (this.type ? " as " + this.type : ""), t);
          }
        };
        _proto3.optional = function optional() {
          return this.isOptional = !0, this;
        };
        return D;
      }();
      function S(s, e) {
        return function () {
          return new D(s, !1, e);
        };
      }
      var b = exports('boolean', S(function (s) {
        if (typeof s == "boolean") return s;
        var e = String(s);
        if (e === "1" || e === "true") return !0;
        if (e === "0" || e === "false") return !1;
        throw E();
      }, "boolean"));
      function pe(s, e) {
        var t = {};
        for (var n in s) {
          var r = s[n];
          if (!r) continue;
          var i = void 0,
            o = void 0;
          if (typeof r == "function" || "parse" in r) i = n, o = typeof r == "function" ? r : r.parse.bind(r);else {
            var a = r.type;
            i = r.from || n, o = typeof a == "function" ? a : a.parse.bind(a);
          }
          try {
            var _a = o(e(i));
            _a !== void 0 && (t[n] = _a);
          } catch (a) {
            throw f(ce, "Unable to parse field \"" + n + "\"", a);
          }
        }
        return t;
      }
      function he(s) {
        var e = s;
        if (typeof e == "string" && (e = JSON.parse(e)), typeof e != "object" || e === null || Array.isArray(e)) throw E();
        return e;
      }
      function g(s, e) {
        return new D(function (t) {
          var n = he(t);
          return pe(s, function (r) {
            return n[r];
          });
        }, !1, e);
      }
      var y = exports('number', S(function (s) {
          if (typeof s == "number") return s;
          if (typeof s == "string") {
            var e = Number(s);
            if (!Number.isNaN(e)) return e;
          }
          throw E();
        }, "number")),
        h = exports('string', S(function (s) {
          if (typeof s == "string" || typeof s == "number") return s.toString();
          throw E();
        }, "string"));
      function ue(s) {
        return g({
          eventType: h(),
          eventData: function eventData(e) {
            return e;
          }
        }).parse(s);
      }
      function et() {
        ["TelegramGameProxy_receiveEvent", "TelegramGameProxy", "Telegram"].forEach(function (s) {
          delete window[s];
        });
      }
      function j(s, e) {
        window.dispatchEvent(new MessageEvent("message", {
          data: JSON.stringify({
            eventType: s,
            eventData: e
          }),
          // We specify window.parent to imitate the case, the parent iframe sent us this event.
          source: window.parent
        }));
      }
      function tt() {
        [["TelegramGameProxy_receiveEvent"],
        // Windows Phone.
        ["TelegramGameProxy", "receiveEvent"],
        // Desktop.
        ["Telegram", "WebView", "receiveEvent"]
        // Android and iOS.
        ].forEach(function (s) {
          var e = window;
          s.forEach(function (t, n, r) {
            if (n === r.length - 1) {
              e[t] = j;
              return;
            }
            t in e || (e[t] = {}), e = e[t];
          });
        });
      }
      var st = {
        clipboard_text_received: g({
          req_id: h(),
          data: function data(s) {
            return s === null ? s : h().optional().parse(s);
          }
        }),
        custom_method_invoked: g({
          req_id: h(),
          result: function result(s) {
            return s;
          },
          error: h().optional()
        }),
        popup_closed: {
          parse: function parse(s) {
            return g({
              button_id: function button_id(e) {
                return e == null ? void 0 : h().parse(e);
              }
            }).parse(s != null ? s : {});
          }
        },
        viewport_changed: g({
          height: y(),
          width: function width(s) {
            return s == null ? window.innerWidth : y().parse(s);
          },
          is_state_stable: b(),
          is_expanded: b()
        })
      };
      function nt() {
        var s = new R(),
          e = new R();
        e.subscribe(function (n) {
          s.emit("event", {
            name: n.event,
            payload: n.args[0]
          });
        }), tt();
        var _J = J(
          // Don't forget to remove created handlers.
          et,
          // Add "resize" event listener to make sure, we always have fresh viewport information.
          // Desktop version of Telegram is sometimes not sending the viewport_changed
          // event. For example, when the MainButton is shown. That's why we should
          // add our own listener to make sure, viewport information is always fresh.
          // Issue: https://github.com/Telegram-Mini-Apps/telegram-apps/issues/10
          G("resize", function () {
            e.emit("viewport_changed", {
              width: window.innerWidth,
              height: window.innerHeight,
              is_state_stable: !0,
              is_expanded: !0
            });
          }),
          // Add listener, which handles events sent from the Telegram web application and also events
          // generated by the local emitEvent function.
          G("message", function (n) {
            if (n.source !== window.parent) return;
            var r;
            try {
              r = ue(n.data);
            } catch (_unused) {
              return;
            }
            var _r = r,
              i = _r.eventType,
              o = _r.eventData,
              a = st[i];
            try {
              var p = a ? a.parse(o) : o;
              e.emit.apply(e, p ? [i, p] : [i]);
            } catch (p) {
              F.error("An error occurred processing the \"" + i + "\" event from the Telegram application.\nPlease, file an issue here:\nhttps://github.com/Telegram-Mini-Apps/telegram-apps/issues/new/choose", r, p);
            }
          }),
          // Clear emitters.
          function () {
            return s.clear();
          }, function () {
            return e.clear();
          }),
          t = _J[1];
        return [{
          on: e.on.bind(e),
          off: e.off.bind(e),
          subscribe: function subscribe(n) {
            return s.on("event", n);
          },
          unsubscribe: function unsubscribe(n) {
            s.off("event", n);
          },
          get count() {
            return e.count + s.count;
          }
        }, t];
      }
      var _oe = oe(function (s) {
          var _nt = nt(),
            e = _nt[0],
            t = _nt[1],
            n = e.off.bind(e);
          return e.off = function (r, i) {
            var o = e.count;
            n(r, i), o && !e.count && s();
          }, [e, t];
        }, function (_ref3) {
          var s = _ref3[1];
          return s();
        }),
        rt = _oe[0];
      function M() {
        return rt()[0];
      }
      function w(s, e, t) {
        return M().on(s, e, t);
      }
      function k(s) {
        return typeof s == "object" && s !== null && !Array.isArray(s);
      }
      function ot(s, e) {
        var t = s.split("."),
          n = e.split("."),
          r = Math.max(t.length, n.length);
        for (var i = 0; i < r; i += 1) {
          var o = parseInt(t[i] || "0", 10),
            a = parseInt(n[i] || "0", 10);
          if (o !== a) return o > a ? 1 : -1;
        }
        return 0;
      }
      function _(s, e) {
        return ot(s, e) <= 0;
      }
      function v(s, e, t) {
        if (typeof t == "string") {
          if (s === "web_app_open_link") {
            if (e === "try_instant_view") return _("6.4", t);
            if (e === "try_browser") return _("7.6", t);
          }
          if (s === "web_app_set_header_color" && e === "color") return _("6.9", t);
          if (s === "web_app_close" && e === "return_back") return _("7.6", t);
        }
        switch (s) {
          case "web_app_open_tg_link":
          case "web_app_open_invoice":
          case "web_app_setup_back_button":
          case "web_app_set_background_color":
          case "web_app_set_header_color":
          case "web_app_trigger_haptic_feedback":
            return _("6.1", e);
          case "web_app_open_popup":
            return _("6.2", e);
          case "web_app_close_scan_qr_popup":
          case "web_app_open_scan_qr_popup":
          case "web_app_read_text_from_clipboard":
            return _("6.4", e);
          case "web_app_switch_inline_query":
            return _("6.7", e);
          case "web_app_invoke_custom_method":
          case "web_app_request_write_access":
          case "web_app_request_phone":
            return _("6.9", e);
          case "web_app_setup_settings_button":
            return _("6.10", e);
          case "web_app_biometry_get_info":
          case "web_app_biometry_open_settings":
          case "web_app_biometry_request_access":
          case "web_app_biometry_request_auth":
          case "web_app_biometry_update_token":
            return _("7.2", e);
          case "web_app_setup_swipe_behavior":
            return _("7.7", e);
          default:
            return ["iframe_ready", "iframe_will_reload", "web_app_close", "web_app_data_send", "web_app_expand", "web_app_open_link", "web_app_ready", "web_app_request_theme", "web_app_request_viewport", "web_app_setup_main_button", "web_app_setup_closing_behavior"].includes(s);
        }
      }
      function le(s) {
        return "external" in s && k(s.external) && "notify" in s.external && typeof s.external.notify == "function";
      }
      function de(s) {
        return "TelegramWebviewProxy" in s && k(s.TelegramWebviewProxy) && "postEvent" in s.TelegramWebviewProxy && typeof s.TelegramWebviewProxy.postEvent == "function";
      }
      function _e() {
        try {
          return window.self !== window.top;
        } catch (_unused2) {
          return !0;
        }
      }
      var at = "https://web.telegram.org";
      var fe = at;
      function ct() {
        return fe;
      }
      function A(s, e, t) {
        var n = {},
          r;
        if (!e && !t ? n = {} : e && t ? (n = t, r = e) : e && ("targetOrigin" in e ? n = e : r = e), _e()) return window.parent.postMessage(JSON.stringify({
          eventType: s,
          eventData: r
        }), n.targetOrigin || ct());
        if (le(window)) {
          window.external.notify(JSON.stringify({
            eventType: s,
            eventData: r
          }));
          return;
        }
        if (de(window)) {
          window.TelegramWebviewProxy.postEvent(s, JSON.stringify(r));
          return;
        }
        throw f(Fe, "Unable to determine current environment and possible way to send event. You are probably trying to use Mini Apps method outside the Telegram application environment.");
      }
      function pt(s) {
        return function (e, t) {
          if (!v(e, s)) throw f(je, "Method \"" + e + "\" is unsupported in Mini Apps version " + s);
          if (k(t) && e === "web_app_set_header_color" && "color" in t && !v(e, "color", s)) throw f(ze, "Parameter \"color\" of \"" + e + "\" method is unsupported in Mini Apps version " + s);
          return A(e, t);
        };
      }
      function ge(s) {
        return function (_ref4) {
          var e = _ref4.req_id;
          return e === s;
        };
      }
      function we(s) {
        return f(Qe, "Timeout reached: " + s + "ms");
      }
      function be(s, e) {
        return Promise.race([typeof s == "function" ? s() : s, new Promise(function (t, n) {
          setTimeout(function () {
            n(we(e));
          }, e);
        })]);
      }
      function d(_x) {
        return _d.apply(this, arguments);
      }
      function _d() {
        _d = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee22(s) {
          var e, t, n, r, i, _J3, o;
          return _regeneratorRuntime().wrap(function _callee22$(_context22) {
            while (1) switch (_context22.prev = _context22.next) {
              case 0:
                t = new Promise(function (a) {
                  return e = a;
                }), n = s.event, r = s.capture, i = s.timeout, _J3 = J(
                // We need to iterate over all tracked events, and create their event listeners.
                (Array.isArray(n) ? n : [n]).map(function (a) {
                  return w(a, function (p) {
                    (!r || (Array.isArray(n) ? r({
                      event: a,
                      payload: p
                    }) : r(p))) && e(p);
                  });
                })), o = _J3[1];
                _context22.prev = 1;
                (s.postEvent || A)(s.method, s.params);
                _context22.next = 5;
                return i ? be(t, i) : t;
              case 5:
                return _context22.abrupt("return", _context22.sent);
              case 6:
                _context22.prev = 6;
                o();
                return _context22.finish(6);
              case 9:
              case "end":
                return _context22.stop();
            }
          }, _callee22, null, [[1,, 6, 9]]);
        }));
        return _d.apply(this, arguments);
      }
      function Q(s) {
        return /^#[\da-f]{6}$/i.test(s);
      }
      function ht(s) {
        return /^#[\da-f]{3}$/i.test(s);
      }
      function me(s) {
        var e = s.replace(/\s/g, "").toLowerCase();
        if (Q(e)) return e;
        if (ht(e)) {
          var n = "#";
          for (var r = 0; r < 3; r += 1) n += e[1 + r].repeat(2);
          return n;
        }
        var t = e.match(/^rgb\((\d{1,3}),(\d{1,3}),(\d{1,3})\)$/) || e.match(/^rgba\((\d{1,3}),(\d{1,3}),(\d{1,3}),\d{1,3}\)$/);
        if (!t) throw new Error("Value \"" + s + "\" does not satisfy any of known RGB formats.");
        return t.slice(1).reduce(function (n, r) {
          var i = parseInt(r, 10).toString(16);
          return n + (i.length === 1 ? "0" : "") + i;
        }, "#");
      }
      var ut = /*#__PURE__*/function () {
        function ut(e) {
          c(this, "ee", new R());
          /**
           * Adds new event listener.
           */
          c(this, "on", this.ee.on.bind(this.ee));
          /**
           * Removes event listener.
           */
          c(this, "off", this.ee.off.bind(this.ee));
          this.state = e;
        }
        /**
         * Clones current state and returns its copy.
         */
        var _proto4 = ut.prototype;
        _proto4.clone = function clone() {
          return _extends({}, this.state);
        };
        _proto4.set = function set(e, t) {
          var _ref6,
            _this5 = this;
          Object.entries(typeof e == "string" ? (_ref6 = {}, _ref6[e] = t, _ref6) : e).reduce(function (r, _ref7) {
            var i = _ref7[0],
              o = _ref7[1];
            return _this5.state[i] === o || o === void 0 ? r : (_this5.state[i] = o, _this5.ee.emit("change:" + i, o), !0);
          }, !1) && this.ee.emit("change", this.state);
        }
        /**
         * Returns value by specified key.
         * @param key - state key.
         */;
        _proto4.get = function get(e) {
          return this.state[e];
        };
        return ut;
      }();
      var Y = function Y(e) {
        c(this, "state");
        /**
         * Gets the state value.
         */
        c(this, "get");
        /**
         * Sets the state value.
         */
        c(this, "set");
        /**
         * Clones the current state.
         */
        c(this, "clone");
        this.state = new ut(e), this.set = this.state.set.bind(this.state), this.get = this.state.get.bind(this.state), this.clone = this.state.clone.bind(this.state);
      };
      function ve(s, e) {
        return function (t) {
          return v(e[t], s);
        };
      }
      var Z = /*#__PURE__*/function (_Y) {
        _inheritsLoose(Z, _Y);
        function Z(t, n, r) {
          var _this6;
          _this6 = _Y.call(this, t) || this;
          /**
           * @returns True, if specified method is supported by the current component.
           */
          c(_assertThisInitialized(_this6), "supports");
          _this6.supports = ve(n, r);
          return _this6;
        }
        return Z;
      }(Y);
      var Ee = exports('date', S(function (s) {
        return s instanceof Date ? s : new Date(y().parse(s) * 1e3);
      }, "Date"));
      function K(s, e) {
        return new D(function (t) {
          if (typeof t != "string" && !(t instanceof URLSearchParams)) throw E();
          var n = typeof t == "string" ? new URLSearchParams(t) : t;
          return pe(s, function (r) {
            var i = n.get(r);
            return i === null ? void 0 : i;
          });
        }, !1, e);
      }
      var dt = g({
          id: y(),
          type: h(),
          title: h(),
          photoUrl: {
            type: h().optional(),
            from: "photo_url"
          },
          username: h().optional()
        }, "Chat").optional(),
        ne = g({
          addedToAttachmentMenu: {
            type: b().optional(),
            from: "added_to_attachment_menu"
          },
          allowsWriteToPm: {
            type: b().optional(),
            from: "allows_write_to_pm"
          },
          firstName: {
            type: h(),
            from: "first_name"
          },
          id: y(),
          isBot: {
            type: b().optional(),
            from: "is_bot"
          },
          isPremium: {
            type: b().optional(),
            from: "is_premium"
          },
          languageCode: {
            type: h().optional(),
            from: "language_code"
          },
          lastName: {
            type: h().optional(),
            from: "last_name"
          },
          photoUrl: {
            type: h().optional(),
            from: "photo_url"
          },
          username: h().optional()
        }, "User").optional();
      function Se() {
        return K({
          authDate: {
            type: Ee(),
            from: "auth_date"
          },
          canSendAfter: {
            type: y().optional(),
            from: "can_send_after"
          },
          chat: dt,
          chatInstance: {
            type: h().optional(),
            from: "chat_instance"
          },
          chatType: {
            type: h().optional(),
            from: "chat_type"
          },
          hash: h(),
          queryId: {
            type: h().optional(),
            from: "query_id"
          },
          receiver: ne,
          startParam: {
            type: h().optional(),
            from: "start_param"
          },
          user: ne
        }, "InitData");
      }
      var _t = exports('rgb', S(function (s) {
        return me(h().parse(s));
      }, "rgb"));
      function ft(s) {
        return s.replace(/_[a-z]/g, function (e) {
          return e[1].toUpperCase();
        });
      }
      function gt(s) {
        return s.replace(/[A-Z]/g, function (e) {
          return "_" + e.toLowerCase();
        });
      }
      var Pe = S(function (s) {
        var e = _t().optional();
        return Object.entries(he(s)).reduce(function (t, _ref8) {
          var n = _ref8[0],
            r = _ref8[1];
          return t[ft(n)] = e.parse(r), t;
        }, {});
      }, "ThemeParams");
      function X(s) {
        return K({
          botInline: {
            type: b().optional(),
            from: "tgWebAppBotInline"
          },
          initData: {
            type: Se().optional(),
            from: "tgWebAppData"
          },
          initDataRaw: {
            type: h().optional(),
            from: "tgWebAppData"
          },
          platform: {
            type: h(),
            from: "tgWebAppPlatform"
          },
          showSettings: {
            type: b().optional(),
            from: "tgWebAppShowSettings"
          },
          startParam: {
            type: h().optional(),
            from: "tgWebAppStartParam"
          },
          themeParams: {
            type: Pe(),
            from: "tgWebAppThemeParams"
          },
          version: {
            type: h(),
            from: "tgWebAppVersion"
          }
        }).parse(s);
      }
      function xe(s) {
        return X(s.replace(/^[^?#]*[?#]/, "").replace(/[?#]/g, "&"));
      }
      function wt() {
        return xe(window.location.href);
      }
      function Ce() {
        return performance.getEntriesByType("navigation")[0];
      }
      function bt() {
        var s = Ce();
        if (!s) throw new Error("Unable to get first navigation entry.");
        return xe(s.name);
      }
      function Te(s) {
        return "telegram-apps/" + s.replace(/[A-Z]/g, function (e) {
          return "-" + e.toLowerCase();
        });
      }
      function Re(s, e) {
        sessionStorage.setItem(Te(s), JSON.stringify(e));
      }
      function Ae(s) {
        var e = sessionStorage.getItem(Te(s));
        try {
          return e ? JSON.parse(e) : void 0;
        } catch (_unused3) {}
      }
      function mt() {
        return X(Ae("launchParams") || "");
      }
      function Ie(s) {
        return JSON.stringify(Object.fromEntries(Object.entries(s).map(function (_ref9) {
          var e = _ref9[0],
            t = _ref9[1];
          return [gt(e), t];
        })));
      }
      function yt(s) {
        var e = s.initDataRaw,
          t = s.themeParams,
          n = s.platform,
          r = s.version,
          i = s.showSettings,
          o = s.startParam,
          a = s.botInline,
          p = new URLSearchParams();
        return p.set("tgWebAppPlatform", n), p.set("tgWebAppThemeParams", Ie(t)), p.set("tgWebAppVersion", r), e && p.set("tgWebAppData", e), o && p.set("tgWebAppStartParam", o), typeof i == "boolean" && p.set("tgWebAppShowSettings", i ? "1" : "0"), typeof a == "boolean" && p.set("tgWebAppBotInline", a ? "1" : "0"), p.toString();
      }
      function qe(s) {
        Re("launchParams", yt(s));
      }
      function vt() {
        var s = [];
        for (var _i = 0, _arr = [
          // Try to retrieve launch parameters from the current location. This method can return
          // nothing in case, location was changed, and then the page was reloaded.
          wt,
          // Then, try using the lower level API - window.performance.
          bt,
          // Finally, try to extract launch parameters from the session storage.
          mt]; _i < _arr.length; _i++) {
          var e = _arr[_i];
          try {
            var t = e();
            return qe(t), t;
          } catch (t) {
            s.push(t instanceof Error ? t.message : JSON.stringify(t));
          }
        }
        throw new Error(["Unable to retrieve launch parameters from any known source. Perhaps, you have opened your app outside Telegram?\n", "📖 Refer to docs for more information:", "https://docs.telegram-mini-apps.com/packages/telegram-apps-sdk/environment\n", "Collected errors:", s.map(function (e) {
          return "\u2014 " + e;
        })].join("\n"));
      }
      function ke() {
        var s = Ce();
        return !!(s && s.type === "reload");
      }
      function Et() {
        var s = 0;
        return function () {
          return (s += 1).toString();
        };
      }
      var _oe2 = oe(Et),
        St = _oe2[0];
      function l(s, e) {
        return function () {
          var t = vt(),
            n = _extends({}, t, {
              postEvent: pt(t.version),
              createRequestId: St()
            });
          if (typeof s == "function") return s(n);
          var _J2 = J(),
            r = _J2[0],
            i = _J2[1],
            o = _J2[2],
            a = e(_extends({}, n, {
              // State should only be passed only in case, current page was reloaded. If we don't add
              // this check, state restoration will work improperly in the web version of Telegram,
              // when we are always working in the same "session" (tab).
              state: ke() ? Ae(s) : void 0,
              addCleanup: r
            })),
            p = function p(u) {
              return o || r(u.on("change", function ($e) {
                Re(s, $e);
              })), u;
            };
          return [a instanceof Promise ? a.then(p) : p(a), i];
        };
      }
      var P = /*#__PURE__*/function (_Z2) {
        _inheritsLoose(P, _Z2);
        function P() {
          var _this8;
          _this8 = _Z2.apply(this, arguments) || this;
          /**
           * Adds a new event listener.
           */
          c(_assertThisInitialized(_this8), "on", _this8.state.on.bind(_this8.state));
          /**
           * Removes the event listener.
           */
          c(_assertThisInitialized(_this8), "off", _this8.state.off.bind(_this8.state));
          return _this8;
        }
        return P;
      }(Z);
      var ee = /*#__PURE__*/function (_Y2) {
        _inheritsLoose(ee, _Y2);
        function ee() {
          var _this12;
          _this12 = _Y2.apply(this, arguments) || this;
          /**
           * Adds a new event listener.
           */
          c(_assertThisInitialized(_this12), "on", _this12.state.on.bind(_this12.state));
          /**
           * Removes the event listener.
           */
          c(_assertThisInitialized(_this12), "off", _this12.state.off.bind(_this12.state));
          return _this12;
        }
        return ee;
      }(Y);
      var Ct = exports('ClosingBehavior', /*#__PURE__*/function (_ee) {
        _inheritsLoose(Ct, _ee);
        function Ct(e, t) {
          var _this13;
          _this13 = _ee.call(this, {
            isConfirmationNeeded: e
          }) || this, _this13.postEvent = t;
          return _this13;
        }
        var _proto7 = Ct.prototype;
        /**
         * Disables the confirmation dialog when closing the Mini App.
         */
        _proto7.disableConfirmation = function disableConfirmation() {
          this.isConfirmationNeeded = !1;
        }
        /**
         * Enables the confirmation dialog when closing the Mini App.
         */;
        _proto7.enableConfirmation = function enableConfirmation() {
          this.isConfirmationNeeded = !0;
        };
        _createClass(Ct, [{
          key: "isConfirmationNeeded",
          get:
          /**
           * True, if the confirmation dialog should be shown while the user is trying to close
           * the Mini App.
           */
          function get() {
            return this.get("isConfirmationNeeded");
          },
          set: function set(e) {
            this.set("isConfirmationNeeded", e), this.postEvent("web_app_setup_closing_behavior", {
              need_confirmation: e
            });
          }
        }]);
        return Ct;
      }(ee));
      var is = exports('initClosingBehavior', l("closingBehavior", function (_ref18) {
        var s = _ref18.postEvent,
          _ref18$state = _ref18.state,
          e = _ref18$state === void 0 ? {
            isConfirmationNeeded: !1
          } : _ref18$state;
        return new Ct(e.isConfirmationNeeded, s);
      }));
      var te = function te(e, t) {
        /**
         * @returns True, if specified method is supported by the current component.
         */
        c(this, "supports");
        this.supports = ve(e, t);
      };
      var kt = exports('InitData', /*#__PURE__*/function () {
        function kt(e) {
          this.initData = e;
        }
        /**
         * @see InitDataParsed.authDate
         */
        _createClass(kt, [{
          key: "authDate",
          get: function get() {
            return this.initData.authDate;
          }
          /**
           * @see InitDataParsed.canSendAfter
           */
        }, {
          key: "canSendAfter",
          get: function get() {
            return this.initData.canSendAfter;
          }
          /**
           * Date after which it is allowed to call
           * the [answerWebAppQuery](https://core.telegram.org/bots/api#answerwebappquery) method.
           */
        }, {
          key: "canSendAfterDate",
          get: function get() {
            var e = this.canSendAfter;
            return e ? new Date(this.authDate.getTime() + e * 1e3) : void 0;
          }
          /**
           * @see InitDataParsed.chat
           */
        }, {
          key: "chat",
          get: function get() {
            return this.initData.chat;
          }
          /**
           * @see InitDataParsed.chatType
           */
        }, {
          key: "chatType",
          get: function get() {
            return this.initData.chatType;
          }
          /**
           * @see InitDataParsed.chatInstance
           */
        }, {
          key: "chatInstance",
          get: function get() {
            return this.initData.chatInstance;
          }
          /**
           * @see InitDataParsed.hash
           */
        }, {
          key: "hash",
          get: function get() {
            return this.initData.hash;
          }
          /**
           * @see InitDataParsed.queryId
           */
        }, {
          key: "queryId",
          get: function get() {
            return this.initData.queryId;
          }
          /**
           * @see InitDataParsed.receiver
           */
        }, {
          key: "receiver",
          get: function get() {
            return this.initData.receiver;
          }
          /**
           * @see InitDataParsed.startParam
           */
        }, {
          key: "startParam",
          get: function get() {
            return this.initData.startParam;
          }
          /**
           * @see InitDataParsed.user
           */
        }, {
          key: "user",
          get: function get() {
            return this.initData.user;
          }
        }]);
        return kt;
      }());
      var cs = exports('initInitData', l(function (_ref21) {
        var s = _ref21.initData;
        return s ? new kt(s) : void 0;
      }));
      function Ve(s, e) {
        return function (t) {
          var _e$t = e[t],
            n = _e$t[0],
            r = _e$t[1];
          return v(n, r, s);
        };
      }
      var Ht = exports('SwipeBehavior', /*#__PURE__*/function (_P6) {
        _inheritsLoose(Ht, _P6);
        function Ht(e, t, n) {
          var _this26;
          _this26 = _P6.call(this, {
            isVerticalSwipeEnabled: e
          }, t, {
            disableVerticalSwipe: "web_app_setup_swipe_behavior",
            enableVerticalSwipe: "web_app_setup_swipe_behavior"
          }) || this, _this26.postEvent = n;
          return _this26;
        }
        var _proto17 = Ht.prototype;
        /**
         * Disables the vertical swipe.
         */
        _proto17.disableVerticalSwipe = function disableVerticalSwipe() {
          this.isVerticalSwipeEnabled = !1;
        }
        /**
         * Enables the vertical swipe.
         */;
        _proto17.enableVerticalSwipe = function enableVerticalSwipe() {
          this.isVerticalSwipeEnabled = !0;
        };
        _createClass(Ht, [{
          key: "isVerticalSwipeEnabled",
          get:
          /**
           * True, if the vertical swipe enabled.
           */
          function get() {
            return this.get("isVerticalSwipeEnabled");
          },
          set: function set(e) {
            this.set("isVerticalSwipeEnabled", e), this.postEvent("web_app_setup_swipe_behavior", {
              allow_vertical_swipe: e
            });
          }
        }]);
        return Ht;
      }(P));
      var gs = exports('initSwipeBehavior', l("swipeBehavior", function (_ref36) {
        var s = _ref36.postEvent,
          _ref36$state = _ref36.state,
          e = _ref36$state === void 0 ? {
            isVerticalSwipeEnabled: !0
          } : _ref36$state,
          t = _ref36.version;
        return new Ht(e.isVerticalSwipeEnabled, t, s);
      }));
      function I(s, e) {
        return s.startsWith(e) ? s : "" + e + s;
      }
      function q(s) {
        return new URL(typeof s == "string" ? s : "" + (s.pathname || "") + I(s.search || "", "?") + I(s.hash || "", "#"), "http://a");
      }
      var Gt = exports('Utils', /*#__PURE__*/function (_te3) {
        _inheritsLoose(Gt, _te3);
        function Gt(t, n, r) {
          var _this28;
          _this28 = _te3.call(this, t, {
            readTextFromClipboard: "web_app_read_text_from_clipboard"
          }) || this;
          /**
           * Checks if specified method parameter is supported by current component.
           */
          c(_assertThisInitialized(_this28), "supportsParam");
          _this28.version = t, _this28.createRequestId = n, _this28.postEvent = r, _this28.supportsParam = Ve(t, {
            "openLink.tryInstantView": ["web_app_open_link", "try_instant_view"]
          });
          return _this28;
        }
        var _proto19 = Gt.prototype;
        _proto19.openLink = function openLink(t, n) {
          var r = q(t).toString();
          if (!v("web_app_open_link", this.version)) {
            window.open(r, "_blank");
            return;
          }
          var i = typeof n == "boolean" ? {
            tryInstantView: n
          } : n || {};
          this.postEvent("web_app_open_link", {
            url: r,
            try_browser: i.tryBrowser,
            try_instant_view: i.tryInstantView
          });
        }
        /**
         * Opens a Telegram link inside Telegram app. The Mini App will be closed. It expects passing
         * link in full format, with hostname "t.me".
         * @param url - URL to be opened.
         * @throws {Error} URL has not allowed hostname.
         */;
        _proto19.openTelegramLink = function openTelegramLink(t) {
          var _URL2 = new URL(t, "https://t.me"),
            n = _URL2.hostname,
            r = _URL2.pathname,
            i = _URL2.search;
          if (n !== "t.me") throw new Error("URL has not allowed hostname: " + n + ". Only \"t.me\" is allowed");
          if (!v("web_app_open_tg_link", this.version)) {
            window.location.href = t;
            return;
          }
          this.postEvent("web_app_open_tg_link", {
            path_full: r + i
          });
        }
        /**
         * Reads text from clipboard and returns string or null. null is returned
         * in cases:
         * - Value in clipboard is not text
         * - Access to clipboard is not allowed
         */;
        _proto19.readTextFromClipboard = /*#__PURE__*/
        function () {
          var _readTextFromClipboard = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee16() {
            var t, _yield$d2, _yield$d2$data, n;
            return _regeneratorRuntime().wrap(function _callee16$(_context16) {
              while (1) switch (_context16.prev = _context16.next) {
                case 0:
                  t = this.createRequestId();
                  _context16.next = 3;
                  return d({
                    method: "web_app_read_text_from_clipboard",
                    event: "clipboard_text_received",
                    postEvent: this.postEvent,
                    params: {
                      req_id: t
                    },
                    capture: ge(t)
                  });
                case 3:
                  _yield$d2 = _context16.sent;
                  _yield$d2$data = _yield$d2.data;
                  n = _yield$d2$data === void 0 ? null : _yield$d2$data;
                  return _context16.abrupt("return", n);
                case 7:
                case "end":
                  return _context16.stop();
              }
            }, _callee16, this);
          }));
          function readTextFromClipboard() {
            return _readTextFromClipboard.apply(this, arguments);
          }
          return readTextFromClipboard;
        }()
        /**
         * Shares specified URL with the passed to the chats, selected by user. After being called,
         * it closes the mini application.
         *
         * This method uses Telegram's Share Links.
         * @param url - URL to share.
         * @param text - text to append after the URL.
         * @see https://core.telegram.org/api/links#share-links
         * @see https://core.telegram.org/widgets/share#custom-buttons
         */;

        _proto19.shareURL = function shareURL(t, n) {
          this.openTelegramLink("https://t.me/share/url?" + new URLSearchParams({
            url: t,
            text: n || ""
          }).toString().replace(/\+/g, "%20"));
        };
        return Gt;
      }(te));
      var ms = exports('initUtils', l(function (_ref38) {
        var s = _ref38.version,
          e = _ref38.postEvent,
          t = _ref38.createRequestId;
        return new Gt(s, t, e);
      }));
      function Cs() {
        return _Cs.apply(this, arguments);
      }
      function _Cs() {
        _Cs = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee26() {
          return _regeneratorRuntime().wrap(function _callee26$(_context26) {
            while (1) switch (_context26.prev = _context26.next) {
              case 0:
                if (!de(window)) {
                  _context26.next = 2;
                  break;
                }
                return _context26.abrupt("return", !0);
              case 2:
                _context26.prev = 2;
                _context26.next = 5;
                return d({
                  method: "web_app_request_theme",
                  event: "theme_changed",
                  timeout: 100
                });
              case 5:
                return _context26.abrupt("return", !0);
              case 8:
                _context26.prev = 8;
                _context26.t0 = _context26["catch"](2);
                return _context26.abrupt("return", !1);
              case 11:
              case "end":
                return _context26.stop();
            }
          }, _callee26, null, [[2, 8]]);
        }));
        return _Cs.apply(this, arguments);
      }
    }
  };
});

System.register("chunks:///_virtual/index2.js", ['./core.js', './x64-core.js', './cipher-core.js', './enc-utf16.js', './enc-base64.js', './enc-base64url.js', './md5.js', './sha1.js', './sha224.js', './sha256.js', './sha384.js', './sha512.js', './sha3.js', './ripemd160.js', './pbkdf2.js', './evpkdf.js', './aes.js', './tripledes.js', './rabbit.js', './rabbit-legacy.js', './rc4.js', './blowfish.js', './mode-cfb.js', './mode-ctr.js', './mode-ctr-gladman.js', './mode-ecb.js', './mode-ofb.js', './pad-ansix923.js', './pad-iso10126.js', './pad-iso97971.js', './pad-nopadding.js', './pad-zeropadding.js', './format-hex.js'], function (exports) {
  var Base, WordArray, BufferedBlockAlgorithm, Hasher, Hex, Latin1, Utf8, HMAC, X64Word, X64WordArray, Cipher, StreamCipher, BlockCipherMode, BlockCipher, CipherParams, SerializableCipher, PasswordBasedCipher, CBC, Pkcs7, OpenSSLFormatter, OpenSSLKdf, Utf16, Utf16BE, Utf16LE, Base64, Base64url, MD5Algo, MD5, HmacMD5, SHA1Algo, SHA1, HmacSHA1, SHA224Algo, SHA224, HmacSHA224, SHA256Algo, SHA256, HmacSHA256, SHA384Algo, SHA384, HmacSHA384, SHA512Algo, SHA512, HmacSHA512, SHA3Algo, SHA3, HmacSHA3, RIPEMD160Algo, RIPEMD160, HmacRIPEMD160, PBKDF2Algo, PBKDF2, EvpKDFAlgo, EvpKDF, AESAlgo, AES, DESAlgo, TripleDESAlgo, DES, TripleDES, RabbitAlgo, Rabbit, RabbitLegacyAlgo, RabbitLegacy, RC4Algo, RC4DropAlgo, RC4, RC4Drop, BlowfishAlgo, Blowfish, CFB, CTR, CTRGladman, ECB, OFB, AnsiX923, Iso10126, Iso97971, NoPadding, ZeroPadding, HexFormatter;
  return {
    setters: [function (module) {
      Base = module.Base;
      WordArray = module.WordArray;
      BufferedBlockAlgorithm = module.BufferedBlockAlgorithm;
      Hasher = module.Hasher;
      Hex = module.Hex;
      Latin1 = module.Latin1;
      Utf8 = module.Utf8;
      HMAC = module.HMAC;
    }, function (module) {
      X64Word = module.X64Word;
      X64WordArray = module.X64WordArray;
    }, function (module) {
      Cipher = module.Cipher;
      StreamCipher = module.StreamCipher;
      BlockCipherMode = module.BlockCipherMode;
      BlockCipher = module.BlockCipher;
      CipherParams = module.CipherParams;
      SerializableCipher = module.SerializableCipher;
      PasswordBasedCipher = module.PasswordBasedCipher;
      CBC = module.CBC;
      Pkcs7 = module.Pkcs7;
      OpenSSLFormatter = module.OpenSSLFormatter;
      OpenSSLKdf = module.OpenSSLKdf;
    }, function (module) {
      Utf16 = module.Utf16;
      Utf16BE = module.Utf16BE;
      Utf16LE = module.Utf16LE;
    }, function (module) {
      Base64 = module.Base64;
    }, function (module) {
      Base64url = module.Base64url;
    }, function (module) {
      MD5Algo = module.MD5Algo;
      MD5 = module.MD5;
      HmacMD5 = module.HmacMD5;
    }, function (module) {
      SHA1Algo = module.SHA1Algo;
      SHA1 = module.SHA1;
      HmacSHA1 = module.HmacSHA1;
    }, function (module) {
      SHA224Algo = module.SHA224Algo;
      SHA224 = module.SHA224;
      HmacSHA224 = module.HmacSHA224;
    }, function (module) {
      SHA256Algo = module.SHA256Algo;
      SHA256 = module.SHA256;
      HmacSHA256 = module.HmacSHA256;
    }, function (module) {
      SHA384Algo = module.SHA384Algo;
      SHA384 = module.SHA384;
      HmacSHA384 = module.HmacSHA384;
    }, function (module) {
      SHA512Algo = module.SHA512Algo;
      SHA512 = module.SHA512;
      HmacSHA512 = module.HmacSHA512;
    }, function (module) {
      SHA3Algo = module.SHA3Algo;
      SHA3 = module.SHA3;
      HmacSHA3 = module.HmacSHA3;
    }, function (module) {
      RIPEMD160Algo = module.RIPEMD160Algo;
      RIPEMD160 = module.RIPEMD160;
      HmacRIPEMD160 = module.HmacRIPEMD160;
    }, function (module) {
      PBKDF2Algo = module.PBKDF2Algo;
      PBKDF2 = module.PBKDF2;
    }, function (module) {
      EvpKDFAlgo = module.EvpKDFAlgo;
      EvpKDF = module.EvpKDF;
    }, function (module) {
      AESAlgo = module.AESAlgo;
      AES = module.AES;
    }, function (module) {
      DESAlgo = module.DESAlgo;
      TripleDESAlgo = module.TripleDESAlgo;
      DES = module.DES;
      TripleDES = module.TripleDES;
    }, function (module) {
      RabbitAlgo = module.RabbitAlgo;
      Rabbit = module.Rabbit;
    }, function (module) {
      RabbitLegacyAlgo = module.RabbitLegacyAlgo;
      RabbitLegacy = module.RabbitLegacy;
    }, function (module) {
      RC4Algo = module.RC4Algo;
      RC4DropAlgo = module.RC4DropAlgo;
      RC4 = module.RC4;
      RC4Drop = module.RC4Drop;
    }, function (module) {
      BlowfishAlgo = module.BlowfishAlgo;
      Blowfish = module.Blowfish;
    }, function (module) {
      CFB = module.CFB;
    }, function (module) {
      CTR = module.CTR;
    }, function (module) {
      CTRGladman = module.CTRGladman;
    }, function (module) {
      ECB = module.ECB;
    }, function (module) {
      OFB = module.OFB;
    }, function (module) {
      AnsiX923 = module.AnsiX923;
    }, function (module) {
      Iso10126 = module.Iso10126;
    }, function (module) {
      Iso97971 = module.Iso97971;
    }, function (module) {
      NoPadding = module.NoPadding;
    }, function (module) {
      ZeroPadding = module.ZeroPadding;
    }, function (module) {
      HexFormatter = module.HexFormatter;
    }],
    execute: function () {
      var CryptoES = exports('default', {
        lib: {
          Base: Base,
          WordArray: WordArray,
          BufferedBlockAlgorithm: BufferedBlockAlgorithm,
          Hasher: Hasher,
          Cipher: Cipher,
          StreamCipher: StreamCipher,
          BlockCipherMode: BlockCipherMode,
          BlockCipher: BlockCipher,
          CipherParams: CipherParams,
          SerializableCipher: SerializableCipher,
          PasswordBasedCipher: PasswordBasedCipher
        },
        x64: {
          Word: X64Word,
          WordArray: X64WordArray
        },
        enc: {
          Hex: Hex,
          Latin1: Latin1,
          Utf8: Utf8,
          Utf16: Utf16,
          Utf16BE: Utf16BE,
          Utf16LE: Utf16LE,
          Base64: Base64,
          Base64url: Base64url
        },
        algo: {
          HMAC: HMAC,
          MD5: MD5Algo,
          SHA1: SHA1Algo,
          SHA224: SHA224Algo,
          SHA256: SHA256Algo,
          SHA384: SHA384Algo,
          SHA512: SHA512Algo,
          SHA3: SHA3Algo,
          RIPEMD160: RIPEMD160Algo,
          PBKDF2: PBKDF2Algo,
          EvpKDF: EvpKDFAlgo,
          AES: AESAlgo,
          DES: DESAlgo,
          TripleDES: TripleDESAlgo,
          Rabbit: RabbitAlgo,
          RabbitLegacy: RabbitLegacyAlgo,
          RC4: RC4Algo,
          RC4Drop: RC4DropAlgo,
          Blowfish: BlowfishAlgo
        },
        mode: {
          CBC: CBC,
          CFB: CFB,
          CTR: CTR,
          CTRGladman: CTRGladman,
          ECB: ECB,
          OFB: OFB
        },
        pad: {
          Pkcs7: Pkcs7,
          AnsiX923: AnsiX923,
          Iso10126: Iso10126,
          Iso97971: Iso97971,
          NoPadding: NoPadding,
          ZeroPadding: ZeroPadding
        },
        format: {
          OpenSSL: OpenSSLFormatter,
          Hex: HexFormatter
        },
        kdf: {
          OpenSSL: OpenSSLKdf
        },
        MD5: MD5,
        HmacMD5: HmacMD5,
        SHA1: SHA1,
        HmacSHA1: HmacSHA1,
        SHA224: SHA224,
        HmacSHA224: HmacSHA224,
        SHA256: SHA256,
        HmacSHA256: HmacSHA256,
        SHA384: SHA384,
        HmacSHA384: HmacSHA384,
        SHA512: SHA512,
        HmacSHA512: HmacSHA512,
        SHA3: SHA3,
        HmacSHA3: HmacSHA3,
        RIPEMD160: RIPEMD160,
        HmacRIPEMD160: HmacRIPEMD160,
        PBKDF2: PBKDF2,
        EvpKDF: EvpKDF,
        AES: AES,
        DES: DES,
        TripleDES: TripleDES,
        Rabbit: Rabbit,
        RabbitLegacy: RabbitLegacy,
        RC4: RC4,
        RC4Drop: RC4Drop,
        Blowfish: Blowfish
      });
    }
  };
});

System.register("chunks:///_virtual/index3.js", ['./cjs-loader.mjs'], function (exports, module) {
  var loader;
  return {
    setters: [function (module) {
      loader = module.default;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        /**
         * A minimal UTF8 implementation for number arrays.
         * @memberof util
         * @namespace
         */
        var utf8 = exports;

        /**
         * Calculates the UTF8 byte length of a string.
         * @param {string} string String
         * @returns {number} Byte length
         */
        utf8.length = function utf8_length(string) {
          var len = 0,
            c = 0;
          for (var i = 0; i < string.length; ++i) {
            c = string.charCodeAt(i);
            if (c < 128) len += 1;else if (c < 2048) len += 2;else if ((c & 0xFC00) === 0xD800 && (string.charCodeAt(i + 1) & 0xFC00) === 0xDC00) {
              ++i;
              len += 4;
            } else len += 3;
          }
          return len;
        };

        /**
         * Reads UTF8 bytes as a string.
         * @param {Uint8Array} buffer Source buffer
         * @param {number} start Source start
         * @param {number} end Source end
         * @returns {string} String read
         */
        utf8.read = function utf8_read(buffer, start, end) {
          var len = end - start;
          if (len < 1) return "";
          var parts = null,
            chunk = [],
            i = 0,
            // char offset
            t; // temporary
          while (start < end) {
            t = buffer[start++];
            if (t < 128) chunk[i++] = t;else if (t > 191 && t < 224) chunk[i++] = (t & 31) << 6 | buffer[start++] & 63;else if (t > 239 && t < 365) {
              t = ((t & 7) << 18 | (buffer[start++] & 63) << 12 | (buffer[start++] & 63) << 6 | buffer[start++] & 63) - 0x10000;
              chunk[i++] = 0xD800 + (t >> 10);
              chunk[i++] = 0xDC00 + (t & 1023);
            } else chunk[i++] = (t & 15) << 12 | (buffer[start++] & 63) << 6 | buffer[start++] & 63;
            if (i > 8191) {
              (parts || (parts = [])).push(String.fromCharCode.apply(String, chunk));
              i = 0;
            }
          }
          if (parts) {
            if (i) parts.push(String.fromCharCode.apply(String, chunk.slice(0, i)));
            return parts.join("");
          }
          return String.fromCharCode.apply(String, chunk.slice(0, i));
        };

        /**
         * Writes a string as UTF8 bytes.
         * @param {string} string Source string
         * @param {Uint8Array} buffer Destination buffer
         * @param {number} offset Destination offset
         * @returns {number} Bytes written
         */
        utf8.write = function utf8_write(string, buffer, offset) {
          var start = offset,
            c1,
            // character 1
            c2; // character 2
          for (var i = 0; i < string.length; ++i) {
            c1 = string.charCodeAt(i);
            if (c1 < 128) {
              buffer[offset++] = c1;
            } else if (c1 < 2048) {
              buffer[offset++] = c1 >> 6 | 192;
              buffer[offset++] = c1 & 63 | 128;
            } else if ((c1 & 0xFC00) === 0xD800 && ((c2 = string.charCodeAt(i + 1)) & 0xFC00) === 0xDC00) {
              c1 = 0x10000 + ((c1 & 0x03FF) << 10) + (c2 & 0x03FF);
              ++i;
              buffer[offset++] = c1 >> 18 | 240;
              buffer[offset++] = c1 >> 12 & 63 | 128;
              buffer[offset++] = c1 >> 6 & 63 | 128;
              buffer[offset++] = c1 & 63 | 128;
            } else {
              buffer[offset++] = c1 >> 12 | 224;
              buffer[offset++] = c1 >> 6 & 63 | 128;
              buffer[offset++] = c1 & 63 | 128;
            }
          }
          return offset - start;
        };

        // #endregion ORIGINAL CODE

        module.exports;
      }, {});
    }
  };
});

System.register("chunks:///_virtual/index4.js", ['./cjs-loader.mjs'], function (exports, module) {
  var loader;
  return {
    setters: [function (module) {
      loader = module.default;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = asPromise;

        /**
         * Callback as used by {@link util.asPromise}.
         * @typedef asPromiseCallback
         * @type {function}
         * @param {Error|null} error Error, if any
         * @param {...*} params Additional arguments
         * @returns {undefined}
         */

        /**
         * Returns a promise from a node-style callback function.
         * @memberof util
         * @param {asPromiseCallback} fn Function to call
         * @param {*} ctx Function context
         * @param {...*} params Function arguments
         * @returns {Promise<*>} Promisified function
         */
        function asPromise(fn, ctx /*, varargs */) {
          var params = new Array(arguments.length - 1),
            offset = 0,
            index = 2,
            pending = true;
          while (index < arguments.length) params[offset++] = arguments[index++];
          return new Promise(function executor(resolve, reject) {
            params[offset] = function callback(err /*, varargs */) {
              if (pending) {
                pending = false;
                if (err) reject(err);else {
                  var params = new Array(arguments.length - 1),
                    offset = 0;
                  while (offset < params.length) params[offset++] = arguments[offset];
                  resolve.apply(null, params);
                }
              }
            };
            try {
              fn.apply(ctx || null, params);
            } catch (err) {
              if (pending) {
                pending = false;
                reject(err);
              }
            }
          });
        }

        // #endregion ORIGINAL CODE

        module.exports;
      }, {});
    }
  };
});

System.register("chunks:///_virtual/index5.js", ['./cjs-loader.mjs'], function (exports, module) {
  var loader;
  return {
    setters: [function (module) {
      loader = module.default;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        /**
         * A minimal base64 implementation for number arrays.
         * @memberof util
         * @namespace
         */
        var base64 = exports;

        /**
         * Calculates the byte length of a base64 encoded string.
         * @param {string} string Base64 encoded string
         * @returns {number} Byte length
         */
        base64.length = function length(string) {
          var p = string.length;
          if (!p) return 0;
          var n = 0;
          while (--p % 4 > 1 && string.charAt(p) === "=") ++n;
          return Math.ceil(string.length * 3) / 4 - n;
        };

        // Base64 encoding table
        var b64 = new Array(64);

        // Base64 decoding table
        var s64 = new Array(123);

        // 65..90, 97..122, 48..57, 43, 47
        for (var i = 0; i < 64;) s64[b64[i] = i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i - 59 | 43] = i++;

        /**
         * Encodes a buffer to a base64 encoded string.
         * @param {Uint8Array} buffer Source buffer
         * @param {number} start Source start
         * @param {number} end Source end
         * @returns {string} Base64 encoded string
         */
        base64.encode = function encode(buffer, start, end) {
          var parts = null,
            chunk = [];
          var i = 0,
            // output index
            j = 0,
            // goto index
            t; // temporary
          while (start < end) {
            var b = buffer[start++];
            switch (j) {
              case 0:
                chunk[i++] = b64[b >> 2];
                t = (b & 3) << 4;
                j = 1;
                break;
              case 1:
                chunk[i++] = b64[t | b >> 4];
                t = (b & 15) << 2;
                j = 2;
                break;
              case 2:
                chunk[i++] = b64[t | b >> 6];
                chunk[i++] = b64[b & 63];
                j = 0;
                break;
            }
            if (i > 8191) {
              (parts || (parts = [])).push(String.fromCharCode.apply(String, chunk));
              i = 0;
            }
          }
          if (j) {
            chunk[i++] = b64[t];
            chunk[i++] = 61;
            if (j === 1) chunk[i++] = 61;
          }
          if (parts) {
            if (i) parts.push(String.fromCharCode.apply(String, chunk.slice(0, i)));
            return parts.join("");
          }
          return String.fromCharCode.apply(String, chunk.slice(0, i));
        };
        var invalidEncoding = "invalid encoding";

        /**
         * Decodes a base64 encoded string to a buffer.
         * @param {string} string Source string
         * @param {Uint8Array} buffer Destination buffer
         * @param {number} offset Destination offset
         * @returns {number} Number of bytes written
         * @throws {Error} If encoding is invalid
         */
        base64.decode = function decode(string, buffer, offset) {
          var start = offset;
          var j = 0,
            // goto index
            t; // temporary
          for (var i = 0; i < string.length;) {
            var c = string.charCodeAt(i++);
            if (c === 61 && j > 1) break;
            if ((c = s64[c]) === undefined) throw Error(invalidEncoding);
            switch (j) {
              case 0:
                t = c;
                j = 1;
                break;
              case 1:
                buffer[offset++] = t << 2 | (c & 48) >> 4;
                t = c;
                j = 2;
                break;
              case 2:
                buffer[offset++] = (t & 15) << 4 | (c & 60) >> 2;
                t = c;
                j = 3;
                break;
              case 3:
                buffer[offset++] = (t & 3) << 6 | c;
                j = 0;
                break;
            }
          }
          if (j === 1) throw Error(invalidEncoding);
          return offset - start;
        };

        /**
         * Tests if the specified string appears to be base64 encoded.
         * @param {string} string String to test
         * @returns {boolean} `true` if probably base64 encoded, otherwise false
         */
        base64.test = function test(string) {
          return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(string);
        };

        // #endregion ORIGINAL CODE

        module.exports;
      }, {});
    }
  };
});

System.register("chunks:///_virtual/index6.js", ['./cjs-loader.mjs'], function (exports, module) {
  var loader;
  return {
    setters: [function (module) {
      loader = module.default;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = EventEmitter;

        /**
         * Constructs a new event emitter instance.
         * @classdesc A minimal event emitter.
         * @memberof util
         * @constructor
         */
        function EventEmitter() {
          /**
           * Registered listeners.
           * @type {Object.<string,*>}
           * @private
           */
          this._listeners = {};
        }

        /**
         * Registers an event listener.
         * @param {string} evt Event name
         * @param {function} fn Listener
         * @param {*} [ctx] Listener context
         * @returns {util.EventEmitter} `this`
         */
        EventEmitter.prototype.on = function on(evt, fn, ctx) {
          (this._listeners[evt] || (this._listeners[evt] = [])).push({
            fn: fn,
            ctx: ctx || this
          });
          return this;
        };

        /**
         * Removes an event listener or any matching listeners if arguments are omitted.
         * @param {string} [evt] Event name. Removes all listeners if omitted.
         * @param {function} [fn] Listener to remove. Removes all listeners of `evt` if omitted.
         * @returns {util.EventEmitter} `this`
         */
        EventEmitter.prototype.off = function off(evt, fn) {
          if (evt === undefined) this._listeners = {};else {
            if (fn === undefined) this._listeners[evt] = [];else {
              var listeners = this._listeners[evt];
              for (var i = 0; i < listeners.length;) if (listeners[i].fn === fn) listeners.splice(i, 1);else ++i;
            }
          }
          return this;
        };

        /**
         * Emits an event by calling its listeners with the specified arguments.
         * @param {string} evt Event name
         * @param {...*} args Arguments
         * @returns {util.EventEmitter} `this`
         */
        EventEmitter.prototype.emit = function emit(evt) {
          var listeners = this._listeners[evt];
          if (listeners) {
            var args = [],
              i = 1;
            for (; i < arguments.length;) args.push(arguments[i++]);
            for (i = 0; i < listeners.length;) listeners[i].fn.apply(listeners[i++].ctx, args);
          }
          return this;
        };

        // #endregion ORIGINAL CODE

        module.exports;
      }, {});
    }
  };
});

System.register("chunks:///_virtual/index7.js", ['./cjs-loader.mjs'], function (exports, module) {
  var loader;
  return {
    setters: [function (module) {
      loader = module.default;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = pool;

        /**
         * An allocator as used by {@link util.pool}.
         * @typedef PoolAllocator
         * @type {function}
         * @param {number} size Buffer size
         * @returns {Uint8Array} Buffer
         */

        /**
         * A slicer as used by {@link util.pool}.
         * @typedef PoolSlicer
         * @type {function}
         * @param {number} start Start offset
         * @param {number} end End offset
         * @returns {Uint8Array} Buffer slice
         * @this {Uint8Array}
         */

        /**
         * A general purpose buffer pool.
         * @memberof util
         * @function
         * @param {PoolAllocator} alloc Allocator
         * @param {PoolSlicer} slice Slicer
         * @param {number} [size=8192] Slab size
         * @returns {PoolAllocator} Pooled allocator
         */
        function pool(alloc, slice, size) {
          var SIZE = size || 8192;
          var MAX = SIZE >>> 1;
          var slab = null;
          var offset = SIZE;
          return function pool_alloc(size) {
            if (size < 1 || size > MAX) return alloc(size);
            if (offset + size > SIZE) {
              slab = alloc(SIZE);
              offset = 0;
            }
            var buf = slice.call(slab, offset, offset += size);
            if (offset & 7)
              // align to 32 bit
              offset = (offset | 7) + 1;
            return buf;
          };
        }

        // #endregion ORIGINAL CODE

        module.exports;
      }, {});
    }
  };
});

System.register("chunks:///_virtual/index8.js", ['./cjs-loader.mjs'], function (exports, module) {
  var loader;
  return {
    setters: [function (module) {
      loader = module.default;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = inquire;

        /**
         * Requires a module only if available.
         * @memberof util
         * @param {string} moduleName Module to require
         * @returns {?Object} Required module if available and not empty, otherwise `null`
         */
        function inquire(moduleName) {
          try {
            var mod = eval("quire".replace(/^/, "re"))(moduleName); // eslint-disable-line no-eval
            if (mod && (mod.length || Object.keys(mod).length)) return mod;
          } catch (e) {} // eslint-disable-line no-empty
          return null;
        }

        // #endregion ORIGINAL CODE

        module.exports;
      }, {});
    }
  };
});

System.register("chunks:///_virtual/index9.js", ['./cjs-loader.mjs'], function (exports, module) {
  var loader;
  return {
    setters: [function (module) {
      loader = module.default;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = factory(factory);

        /**
         * Reads / writes floats / doubles from / to buffers.
         * @name util.float
         * @namespace
         */

        /**
         * Writes a 32 bit float to a buffer using little endian byte order.
         * @name util.float.writeFloatLE
         * @function
         * @param {number} val Value to write
         * @param {Uint8Array} buf Target buffer
         * @param {number} pos Target buffer offset
         * @returns {undefined}
         */

        /**
         * Writes a 32 bit float to a buffer using big endian byte order.
         * @name util.float.writeFloatBE
         * @function
         * @param {number} val Value to write
         * @param {Uint8Array} buf Target buffer
         * @param {number} pos Target buffer offset
         * @returns {undefined}
         */

        /**
         * Reads a 32 bit float from a buffer using little endian byte order.
         * @name util.float.readFloatLE
         * @function
         * @param {Uint8Array} buf Source buffer
         * @param {number} pos Source buffer offset
         * @returns {number} Value read
         */

        /**
         * Reads a 32 bit float from a buffer using big endian byte order.
         * @name util.float.readFloatBE
         * @function
         * @param {Uint8Array} buf Source buffer
         * @param {number} pos Source buffer offset
         * @returns {number} Value read
         */

        /**
         * Writes a 64 bit double to a buffer using little endian byte order.
         * @name util.float.writeDoubleLE
         * @function
         * @param {number} val Value to write
         * @param {Uint8Array} buf Target buffer
         * @param {number} pos Target buffer offset
         * @returns {undefined}
         */

        /**
         * Writes a 64 bit double to a buffer using big endian byte order.
         * @name util.float.writeDoubleBE
         * @function
         * @param {number} val Value to write
         * @param {Uint8Array} buf Target buffer
         * @param {number} pos Target buffer offset
         * @returns {undefined}
         */

        /**
         * Reads a 64 bit double from a buffer using little endian byte order.
         * @name util.float.readDoubleLE
         * @function
         * @param {Uint8Array} buf Source buffer
         * @param {number} pos Source buffer offset
         * @returns {number} Value read
         */

        /**
         * Reads a 64 bit double from a buffer using big endian byte order.
         * @name util.float.readDoubleBE
         * @function
         * @param {Uint8Array} buf Source buffer
         * @param {number} pos Source buffer offset
         * @returns {number} Value read
         */

        // Factory function for the purpose of node-based testing in modified global environments
        function factory(exports) {
          // float: typed array
          if (typeof Float32Array !== "undefined") (function () {
            var f32 = new Float32Array([-0]),
              f8b = new Uint8Array(f32.buffer),
              le = f8b[3] === 128;
            function writeFloat_f32_cpy(val, buf, pos) {
              f32[0] = val;
              buf[pos] = f8b[0];
              buf[pos + 1] = f8b[1];
              buf[pos + 2] = f8b[2];
              buf[pos + 3] = f8b[3];
            }
            function writeFloat_f32_rev(val, buf, pos) {
              f32[0] = val;
              buf[pos] = f8b[3];
              buf[pos + 1] = f8b[2];
              buf[pos + 2] = f8b[1];
              buf[pos + 3] = f8b[0];
            }

            /* istanbul ignore next */
            exports.writeFloatLE = le ? writeFloat_f32_cpy : writeFloat_f32_rev;
            /* istanbul ignore next */
            exports.writeFloatBE = le ? writeFloat_f32_rev : writeFloat_f32_cpy;
            function readFloat_f32_cpy(buf, pos) {
              f8b[0] = buf[pos];
              f8b[1] = buf[pos + 1];
              f8b[2] = buf[pos + 2];
              f8b[3] = buf[pos + 3];
              return f32[0];
            }
            function readFloat_f32_rev(buf, pos) {
              f8b[3] = buf[pos];
              f8b[2] = buf[pos + 1];
              f8b[1] = buf[pos + 2];
              f8b[0] = buf[pos + 3];
              return f32[0];
            }

            /* istanbul ignore next */
            exports.readFloatLE = le ? readFloat_f32_cpy : readFloat_f32_rev;
            /* istanbul ignore next */
            exports.readFloatBE = le ? readFloat_f32_rev : readFloat_f32_cpy;

            // float: ieee754
          })();else (function () {
            function writeFloat_ieee754(writeUint, val, buf, pos) {
              var sign = val < 0 ? 1 : 0;
              if (sign) val = -val;
              if (val === 0) writeUint(1 / val > 0 ? /* positive */0 : /* negative 0 */2147483648, buf, pos);else if (isNaN(val)) writeUint(2143289344, buf, pos);else if (val > 3.4028234663852886e+38)
                // +-Infinity
                writeUint((sign << 31 | 2139095040) >>> 0, buf, pos);else if (val < 1.1754943508222875e-38)
                // denormal
                writeUint((sign << 31 | Math.round(val / 1.401298464324817e-45)) >>> 0, buf, pos);else {
                var exponent = Math.floor(Math.log(val) / Math.LN2),
                  mantissa = Math.round(val * Math.pow(2, -exponent) * 8388608) & 8388607;
                writeUint((sign << 31 | exponent + 127 << 23 | mantissa) >>> 0, buf, pos);
              }
            }
            exports.writeFloatLE = writeFloat_ieee754.bind(null, writeUintLE);
            exports.writeFloatBE = writeFloat_ieee754.bind(null, writeUintBE);
            function readFloat_ieee754(readUint, buf, pos) {
              var uint = readUint(buf, pos),
                sign = (uint >> 31) * 2 + 1,
                exponent = uint >>> 23 & 255,
                mantissa = uint & 8388607;
              return exponent === 255 ? mantissa ? NaN : sign * Infinity : exponent === 0 // denormal
              ? sign * 1.401298464324817e-45 * mantissa : sign * Math.pow(2, exponent - 150) * (mantissa + 8388608);
            }
            exports.readFloatLE = readFloat_ieee754.bind(null, readUintLE);
            exports.readFloatBE = readFloat_ieee754.bind(null, readUintBE);
          })();

          // double: typed array
          if (typeof Float64Array !== "undefined") (function () {
            var f64 = new Float64Array([-0]),
              f8b = new Uint8Array(f64.buffer),
              le = f8b[7] === 128;
            function writeDouble_f64_cpy(val, buf, pos) {
              f64[0] = val;
              buf[pos] = f8b[0];
              buf[pos + 1] = f8b[1];
              buf[pos + 2] = f8b[2];
              buf[pos + 3] = f8b[3];
              buf[pos + 4] = f8b[4];
              buf[pos + 5] = f8b[5];
              buf[pos + 6] = f8b[6];
              buf[pos + 7] = f8b[7];
            }
            function writeDouble_f64_rev(val, buf, pos) {
              f64[0] = val;
              buf[pos] = f8b[7];
              buf[pos + 1] = f8b[6];
              buf[pos + 2] = f8b[5];
              buf[pos + 3] = f8b[4];
              buf[pos + 4] = f8b[3];
              buf[pos + 5] = f8b[2];
              buf[pos + 6] = f8b[1];
              buf[pos + 7] = f8b[0];
            }

            /* istanbul ignore next */
            exports.writeDoubleLE = le ? writeDouble_f64_cpy : writeDouble_f64_rev;
            /* istanbul ignore next */
            exports.writeDoubleBE = le ? writeDouble_f64_rev : writeDouble_f64_cpy;
            function readDouble_f64_cpy(buf, pos) {
              f8b[0] = buf[pos];
              f8b[1] = buf[pos + 1];
              f8b[2] = buf[pos + 2];
              f8b[3] = buf[pos + 3];
              f8b[4] = buf[pos + 4];
              f8b[5] = buf[pos + 5];
              f8b[6] = buf[pos + 6];
              f8b[7] = buf[pos + 7];
              return f64[0];
            }
            function readDouble_f64_rev(buf, pos) {
              f8b[7] = buf[pos];
              f8b[6] = buf[pos + 1];
              f8b[5] = buf[pos + 2];
              f8b[4] = buf[pos + 3];
              f8b[3] = buf[pos + 4];
              f8b[2] = buf[pos + 5];
              f8b[1] = buf[pos + 6];
              f8b[0] = buf[pos + 7];
              return f64[0];
            }

            /* istanbul ignore next */
            exports.readDoubleLE = le ? readDouble_f64_cpy : readDouble_f64_rev;
            /* istanbul ignore next */
            exports.readDoubleBE = le ? readDouble_f64_rev : readDouble_f64_cpy;

            // double: ieee754
          })();else (function () {
            function writeDouble_ieee754(writeUint, off0, off1, val, buf, pos) {
              var sign = val < 0 ? 1 : 0;
              if (sign) val = -val;
              if (val === 0) {
                writeUint(0, buf, pos + off0);
                writeUint(1 / val > 0 ? /* positive */0 : /* negative 0 */2147483648, buf, pos + off1);
              } else if (isNaN(val)) {
                writeUint(0, buf, pos + off0);
                writeUint(2146959360, buf, pos + off1);
              } else if (val > 1.7976931348623157e+308) {
                // +-Infinity
                writeUint(0, buf, pos + off0);
                writeUint((sign << 31 | 2146435072) >>> 0, buf, pos + off1);
              } else {
                var mantissa;
                if (val < 2.2250738585072014e-308) {
                  // denormal
                  mantissa = val / 5e-324;
                  writeUint(mantissa >>> 0, buf, pos + off0);
                  writeUint((sign << 31 | mantissa / 4294967296) >>> 0, buf, pos + off1);
                } else {
                  var exponent = Math.floor(Math.log(val) / Math.LN2);
                  if (exponent === 1024) exponent = 1023;
                  mantissa = val * Math.pow(2, -exponent);
                  writeUint(mantissa * 4503599627370496 >>> 0, buf, pos + off0);
                  writeUint((sign << 31 | exponent + 1023 << 20 | mantissa * 1048576 & 1048575) >>> 0, buf, pos + off1);
                }
              }
            }
            exports.writeDoubleLE = writeDouble_ieee754.bind(null, writeUintLE, 0, 4);
            exports.writeDoubleBE = writeDouble_ieee754.bind(null, writeUintBE, 4, 0);
            function readDouble_ieee754(readUint, off0, off1, buf, pos) {
              var lo = readUint(buf, pos + off0),
                hi = readUint(buf, pos + off1);
              var sign = (hi >> 31) * 2 + 1,
                exponent = hi >>> 20 & 2047,
                mantissa = 4294967296 * (hi & 1048575) + lo;
              return exponent === 2047 ? mantissa ? NaN : sign * Infinity : exponent === 0 // denormal
              ? sign * 5e-324 * mantissa : sign * Math.pow(2, exponent - 1075) * (mantissa + 4503599627370496);
            }
            exports.readDoubleLE = readDouble_ieee754.bind(null, readUintLE, 0, 4);
            exports.readDoubleBE = readDouble_ieee754.bind(null, readUintBE, 4, 0);
          })();
          return exports;
        }

        // uint helpers

        function writeUintLE(val, buf, pos) {
          buf[pos] = val & 255;
          buf[pos + 1] = val >>> 8 & 255;
          buf[pos + 2] = val >>> 16 & 255;
          buf[pos + 3] = val >>> 24;
        }
        function writeUintBE(val, buf, pos) {
          buf[pos] = val >>> 24;
          buf[pos + 1] = val >>> 16 & 255;
          buf[pos + 2] = val >>> 8 & 255;
          buf[pos + 3] = val & 255;
        }
        function readUintLE(buf, pos) {
          return (buf[pos] | buf[pos + 1] << 8 | buf[pos + 2] << 16 | buf[pos + 3] << 24) >>> 0;
        }
        function readUintBE(buf, pos) {
          return (buf[pos] << 24 | buf[pos + 1] << 16 | buf[pos + 2] << 8 | buf[pos + 3]) >>> 0;
        }

        // #endregion ORIGINAL CODE

        module.exports;
        module.exports.writeFloatLE;
        module.exports.writeFloatBE;
        module.exports.readFloatLE;
        module.exports.readFloatBE;
        module.exports.writeDoubleLE;
        module.exports.writeDoubleBE;
        module.exports.readDoubleLE;
        module.exports.readDoubleBE;
      }, {});
    }
  };
});

System.register("chunks:///_virtual/longbits.js", ['./cjs-loader.mjs', './minimal2.js'], function (exports, module) {
  var loader, __cjsMetaURL$1;
  return {
    setters: [function (module) {
      loader = module.default;
    }, function (module) {
      __cjsMetaURL$1 = module.__cjsMetaURL;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = LongBits;
        var util = require("../util/minimal");

        /**
         * Constructs new long bits.
         * @classdesc Helper class for working with the low and high bits of a 64 bit value.
         * @memberof util
         * @constructor
         * @param {number} lo Low 32 bits, unsigned
         * @param {number} hi High 32 bits, unsigned
         */
        function LongBits(lo, hi) {
          // note that the casts below are theoretically unnecessary as of today, but older statically
          // generated converter code might still call the ctor with signed 32bits. kept for compat.

          /**
           * Low bits.
           * @type {number}
           */
          this.lo = lo >>> 0;

          /**
           * High bits.
           * @type {number}
           */
          this.hi = hi >>> 0;
        }

        /**
         * Zero bits.
         * @memberof util.LongBits
         * @type {util.LongBits}
         */
        var zero = LongBits.zero = new LongBits(0, 0);
        zero.toNumber = function () {
          return 0;
        };
        zero.zzEncode = zero.zzDecode = function () {
          return this;
        };
        zero.length = function () {
          return 1;
        };

        /**
         * Zero hash.
         * @memberof util.LongBits
         * @type {string}
         */
        var zeroHash = LongBits.zeroHash = "\0\0\0\0\0\0\0\0";

        /**
         * Constructs new long bits from the specified number.
         * @param {number} value Value
         * @returns {util.LongBits} Instance
         */
        LongBits.fromNumber = function fromNumber(value) {
          if (value === 0) return zero;
          var sign = value < 0;
          if (sign) value = -value;
          var lo = value >>> 0,
            hi = (value - lo) / 4294967296 >>> 0;
          if (sign) {
            hi = ~hi >>> 0;
            lo = ~lo >>> 0;
            if (++lo > 4294967295) {
              lo = 0;
              if (++hi > 4294967295) hi = 0;
            }
          }
          return new LongBits(lo, hi);
        };

        /**
         * Constructs new long bits from a number, long or string.
         * @param {Long|number|string} value Value
         * @returns {util.LongBits} Instance
         */
        LongBits.from = function from(value) {
          if (typeof value === "number") return LongBits.fromNumber(value);
          if (util.isString(value)) {
            /* istanbul ignore else */
            if (util.Long) value = util.Long.fromString(value);else return LongBits.fromNumber(parseInt(value, 10));
          }
          return value.low || value.high ? new LongBits(value.low >>> 0, value.high >>> 0) : zero;
        };

        /**
         * Converts this long bits to a possibly unsafe JavaScript number.
         * @param {boolean} [unsigned=false] Whether unsigned or not
         * @returns {number} Possibly unsafe number
         */
        LongBits.prototype.toNumber = function toNumber(unsigned) {
          if (!unsigned && this.hi >>> 31) {
            var lo = ~this.lo + 1 >>> 0,
              hi = ~this.hi >>> 0;
            if (!lo) hi = hi + 1 >>> 0;
            return -(lo + hi * 4294967296);
          }
          return this.lo + this.hi * 4294967296;
        };

        /**
         * Converts this long bits to a long.
         * @param {boolean} [unsigned=false] Whether unsigned or not
         * @returns {Long} Long
         */
        LongBits.prototype.toLong = function toLong(unsigned) {
          return util.Long ? new util.Long(this.lo | 0, this.hi | 0, Boolean(unsigned))
          /* istanbul ignore next */ : {
            low: this.lo | 0,
            high: this.hi | 0,
            unsigned: Boolean(unsigned)
          };
        };
        var charCodeAt = String.prototype.charCodeAt;

        /**
         * Constructs new long bits from the specified 8 characters long hash.
         * @param {string} hash Hash
         * @returns {util.LongBits} Bits
         */
        LongBits.fromHash = function fromHash(hash) {
          if (hash === zeroHash) return zero;
          return new LongBits((charCodeAt.call(hash, 0) | charCodeAt.call(hash, 1) << 8 | charCodeAt.call(hash, 2) << 16 | charCodeAt.call(hash, 3) << 24) >>> 0, (charCodeAt.call(hash, 4) | charCodeAt.call(hash, 5) << 8 | charCodeAt.call(hash, 6) << 16 | charCodeAt.call(hash, 7) << 24) >>> 0);
        };

        /**
         * Converts this long bits to a 8 characters long hash.
         * @returns {string} Hash
         */
        LongBits.prototype.toHash = function toHash() {
          return String.fromCharCode(this.lo & 255, this.lo >>> 8 & 255, this.lo >>> 16 & 255, this.lo >>> 24, this.hi & 255, this.hi >>> 8 & 255, this.hi >>> 16 & 255, this.hi >>> 24);
        };

        /**
         * Zig-zag encodes this long bits.
         * @returns {util.LongBits} `this`
         */
        LongBits.prototype.zzEncode = function zzEncode() {
          var mask = this.hi >> 31;
          this.hi = ((this.hi << 1 | this.lo >>> 31) ^ mask) >>> 0;
          this.lo = (this.lo << 1 ^ mask) >>> 0;
          return this;
        };

        /**
         * Zig-zag decodes this long bits.
         * @returns {util.LongBits} `this`
         */
        LongBits.prototype.zzDecode = function zzDecode() {
          var mask = -(this.lo & 1);
          this.lo = ((this.lo >>> 1 | this.hi << 31) ^ mask) >>> 0;
          this.hi = (this.hi >>> 1 ^ mask) >>> 0;
          return this;
        };

        /**
         * Calculates the length of this longbits when encoded as a varint.
         * @returns {number} Length
         */
        LongBits.prototype.length = function length() {
          var part0 = this.lo,
            part1 = (this.lo >>> 28 | this.hi << 4) >>> 0,
            part2 = this.hi >>> 24;
          return part2 === 0 ? part1 === 0 ? part0 < 16384 ? part0 < 128 ? 1 : 2 : part0 < 2097152 ? 3 : 4 : part1 < 16384 ? part1 < 128 ? 5 : 6 : part1 < 2097152 ? 7 : 8 : part2 < 128 ? 9 : 10;
        };

        // #endregion ORIGINAL CODE

        module.exports;
      }, function () {
        return {
          '../util/minimal': __cjsMetaURL$1
        };
      });
    }
  };
});

System.register("chunks:///_virtual/md5.js", ['./rollupPluginModLoBabelHelpers.js', './core.js'], function (exports) {
  var _inheritsLoose, Hasher, WordArray;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      Hasher = module.Hasher;
      WordArray = module.WordArray;
    }],
    execute: function () {
      // Constants table
      var T = [];

      // Compute constants
      for (var i = 0; i < 64; i += 1) {
        T[i] = Math.abs(Math.sin(i + 1)) * 0x100000000 | 0;
      }
      var FF = function FF(a, b, c, d, x, s, t) {
        var n = a + (b & c | ~b & d) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };
      var GG = function GG(a, b, c, d, x, s, t) {
        var n = a + (b & d | c & ~d) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };
      var HH = function HH(a, b, c, d, x, s, t) {
        var n = a + (b ^ c ^ d) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };
      var II = function II(a, b, c, d, x, s, t) {
        var n = a + (c ^ (b | ~d)) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };

      /**
       * MD5 hash algorithm.
       */
      var MD5Algo = exports('MD5Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(MD5Algo, _Hasher);
        function MD5Algo() {
          return _Hasher.apply(this, arguments) || this;
        }
        var _proto = MD5Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new WordArray([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;

          // Swap endian
          for (var _i = 0; _i < 16; _i += 1) {
            // Shortcuts
            var offset_i = offset + _i;
            var M_offset_i = M[offset_i];
            _M[offset_i] = (M_offset_i << 8 | M_offset_i >>> 24) & 0x00ff00ff | (M_offset_i << 24 | M_offset_i >>> 8) & 0xff00ff00;
          }

          // Shortcuts
          var H = this._hash.words;
          var M_offset_0 = _M[offset + 0];
          var M_offset_1 = _M[offset + 1];
          var M_offset_2 = _M[offset + 2];
          var M_offset_3 = _M[offset + 3];
          var M_offset_4 = _M[offset + 4];
          var M_offset_5 = _M[offset + 5];
          var M_offset_6 = _M[offset + 6];
          var M_offset_7 = _M[offset + 7];
          var M_offset_8 = _M[offset + 8];
          var M_offset_9 = _M[offset + 9];
          var M_offset_10 = _M[offset + 10];
          var M_offset_11 = _M[offset + 11];
          var M_offset_12 = _M[offset + 12];
          var M_offset_13 = _M[offset + 13];
          var M_offset_14 = _M[offset + 14];
          var M_offset_15 = _M[offset + 15];

          // Working varialbes
          var a = H[0];
          var b = H[1];
          var c = H[2];
          var d = H[3];

          // Computation
          a = FF(a, b, c, d, M_offset_0, 7, T[0]);
          d = FF(d, a, b, c, M_offset_1, 12, T[1]);
          c = FF(c, d, a, b, M_offset_2, 17, T[2]);
          b = FF(b, c, d, a, M_offset_3, 22, T[3]);
          a = FF(a, b, c, d, M_offset_4, 7, T[4]);
          d = FF(d, a, b, c, M_offset_5, 12, T[5]);
          c = FF(c, d, a, b, M_offset_6, 17, T[6]);
          b = FF(b, c, d, a, M_offset_7, 22, T[7]);
          a = FF(a, b, c, d, M_offset_8, 7, T[8]);
          d = FF(d, a, b, c, M_offset_9, 12, T[9]);
          c = FF(c, d, a, b, M_offset_10, 17, T[10]);
          b = FF(b, c, d, a, M_offset_11, 22, T[11]);
          a = FF(a, b, c, d, M_offset_12, 7, T[12]);
          d = FF(d, a, b, c, M_offset_13, 12, T[13]);
          c = FF(c, d, a, b, M_offset_14, 17, T[14]);
          b = FF(b, c, d, a, M_offset_15, 22, T[15]);
          a = GG(a, b, c, d, M_offset_1, 5, T[16]);
          d = GG(d, a, b, c, M_offset_6, 9, T[17]);
          c = GG(c, d, a, b, M_offset_11, 14, T[18]);
          b = GG(b, c, d, a, M_offset_0, 20, T[19]);
          a = GG(a, b, c, d, M_offset_5, 5, T[20]);
          d = GG(d, a, b, c, M_offset_10, 9, T[21]);
          c = GG(c, d, a, b, M_offset_15, 14, T[22]);
          b = GG(b, c, d, a, M_offset_4, 20, T[23]);
          a = GG(a, b, c, d, M_offset_9, 5, T[24]);
          d = GG(d, a, b, c, M_offset_14, 9, T[25]);
          c = GG(c, d, a, b, M_offset_3, 14, T[26]);
          b = GG(b, c, d, a, M_offset_8, 20, T[27]);
          a = GG(a, b, c, d, M_offset_13, 5, T[28]);
          d = GG(d, a, b, c, M_offset_2, 9, T[29]);
          c = GG(c, d, a, b, M_offset_7, 14, T[30]);
          b = GG(b, c, d, a, M_offset_12, 20, T[31]);
          a = HH(a, b, c, d, M_offset_5, 4, T[32]);
          d = HH(d, a, b, c, M_offset_8, 11, T[33]);
          c = HH(c, d, a, b, M_offset_11, 16, T[34]);
          b = HH(b, c, d, a, M_offset_14, 23, T[35]);
          a = HH(a, b, c, d, M_offset_1, 4, T[36]);
          d = HH(d, a, b, c, M_offset_4, 11, T[37]);
          c = HH(c, d, a, b, M_offset_7, 16, T[38]);
          b = HH(b, c, d, a, M_offset_10, 23, T[39]);
          a = HH(a, b, c, d, M_offset_13, 4, T[40]);
          d = HH(d, a, b, c, M_offset_0, 11, T[41]);
          c = HH(c, d, a, b, M_offset_3, 16, T[42]);
          b = HH(b, c, d, a, M_offset_6, 23, T[43]);
          a = HH(a, b, c, d, M_offset_9, 4, T[44]);
          d = HH(d, a, b, c, M_offset_12, 11, T[45]);
          c = HH(c, d, a, b, M_offset_15, 16, T[46]);
          b = HH(b, c, d, a, M_offset_2, 23, T[47]);
          a = II(a, b, c, d, M_offset_0, 6, T[48]);
          d = II(d, a, b, c, M_offset_7, 10, T[49]);
          c = II(c, d, a, b, M_offset_14, 15, T[50]);
          b = II(b, c, d, a, M_offset_5, 21, T[51]);
          a = II(a, b, c, d, M_offset_12, 6, T[52]);
          d = II(d, a, b, c, M_offset_3, 10, T[53]);
          c = II(c, d, a, b, M_offset_10, 15, T[54]);
          b = II(b, c, d, a, M_offset_1, 21, T[55]);
          a = II(a, b, c, d, M_offset_8, 6, T[56]);
          d = II(d, a, b, c, M_offset_15, 10, T[57]);
          c = II(c, d, a, b, M_offset_6, 15, T[58]);
          b = II(b, c, d, a, M_offset_13, 21, T[59]);
          a = II(a, b, c, d, M_offset_4, 6, T[60]);
          d = II(d, a, b, c, M_offset_11, 10, T[61]);
          c = II(c, d, a, b, M_offset_2, 15, T[62]);
          b = II(b, c, d, a, M_offset_9, 21, T[63]);

          // Intermediate hash value
          H[0] = H[0] + a | 0;
          H[1] = H[1] + b | 0;
          H[2] = H[2] + c | 0;
          H[3] = H[3] + d | 0;
        }
        /* eslint-ensable no-param-reassign */;
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          var nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
          var nBitsTotalL = nBitsTotal;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 15] = (nBitsTotalH << 8 | nBitsTotalH >>> 24) & 0x00ff00ff | (nBitsTotalH << 24 | nBitsTotalH >>> 8) & 0xff00ff00;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 14] = (nBitsTotalL << 8 | nBitsTotalL >>> 24) & 0x00ff00ff | (nBitsTotalL << 24 | nBitsTotalL >>> 8) & 0xff00ff00;
          data.sigBytes = (dataWords.length + 1) * 4;

          // Hash final blocks
          this._process();

          // Shortcuts
          var hash = this._hash;
          var H = hash.words;

          // Swap endian
          for (var _i2 = 0; _i2 < 4; _i2 += 1) {
            // Shortcut
            var H_i = H[_i2];
            H[_i2] = (H_i << 8 | H_i >>> 24) & 0x00ff00ff | (H_i << 24 | H_i >>> 8) & 0xff00ff00;
          }

          // Return final computed hash
          return hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return MD5Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.MD5('message');
       *     var hash = CryptoJS.MD5(wordArray);
       */
      var MD5 = exports('MD5', Hasher._createHelper(MD5Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacMD5(message, key);
       */
      var HmacMD5 = exports('HmacMD5', Hasher._createHmacHelper(MD5Algo));
    }
  };
});

System.register("chunks:///_virtual/minimal.js", ['./cjs-loader.mjs', './index-minimal.js'], function (exports, module) {
  var loader, __cjsMetaURL$1;
  return {
    setters: [function (module) {
      loader = module.default;
    }, function (module) {
      __cjsMetaURL$1 = module.__cjsMetaURL;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = require("./src/index-minimal");

        // #endregion ORIGINAL CODE

        module.exports;
      }, function () {
        return {
          './src/index-minimal': __cjsMetaURL$1
        };
      });
    }
  };
});

System.register("chunks:///_virtual/minimal2.js", ['./cjs-loader.mjs', './index4.js', './index5.js', './index6.js', './index9.js', './index8.js', './index3.js', './index7.js', './longbits.js'], function (exports, module) {
  var loader, __cjsMetaURL$1, __cjsMetaURL$2, __cjsMetaURL$3, __cjsMetaURL$4, __cjsMetaURL$5, __cjsMetaURL$6, __cjsMetaURL$7, __cjsMetaURL$8;
  return {
    setters: [function (module) {
      loader = module.default;
    }, function (module) {
      __cjsMetaURL$1 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$2 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$3 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$4 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$5 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$6 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$7 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$8 = module.__cjsMetaURL;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        var util = exports;

        // used to return a Promise where callback is omitted
        util.asPromise = require("@protobufjs/aspromise");

        // converts to / from base64 encoded strings
        util.base64 = require("@protobufjs/base64");

        // base class of rpc.Service
        util.EventEmitter = require("@protobufjs/eventemitter");

        // float handling accross browsers
        util["float"] = require("@protobufjs/float");

        // requires modules optionally and hides the call from bundlers
        util.inquire = require("@protobufjs/inquire");

        // converts to / from utf8 encoded strings
        util.utf8 = require("@protobufjs/utf8");

        // provides a node-like buffer pool in the browser
        util.pool = require("@protobufjs/pool");

        // utility to work with the low and high bits of a 64 bit value
        util.LongBits = require("./longbits");

        /**
         * Whether running within node or not.
         * @memberof util
         * @type {boolean}
         */
        util.isNode = Boolean(typeof global !== "undefined" && global && global.process && global.process.versions && global.process.versions.node);

        /**
         * Global object reference.
         * @memberof util
         * @type {Object}
         */
        util.global = util.isNode && global || typeof window !== "undefined" && window || typeof self !== "undefined" && self || this; // eslint-disable-line no-invalid-this

        /**
         * An immuable empty array.
         * @memberof util
         * @type {Array.<*>}
         * @const
         */
        util.emptyArray = Object.freeze ? Object.freeze([]) : /* istanbul ignore next */[]; // used on prototypes

        /**
         * An immutable empty object.
         * @type {Object}
         * @const
         */
        util.emptyObject = Object.freeze ? Object.freeze({}) : /* istanbul ignore next */{}; // used on prototypes

        /**
         * Tests if the specified value is an integer.
         * @function
         * @param {*} value Value to test
         * @returns {boolean} `true` if the value is an integer
         */
        util.isInteger = Number.isInteger || /* istanbul ignore next */function isInteger(value) {
          return typeof value === "number" && isFinite(value) && Math.floor(value) === value;
        };

        /**
         * Tests if the specified value is a string.
         * @param {*} value Value to test
         * @returns {boolean} `true` if the value is a string
         */
        util.isString = function isString(value) {
          return typeof value === "string" || value instanceof String;
        };

        /**
         * Tests if the specified value is a non-null object.
         * @param {*} value Value to test
         * @returns {boolean} `true` if the value is a non-null object
         */
        util.isObject = function isObject(value) {
          return value && typeof value === "object";
        };

        /**
         * Checks if a property on a message is considered to be present.
         * This is an alias of {@link util.isSet}.
         * @function
         * @param {Object} obj Plain object or message instance
         * @param {string} prop Property name
         * @returns {boolean} `true` if considered to be present, otherwise `false`
         */
        util.isset =
        /**
         * Checks if a property on a message is considered to be present.
         * @param {Object} obj Plain object or message instance
         * @param {string} prop Property name
         * @returns {boolean} `true` if considered to be present, otherwise `false`
         */
        util.isSet = function isSet(obj, prop) {
          var value = obj[prop];
          if (value != null && obj.hasOwnProperty(prop))
            // eslint-disable-line eqeqeq, no-prototype-builtins
            return typeof value !== "object" || (Array.isArray(value) ? value.length : Object.keys(value).length) > 0;
          return false;
        };

        /**
         * Any compatible Buffer instance.
         * This is a minimal stand-alone definition of a Buffer instance. The actual type is that exported by node's typings.
         * @interface Buffer
         * @extends Uint8Array
         */

        /**
         * Node's Buffer class if available.
         * @type {Constructor<Buffer>}
         */
        util.Buffer = function () {
          try {
            var Buffer = util.inquire("buffer").Buffer;
            // refuse to use non-node buffers if not explicitly assigned (perf reasons):
            return Buffer.prototype.utf8Write ? Buffer : /* istanbul ignore next */null;
          } catch (e) {
            /* istanbul ignore next */
            return null;
          }
        }();

        // Internal alias of or polyfull for Buffer.from.
        util._Buffer_from = null;

        // Internal alias of or polyfill for Buffer.allocUnsafe.
        util._Buffer_allocUnsafe = null;

        /**
         * Creates a new buffer of whatever type supported by the environment.
         * @param {number|number[]} [sizeOrArray=0] Buffer size or number array
         * @returns {Uint8Array|Buffer} Buffer
         */
        util.newBuffer = function newBuffer(sizeOrArray) {
          /* istanbul ignore next */
          return typeof sizeOrArray === "number" ? util.Buffer ? util._Buffer_allocUnsafe(sizeOrArray) : new util.Array(sizeOrArray) : util.Buffer ? util._Buffer_from(sizeOrArray) : typeof Uint8Array === "undefined" ? sizeOrArray : new Uint8Array(sizeOrArray);
        };

        /**
         * Array implementation used in the browser. `Uint8Array` if supported, otherwise `Array`.
         * @type {Constructor<Uint8Array>}
         */
        util.Array = typeof Uint8Array !== "undefined" ? Uint8Array /* istanbul ignore next */ : Array;

        /**
         * Any compatible Long instance.
         * This is a minimal stand-alone definition of a Long instance. The actual type is that exported by long.js.
         * @interface Long
         * @property {number} low Low bits
         * @property {number} high High bits
         * @property {boolean} unsigned Whether unsigned or not
         */

        /**
         * Long.js's Long class if available.
         * @type {Constructor<Long>}
         */
        util.Long = /* istanbul ignore next */util.global.dcodeIO && /* istanbul ignore next */util.global.dcodeIO.Long || /* istanbul ignore next */util.global.Long || util.inquire("long");

        /**
         * Regular expression used to verify 2 bit (`bool`) map keys.
         * @type {RegExp}
         * @const
         */
        util.key2Re = /^true|false|0|1$/;

        /**
         * Regular expression used to verify 32 bit (`int32` etc.) map keys.
         * @type {RegExp}
         * @const
         */
        util.key32Re = /^-?(?:0|[1-9][0-9]*)$/;

        /**
         * Regular expression used to verify 64 bit (`int64` etc.) map keys.
         * @type {RegExp}
         * @const
         */
        util.key64Re = /^(?:[\\x00-\\xff]{8}|-?(?:0|[1-9][0-9]*))$/;

        /**
         * Converts a number or long to an 8 characters long hash string.
         * @param {Long|number} value Value to convert
         * @returns {string} Hash
         */
        util.longToHash = function longToHash(value) {
          return value ? util.LongBits.from(value).toHash() : util.LongBits.zeroHash;
        };

        /**
         * Converts an 8 characters long hash string to a long or number.
         * @param {string} hash Hash
         * @param {boolean} [unsigned=false] Whether unsigned or not
         * @returns {Long|number} Original value
         */
        util.longFromHash = function longFromHash(hash, unsigned) {
          var bits = util.LongBits.fromHash(hash);
          if (util.Long) return util.Long.fromBits(bits.lo, bits.hi, unsigned);
          return bits.toNumber(Boolean(unsigned));
        };

        /**
         * Merges the properties of the source object into the destination object.
         * @memberof util
         * @param {Object.<string,*>} dst Destination object
         * @param {Object.<string,*>} src Source object
         * @param {boolean} [ifNotSet=false] Merges only if the key is not already set
         * @returns {Object.<string,*>} Destination object
         */
        function merge(dst, src, ifNotSet) {
          // used by converters
          for (var keys = Object.keys(src), i = 0; i < keys.length; ++i) if (dst[keys[i]] === undefined || !ifNotSet) dst[keys[i]] = src[keys[i]];
          return dst;
        }
        util.merge = merge;

        /**
         * Converts the first character of a string to lower case.
         * @param {string} str String to convert
         * @returns {string} Converted string
         */
        util.lcFirst = function lcFirst(str) {
          return str.charAt(0).toLowerCase() + str.substring(1);
        };

        /**
         * Creates a custom error constructor.
         * @memberof util
         * @param {string} name Error name
         * @returns {Constructor<Error>} Custom error constructor
         */
        function newError(name) {
          function CustomError(message, properties) {
            if (!(this instanceof CustomError)) return new CustomError(message, properties);

            // Error.call(this, message);
            // ^ just returns a new error instance because the ctor can be called as a function

            Object.defineProperty(this, "message", {
              get: function get() {
                return message;
              }
            });

            /* istanbul ignore next */
            if (Error.captureStackTrace)
              // node
              Error.captureStackTrace(this, CustomError);else Object.defineProperty(this, "stack", {
              value: new Error().stack || ""
            });
            if (properties) merge(this, properties);
          }
          CustomError.prototype = Object.create(Error.prototype, {
            constructor: {
              value: CustomError,
              writable: true,
              enumerable: false,
              configurable: true
            },
            name: {
              get: function get() {
                return name;
              },
              set: undefined,
              enumerable: false,
              // configurable: false would accurately preserve the behavior of
              // the original, but I'm guessing that was not intentional.
              // For an actual error subclass, this property would
              // be configurable.
              configurable: true
            },
            toString: {
              value: function value() {
                return this.name + ": " + this.message;
              },
              writable: true,
              enumerable: false,
              configurable: true
            }
          });
          return CustomError;
        }
        util.newError = newError;

        /**
         * Constructs a new protocol error.
         * @classdesc Error subclass indicating a protocol specifc error.
         * @memberof util
         * @extends Error
         * @template T extends Message<T>
         * @constructor
         * @param {string} message Error message
         * @param {Object.<string,*>} [properties] Additional properties
         * @example
         * try {
         *     MyMessage.decode(someBuffer); // throws if required fields are missing
         * } catch (e) {
         *     if (e instanceof ProtocolError && e.instance)
         *         console.log("decoded so far: " + JSON.stringify(e.instance));
         * }
         */
        util.ProtocolError = newError("ProtocolError");

        /**
         * So far decoded message instance.
         * @name util.ProtocolError#instance
         * @type {Message<T>}
         */

        /**
         * A OneOf getter as returned by {@link util.oneOfGetter}.
         * @typedef OneOfGetter
         * @type {function}
         * @returns {string|undefined} Set field name, if any
         */

        /**
         * Builds a getter for a oneof's present field name.
         * @param {string[]} fieldNames Field names
         * @returns {OneOfGetter} Unbound getter
         */
        util.oneOfGetter = function getOneOf(fieldNames) {
          var fieldMap = {};
          for (var i = 0; i < fieldNames.length; ++i) fieldMap[fieldNames[i]] = 1;

          /**
           * @returns {string|undefined} Set field name, if any
           * @this Object
           * @ignore
           */
          return function () {
            // eslint-disable-line consistent-return
            for (var keys = Object.keys(this), i = keys.length - 1; i > -1; --i) if (fieldMap[keys[i]] === 1 && this[keys[i]] !== undefined && this[keys[i]] !== null) return keys[i];
          };
        };

        /**
         * A OneOf setter as returned by {@link util.oneOfSetter}.
         * @typedef OneOfSetter
         * @type {function}
         * @param {string|undefined} value Field name
         * @returns {undefined}
         */

        /**
         * Builds a setter for a oneof's present field name.
         * @param {string[]} fieldNames Field names
         * @returns {OneOfSetter} Unbound setter
         */
        util.oneOfSetter = function setOneOf(fieldNames) {
          /**
           * @param {string} name Field name
           * @returns {undefined}
           * @this Object
           * @ignore
           */
          return function (name) {
            for (var i = 0; i < fieldNames.length; ++i) if (fieldNames[i] !== name) delete this[fieldNames[i]];
          };
        };

        /**
         * Default conversion options used for {@link Message#toJSON} implementations.
         *
         * These options are close to proto3's JSON mapping with the exception that internal types like Any are handled just like messages. More precisely:
         *
         * - Longs become strings
         * - Enums become string keys
         * - Bytes become base64 encoded strings
         * - (Sub-)Messages become plain objects
         * - Maps become plain objects with all string keys
         * - Repeated fields become arrays
         * - NaN and Infinity for float and double fields become strings
         *
         * @type {IConversionOptions}
         * @see https://developers.google.com/protocol-buffers/docs/proto3?hl=en#json
         */
        util.toJSONOptions = {
          longs: String,
          enums: String,
          bytes: String,
          json: true
        };

        // Sets up buffer utility according to the environment (called in index-minimal)
        util._configure = function () {
          var Buffer = util.Buffer;
          /* istanbul ignore if */
          if (!Buffer) {
            util._Buffer_from = util._Buffer_allocUnsafe = null;
            return;
          }
          // because node 4.x buffers are incompatible & immutable
          // see: https://github.com/dcodeIO/protobuf.js/pull/665
          util._Buffer_from = Buffer.from !== Uint8Array.from && Buffer.from || /* istanbul ignore next */
          function Buffer_from(value, encoding) {
            return new Buffer(value, encoding);
          };
          util._Buffer_allocUnsafe = Buffer.allocUnsafe || /* istanbul ignore next */
          function Buffer_allocUnsafe(size) {
            return new Buffer(size);
          };
        };

        // #endregion ORIGINAL CODE

        module.exports;
      }, function () {
        return {
          '@protobufjs/aspromise': __cjsMetaURL$1,
          '@protobufjs/base64': __cjsMetaURL$2,
          '@protobufjs/eventemitter': __cjsMetaURL$3,
          '@protobufjs/float': __cjsMetaURL$4,
          '@protobufjs/inquire': __cjsMetaURL$5,
          '@protobufjs/utf8': __cjsMetaURL$6,
          '@protobufjs/pool': __cjsMetaURL$7,
          './longbits': __cjsMetaURL$8
        };
      });
    }
  };
});

System.register("chunks:///_virtual/mode-cfb.js", ['./rollupPluginModLoBabelHelpers.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, BlockCipherMode;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      BlockCipherMode = module.BlockCipherMode;
    }],
    execute: function () {
      function generateKeystreamAndEncrypt(words, offset, blockSize, cipher) {
        var _words = words;
        var keystream;

        // Shortcut
        var iv = this._iv;

        // Generate keystream
        if (iv) {
          keystream = iv.slice(0);

          // Remove IV for subsequent blocks
          this._iv = undefined;
        } else {
          keystream = this._prevBlock;
        }
        cipher.encryptBlock(keystream, 0);

        // Encrypt
        for (var i = 0; i < blockSize; i += 1) {
          _words[offset + i] ^= keystream[i];
        }
      }

      /**
       * Cipher Feedback block mode.
       */
      var CFB = exports('CFB', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(CFB, _BlockCipherMode);
        function CFB() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return CFB;
      }(BlockCipherMode));
      CFB.Encryptor = /*#__PURE__*/function (_CFB) {
        _inheritsLoose(_class, _CFB);
        function _class() {
          return _CFB.apply(this, arguments) || this;
        }
        var _proto = _class.prototype;
        _proto.processBlock = function processBlock(words, offset) {
          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;
          generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

          // Remember this block to use with next block
          this._prevBlock = words.slice(offset, offset + blockSize);
        };
        return _class;
      }(CFB);
      CFB.Decryptor = /*#__PURE__*/function (_CFB2) {
        _inheritsLoose(_class2, _CFB2);
        function _class2() {
          return _CFB2.apply(this, arguments) || this;
        }
        var _proto2 = _class2.prototype;
        _proto2.processBlock = function processBlock(words, offset) {
          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;

          // Remember this block to use with next block
          var thisBlock = words.slice(offset, offset + blockSize);
          generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

          // This block becomes the previous block
          this._prevBlock = thisBlock;
        };
        return _class2;
      }(CFB);
    }
  };
});

System.register("chunks:///_virtual/mode-ctr-gladman.js", ['./rollupPluginModLoBabelHelpers.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, BlockCipherMode;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      BlockCipherMode = module.BlockCipherMode;
    }],
    execute: function () {
      var incWord = function incWord(word) {
        var _word = word;
        if ((word >> 24 & 0xff) === 0xff) {
          // overflow
          var b1 = word >> 16 & 0xff;
          var b2 = word >> 8 & 0xff;
          var b3 = word & 0xff;
          if (b1 === 0xff) {
            // overflow b1
            b1 = 0;
            if (b2 === 0xff) {
              b2 = 0;
              if (b3 === 0xff) {
                b3 = 0;
              } else {
                b3 += 1;
              }
            } else {
              b2 += 1;
            }
          } else {
            b1 += 1;
          }
          _word = 0;
          _word += b1 << 16;
          _word += b2 << 8;
          _word += b3;
        } else {
          _word += 0x01 << 24;
        }
        return _word;
      };
      var incCounter = function incCounter(counter) {
        var _counter = counter;
        _counter[0] = incWord(_counter[0]);
        if (_counter[0] === 0) {
          // encr_data in fileenc.c from  Dr Brian Gladman's counts only with DWORD j < 8
          _counter[1] = incWord(_counter[1]);
        }
        return _counter;
      };

      /** @preserve
       * Counter block mode compatible with  Dr Brian Gladman fileenc.c
       * derived from CryptoJS.mode.CTR
       * Jan Hruby jhruby.web@gmail.com
       */
      var CTRGladman = exports('CTRGladman', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(CTRGladman, _BlockCipherMode);
        function CTRGladman() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return CTRGladman;
      }(BlockCipherMode));
      CTRGladman.Encryptor = /*#__PURE__*/function (_CTRGladman) {
        _inheritsLoose(_class, _CTRGladman);
        function _class() {
          return _CTRGladman.apply(this, arguments) || this;
        }
        var _proto = _class.prototype;
        _proto.processBlock = function processBlock(words, offset) {
          var _words = words;

          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;
          var iv = this._iv;
          var counter = this._counter;

          // Generate keystream
          if (iv) {
            this._counter = iv.slice(0);
            counter = this._counter;

            // Remove IV for subsequent blocks
            this._iv = undefined;
          }
          incCounter(counter);
          var keystream = counter.slice(0);
          cipher.encryptBlock(keystream, 0);

          // Encrypt
          for (var i = 0; i < blockSize; i += 1) {
            _words[offset + i] ^= keystream[i];
          }
        };
        return _class;
      }(CTRGladman);
      CTRGladman.Decryptor = CTRGladman.Encryptor;
    }
  };
});

System.register("chunks:///_virtual/mode-ctr.js", ['./rollupPluginModLoBabelHelpers.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, BlockCipherMode;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      BlockCipherMode = module.BlockCipherMode;
    }],
    execute: function () {
      /**
       * Counter block mode.
       */
      var CTR = exports('CTR', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(CTR, _BlockCipherMode);
        function CTR() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return CTR;
      }(BlockCipherMode));
      CTR.Encryptor = /*#__PURE__*/function (_CTR) {
        _inheritsLoose(_class, _CTR);
        function _class() {
          return _CTR.apply(this, arguments) || this;
        }
        var _proto = _class.prototype;
        _proto.processBlock = function processBlock(words, offset) {
          var _words = words;

          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;
          var iv = this._iv;
          var counter = this._counter;

          // Generate keystream
          if (iv) {
            this._counter = iv.slice(0);
            counter = this._counter;

            // Remove IV for subsequent blocks
            this._iv = undefined;
          }
          var keystream = counter.slice(0);
          cipher.encryptBlock(keystream, 0);

          // Increment counter
          counter[blockSize - 1] = counter[blockSize - 1] + 1 | 0;

          // Encrypt
          for (var i = 0; i < blockSize; i += 1) {
            _words[offset + i] ^= keystream[i];
          }
        };
        return _class;
      }(CTR);
      CTR.Decryptor = CTR.Encryptor;
    }
  };
});

System.register("chunks:///_virtual/mode-ecb.js", ['./rollupPluginModLoBabelHelpers.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, BlockCipherMode;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      BlockCipherMode = module.BlockCipherMode;
    }],
    execute: function () {
      /**
       * Electronic Codebook block mode.
       */
      var ECB = exports('ECB', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(ECB, _BlockCipherMode);
        function ECB() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return ECB;
      }(BlockCipherMode));
      ECB.Encryptor = /*#__PURE__*/function (_ECB) {
        _inheritsLoose(_class, _ECB);
        function _class() {
          return _ECB.apply(this, arguments) || this;
        }
        var _proto = _class.prototype;
        _proto.processBlock = function processBlock(words, offset) {
          this._cipher.encryptBlock(words, offset);
        };
        return _class;
      }(ECB);
      ECB.Decryptor = /*#__PURE__*/function (_ECB2) {
        _inheritsLoose(_class2, _ECB2);
        function _class2() {
          return _ECB2.apply(this, arguments) || this;
        }
        var _proto2 = _class2.prototype;
        _proto2.processBlock = function processBlock(words, offset) {
          this._cipher.decryptBlock(words, offset);
        };
        return _class2;
      }(ECB);
    }
  };
});

System.register("chunks:///_virtual/mode-ofb.js", ['./rollupPluginModLoBabelHelpers.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, BlockCipherMode;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      BlockCipherMode = module.BlockCipherMode;
    }],
    execute: function () {
      /**
       * Output Feedback block mode.
       */
      var OFB = exports('OFB', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(OFB, _BlockCipherMode);
        function OFB() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return OFB;
      }(BlockCipherMode));
      OFB.Encryptor = /*#__PURE__*/function (_OFB) {
        _inheritsLoose(_class, _OFB);
        function _class() {
          return _OFB.apply(this, arguments) || this;
        }
        var _proto = _class.prototype;
        _proto.processBlock = function processBlock(words, offset) {
          var _words = words;

          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;
          var iv = this._iv;
          var keystream = this._keystream;

          // Generate keystream
          if (iv) {
            this._keystream = iv.slice(0);
            keystream = this._keystream;

            // Remove IV for subsequent blocks
            this._iv = undefined;
          }
          cipher.encryptBlock(keystream, 0);

          // Encrypt
          for (var i = 0; i < blockSize; i += 1) {
            _words[offset + i] ^= keystream[i];
          }
        };
        return _class;
      }(OFB);
      OFB.Decryptor = OFB.Encryptor;
    }
  };
});

System.register("chunks:///_virtual/pad-ansix923.js", [], function (exports) {
  return {
    execute: function () {
      /**
       * ANSI X.923 padding strategy.
       */
      var AnsiX923 = exports('AnsiX923', {
        pad: function pad(data, blockSize) {
          var _data = data;

          // Shortcuts
          var dataSigBytes = _data.sigBytes;
          var blockSizeBytes = blockSize * 4;

          // Count padding bytes
          var nPaddingBytes = blockSizeBytes - dataSigBytes % blockSizeBytes;

          // Compute last byte position
          var lastBytePos = dataSigBytes + nPaddingBytes - 1;

          // Pad
          _data.clamp();
          _data.words[lastBytePos >>> 2] |= nPaddingBytes << 24 - lastBytePos % 4 * 8;
          _data.sigBytes += nPaddingBytes;
        },
        unpad: function unpad(data) {
          var _data = data;

          // Get number of padding bytes from last byte
          var nPaddingBytes = _data.words[_data.sigBytes - 1 >>> 2] & 0xff;

          // Remove padding
          _data.sigBytes -= nPaddingBytes;
        }
      });
    }
  };
});

System.register("chunks:///_virtual/pad-iso10126.js", ['./core.js'], function (exports) {
  var WordArray;
  return {
    setters: [function (module) {
      WordArray = module.WordArray;
    }],
    execute: function () {
      /**
       * ISO 10126 padding strategy.
       */
      var Iso10126 = exports('Iso10126', {
        pad: function pad(data, blockSize) {
          // Shortcut
          var blockSizeBytes = blockSize * 4;

          // Count padding bytes
          var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

          // Pad
          data.concat(WordArray.random(nPaddingBytes - 1)).concat(WordArray.create([nPaddingBytes << 24], 1));
        },
        unpad: function unpad(data) {
          var _data = data;
          // Get number of padding bytes from last byte
          var nPaddingBytes = _data.words[_data.sigBytes - 1 >>> 2] & 0xff;

          // Remove padding
          _data.sigBytes -= nPaddingBytes;
        }
      });
    }
  };
});

System.register("chunks:///_virtual/pad-iso97971.js", ['./core.js', './pad-zeropadding.js'], function (exports) {
  var WordArray, ZeroPadding;
  return {
    setters: [function (module) {
      WordArray = module.WordArray;
    }, function (module) {
      ZeroPadding = module.ZeroPadding;
    }],
    execute: function () {
      /**
       * ISO/IEC 9797-1 Padding Method 2.
       */
      var Iso97971 = exports('Iso97971', {
        pad: function pad(data, blockSize) {
          // Add 0x80 byte
          data.concat(WordArray.create([0x80000000], 1));

          // Zero pad the rest
          ZeroPadding.pad(data, blockSize);
        },
        unpad: function unpad(data) {
          var _data = data;

          // Remove zero padding
          ZeroPadding.unpad(_data);

          // Remove one more byte -- the 0x80 byte
          _data.sigBytes -= 1;
        }
      });
    }
  };
});

System.register("chunks:///_virtual/pad-nopadding.js", [], function (exports) {
  return {
    execute: function () {
      /**
       * A noop padding strategy.
       */
      var NoPadding = exports('NoPadding', {
        pad: function pad() {},
        unpad: function unpad() {}
      });
    }
  };
});

System.register("chunks:///_virtual/pad-zeropadding.js", [], function (exports) {
  return {
    execute: function () {
      /**
       * Zero padding strategy.
       */
      var ZeroPadding = exports('ZeroPadding', {
        pad: function pad(data, blockSize) {
          var _data = data;

          // Shortcut
          var blockSizeBytes = blockSize * 4;

          // Pad
          _data.clamp();
          _data.sigBytes += blockSizeBytes - (data.sigBytes % blockSizeBytes || blockSizeBytes);
        },
        unpad: function unpad(data) {
          var _data = data;

          // Shortcut
          var dataWords = _data.words;

          // Unpad
          for (var i = _data.sigBytes - 1; i >= 0; i -= 1) {
            if (dataWords[i >>> 2] >>> 24 - i % 4 * 8 & 0xff) {
              _data.sigBytes = i + 1;
              break;
            }
          }
        }
      });
    }
  };
});

System.register("chunks:///_virtual/pbkdf2.js", ['./rollupPluginModLoBabelHelpers.js', './core.js', './sha256.js'], function (exports) {
  var _inheritsLoose, Base, HMAC, WordArray, SHA256Algo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      Base = module.Base;
      HMAC = module.HMAC;
      WordArray = module.WordArray;
    }, function (module) {
      SHA256Algo = module.SHA256Algo;
    }],
    execute: function () {
      /**
       * Password-Based Key Derivation Function 2 algorithm.
       */
      var PBKDF2Algo = exports('PBKDF2Algo', /*#__PURE__*/function (_Base) {
        _inheritsLoose(PBKDF2Algo, _Base);
        /**
         * Initializes a newly created key derivation function.
         *
         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
         *
         * @example
         *
         *     const kdf = CryptoJS.algo.PBKDF2.create();
         *     const kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8 });
         *     const kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8, iterations: 1000 });
         */
        function PBKDF2Algo(cfg) {
          var _this;
          _this = _Base.call(this) || this;

          /**
           * Configuration options.
           * 
           * The default `hasher` and `interations` is different from CryptoJs to enhance security:
           * https://github.com/entronad/crypto-es/security/advisories/GHSA-mpj8-q39x-wq5h
           *
           * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
           * @property {Hasher} hasher The hasher to use. Default: SHA256
           * @property {number} iterations The number of iterations to perform. Default: 250000
           */
          _this.cfg = Object.assign(new Base(), {
            keySize: 128 / 32,
            hasher: SHA256Algo,
            iterations: 250000
          }, cfg);
          return _this;
        }

        /**
         * Computes the Password-Based Key Derivation Function 2.
         *
         * @param {WordArray|string} password The password.
         * @param {WordArray|string} salt A salt.
         *
         * @return {WordArray} The derived key.
         *
         * @example
         *
         *     const key = kdf.compute(password, salt);
         */
        var _proto = PBKDF2Algo.prototype;
        _proto.compute = function compute(password, salt) {
          // Shortcut
          var cfg = this.cfg;

          // Init HMAC
          var hmac = HMAC.create(cfg.hasher, password);

          // Initial values
          var derivedKey = WordArray.create();
          var blockIndex = WordArray.create([0x00000001]);

          // Shortcuts
          var derivedKeyWords = derivedKey.words;
          var blockIndexWords = blockIndex.words;
          var keySize = cfg.keySize,
            iterations = cfg.iterations;

          // Generate key
          while (derivedKeyWords.length < keySize) {
            var block = hmac.update(salt).finalize(blockIndex);
            hmac.reset();

            // Shortcuts
            var blockWords = block.words;
            var blockWordsLength = blockWords.length;

            // Iterations
            var intermediate = block;
            for (var i = 1; i < iterations; i += 1) {
              intermediate = hmac.finalize(intermediate);
              hmac.reset();

              // Shortcut
              var intermediateWords = intermediate.words;

              // XOR intermediate with block
              for (var j = 0; j < blockWordsLength; j += 1) {
                blockWords[j] ^= intermediateWords[j];
              }
            }
            derivedKey.concat(block);
            blockIndexWords[0] += 1;
          }
          derivedKey.sigBytes = keySize * 4;
          return derivedKey;
        };
        return PBKDF2Algo;
      }(Base));

      /**
       * Computes the Password-Based Key Derivation Function 2.
       *
       * @param {WordArray|string} password The password.
       * @param {WordArray|string} salt A salt.
       * @param {Object} cfg (Optional) The configuration options to use for this computation.
       *
       * @return {WordArray} The derived key.
       *
       * @static
       *
       * @example
       *
       *     var key = CryptoJS.PBKDF2(password, salt);
       *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8 });
       *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
       */
      var PBKDF2 = exports('PBKDF2', function PBKDF2(password, salt, cfg) {
        return PBKDF2Algo.create(cfg).compute(password, salt);
      });
    }
  };
});

System.register("chunks:///_virtual/rabbit-legacy.js", ['./rollupPluginModLoBabelHelpers.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, StreamCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      StreamCipher = module.StreamCipher;
    }],
    execute: function () {
      // Reusable objects
      var S = [];
      var C_ = [];
      var G = [];
      function nextState() {
        // Shortcuts
        var X = this._X;
        var C = this._C;

        // Save old counter values
        for (var i = 0; i < 8; i += 1) {
          C_[i] = C[i];
        }

        // Calculate new counter values
        C[0] = C[0] + 0x4d34d34d + this._b | 0;
        C[1] = C[1] + 0xd34d34d3 + (C[0] >>> 0 < C_[0] >>> 0 ? 1 : 0) | 0;
        C[2] = C[2] + 0x34d34d34 + (C[1] >>> 0 < C_[1] >>> 0 ? 1 : 0) | 0;
        C[3] = C[3] + 0x4d34d34d + (C[2] >>> 0 < C_[2] >>> 0 ? 1 : 0) | 0;
        C[4] = C[4] + 0xd34d34d3 + (C[3] >>> 0 < C_[3] >>> 0 ? 1 : 0) | 0;
        C[5] = C[5] + 0x34d34d34 + (C[4] >>> 0 < C_[4] >>> 0 ? 1 : 0) | 0;
        C[6] = C[6] + 0x4d34d34d + (C[5] >>> 0 < C_[5] >>> 0 ? 1 : 0) | 0;
        C[7] = C[7] + 0xd34d34d3 + (C[6] >>> 0 < C_[6] >>> 0 ? 1 : 0) | 0;
        this._b = C[7] >>> 0 < C_[7] >>> 0 ? 1 : 0;

        // Calculate the g-values
        for (var _i = 0; _i < 8; _i += 1) {
          var gx = X[_i] + C[_i];

          // Construct high and low argument for squaring
          var ga = gx & 0xffff;
          var gb = gx >>> 16;

          // Calculate high and low result of squaring
          var gh = ((ga * ga >>> 17) + ga * gb >>> 15) + gb * gb;
          var gl = ((gx & 0xffff0000) * gx | 0) + ((gx & 0x0000ffff) * gx | 0);

          // High XOR low
          G[_i] = gh ^ gl;
        }

        // Calculate new state values
        X[0] = G[0] + (G[7] << 16 | G[7] >>> 16) + (G[6] << 16 | G[6] >>> 16) | 0;
        X[1] = G[1] + (G[0] << 8 | G[0] >>> 24) + G[7] | 0;
        X[2] = G[2] + (G[1] << 16 | G[1] >>> 16) + (G[0] << 16 | G[0] >>> 16) | 0;
        X[3] = G[3] + (G[2] << 8 | G[2] >>> 24) + G[1] | 0;
        X[4] = G[4] + (G[3] << 16 | G[3] >>> 16) + (G[2] << 16 | G[2] >>> 16) | 0;
        X[5] = G[5] + (G[4] << 8 | G[4] >>> 24) + G[3] | 0;
        X[6] = G[6] + (G[5] << 16 | G[5] >>> 16) + (G[4] << 16 | G[4] >>> 16) | 0;
        X[7] = G[7] + (G[6] << 8 | G[6] >>> 24) + G[5] | 0;
      }

      /**
       * Rabbit stream cipher algorithm.
       *
       * This is a legacy version that neglected to convert the key to little-endian.
       * This error doesn't affect the cipher's security,
       * but it does affect its compatibility with other implementations.
       */
      var RabbitLegacyAlgo = exports('RabbitLegacyAlgo', /*#__PURE__*/function (_StreamCipher) {
        _inheritsLoose(RabbitLegacyAlgo, _StreamCipher);
        function RabbitLegacyAlgo() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _StreamCipher.call.apply(_StreamCipher, [this].concat(args)) || this;
          _this.blockSize = 128 / 32;
          _this.ivSize = 64 / 32;
          return _this;
        }
        var _proto = RabbitLegacyAlgo.prototype;
        _proto._doReset = function _doReset() {
          // Shortcuts
          var K = this._key.words;
          var iv = this.cfg.iv;

          // Generate initial state values
          this._X = [K[0], K[3] << 16 | K[2] >>> 16, K[1], K[0] << 16 | K[3] >>> 16, K[2], K[1] << 16 | K[0] >>> 16, K[3], K[2] << 16 | K[1] >>> 16];
          var X = this._X;

          // Generate initial counter values
          this._C = [K[2] << 16 | K[2] >>> 16, K[0] & 0xffff0000 | K[1] & 0x0000ffff, K[3] << 16 | K[3] >>> 16, K[1] & 0xffff0000 | K[2] & 0x0000ffff, K[0] << 16 | K[0] >>> 16, K[2] & 0xffff0000 | K[3] & 0x0000ffff, K[1] << 16 | K[1] >>> 16, K[3] & 0xffff0000 | K[0] & 0x0000ffff];
          var C = this._C;

          // Carry bit
          this._b = 0;

          // Iterate the system four times
          for (var i = 0; i < 4; i += 1) {
            nextState.call(this);
          }

          // Modify the counters
          for (var _i2 = 0; _i2 < 8; _i2 += 1) {
            C[_i2] ^= X[_i2 + 4 & 7];
          }

          // IV setup
          if (iv) {
            // Shortcuts
            var IV = iv.words;
            var IV_0 = IV[0];
            var IV_1 = IV[1];

            // Generate four subvectors
            var i0 = (IV_0 << 8 | IV_0 >>> 24) & 0x00ff00ff | (IV_0 << 24 | IV_0 >>> 8) & 0xff00ff00;
            var i2 = (IV_1 << 8 | IV_1 >>> 24) & 0x00ff00ff | (IV_1 << 24 | IV_1 >>> 8) & 0xff00ff00;
            var i1 = i0 >>> 16 | i2 & 0xffff0000;
            var i3 = i2 << 16 | i0 & 0x0000ffff;

            // Modify counter values
            C[0] ^= i0;
            C[1] ^= i1;
            C[2] ^= i2;
            C[3] ^= i3;
            C[4] ^= i0;
            C[5] ^= i1;
            C[6] ^= i2;
            C[7] ^= i3;

            // Iterate the system four times
            for (var _i3 = 0; _i3 < 4; _i3 += 1) {
              nextState.call(this);
            }
          }
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;

          // Shortcut
          var X = this._X;

          // Iterate the system
          nextState.call(this);

          // Generate four keystream words
          S[0] = X[0] ^ X[5] >>> 16 ^ X[3] << 16;
          S[1] = X[2] ^ X[7] >>> 16 ^ X[5] << 16;
          S[2] = X[4] ^ X[1] >>> 16 ^ X[7] << 16;
          S[3] = X[6] ^ X[3] >>> 16 ^ X[1] << 16;
          for (var i = 0; i < 4; i += 1) {
            // Swap endian
            S[i] = (S[i] << 8 | S[i] >>> 24) & 0x00ff00ff | (S[i] << 24 | S[i] >>> 8) & 0xff00ff00;

            // Encrypt
            _M[offset + i] ^= S[i];
          }
        };
        return RabbitLegacyAlgo;
      }(StreamCipher));

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.RabbitLegacy.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.RabbitLegacy.decrypt(ciphertext, key, cfg);
       */
      var RabbitLegacy = exports('RabbitLegacy', StreamCipher._createHelper(RabbitLegacyAlgo));
    }
  };
});

System.register("chunks:///_virtual/rabbit.js", ['./rollupPluginModLoBabelHelpers.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, StreamCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      StreamCipher = module.StreamCipher;
    }],
    execute: function () {
      // Reusable objects
      var S = [];
      var C_ = [];
      var G = [];
      function nextState() {
        // Shortcuts
        var X = this._X;
        var C = this._C;

        // Save old counter values
        for (var i = 0; i < 8; i += 1) {
          C_[i] = C[i];
        }

        // Calculate new counter values
        C[0] = C[0] + 0x4d34d34d + this._b | 0;
        C[1] = C[1] + 0xd34d34d3 + (C[0] >>> 0 < C_[0] >>> 0 ? 1 : 0) | 0;
        C[2] = C[2] + 0x34d34d34 + (C[1] >>> 0 < C_[1] >>> 0 ? 1 : 0) | 0;
        C[3] = C[3] + 0x4d34d34d + (C[2] >>> 0 < C_[2] >>> 0 ? 1 : 0) | 0;
        C[4] = C[4] + 0xd34d34d3 + (C[3] >>> 0 < C_[3] >>> 0 ? 1 : 0) | 0;
        C[5] = C[5] + 0x34d34d34 + (C[4] >>> 0 < C_[4] >>> 0 ? 1 : 0) | 0;
        C[6] = C[6] + 0x4d34d34d + (C[5] >>> 0 < C_[5] >>> 0 ? 1 : 0) | 0;
        C[7] = C[7] + 0xd34d34d3 + (C[6] >>> 0 < C_[6] >>> 0 ? 1 : 0) | 0;
        this._b = C[7] >>> 0 < C_[7] >>> 0 ? 1 : 0;

        // Calculate the g-values
        for (var _i = 0; _i < 8; _i += 1) {
          var gx = X[_i] + C[_i];

          // Construct high and low argument for squaring
          var ga = gx & 0xffff;
          var gb = gx >>> 16;

          // Calculate high and low result of squaring
          var gh = ((ga * ga >>> 17) + ga * gb >>> 15) + gb * gb;
          var gl = ((gx & 0xffff0000) * gx | 0) + ((gx & 0x0000ffff) * gx | 0);

          // High XOR low
          G[_i] = gh ^ gl;
        }

        // Calculate new state values
        X[0] = G[0] + (G[7] << 16 | G[7] >>> 16) + (G[6] << 16 | G[6] >>> 16) | 0;
        X[1] = G[1] + (G[0] << 8 | G[0] >>> 24) + G[7] | 0;
        X[2] = G[2] + (G[1] << 16 | G[1] >>> 16) + (G[0] << 16 | G[0] >>> 16) | 0;
        X[3] = G[3] + (G[2] << 8 | G[2] >>> 24) + G[1] | 0;
        X[4] = G[4] + (G[3] << 16 | G[3] >>> 16) + (G[2] << 16 | G[2] >>> 16) | 0;
        X[5] = G[5] + (G[4] << 8 | G[4] >>> 24) + G[3] | 0;
        X[6] = G[6] + (G[5] << 16 | G[5] >>> 16) + (G[4] << 16 | G[4] >>> 16) | 0;
        X[7] = G[7] + (G[6] << 8 | G[6] >>> 24) + G[5] | 0;
      }

      /**
       * Rabbit stream cipher algorithm
       */
      var RabbitAlgo = exports('RabbitAlgo', /*#__PURE__*/function (_StreamCipher) {
        _inheritsLoose(RabbitAlgo, _StreamCipher);
        function RabbitAlgo() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _StreamCipher.call.apply(_StreamCipher, [this].concat(args)) || this;
          _this.blockSize = 128 / 32;
          _this.ivSize = 64 / 32;
          return _this;
        }
        var _proto = RabbitAlgo.prototype;
        _proto._doReset = function _doReset() {
          // Shortcuts
          var K = this._key.words;
          var iv = this.cfg.iv;

          // Swap endian
          for (var i = 0; i < 4; i += 1) {
            K[i] = (K[i] << 8 | K[i] >>> 24) & 0x00ff00ff | (K[i] << 24 | K[i] >>> 8) & 0xff00ff00;
          }

          // Generate initial state values
          this._X = [K[0], K[3] << 16 | K[2] >>> 16, K[1], K[0] << 16 | K[3] >>> 16, K[2], K[1] << 16 | K[0] >>> 16, K[3], K[2] << 16 | K[1] >>> 16];
          var X = this._X;

          // Generate initial counter values
          this._C = [K[2] << 16 | K[2] >>> 16, K[0] & 0xffff0000 | K[1] & 0x0000ffff, K[3] << 16 | K[3] >>> 16, K[1] & 0xffff0000 | K[2] & 0x0000ffff, K[0] << 16 | K[0] >>> 16, K[2] & 0xffff0000 | K[3] & 0x0000ffff, K[1] << 16 | K[1] >>> 16, K[3] & 0xffff0000 | K[0] & 0x0000ffff];
          var C = this._C;

          // Carry bit
          this._b = 0;

          // Iterate the system four times
          for (var _i2 = 0; _i2 < 4; _i2 += 1) {
            nextState.call(this);
          }

          // Modify the counters
          for (var _i3 = 0; _i3 < 8; _i3 += 1) {
            C[_i3] ^= X[_i3 + 4 & 7];
          }

          // IV setup
          if (iv) {
            // Shortcuts
            var IV = iv.words;
            var IV_0 = IV[0];
            var IV_1 = IV[1];

            // Generate four subvectors
            var i0 = (IV_0 << 8 | IV_0 >>> 24) & 0x00ff00ff | (IV_0 << 24 | IV_0 >>> 8) & 0xff00ff00;
            var i2 = (IV_1 << 8 | IV_1 >>> 24) & 0x00ff00ff | (IV_1 << 24 | IV_1 >>> 8) & 0xff00ff00;
            var i1 = i0 >>> 16 | i2 & 0xffff0000;
            var i3 = i2 << 16 | i0 & 0x0000ffff;

            // Modify counter values
            C[0] ^= i0;
            C[1] ^= i1;
            C[2] ^= i2;
            C[3] ^= i3;
            C[4] ^= i0;
            C[5] ^= i1;
            C[6] ^= i2;
            C[7] ^= i3;

            // Iterate the system four times
            for (var _i4 = 0; _i4 < 4; _i4 += 1) {
              nextState.call(this);
            }
          }
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;

          // Shortcut
          var X = this._X;

          // Iterate the system
          nextState.call(this);

          // Generate four keystream words
          S[0] = X[0] ^ X[5] >>> 16 ^ X[3] << 16;
          S[1] = X[2] ^ X[7] >>> 16 ^ X[5] << 16;
          S[2] = X[4] ^ X[1] >>> 16 ^ X[7] << 16;
          S[3] = X[6] ^ X[3] >>> 16 ^ X[1] << 16;
          for (var i = 0; i < 4; i += 1) {
            // Swap endian
            S[i] = (S[i] << 8 | S[i] >>> 24) & 0x00ff00ff | (S[i] << 24 | S[i] >>> 8) & 0xff00ff00;

            // Encrypt
            _M[offset + i] ^= S[i];
          }
        };
        return RabbitAlgo;
      }(StreamCipher));

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.Rabbit.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.Rabbit.decrypt(ciphertext, key, cfg);
       */
      var Rabbit = exports('Rabbit', StreamCipher._createHelper(RabbitAlgo));
    }
  };
});

System.register("chunks:///_virtual/rc4.js", ['./rollupPluginModLoBabelHelpers.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, StreamCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      StreamCipher = module.StreamCipher;
    }],
    execute: function () {
      function generateKeystreamWord() {
        // Shortcuts
        var S = this._S;
        var i = this._i;
        var j = this._j;

        // Generate keystream word
        var keystreamWord = 0;
        for (var n = 0; n < 4; n += 1) {
          i = (i + 1) % 256;
          j = (j + S[i]) % 256;

          // Swap
          var t = S[i];
          S[i] = S[j];
          S[j] = t;
          keystreamWord |= S[(S[i] + S[j]) % 256] << 24 - n * 8;
        }

        // Update counters
        this._i = i;
        this._j = j;
        return keystreamWord;
      }

      /**
       * RC4 stream cipher algorithm.
       */
      var RC4Algo = exports('RC4Algo', /*#__PURE__*/function (_StreamCipher) {
        _inheritsLoose(RC4Algo, _StreamCipher);
        function RC4Algo() {
          return _StreamCipher.apply(this, arguments) || this;
        }
        var _proto = RC4Algo.prototype;
        _proto._doReset = function _doReset() {
          // Shortcuts
          var key = this._key;
          var keyWords = key.words;
          var keySigBytes = key.sigBytes;

          // Init sbox
          this._S = [];
          var S = this._S;
          for (var i = 0; i < 256; i += 1) {
            S[i] = i;
          }

          // Key setup
          for (var _i = 0, j = 0; _i < 256; _i += 1) {
            var keyByteIndex = _i % keySigBytes;
            var keyByte = keyWords[keyByteIndex >>> 2] >>> 24 - keyByteIndex % 4 * 8 & 0xff;
            j = (j + S[_i] + keyByte) % 256;

            // Swap
            var t = S[_i];
            S[_i] = S[j];
            S[j] = t;
          }

          // Counters
          this._j = 0;
          this._i = this._j;
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;
          _M[offset] ^= generateKeystreamWord.call(this);
        };
        return RC4Algo;
      }(StreamCipher));
      RC4Algo.keySize = 256 / 32;
      RC4Algo.ivSize = 0;

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.RC4.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.RC4.decrypt(ciphertext, key, cfg);
       */
      var RC4 = exports('RC4', StreamCipher._createHelper(RC4Algo));

      /**
       * Modified RC4 stream cipher algorithm.
       */
      var RC4DropAlgo = exports('RC4DropAlgo', /*#__PURE__*/function (_RC4Algo) {
        _inheritsLoose(RC4DropAlgo, _RC4Algo);
        function RC4DropAlgo() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _RC4Algo.call.apply(_RC4Algo, [this].concat(args)) || this;

          /**
           * Configuration options.
           *
           * @property {number} drop The number of keystream words to drop. Default 192
           */
          Object.assign(_this.cfg, {
            drop: 192
          });
          return _this;
        }
        var _proto2 = RC4DropAlgo.prototype;
        _proto2._doReset = function _doReset() {
          _RC4Algo.prototype._doReset.call(this);

          // Drop
          for (var i = this.cfg.drop; i > 0; i -= 1) {
            generateKeystreamWord.call(this);
          }
        };
        return RC4DropAlgo;
      }(RC4Algo));

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.RC4Drop.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.RC4Drop.decrypt(ciphertext, key, cfg);
       */
      var RC4Drop = exports('RC4Drop', StreamCipher._createHelper(RC4DropAlgo));
    }
  };
});

System.register("chunks:///_virtual/reader_buffer.js", ['./cjs-loader.mjs', './reader.js', './minimal2.js'], function (exports, module) {
  var loader, __cjsMetaURL$1, __cjsMetaURL$2;
  return {
    setters: [function (module) {
      loader = module.default;
    }, function (module) {
      __cjsMetaURL$1 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$2 = module.__cjsMetaURL;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = BufferReader;

        // extends Reader
        var Reader = require("./reader");
        (BufferReader.prototype = Object.create(Reader.prototype)).constructor = BufferReader;
        var util = require("./util/minimal");

        /**
         * Constructs a new buffer reader instance.
         * @classdesc Wire format reader using node buffers.
         * @extends Reader
         * @constructor
         * @param {Buffer} buffer Buffer to read from
         */
        function BufferReader(buffer) {
          Reader.call(this, buffer);

          /**
           * Read buffer.
           * @name BufferReader#buf
           * @type {Buffer}
           */
        }

        BufferReader._configure = function () {
          /* istanbul ignore else */
          if (util.Buffer) BufferReader.prototype._slice = util.Buffer.prototype.slice;
        };

        /**
         * @override
         */
        BufferReader.prototype.string = function read_string_buffer() {
          var len = this.uint32(); // modifies pos
          return this.buf.utf8Slice ? this.buf.utf8Slice(this.pos, this.pos = Math.min(this.pos + len, this.len)) : this.buf.toString("utf-8", this.pos, this.pos = Math.min(this.pos + len, this.len));
        };

        /**
         * Reads a sequence of bytes preceeded by its length as a varint.
         * @name BufferReader#bytes
         * @function
         * @returns {Buffer} Value read
         */

        BufferReader._configure();

        // #endregion ORIGINAL CODE

        module.exports;
      }, function () {
        return {
          './reader': __cjsMetaURL$1,
          './util/minimal': __cjsMetaURL$2
        };
      });
    }
  };
});

System.register("chunks:///_virtual/reader.js", ['./cjs-loader.mjs', './minimal2.js'], function (exports, module) {
  var loader, __cjsMetaURL$1;
  return {
    setters: [function (module) {
      loader = module.default;
    }, function (module) {
      __cjsMetaURL$1 = module.__cjsMetaURL;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = Reader;
        var util = require("./util/minimal");
        var BufferReader; // cyclic

        var LongBits = util.LongBits,
          utf8 = util.utf8;

        /* istanbul ignore next */
        function indexOutOfRange(reader, writeLength) {
          return RangeError("index out of range: " + reader.pos + " + " + (writeLength || 1) + " > " + reader.len);
        }

        /**
         * Constructs a new reader instance using the specified buffer.
         * @classdesc Wire format reader using `Uint8Array` if available, otherwise `Array`.
         * @constructor
         * @param {Uint8Array} buffer Buffer to read from
         */
        function Reader(buffer) {
          /**
           * Read buffer.
           * @type {Uint8Array}
           */
          this.buf = buffer;

          /**
           * Read buffer position.
           * @type {number}
           */
          this.pos = 0;

          /**
           * Read buffer length.
           * @type {number}
           */
          this.len = buffer.length;
        }
        var create_array = typeof Uint8Array !== "undefined" ? function create_typed_array(buffer) {
          if (buffer instanceof Uint8Array || Array.isArray(buffer)) return new Reader(buffer);
          throw Error("illegal buffer");
        }
        /* istanbul ignore next */ : function create_array(buffer) {
          if (Array.isArray(buffer)) return new Reader(buffer);
          throw Error("illegal buffer");
        };
        var create = function create() {
          return util.Buffer ? function create_buffer_setup(buffer) {
            return (Reader.create = function create_buffer(buffer) {
              return util.Buffer.isBuffer(buffer) ? new BufferReader(buffer)
              /* istanbul ignore next */ : create_array(buffer);
            })(buffer);
          }
          /* istanbul ignore next */ : create_array;
        };

        /**
         * Creates a new reader using the specified buffer.
         * @function
         * @param {Uint8Array|Buffer} buffer Buffer to read from
         * @returns {Reader|BufferReader} A {@link BufferReader} if `buffer` is a Buffer, otherwise a {@link Reader}
         * @throws {Error} If `buffer` is not a valid buffer
         */
        Reader.create = create();
        Reader.prototype._slice = util.Array.prototype.subarray || /* istanbul ignore next */util.Array.prototype.slice;

        /**
         * Reads a varint as an unsigned 32 bit value.
         * @function
         * @returns {number} Value read
         */
        Reader.prototype.uint32 = function read_uint32_setup() {
          var value = 4294967295; // optimizer type-hint, tends to deopt otherwise (?!)
          return function read_uint32() {
            value = (this.buf[this.pos] & 127) >>> 0;
            if (this.buf[this.pos++] < 128) return value;
            value = (value | (this.buf[this.pos] & 127) << 7) >>> 0;
            if (this.buf[this.pos++] < 128) return value;
            value = (value | (this.buf[this.pos] & 127) << 14) >>> 0;
            if (this.buf[this.pos++] < 128) return value;
            value = (value | (this.buf[this.pos] & 127) << 21) >>> 0;
            if (this.buf[this.pos++] < 128) return value;
            value = (value | (this.buf[this.pos] & 15) << 28) >>> 0;
            if (this.buf[this.pos++] < 128) return value;

            /* istanbul ignore if */
            if ((this.pos += 5) > this.len) {
              this.pos = this.len;
              throw indexOutOfRange(this, 10);
            }
            return value;
          };
        }();

        /**
         * Reads a varint as a signed 32 bit value.
         * @returns {number} Value read
         */
        Reader.prototype.int32 = function read_int32() {
          return this.uint32() | 0;
        };

        /**
         * Reads a zig-zag encoded varint as a signed 32 bit value.
         * @returns {number} Value read
         */
        Reader.prototype.sint32 = function read_sint32() {
          var value = this.uint32();
          return value >>> 1 ^ -(value & 1) | 0;
        };

        /* eslint-disable no-invalid-this */

        function readLongVarint() {
          // tends to deopt with local vars for octet etc.
          var bits = new LongBits(0, 0);
          var i = 0;
          if (this.len - this.pos > 4) {
            // fast route (lo)
            for (; i < 4; ++i) {
              // 1st..4th
              bits.lo = (bits.lo | (this.buf[this.pos] & 127) << i * 7) >>> 0;
              if (this.buf[this.pos++] < 128) return bits;
            }
            // 5th
            bits.lo = (bits.lo | (this.buf[this.pos] & 127) << 28) >>> 0;
            bits.hi = (bits.hi | (this.buf[this.pos] & 127) >> 4) >>> 0;
            if (this.buf[this.pos++] < 128) return bits;
            i = 0;
          } else {
            for (; i < 3; ++i) {
              /* istanbul ignore if */
              if (this.pos >= this.len) throw indexOutOfRange(this);
              // 1st..3th
              bits.lo = (bits.lo | (this.buf[this.pos] & 127) << i * 7) >>> 0;
              if (this.buf[this.pos++] < 128) return bits;
            }
            // 4th
            bits.lo = (bits.lo | (this.buf[this.pos++] & 127) << i * 7) >>> 0;
            return bits;
          }
          if (this.len - this.pos > 4) {
            // fast route (hi)
            for (; i < 5; ++i) {
              // 6th..10th
              bits.hi = (bits.hi | (this.buf[this.pos] & 127) << i * 7 + 3) >>> 0;
              if (this.buf[this.pos++] < 128) return bits;
            }
          } else {
            for (; i < 5; ++i) {
              /* istanbul ignore if */
              if (this.pos >= this.len) throw indexOutOfRange(this);
              // 6th..10th
              bits.hi = (bits.hi | (this.buf[this.pos] & 127) << i * 7 + 3) >>> 0;
              if (this.buf[this.pos++] < 128) return bits;
            }
          }
          /* istanbul ignore next */
          throw Error("invalid varint encoding");
        }

        /* eslint-enable no-invalid-this */

        /**
         * Reads a varint as a signed 64 bit value.
         * @name Reader#int64
         * @function
         * @returns {Long} Value read
         */

        /**
         * Reads a varint as an unsigned 64 bit value.
         * @name Reader#uint64
         * @function
         * @returns {Long} Value read
         */

        /**
         * Reads a zig-zag encoded varint as a signed 64 bit value.
         * @name Reader#sint64
         * @function
         * @returns {Long} Value read
         */

        /**
         * Reads a varint as a boolean.
         * @returns {boolean} Value read
         */
        Reader.prototype.bool = function read_bool() {
          return this.uint32() !== 0;
        };
        function readFixed32_end(buf, end) {
          // note that this uses `end`, not `pos`
          return (buf[end - 4] | buf[end - 3] << 8 | buf[end - 2] << 16 | buf[end - 1] << 24) >>> 0;
        }

        /**
         * Reads fixed 32 bits as an unsigned 32 bit integer.
         * @returns {number} Value read
         */
        Reader.prototype.fixed32 = function read_fixed32() {
          /* istanbul ignore if */
          if (this.pos + 4 > this.len) throw indexOutOfRange(this, 4);
          return readFixed32_end(this.buf, this.pos += 4);
        };

        /**
         * Reads fixed 32 bits as a signed 32 bit integer.
         * @returns {number} Value read
         */
        Reader.prototype.sfixed32 = function read_sfixed32() {
          /* istanbul ignore if */
          if (this.pos + 4 > this.len) throw indexOutOfRange(this, 4);
          return readFixed32_end(this.buf, this.pos += 4) | 0;
        };

        /* eslint-disable no-invalid-this */

        function readFixed64( /* this: Reader */
        ) {
          /* istanbul ignore if */
          if (this.pos + 8 > this.len) throw indexOutOfRange(this, 8);
          return new LongBits(readFixed32_end(this.buf, this.pos += 4), readFixed32_end(this.buf, this.pos += 4));
        }

        /* eslint-enable no-invalid-this */

        /**
         * Reads fixed 64 bits.
         * @name Reader#fixed64
         * @function
         * @returns {Long} Value read
         */

        /**
         * Reads zig-zag encoded fixed 64 bits.
         * @name Reader#sfixed64
         * @function
         * @returns {Long} Value read
         */

        /**
         * Reads a float (32 bit) as a number.
         * @function
         * @returns {number} Value read
         */
        Reader.prototype["float"] = function read_float() {
          /* istanbul ignore if */
          if (this.pos + 4 > this.len) throw indexOutOfRange(this, 4);
          var value = util["float"].readFloatLE(this.buf, this.pos);
          this.pos += 4;
          return value;
        };

        /**
         * Reads a double (64 bit float) as a number.
         * @function
         * @returns {number} Value read
         */
        Reader.prototype["double"] = function read_double() {
          /* istanbul ignore if */
          if (this.pos + 8 > this.len) throw indexOutOfRange(this, 4);
          var value = util["float"].readDoubleLE(this.buf, this.pos);
          this.pos += 8;
          return value;
        };

        /**
         * Reads a sequence of bytes preceeded by its length as a varint.
         * @returns {Uint8Array} Value read
         */
        Reader.prototype.bytes = function read_bytes() {
          var length = this.uint32(),
            start = this.pos,
            end = this.pos + length;

          /* istanbul ignore if */
          if (end > this.len) throw indexOutOfRange(this, length);
          this.pos += length;
          if (Array.isArray(this.buf))
            // plain array
            return this.buf.slice(start, end);
          if (start === end) {
            // fix for IE 10/Win8 and others' subarray returning array of size 1
            var nativeBuffer = util.Buffer;
            return nativeBuffer ? nativeBuffer.alloc(0) : new this.buf.constructor(0);
          }
          return this._slice.call(this.buf, start, end);
        };

        /**
         * Reads a string preceeded by its byte length as a varint.
         * @returns {string} Value read
         */
        Reader.prototype.string = function read_string() {
          var bytes = this.bytes();
          return utf8.read(bytes, 0, bytes.length);
        };

        /**
         * Skips the specified number of bytes if specified, otherwise skips a varint.
         * @param {number} [length] Length if known, otherwise a varint is assumed
         * @returns {Reader} `this`
         */
        Reader.prototype.skip = function skip(length) {
          if (typeof length === "number") {
            /* istanbul ignore if */
            if (this.pos + length > this.len) throw indexOutOfRange(this, length);
            this.pos += length;
          } else {
            do {
              /* istanbul ignore if */
              if (this.pos >= this.len) throw indexOutOfRange(this);
            } while (this.buf[this.pos++] & 128);
          }
          return this;
        };

        /**
         * Skips the next element of the specified wire type.
         * @param {number} wireType Wire type received
         * @returns {Reader} `this`
         */
        Reader.prototype.skipType = function (wireType) {
          switch (wireType) {
            case 0:
              this.skip();
              break;
            case 1:
              this.skip(8);
              break;
            case 2:
              this.skip(this.uint32());
              break;
            case 3:
              while ((wireType = this.uint32() & 7) !== 4) {
                this.skipType(wireType);
              }
              break;
            case 5:
              this.skip(4);
              break;

            /* istanbul ignore next */
            default:
              throw Error("invalid wire type " + wireType + " at offset " + this.pos);
          }
          return this;
        };
        Reader._configure = function (BufferReader_) {
          BufferReader = BufferReader_;
          Reader.create = create();
          BufferReader._configure();
          var fn = util.Long ? "toLong" : /* istanbul ignore next */"toNumber";
          util.merge(Reader.prototype, {
            int64: function read_int64() {
              return readLongVarint.call(this)[fn](false);
            },
            uint64: function read_uint64() {
              return readLongVarint.call(this)[fn](true);
            },
            sint64: function read_sint64() {
              return readLongVarint.call(this).zzDecode()[fn](false);
            },
            fixed64: function read_fixed64() {
              return readFixed64.call(this)[fn](true);
            },
            sfixed64: function read_sfixed64() {
              return readFixed64.call(this)[fn](false);
            }
          });
        };

        // #endregion ORIGINAL CODE

        module.exports;
      }, function () {
        return {
          './util/minimal': __cjsMetaURL$1
        };
      });
    }
  };
});

System.register("chunks:///_virtual/ripemd160.js", ['./rollupPluginModLoBabelHelpers.js', './core.js'], function (exports) {
  var _inheritsLoose, WordArray, Hasher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      WordArray = module.WordArray;
      Hasher = module.Hasher;
    }],
    execute: function () {
      // Constants table
      var _zl = WordArray.create([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]);
      var _zr = WordArray.create([5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]);
      var _sl = WordArray.create([11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]);
      var _sr = WordArray.create([8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]);
      var _hl = WordArray.create([0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]);
      var _hr = WordArray.create([0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]);
      var f1 = function f1(x, y, z) {
        return x ^ y ^ z;
      };
      var f2 = function f2(x, y, z) {
        return x & y | ~x & z;
      };
      var f3 = function f3(x, y, z) {
        return (x | ~y) ^ z;
      };
      var f4 = function f4(x, y, z) {
        return x & z | y & ~z;
      };
      var f5 = function f5(x, y, z) {
        return x ^ (y | ~z);
      };
      var rotl = function rotl(x, n) {
        return x << n | x >>> 32 - n;
      };

      /**
       * RIPEMD160 hash algorithm.
       */
      var RIPEMD160Algo = exports('RIPEMD160Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(RIPEMD160Algo, _Hasher);
        function RIPEMD160Algo() {
          return _Hasher.apply(this, arguments) || this;
        }
        var _proto = RIPEMD160Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;

          // Swap endian
          for (var i = 0; i < 16; i += 1) {
            // Shortcuts
            var offset_i = offset + i;
            var M_offset_i = _M[offset_i];

            // Swap
            _M[offset_i] = (M_offset_i << 8 | M_offset_i >>> 24) & 0x00ff00ff | (M_offset_i << 24 | M_offset_i >>> 8) & 0xff00ff00;
          }
          // Shortcut
          var H = this._hash.words;
          var hl = _hl.words;
          var hr = _hr.words;
          var zl = _zl.words;
          var zr = _zr.words;
          var sl = _sl.words;
          var sr = _sr.words;

          // Working variables
          var al = H[0];
          var bl = H[1];
          var cl = H[2];
          var dl = H[3];
          var el = H[4];
          var ar = H[0];
          var br = H[1];
          var cr = H[2];
          var dr = H[3];
          var er = H[4];

          // Computation
          var t;
          for (var _i = 0; _i < 80; _i += 1) {
            t = al + _M[offset + zl[_i]] | 0;
            if (_i < 16) {
              t += f1(bl, cl, dl) + hl[0];
            } else if (_i < 32) {
              t += f2(bl, cl, dl) + hl[1];
            } else if (_i < 48) {
              t += f3(bl, cl, dl) + hl[2];
            } else if (_i < 64) {
              t += f4(bl, cl, dl) + hl[3];
            } else {
              // if (i<80) {
              t += f5(bl, cl, dl) + hl[4];
            }
            t |= 0;
            t = rotl(t, sl[_i]);
            t = t + el | 0;
            al = el;
            el = dl;
            dl = rotl(cl, 10);
            cl = bl;
            bl = t;
            t = ar + _M[offset + zr[_i]] | 0;
            if (_i < 16) {
              t += f5(br, cr, dr) + hr[0];
            } else if (_i < 32) {
              t += f4(br, cr, dr) + hr[1];
            } else if (_i < 48) {
              t += f3(br, cr, dr) + hr[2];
            } else if (_i < 64) {
              t += f2(br, cr, dr) + hr[3];
            } else {
              // if (i<80) {
              t += f1(br, cr, dr) + hr[4];
            }
            t |= 0;
            t = rotl(t, sr[_i]);
            t = t + er | 0;
            ar = er;
            er = dr;
            dr = rotl(cr, 10);
            cr = br;
            br = t;
          }
          // Intermediate hash value
          t = H[1] + cl + dr | 0;
          H[1] = H[2] + dl + er | 0;
          H[2] = H[3] + el + ar | 0;
          H[3] = H[4] + al + br | 0;
          H[4] = H[0] + bl + cr | 0;
          H[0] = t;
        };
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 14] = (nBitsTotal << 8 | nBitsTotal >>> 24) & 0x00ff00ff | (nBitsTotal << 24 | nBitsTotal >>> 8) & 0xff00ff00;
          data.sigBytes = (dataWords.length + 1) * 4;

          // Hash final blocks
          this._process();

          // Shortcuts
          var hash = this._hash;
          var H = hash.words;

          // Swap endian
          for (var i = 0; i < 5; i += 1) {
            // Shortcut
            var H_i = H[i];

            // Swap
            H[i] = (H_i << 8 | H_i >>> 24) & 0x00ff00ff | (H_i << 24 | H_i >>> 8) & 0xff00ff00;
          }

          // Return final computed hash
          return hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return RIPEMD160Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.RIPEMD160('message');
       *     var hash = CryptoJS.RIPEMD160(wordArray);
       */
      var RIPEMD160 = exports('RIPEMD160', Hasher._createHelper(RIPEMD160Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacRIPEMD160(message, key);
       */
      var HmacRIPEMD160 = exports('HmacRIPEMD160', Hasher._createHmacHelper(RIPEMD160Algo));
    }
  };
});

System.register("chunks:///_virtual/rollupPluginModLoBabelHelpers.js", [], function (exports) {
  return {
    execute: function () {
      exports({
        applyDecoratedDescriptor: _applyDecoratedDescriptor,
        arrayLikeToArray: _arrayLikeToArray,
        assertThisInitialized: _assertThisInitialized,
        asyncToGenerator: _asyncToGenerator,
        construct: _construct,
        createClass: _createClass,
        createForOfIteratorHelperLoose: _createForOfIteratorHelperLoose,
        extends: _extends,
        getPrototypeOf: _getPrototypeOf,
        inheritsLoose: _inheritsLoose,
        initializerDefineProperty: _initializerDefineProperty,
        isNativeFunction: _isNativeFunction,
        isNativeReflectConstruct: _isNativeReflectConstruct,
        regeneratorRuntime: _regeneratorRuntime,
        setPrototypeOf: _setPrototypeOf,
        toPrimitive: _toPrimitive,
        toPropertyKey: _toPropertyKey,
        unsupportedIterableToArray: _unsupportedIterableToArray,
        wrapNativeSuper: _wrapNativeSuper
      });
      function _regeneratorRuntime() {
        /*! regenerator-runtime -- Copyright (c) 2014-present, Facebook, Inc. -- license (MIT): https://github.com/facebook/regenerator/blob/main/LICENSE */
        _regeneratorRuntime = exports('regeneratorRuntime', function () {
          return e;
        });
        var t,
          e = {},
          r = Object.prototype,
          n = r.hasOwnProperty,
          o = Object.defineProperty || function (t, e, r) {
            t[e] = r.value;
          },
          i = "function" == typeof Symbol ? Symbol : {},
          a = i.iterator || "@@iterator",
          c = i.asyncIterator || "@@asyncIterator",
          u = i.toStringTag || "@@toStringTag";
        function define(t, e, r) {
          return Object.defineProperty(t, e, {
            value: r,
            enumerable: !0,
            configurable: !0,
            writable: !0
          }), t[e];
        }
        try {
          define({}, "");
        } catch (t) {
          define = function (t, e, r) {
            return t[e] = r;
          };
        }
        function wrap(t, e, r, n) {
          var i = e && e.prototype instanceof Generator ? e : Generator,
            a = Object.create(i.prototype),
            c = new Context(n || []);
          return o(a, "_invoke", {
            value: makeInvokeMethod(t, r, c)
          }), a;
        }
        function tryCatch(t, e, r) {
          try {
            return {
              type: "normal",
              arg: t.call(e, r)
            };
          } catch (t) {
            return {
              type: "throw",
              arg: t
            };
          }
        }
        e.wrap = wrap;
        var h = "suspendedStart",
          l = "suspendedYield",
          f = "executing",
          s = "completed",
          y = {};
        function Generator() {}
        function GeneratorFunction() {}
        function GeneratorFunctionPrototype() {}
        var p = {};
        define(p, a, function () {
          return this;
        });
        var d = Object.getPrototypeOf,
          v = d && d(d(values([])));
        v && v !== r && n.call(v, a) && (p = v);
        var g = GeneratorFunctionPrototype.prototype = Generator.prototype = Object.create(p);
        function defineIteratorMethods(t) {
          ["next", "throw", "return"].forEach(function (e) {
            define(t, e, function (t) {
              return this._invoke(e, t);
            });
          });
        }
        function AsyncIterator(t, e) {
          function invoke(r, o, i, a) {
            var c = tryCatch(t[r], t, o);
            if ("throw" !== c.type) {
              var u = c.arg,
                h = u.value;
              return h && "object" == typeof h && n.call(h, "__await") ? e.resolve(h.__await).then(function (t) {
                invoke("next", t, i, a);
              }, function (t) {
                invoke("throw", t, i, a);
              }) : e.resolve(h).then(function (t) {
                u.value = t, i(u);
              }, function (t) {
                return invoke("throw", t, i, a);
              });
            }
            a(c.arg);
          }
          var r;
          o(this, "_invoke", {
            value: function (t, n) {
              function callInvokeWithMethodAndArg() {
                return new e(function (e, r) {
                  invoke(t, n, e, r);
                });
              }
              return r = r ? r.then(callInvokeWithMethodAndArg, callInvokeWithMethodAndArg) : callInvokeWithMethodAndArg();
            }
          });
        }
        function makeInvokeMethod(e, r, n) {
          var o = h;
          return function (i, a) {
            if (o === f) throw new Error("Generator is already running");
            if (o === s) {
              if ("throw" === i) throw a;
              return {
                value: t,
                done: !0
              };
            }
            for (n.method = i, n.arg = a;;) {
              var c = n.delegate;
              if (c) {
                var u = maybeInvokeDelegate(c, n);
                if (u) {
                  if (u === y) continue;
                  return u;
                }
              }
              if ("next" === n.method) n.sent = n._sent = n.arg;else if ("throw" === n.method) {
                if (o === h) throw o = s, n.arg;
                n.dispatchException(n.arg);
              } else "return" === n.method && n.abrupt("return", n.arg);
              o = f;
              var p = tryCatch(e, r, n);
              if ("normal" === p.type) {
                if (o = n.done ? s : l, p.arg === y) continue;
                return {
                  value: p.arg,
                  done: n.done
                };
              }
              "throw" === p.type && (o = s, n.method = "throw", n.arg = p.arg);
            }
          };
        }
        function maybeInvokeDelegate(e, r) {
          var n = r.method,
            o = e.iterator[n];
          if (o === t) return r.delegate = null, "throw" === n && e.iterator.return && (r.method = "return", r.arg = t, maybeInvokeDelegate(e, r), "throw" === r.method) || "return" !== n && (r.method = "throw", r.arg = new TypeError("The iterator does not provide a '" + n + "' method")), y;
          var i = tryCatch(o, e.iterator, r.arg);
          if ("throw" === i.type) return r.method = "throw", r.arg = i.arg, r.delegate = null, y;
          var a = i.arg;
          return a ? a.done ? (r[e.resultName] = a.value, r.next = e.nextLoc, "return" !== r.method && (r.method = "next", r.arg = t), r.delegate = null, y) : a : (r.method = "throw", r.arg = new TypeError("iterator result is not an object"), r.delegate = null, y);
        }
        function pushTryEntry(t) {
          var e = {
            tryLoc: t[0]
          };
          1 in t && (e.catchLoc = t[1]), 2 in t && (e.finallyLoc = t[2], e.afterLoc = t[3]), this.tryEntries.push(e);
        }
        function resetTryEntry(t) {
          var e = t.completion || {};
          e.type = "normal", delete e.arg, t.completion = e;
        }
        function Context(t) {
          this.tryEntries = [{
            tryLoc: "root"
          }], t.forEach(pushTryEntry, this), this.reset(!0);
        }
        function values(e) {
          if (e || "" === e) {
            var r = e[a];
            if (r) return r.call(e);
            if ("function" == typeof e.next) return e;
            if (!isNaN(e.length)) {
              var o = -1,
                i = function next() {
                  for (; ++o < e.length;) if (n.call(e, o)) return next.value = e[o], next.done = !1, next;
                  return next.value = t, next.done = !0, next;
                };
              return i.next = i;
            }
          }
          throw new TypeError(typeof e + " is not iterable");
        }
        return GeneratorFunction.prototype = GeneratorFunctionPrototype, o(g, "constructor", {
          value: GeneratorFunctionPrototype,
          configurable: !0
        }), o(GeneratorFunctionPrototype, "constructor", {
          value: GeneratorFunction,
          configurable: !0
        }), GeneratorFunction.displayName = define(GeneratorFunctionPrototype, u, "GeneratorFunction"), e.isGeneratorFunction = function (t) {
          var e = "function" == typeof t && t.constructor;
          return !!e && (e === GeneratorFunction || "GeneratorFunction" === (e.displayName || e.name));
        }, e.mark = function (t) {
          return Object.setPrototypeOf ? Object.setPrototypeOf(t, GeneratorFunctionPrototype) : (t.__proto__ = GeneratorFunctionPrototype, define(t, u, "GeneratorFunction")), t.prototype = Object.create(g), t;
        }, e.awrap = function (t) {
          return {
            __await: t
          };
        }, defineIteratorMethods(AsyncIterator.prototype), define(AsyncIterator.prototype, c, function () {
          return this;
        }), e.AsyncIterator = AsyncIterator, e.async = function (t, r, n, o, i) {
          void 0 === i && (i = Promise);
          var a = new AsyncIterator(wrap(t, r, n, o), i);
          return e.isGeneratorFunction(r) ? a : a.next().then(function (t) {
            return t.done ? t.value : a.next();
          });
        }, defineIteratorMethods(g), define(g, u, "Generator"), define(g, a, function () {
          return this;
        }), define(g, "toString", function () {
          return "[object Generator]";
        }), e.keys = function (t) {
          var e = Object(t),
            r = [];
          for (var n in e) r.push(n);
          return r.reverse(), function next() {
            for (; r.length;) {
              var t = r.pop();
              if (t in e) return next.value = t, next.done = !1, next;
            }
            return next.done = !0, next;
          };
        }, e.values = values, Context.prototype = {
          constructor: Context,
          reset: function (e) {
            if (this.prev = 0, this.next = 0, this.sent = this._sent = t, this.done = !1, this.delegate = null, this.method = "next", this.arg = t, this.tryEntries.forEach(resetTryEntry), !e) for (var r in this) "t" === r.charAt(0) && n.call(this, r) && !isNaN(+r.slice(1)) && (this[r] = t);
          },
          stop: function () {
            this.done = !0;
            var t = this.tryEntries[0].completion;
            if ("throw" === t.type) throw t.arg;
            return this.rval;
          },
          dispatchException: function (e) {
            if (this.done) throw e;
            var r = this;
            function handle(n, o) {
              return a.type = "throw", a.arg = e, r.next = n, o && (r.method = "next", r.arg = t), !!o;
            }
            for (var o = this.tryEntries.length - 1; o >= 0; --o) {
              var i = this.tryEntries[o],
                a = i.completion;
              if ("root" === i.tryLoc) return handle("end");
              if (i.tryLoc <= this.prev) {
                var c = n.call(i, "catchLoc"),
                  u = n.call(i, "finallyLoc");
                if (c && u) {
                  if (this.prev < i.catchLoc) return handle(i.catchLoc, !0);
                  if (this.prev < i.finallyLoc) return handle(i.finallyLoc);
                } else if (c) {
                  if (this.prev < i.catchLoc) return handle(i.catchLoc, !0);
                } else {
                  if (!u) throw new Error("try statement without catch or finally");
                  if (this.prev < i.finallyLoc) return handle(i.finallyLoc);
                }
              }
            }
          },
          abrupt: function (t, e) {
            for (var r = this.tryEntries.length - 1; r >= 0; --r) {
              var o = this.tryEntries[r];
              if (o.tryLoc <= this.prev && n.call(o, "finallyLoc") && this.prev < o.finallyLoc) {
                var i = o;
                break;
              }
            }
            i && ("break" === t || "continue" === t) && i.tryLoc <= e && e <= i.finallyLoc && (i = null);
            var a = i ? i.completion : {};
            return a.type = t, a.arg = e, i ? (this.method = "next", this.next = i.finallyLoc, y) : this.complete(a);
          },
          complete: function (t, e) {
            if ("throw" === t.type) throw t.arg;
            return "break" === t.type || "continue" === t.type ? this.next = t.arg : "return" === t.type ? (this.rval = this.arg = t.arg, this.method = "return", this.next = "end") : "normal" === t.type && e && (this.next = e), y;
          },
          finish: function (t) {
            for (var e = this.tryEntries.length - 1; e >= 0; --e) {
              var r = this.tryEntries[e];
              if (r.finallyLoc === t) return this.complete(r.completion, r.afterLoc), resetTryEntry(r), y;
            }
          },
          catch: function (t) {
            for (var e = this.tryEntries.length - 1; e >= 0; --e) {
              var r = this.tryEntries[e];
              if (r.tryLoc === t) {
                var n = r.completion;
                if ("throw" === n.type) {
                  var o = n.arg;
                  resetTryEntry(r);
                }
                return o;
              }
            }
            throw new Error("illegal catch attempt");
          },
          delegateYield: function (e, r, n) {
            return this.delegate = {
              iterator: values(e),
              resultName: r,
              nextLoc: n
            }, "next" === this.method && (this.arg = t), y;
          }
        }, e;
      }
      function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) {
        try {
          var info = gen[key](arg);
          var value = info.value;
        } catch (error) {
          reject(error);
          return;
        }
        if (info.done) {
          resolve(value);
        } else {
          Promise.resolve(value).then(_next, _throw);
        }
      }
      function _asyncToGenerator(fn) {
        return function () {
          var self = this,
            args = arguments;
          return new Promise(function (resolve, reject) {
            var gen = fn.apply(self, args);
            function _next(value) {
              asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value);
            }
            function _throw(err) {
              asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err);
            }
            _next(undefined);
          });
        };
      }
      function _defineProperties(target, props) {
        for (var i = 0; i < props.length; i++) {
          var descriptor = props[i];
          descriptor.enumerable = descriptor.enumerable || false;
          descriptor.configurable = true;
          if ("value" in descriptor) descriptor.writable = true;
          Object.defineProperty(target, _toPropertyKey(descriptor.key), descriptor);
        }
      }
      function _createClass(Constructor, protoProps, staticProps) {
        if (protoProps) _defineProperties(Constructor.prototype, protoProps);
        if (staticProps) _defineProperties(Constructor, staticProps);
        Object.defineProperty(Constructor, "prototype", {
          writable: false
        });
        return Constructor;
      }
      function _extends() {
        _extends = exports('extends', Object.assign ? Object.assign.bind() : function (target) {
          for (var i = 1; i < arguments.length; i++) {
            var source = arguments[i];
            for (var key in source) {
              if (Object.prototype.hasOwnProperty.call(source, key)) {
                target[key] = source[key];
              }
            }
          }
          return target;
        });
        return _extends.apply(this, arguments);
      }
      function _inheritsLoose(subClass, superClass) {
        subClass.prototype = Object.create(superClass.prototype);
        subClass.prototype.constructor = subClass;
        _setPrototypeOf(subClass, superClass);
      }
      function _getPrototypeOf(o) {
        _getPrototypeOf = exports('getPrototypeOf', Object.setPrototypeOf ? Object.getPrototypeOf.bind() : function _getPrototypeOf(o) {
          return o.__proto__ || Object.getPrototypeOf(o);
        });
        return _getPrototypeOf(o);
      }
      function _setPrototypeOf(o, p) {
        _setPrototypeOf = exports('setPrototypeOf', Object.setPrototypeOf ? Object.setPrototypeOf.bind() : function _setPrototypeOf(o, p) {
          o.__proto__ = p;
          return o;
        });
        return _setPrototypeOf(o, p);
      }
      function _isNativeReflectConstruct() {
        if (typeof Reflect === "undefined" || !Reflect.construct) return false;
        if (Reflect.construct.sham) return false;
        if (typeof Proxy === "function") return true;
        try {
          Boolean.prototype.valueOf.call(Reflect.construct(Boolean, [], function () {}));
          return true;
        } catch (e) {
          return false;
        }
      }
      function _construct(Parent, args, Class) {
        if (_isNativeReflectConstruct()) {
          _construct = exports('construct', Reflect.construct.bind());
        } else {
          _construct = exports('construct', function _construct(Parent, args, Class) {
            var a = [null];
            a.push.apply(a, args);
            var Constructor = Function.bind.apply(Parent, a);
            var instance = new Constructor();
            if (Class) _setPrototypeOf(instance, Class.prototype);
            return instance;
          });
        }
        return _construct.apply(null, arguments);
      }
      function _isNativeFunction(fn) {
        return Function.toString.call(fn).indexOf("[native code]") !== -1;
      }
      function _wrapNativeSuper(Class) {
        var _cache = typeof Map === "function" ? new Map() : undefined;
        _wrapNativeSuper = exports('wrapNativeSuper', function _wrapNativeSuper(Class) {
          if (Class === null || !_isNativeFunction(Class)) return Class;
          if (typeof Class !== "function") {
            throw new TypeError("Super expression must either be null or a function");
          }
          if (typeof _cache !== "undefined") {
            if (_cache.has(Class)) return _cache.get(Class);
            _cache.set(Class, Wrapper);
          }
          function Wrapper() {
            return _construct(Class, arguments, _getPrototypeOf(this).constructor);
          }
          Wrapper.prototype = Object.create(Class.prototype, {
            constructor: {
              value: Wrapper,
              enumerable: false,
              writable: true,
              configurable: true
            }
          });
          return _setPrototypeOf(Wrapper, Class);
        });
        return _wrapNativeSuper(Class);
      }
      function _assertThisInitialized(self) {
        if (self === void 0) {
          throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
        }
        return self;
      }
      function _unsupportedIterableToArray(o, minLen) {
        if (!o) return;
        if (typeof o === "string") return _arrayLikeToArray(o, minLen);
        var n = Object.prototype.toString.call(o).slice(8, -1);
        if (n === "Object" && o.constructor) n = o.constructor.name;
        if (n === "Map" || n === "Set") return Array.from(o);
        if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen);
      }
      function _arrayLikeToArray(arr, len) {
        if (len == null || len > arr.length) len = arr.length;
        for (var i = 0, arr2 = new Array(len); i < len; i++) arr2[i] = arr[i];
        return arr2;
      }
      function _createForOfIteratorHelperLoose(o, allowArrayLike) {
        var it = typeof Symbol !== "undefined" && o[Symbol.iterator] || o["@@iterator"];
        if (it) return (it = it.call(o)).next.bind(it);
        if (Array.isArray(o) || (it = _unsupportedIterableToArray(o)) || allowArrayLike && o && typeof o.length === "number") {
          if (it) o = it;
          var i = 0;
          return function () {
            if (i >= o.length) return {
              done: true
            };
            return {
              done: false,
              value: o[i++]
            };
          };
        }
        throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
      }
      function _toPrimitive(input, hint) {
        if (typeof input !== "object" || input === null) return input;
        var prim = input[Symbol.toPrimitive];
        if (prim !== undefined) {
          var res = prim.call(input, hint || "default");
          if (typeof res !== "object") return res;
          throw new TypeError("@@toPrimitive must return a primitive value.");
        }
        return (hint === "string" ? String : Number)(input);
      }
      function _toPropertyKey(arg) {
        var key = _toPrimitive(arg, "string");
        return typeof key === "symbol" ? key : String(key);
      }
      function _initializerDefineProperty(target, property, descriptor, context) {
        if (!descriptor) return;
        Object.defineProperty(target, property, {
          enumerable: descriptor.enumerable,
          configurable: descriptor.configurable,
          writable: descriptor.writable,
          value: descriptor.initializer ? descriptor.initializer.call(context) : void 0
        });
      }
      function _applyDecoratedDescriptor(target, property, decorators, descriptor, context) {
        var desc = {};
        Object.keys(descriptor).forEach(function (key) {
          desc[key] = descriptor[key];
        });
        desc.enumerable = !!desc.enumerable;
        desc.configurable = !!desc.configurable;
        if ('value' in desc || desc.initializer) {
          desc.writable = true;
        }
        desc = decorators.slice().reverse().reduce(function (desc, decorator) {
          return decorator(target, property, desc) || desc;
        }, desc);
        if (context && desc.initializer !== void 0) {
          desc.value = desc.initializer ? desc.initializer.call(context) : void 0;
          desc.initializer = undefined;
        }
        if (desc.initializer === void 0) {
          Object.defineProperty(target, property, desc);
          desc = null;
        }
        return desc;
      }
    }
  };
});

System.register("chunks:///_virtual/roots.js", ['./cjs-loader.mjs'], function (exports, module) {
  var loader;
  return {
    setters: [function (module) {
      loader = module.default;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = {};

        /**
         * Named roots.
         * This is where pbjs stores generated structures (the option `-r, --root` specifies a name).
         * Can also be used manually to make roots available across modules.
         * @name roots
         * @type {Object.<string,Root>}
         * @example
         * // pbjs -r myroot -o compiled.js ...
         *
         * // in another module:
         * require("./compiled.js");
         *
         * // in any subsequent module:
         * var root = protobuf.roots["myroot"];
         */

        // #endregion ORIGINAL CODE

        module.exports;
      }, {});
    }
  };
});

System.register("chunks:///_virtual/rpc.js", ['./cjs-loader.mjs', './service.js'], function (exports, module) {
  var loader, __cjsMetaURL$1;
  return {
    setters: [function (module) {
      loader = module.default;
    }, function (module) {
      __cjsMetaURL$1 = module.__cjsMetaURL;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        /**
         * Streaming RPC helpers.
         * @namespace
         */
        var rpc = exports;

        /**
         * RPC implementation passed to {@link Service#create} performing a service request on network level, i.e. by utilizing http requests or websockets.
         * @typedef RPCImpl
         * @type {function}
         * @param {Method|rpc.ServiceMethod<Message<{}>,Message<{}>>} method Reflected or static method being called
         * @param {Uint8Array} requestData Request data
         * @param {RPCImplCallback} callback Callback function
         * @returns {undefined}
         * @example
         * function rpcImpl(method, requestData, callback) {
         *     if (protobuf.util.lcFirst(method.name) !== "myMethod") // compatible with static code
         *         throw Error("no such method");
         *     asynchronouslyObtainAResponse(requestData, function(err, responseData) {
         *         callback(err, responseData);
         *     });
         * }
         */

        /**
         * Node-style callback as used by {@link RPCImpl}.
         * @typedef RPCImplCallback
         * @type {function}
         * @param {Error|null} error Error, if any, otherwise `null`
         * @param {Uint8Array|null} [response] Response data or `null` to signal end of stream, if there hasn't been an error
         * @returns {undefined}
         */

        rpc.Service = require("./rpc/service");

        // #endregion ORIGINAL CODE

        module.exports;
      }, function () {
        return {
          './rpc/service': __cjsMetaURL$1
        };
      });
    }
  };
});

System.register("chunks:///_virtual/service.js", ['./cjs-loader.mjs', './minimal2.js'], function (exports, module) {
  var loader, __cjsMetaURL$1;
  return {
    setters: [function (module) {
      loader = module.default;
    }, function (module) {
      __cjsMetaURL$1 = module.__cjsMetaURL;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = Service;
        var util = require("../util/minimal");

        // Extends EventEmitter
        (Service.prototype = Object.create(util.EventEmitter.prototype)).constructor = Service;

        /**
         * A service method callback as used by {@link rpc.ServiceMethod|ServiceMethod}.
         *
         * Differs from {@link RPCImplCallback} in that it is an actual callback of a service method which may not return `response = null`.
         * @typedef rpc.ServiceMethodCallback
         * @template TRes extends Message<TRes>
         * @type {function}
         * @param {Error|null} error Error, if any
         * @param {TRes} [response] Response message
         * @returns {undefined}
         */

        /**
         * A service method part of a {@link rpc.Service} as created by {@link Service.create}.
         * @typedef rpc.ServiceMethod
         * @template TReq extends Message<TReq>
         * @template TRes extends Message<TRes>
         * @type {function}
         * @param {TReq|Properties<TReq>} request Request message or plain object
         * @param {rpc.ServiceMethodCallback<TRes>} [callback] Node-style callback called with the error, if any, and the response message
         * @returns {Promise<Message<TRes>>} Promise if `callback` has been omitted, otherwise `undefined`
         */

        /**
         * Constructs a new RPC service instance.
         * @classdesc An RPC service as returned by {@link Service#create}.
         * @exports rpc.Service
         * @extends util.EventEmitter
         * @constructor
         * @param {RPCImpl} rpcImpl RPC implementation
         * @param {boolean} [requestDelimited=false] Whether requests are length-delimited
         * @param {boolean} [responseDelimited=false] Whether responses are length-delimited
         */
        function Service(rpcImpl, requestDelimited, responseDelimited) {
          if (typeof rpcImpl !== "function") throw TypeError("rpcImpl must be a function");
          util.EventEmitter.call(this);

          /**
           * RPC implementation. Becomes `null` once the service is ended.
           * @type {RPCImpl|null}
           */
          this.rpcImpl = rpcImpl;

          /**
           * Whether requests are length-delimited.
           * @type {boolean}
           */
          this.requestDelimited = Boolean(requestDelimited);

          /**
           * Whether responses are length-delimited.
           * @type {boolean}
           */
          this.responseDelimited = Boolean(responseDelimited);
        }

        /**
         * Calls a service method through {@link rpc.Service#rpcImpl|rpcImpl}.
         * @param {Method|rpc.ServiceMethod<TReq,TRes>} method Reflected or static method
         * @param {Constructor<TReq>} requestCtor Request constructor
         * @param {Constructor<TRes>} responseCtor Response constructor
         * @param {TReq|Properties<TReq>} request Request message or plain object
         * @param {rpc.ServiceMethodCallback<TRes>} callback Service callback
         * @returns {undefined}
         * @template TReq extends Message<TReq>
         * @template TRes extends Message<TRes>
         */
        Service.prototype.rpcCall = function rpcCall(method, requestCtor, responseCtor, request, callback) {
          if (!request) throw TypeError("request must be specified");
          var self = this;
          if (!callback) return util.asPromise(rpcCall, self, method, requestCtor, responseCtor, request);
          if (!self.rpcImpl) {
            setTimeout(function () {
              callback(Error("already ended"));
            }, 0);
            return undefined;
          }
          try {
            return self.rpcImpl(method, requestCtor[self.requestDelimited ? "encodeDelimited" : "encode"](request).finish(), function rpcCallback(err, response) {
              if (err) {
                self.emit("error", err, method);
                return callback(err);
              }
              if (response === null) {
                self.end( /* endedByRPC */true);
                return undefined;
              }
              if (!(response instanceof responseCtor)) {
                try {
                  response = responseCtor[self.responseDelimited ? "decodeDelimited" : "decode"](response);
                } catch (err) {
                  self.emit("error", err, method);
                  return callback(err);
                }
              }
              self.emit("data", response, method);
              return callback(null, response);
            });
          } catch (err) {
            self.emit("error", err, method);
            setTimeout(function () {
              callback(err);
            }, 0);
            return undefined;
          }
        };

        /**
         * Ends this service and emits the `end` event.
         * @param {boolean} [endedByRPC=false] Whether the service has been ended by the RPC implementation.
         * @returns {rpc.Service} `this`
         */
        Service.prototype.end = function end(endedByRPC) {
          if (this.rpcImpl) {
            if (!endedByRPC)
              // signal end to rpcImpl
              this.rpcImpl(null, null, null);
            this.rpcImpl = null;
            this.emit("end").off();
          }
          return this;
        };

        // #endregion ORIGINAL CODE

        module.exports;
      }, function () {
        return {
          '../util/minimal': __cjsMetaURL$1
        };
      });
    }
  };
});

System.register("chunks:///_virtual/sha1.js", ['./rollupPluginModLoBabelHelpers.js', './core.js'], function (exports) {
  var _inheritsLoose, Hasher, WordArray;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      Hasher = module.Hasher;
      WordArray = module.WordArray;
    }],
    execute: function () {
      // Reusable object
      var W = [];

      /**
       * SHA-1 hash algorithm.
       */
      var SHA1Algo = exports('SHA1Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(SHA1Algo, _Hasher);
        function SHA1Algo() {
          return _Hasher.apply(this, arguments) || this;
        }
        var _proto = SHA1Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new WordArray([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          // Shortcut
          var H = this._hash.words;

          // Working variables
          var a = H[0];
          var b = H[1];
          var c = H[2];
          var d = H[3];
          var e = H[4];

          // Computation
          for (var i = 0; i < 80; i += 1) {
            if (i < 16) {
              W[i] = M[offset + i] | 0;
            } else {
              var n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
              W[i] = n << 1 | n >>> 31;
            }
            var t = (a << 5 | a >>> 27) + e + W[i];
            if (i < 20) {
              t += (b & c | ~b & d) + 0x5a827999;
            } else if (i < 40) {
              t += (b ^ c ^ d) + 0x6ed9eba1;
            } else if (i < 60) {
              t += (b & c | b & d | c & d) - 0x70e44324;
            } else /* if (i < 80) */{
                t += (b ^ c ^ d) - 0x359d3e2a;
              }
            e = d;
            d = c;
            c = b << 30 | b >>> 2;
            b = a;
            a = t;
          }

          // Intermediate hash value
          H[0] = H[0] + a | 0;
          H[1] = H[1] + b | 0;
          H[2] = H[2] + c | 0;
          H[3] = H[3] + d | 0;
          H[4] = H[4] + e | 0;
        };
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 15] = nBitsTotal;
          data.sigBytes = dataWords.length * 4;

          // Hash final blocks
          this._process();

          // Return final computed hash
          return this._hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return SHA1Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA1('message');
       *     var hash = CryptoJS.SHA1(wordArray);
       */
      var SHA1 = exports('SHA1', Hasher._createHelper(SHA1Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA1(message, key);
       */
      var HmacSHA1 = exports('HmacSHA1', Hasher._createHmacHelper(SHA1Algo));
    }
  };
});

System.register("chunks:///_virtual/sha224.js", ['./rollupPluginModLoBabelHelpers.js', './core.js', './sha256.js'], function (exports) {
  var _inheritsLoose, WordArray, SHA256Algo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      WordArray = module.WordArray;
    }, function (module) {
      SHA256Algo = module.SHA256Algo;
    }],
    execute: function () {
      /**
       * SHA-224 hash algorithm.
       */
      var SHA224Algo = exports('SHA224Algo', /*#__PURE__*/function (_SHA256Algo) {
        _inheritsLoose(SHA224Algo, _SHA256Algo);
        function SHA224Algo() {
          return _SHA256Algo.apply(this, arguments) || this;
        }
        var _proto = SHA224Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new WordArray([0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]);
        };
        _proto._doFinalize = function _doFinalize() {
          var hash = _SHA256Algo.prototype._doFinalize.call(this);
          hash.sigBytes -= 4;
          return hash;
        };
        return SHA224Algo;
      }(SHA256Algo));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA224('message');
       *     var hash = CryptoJS.SHA224(wordArray);
       */
      var SHA224 = exports('SHA224', SHA256Algo._createHelper(SHA224Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA224(message, key);
       */
      var HmacSHA224 = exports('HmacSHA224', SHA256Algo._createHmacHelper(SHA224Algo));
    }
  };
});

System.register("chunks:///_virtual/sha256.js", ['./rollupPluginModLoBabelHelpers.js', './core.js'], function (exports) {
  var _inheritsLoose, Hasher, WordArray;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      Hasher = module.Hasher;
      WordArray = module.WordArray;
    }],
    execute: function () {
      // Initialization and round constants tables
      var H = [];
      var K = [];

      // Compute constants
      var isPrime = function isPrime(n) {
        var sqrtN = Math.sqrt(n);
        for (var factor = 2; factor <= sqrtN; factor += 1) {
          if (!(n % factor)) {
            return false;
          }
        }
        return true;
      };
      var getFractionalBits = function getFractionalBits(n) {
        return (n - (n | 0)) * 0x100000000 | 0;
      };
      var n = 2;
      var nPrime = 0;
      while (nPrime < 64) {
        if (isPrime(n)) {
          if (nPrime < 8) {
            H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
          }
          K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));
          nPrime += 1;
        }
        n += 1;
      }

      // Reusable object
      var W = [];

      /**
       * SHA-256 hash algorithm.
       */
      var SHA256Algo = exports('SHA256Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(SHA256Algo, _Hasher);
        function SHA256Algo() {
          return _Hasher.apply(this, arguments) || this;
        }
        var _proto = SHA256Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new WordArray(H.slice(0));
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          // Shortcut
          var _H = this._hash.words;

          // Working variables
          var a = _H[0];
          var b = _H[1];
          var c = _H[2];
          var d = _H[3];
          var e = _H[4];
          var f = _H[5];
          var g = _H[6];
          var h = _H[7];

          // Computation
          for (var i = 0; i < 64; i += 1) {
            if (i < 16) {
              W[i] = M[offset + i] | 0;
            } else {
              var gamma0x = W[i - 15];
              var gamma0 = (gamma0x << 25 | gamma0x >>> 7) ^ (gamma0x << 14 | gamma0x >>> 18) ^ gamma0x >>> 3;
              var gamma1x = W[i - 2];
              var gamma1 = (gamma1x << 15 | gamma1x >>> 17) ^ (gamma1x << 13 | gamma1x >>> 19) ^ gamma1x >>> 10;
              W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
            }
            var ch = e & f ^ ~e & g;
            var maj = a & b ^ a & c ^ b & c;
            var sigma0 = (a << 30 | a >>> 2) ^ (a << 19 | a >>> 13) ^ (a << 10 | a >>> 22);
            var sigma1 = (e << 26 | e >>> 6) ^ (e << 21 | e >>> 11) ^ (e << 7 | e >>> 25);
            var t1 = h + sigma1 + ch + K[i] + W[i];
            var t2 = sigma0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1 | 0;
            d = c;
            c = b;
            b = a;
            a = t1 + t2 | 0;
          }

          // Intermediate hash value
          _H[0] = _H[0] + a | 0;
          _H[1] = _H[1] + b | 0;
          _H[2] = _H[2] + c | 0;
          _H[3] = _H[3] + d | 0;
          _H[4] = _H[4] + e | 0;
          _H[5] = _H[5] + f | 0;
          _H[6] = _H[6] + g | 0;
          _H[7] = _H[7] + h | 0;
        };
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 15] = nBitsTotal;
          data.sigBytes = dataWords.length * 4;

          // Hash final blocks
          this._process();

          // Return final computed hash
          return this._hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return SHA256Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA256('message');
       *     var hash = CryptoJS.SHA256(wordArray);
       */
      var SHA256 = exports('SHA256', Hasher._createHelper(SHA256Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA256(message, key);
       */
      var HmacSHA256 = exports('HmacSHA256', Hasher._createHmacHelper(SHA256Algo));
    }
  };
});

System.register("chunks:///_virtual/sha3.js", ['./rollupPluginModLoBabelHelpers.js', './core.js', './x64-core.js'], function (exports) {
  var _inheritsLoose, Hasher, WordArray, X64Word;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      Hasher = module.Hasher;
      WordArray = module.WordArray;
    }, function (module) {
      X64Word = module.X64Word;
    }],
    execute: function () {
      // Constants tables
      var RHO_OFFSETS = [];
      var PI_INDEXES = [];
      var ROUND_CONSTANTS = [];

      // Compute Constants
      // Compute rho offset constants
      var _x = 1;
      var _y = 0;
      for (var t = 0; t < 24; t += 1) {
        RHO_OFFSETS[_x + 5 * _y] = (t + 1) * (t + 2) / 2 % 64;
        var newX = _y % 5;
        var newY = (2 * _x + 3 * _y) % 5;
        _x = newX;
        _y = newY;
      }

      // Compute pi index constants
      for (var x = 0; x < 5; x += 1) {
        for (var y = 0; y < 5; y += 1) {
          PI_INDEXES[x + 5 * y] = y + (2 * x + 3 * y) % 5 * 5;
        }
      }

      // Compute round constants
      var LFSR = 0x01;
      for (var i = 0; i < 24; i += 1) {
        var roundConstantMsw = 0;
        var roundConstantLsw = 0;
        for (var j = 0; j < 7; j += 1) {
          if (LFSR & 0x01) {
            var bitPosition = (1 << j) - 1;
            if (bitPosition < 32) {
              roundConstantLsw ^= 1 << bitPosition;
            } else /* if (bitPosition >= 32) */{
                roundConstantMsw ^= 1 << bitPosition - 32;
              }
          }

          // Compute next LFSR
          if (LFSR & 0x80) {
            // Primitive polynomial over GF(2): x^8 + x^6 + x^5 + x^4 + 1
            LFSR = LFSR << 1 ^ 0x71;
          } else {
            LFSR <<= 1;
          }
        }
        ROUND_CONSTANTS[i] = X64Word.create(roundConstantMsw, roundConstantLsw);
      }

      // Reusable objects for temporary values
      var T = [];
      for (var _i = 0; _i < 25; _i += 1) {
        T[_i] = X64Word.create();
      }

      /**
       * SHA-3 hash algorithm.
       */
      var SHA3Algo = exports('SHA3Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(SHA3Algo, _Hasher);
        function SHA3Algo(cfg) {
          /**
           * Configuration options.
           *
           * @property {number} outputLength
           *   The desired number of bits in the output hash.
           *   Only values permitted are: 224, 256, 384, 512.
           *   Default: 512
           */
          return _Hasher.call(this, Object.assign({
            outputLength: 512
          }, cfg)) || this;
        }
        var _proto = SHA3Algo.prototype;
        _proto._doReset = function _doReset() {
          this._state = [];
          var state = this._state;
          for (var _i2 = 0; _i2 < 25; _i2 += 1) {
            state[_i2] = new X64Word();
          }
          this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          // Shortcuts
          var state = this._state;
          var nBlockSizeLanes = this.blockSize / 2;

          // Absorb
          for (var _i3 = 0; _i3 < nBlockSizeLanes; _i3 += 1) {
            // Shortcuts
            var M2i = M[offset + 2 * _i3];
            var M2i1 = M[offset + 2 * _i3 + 1];

            // Swap endian
            M2i = (M2i << 8 | M2i >>> 24) & 0x00ff00ff | (M2i << 24 | M2i >>> 8) & 0xff00ff00;
            M2i1 = (M2i1 << 8 | M2i1 >>> 24) & 0x00ff00ff | (M2i1 << 24 | M2i1 >>> 8) & 0xff00ff00;

            // Absorb message into state
            var lane = state[_i3];
            lane.high ^= M2i1;
            lane.low ^= M2i;
          }

          // Rounds
          for (var round = 0; round < 24; round += 1) {
            // Theta
            for (var _x2 = 0; _x2 < 5; _x2 += 1) {
              // Mix column lanes
              var tMsw = 0;
              var tLsw = 0;
              for (var _y2 = 0; _y2 < 5; _y2 += 1) {
                var _lane = state[_x2 + 5 * _y2];
                tMsw ^= _lane.high;
                tLsw ^= _lane.low;
              }

              // Temporary values
              var Tx = T[_x2];
              Tx.high = tMsw;
              Tx.low = tLsw;
            }
            for (var _x3 = 0; _x3 < 5; _x3 += 1) {
              // Shortcuts
              var Tx4 = T[(_x3 + 4) % 5];
              var Tx1 = T[(_x3 + 1) % 5];
              var Tx1Msw = Tx1.high;
              var Tx1Lsw = Tx1.low;

              // Mix surrounding columns
              var _tMsw = Tx4.high ^ (Tx1Msw << 1 | Tx1Lsw >>> 31);
              var _tLsw = Tx4.low ^ (Tx1Lsw << 1 | Tx1Msw >>> 31);
              for (var _y3 = 0; _y3 < 5; _y3 += 1) {
                var _lane2 = state[_x3 + 5 * _y3];
                _lane2.high ^= _tMsw;
                _lane2.low ^= _tLsw;
              }
            }

            // Rho Pi
            for (var laneIndex = 1; laneIndex < 25; laneIndex += 1) {
              var _tMsw2 = void 0;
              var _tLsw2 = void 0;

              // Shortcuts
              var _lane3 = state[laneIndex];
              var laneMsw = _lane3.high;
              var laneLsw = _lane3.low;
              var rhoOffset = RHO_OFFSETS[laneIndex];

              // Rotate lanes
              if (rhoOffset < 32) {
                _tMsw2 = laneMsw << rhoOffset | laneLsw >>> 32 - rhoOffset;
                _tLsw2 = laneLsw << rhoOffset | laneMsw >>> 32 - rhoOffset;
              } else /* if (rhoOffset >= 32) */{
                  _tMsw2 = laneLsw << rhoOffset - 32 | laneMsw >>> 64 - rhoOffset;
                  _tLsw2 = laneMsw << rhoOffset - 32 | laneLsw >>> 64 - rhoOffset;
                }

              // Transpose lanes
              var TPiLane = T[PI_INDEXES[laneIndex]];
              TPiLane.high = _tMsw2;
              TPiLane.low = _tLsw2;
            }

            // Rho pi at x = y = 0
            var T0 = T[0];
            var state0 = state[0];
            T0.high = state0.high;
            T0.low = state0.low;

            // Chi
            for (var _x4 = 0; _x4 < 5; _x4 += 1) {
              for (var _y4 = 0; _y4 < 5; _y4 += 1) {
                // Shortcuts
                var _laneIndex = _x4 + 5 * _y4;
                var _lane4 = state[_laneIndex];
                var TLane = T[_laneIndex];
                var Tx1Lane = T[(_x4 + 1) % 5 + 5 * _y4];
                var Tx2Lane = T[(_x4 + 2) % 5 + 5 * _y4];

                // Mix rows
                _lane4.high = TLane.high ^ ~Tx1Lane.high & Tx2Lane.high;
                _lane4.low = TLane.low ^ ~Tx1Lane.low & Tx2Lane.low;
              }
            }

            // Iota
            var _lane5 = state[0];
            var roundConstant = ROUND_CONSTANTS[round];
            _lane5.high ^= roundConstant.high;
            _lane5.low ^= roundConstant.low;
          }
        };
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsLeft = data.sigBytes * 8;
          var blockSizeBits = this.blockSize * 32;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x1 << 24 - nBitsLeft % 32;
          dataWords[(Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits >>> 5) - 1] |= 0x80;
          data.sigBytes = dataWords.length * 4;

          // Hash final blocks
          this._process();

          // Shortcuts
          var state = this._state;
          var outputLengthBytes = this.cfg.outputLength / 8;
          var outputLengthLanes = outputLengthBytes / 8;

          // Squeeze
          var hashWords = [];
          for (var _i4 = 0; _i4 < outputLengthLanes; _i4 += 1) {
            // Shortcuts
            var lane = state[_i4];
            var laneMsw = lane.high;
            var laneLsw = lane.low;

            // Swap endian
            laneMsw = (laneMsw << 8 | laneMsw >>> 24) & 0x00ff00ff | (laneMsw << 24 | laneMsw >>> 8) & 0xff00ff00;
            laneLsw = (laneLsw << 8 | laneLsw >>> 24) & 0x00ff00ff | (laneLsw << 24 | laneLsw >>> 8) & 0xff00ff00;

            // Squeeze state to retrieve hash
            hashWords.push(laneLsw);
            hashWords.push(laneMsw);
          }

          // Return final computed hash
          return new WordArray(hashWords, outputLengthBytes);
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._state = this._state.slice(0);
          var state = clone._state;
          for (var _i5 = 0; _i5 < 25; _i5 += 1) {
            state[_i5] = state[_i5].clone();
          }
          return clone;
        };
        return SHA3Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA3('message');
       *     var hash = CryptoJS.SHA3(wordArray);
       */
      var SHA3 = exports('SHA3', Hasher._createHelper(SHA3Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA3(message, key);
       */
      var HmacSHA3 = exports('HmacSHA3', Hasher._createHmacHelper(SHA3Algo));
    }
  };
});

System.register("chunks:///_virtual/sha384.js", ['./rollupPluginModLoBabelHelpers.js', './x64-core.js', './sha512.js'], function (exports) {
  var _inheritsLoose, X64WordArray, X64Word, SHA512Algo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      X64WordArray = module.X64WordArray;
      X64Word = module.X64Word;
    }, function (module) {
      SHA512Algo = module.SHA512Algo;
    }],
    execute: function () {
      /**
       * SHA-384 hash algorithm.
       */
      var SHA384Algo = exports('SHA384Algo', /*#__PURE__*/function (_SHA512Algo) {
        _inheritsLoose(SHA384Algo, _SHA512Algo);
        function SHA384Algo() {
          return _SHA512Algo.apply(this, arguments) || this;
        }
        var _proto = SHA384Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new X64WordArray([new X64Word(0xcbbb9d5d, 0xc1059ed8), new X64Word(0x629a292a, 0x367cd507), new X64Word(0x9159015a, 0x3070dd17), new X64Word(0x152fecd8, 0xf70e5939), new X64Word(0x67332667, 0xffc00b31), new X64Word(0x8eb44a87, 0x68581511), new X64Word(0xdb0c2e0d, 0x64f98fa7), new X64Word(0x47b5481d, 0xbefa4fa4)]);
        };
        _proto._doFinalize = function _doFinalize() {
          var hash = _SHA512Algo.prototype._doFinalize.call(this);
          hash.sigBytes -= 16;
          return hash;
        };
        return SHA384Algo;
      }(SHA512Algo));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA384('message');
       *     var hash = CryptoJS.SHA384(wordArray);
       */
      var SHA384 = exports('SHA384', SHA512Algo._createHelper(SHA384Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA384(message, key);
       */
      var HmacSHA384 = exports('HmacSHA384', SHA512Algo._createHmacHelper(SHA384Algo));
    }
  };
});

System.register("chunks:///_virtual/sha512.js", ['./rollupPluginModLoBabelHelpers.js', './core.js', './x64-core.js'], function (exports) {
  var _inheritsLoose, Hasher, X64Word, X64WordArray;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      Hasher = module.Hasher;
    }, function (module) {
      X64Word = module.X64Word;
      X64WordArray = module.X64WordArray;
    }],
    execute: function () {
      // Constants
      var K = [new X64Word(0x428a2f98, 0xd728ae22), new X64Word(0x71374491, 0x23ef65cd), new X64Word(0xb5c0fbcf, 0xec4d3b2f), new X64Word(0xe9b5dba5, 0x8189dbbc), new X64Word(0x3956c25b, 0xf348b538), new X64Word(0x59f111f1, 0xb605d019), new X64Word(0x923f82a4, 0xaf194f9b), new X64Word(0xab1c5ed5, 0xda6d8118), new X64Word(0xd807aa98, 0xa3030242), new X64Word(0x12835b01, 0x45706fbe), new X64Word(0x243185be, 0x4ee4b28c), new X64Word(0x550c7dc3, 0xd5ffb4e2), new X64Word(0x72be5d74, 0xf27b896f), new X64Word(0x80deb1fe, 0x3b1696b1), new X64Word(0x9bdc06a7, 0x25c71235), new X64Word(0xc19bf174, 0xcf692694), new X64Word(0xe49b69c1, 0x9ef14ad2), new X64Word(0xefbe4786, 0x384f25e3), new X64Word(0x0fc19dc6, 0x8b8cd5b5), new X64Word(0x240ca1cc, 0x77ac9c65), new X64Word(0x2de92c6f, 0x592b0275), new X64Word(0x4a7484aa, 0x6ea6e483), new X64Word(0x5cb0a9dc, 0xbd41fbd4), new X64Word(0x76f988da, 0x831153b5), new X64Word(0x983e5152, 0xee66dfab), new X64Word(0xa831c66d, 0x2db43210), new X64Word(0xb00327c8, 0x98fb213f), new X64Word(0xbf597fc7, 0xbeef0ee4), new X64Word(0xc6e00bf3, 0x3da88fc2), new X64Word(0xd5a79147, 0x930aa725), new X64Word(0x06ca6351, 0xe003826f), new X64Word(0x14292967, 0x0a0e6e70), new X64Word(0x27b70a85, 0x46d22ffc), new X64Word(0x2e1b2138, 0x5c26c926), new X64Word(0x4d2c6dfc, 0x5ac42aed), new X64Word(0x53380d13, 0x9d95b3df), new X64Word(0x650a7354, 0x8baf63de), new X64Word(0x766a0abb, 0x3c77b2a8), new X64Word(0x81c2c92e, 0x47edaee6), new X64Word(0x92722c85, 0x1482353b), new X64Word(0xa2bfe8a1, 0x4cf10364), new X64Word(0xa81a664b, 0xbc423001), new X64Word(0xc24b8b70, 0xd0f89791), new X64Word(0xc76c51a3, 0x0654be30), new X64Word(0xd192e819, 0xd6ef5218), new X64Word(0xd6990624, 0x5565a910), new X64Word(0xf40e3585, 0x5771202a), new X64Word(0x106aa070, 0x32bbd1b8), new X64Word(0x19a4c116, 0xb8d2d0c8), new X64Word(0x1e376c08, 0x5141ab53), new X64Word(0x2748774c, 0xdf8eeb99), new X64Word(0x34b0bcb5, 0xe19b48a8), new X64Word(0x391c0cb3, 0xc5c95a63), new X64Word(0x4ed8aa4a, 0xe3418acb), new X64Word(0x5b9cca4f, 0x7763e373), new X64Word(0x682e6ff3, 0xd6b2b8a3), new X64Word(0x748f82ee, 0x5defb2fc), new X64Word(0x78a5636f, 0x43172f60), new X64Word(0x84c87814, 0xa1f0ab72), new X64Word(0x8cc70208, 0x1a6439ec), new X64Word(0x90befffa, 0x23631e28), new X64Word(0xa4506ceb, 0xde82bde9), new X64Word(0xbef9a3f7, 0xb2c67915), new X64Word(0xc67178f2, 0xe372532b), new X64Word(0xca273ece, 0xea26619c), new X64Word(0xd186b8c7, 0x21c0c207), new X64Word(0xeada7dd6, 0xcde0eb1e), new X64Word(0xf57d4f7f, 0xee6ed178), new X64Word(0x06f067aa, 0x72176fba), new X64Word(0x0a637dc5, 0xa2c898a6), new X64Word(0x113f9804, 0xbef90dae), new X64Word(0x1b710b35, 0x131c471b), new X64Word(0x28db77f5, 0x23047d84), new X64Word(0x32caab7b, 0x40c72493), new X64Word(0x3c9ebe0a, 0x15c9bebc), new X64Word(0x431d67c4, 0x9c100d4c), new X64Word(0x4cc5d4be, 0xcb3e42b6), new X64Word(0x597f299c, 0xfc657e2a), new X64Word(0x5fcb6fab, 0x3ad6faec), new X64Word(0x6c44198c, 0x4a475817)];

      // Reusable objects
      var W = [];
      for (var i = 0; i < 80; i += 1) {
        W[i] = new X64Word();
      }

      /**
       * SHA-512 hash algorithm.
       */
      var SHA512Algo = exports('SHA512Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(SHA512Algo, _Hasher);
        function SHA512Algo() {
          var _this;
          _this = _Hasher.call(this) || this;
          _this.blockSize = 1024 / 32;
          return _this;
        }
        var _proto = SHA512Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new X64WordArray([new X64Word(0x6a09e667, 0xf3bcc908), new X64Word(0xbb67ae85, 0x84caa73b), new X64Word(0x3c6ef372, 0xfe94f82b), new X64Word(0xa54ff53a, 0x5f1d36f1), new X64Word(0x510e527f, 0xade682d1), new X64Word(0x9b05688c, 0x2b3e6c1f), new X64Word(0x1f83d9ab, 0xfb41bd6b), new X64Word(0x5be0cd19, 0x137e2179)]);
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          // Shortcuts
          var H = this._hash.words;
          var H0 = H[0];
          var H1 = H[1];
          var H2 = H[2];
          var H3 = H[3];
          var H4 = H[4];
          var H5 = H[5];
          var H6 = H[6];
          var H7 = H[7];
          var H0h = H0.high;
          var H0l = H0.low;
          var H1h = H1.high;
          var H1l = H1.low;
          var H2h = H2.high;
          var H2l = H2.low;
          var H3h = H3.high;
          var H3l = H3.low;
          var H4h = H4.high;
          var H4l = H4.low;
          var H5h = H5.high;
          var H5l = H5.low;
          var H6h = H6.high;
          var H6l = H6.low;
          var H7h = H7.high;
          var H7l = H7.low;

          // Working variables
          var ah = H0h;
          var al = H0l;
          var bh = H1h;
          var bl = H1l;
          var ch = H2h;
          var cl = H2l;
          var dh = H3h;
          var dl = H3l;
          var eh = H4h;
          var el = H4l;
          var fh = H5h;
          var fl = H5l;
          var gh = H6h;
          var gl = H6l;
          var hh = H7h;
          var hl = H7l;

          // Rounds
          for (var _i = 0; _i < 80; _i += 1) {
            var Wil = void 0;
            var Wih = void 0;

            // Shortcut
            var Wi = W[_i];

            // Extend message
            if (_i < 16) {
              Wi.high = M[offset + _i * 2] | 0;
              Wih = Wi.high;
              Wi.low = M[offset + _i * 2 + 1] | 0;
              Wil = Wi.low;
            } else {
              // Gamma0
              var gamma0x = W[_i - 15];
              var gamma0xh = gamma0x.high;
              var gamma0xl = gamma0x.low;
              var gamma0h = (gamma0xh >>> 1 | gamma0xl << 31) ^ (gamma0xh >>> 8 | gamma0xl << 24) ^ gamma0xh >>> 7;
              var gamma0l = (gamma0xl >>> 1 | gamma0xh << 31) ^ (gamma0xl >>> 8 | gamma0xh << 24) ^ (gamma0xl >>> 7 | gamma0xh << 25);

              // Gamma1
              var gamma1x = W[_i - 2];
              var gamma1xh = gamma1x.high;
              var gamma1xl = gamma1x.low;
              var gamma1h = (gamma1xh >>> 19 | gamma1xl << 13) ^ (gamma1xh << 3 | gamma1xl >>> 29) ^ gamma1xh >>> 6;
              var gamma1l = (gamma1xl >>> 19 | gamma1xh << 13) ^ (gamma1xl << 3 | gamma1xh >>> 29) ^ (gamma1xl >>> 6 | gamma1xh << 26);

              // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
              var Wi7 = W[_i - 7];
              var Wi7h = Wi7.high;
              var Wi7l = Wi7.low;
              var Wi16 = W[_i - 16];
              var Wi16h = Wi16.high;
              var Wi16l = Wi16.low;
              Wil = gamma0l + Wi7l;
              Wih = gamma0h + Wi7h + (Wil >>> 0 < gamma0l >>> 0 ? 1 : 0);
              Wil += gamma1l;
              Wih = Wih + gamma1h + (Wil >>> 0 < gamma1l >>> 0 ? 1 : 0);
              Wil += Wi16l;
              Wih = Wih + Wi16h + (Wil >>> 0 < Wi16l >>> 0 ? 1 : 0);
              Wi.high = Wih;
              Wi.low = Wil;
            }
            var chh = eh & fh ^ ~eh & gh;
            var chl = el & fl ^ ~el & gl;
            var majh = ah & bh ^ ah & ch ^ bh & ch;
            var majl = al & bl ^ al & cl ^ bl & cl;
            var sigma0h = (ah >>> 28 | al << 4) ^ (ah << 30 | al >>> 2) ^ (ah << 25 | al >>> 7);
            var sigma0l = (al >>> 28 | ah << 4) ^ (al << 30 | ah >>> 2) ^ (al << 25 | ah >>> 7);
            var sigma1h = (eh >>> 14 | el << 18) ^ (eh >>> 18 | el << 14) ^ (eh << 23 | el >>> 9);
            var sigma1l = (el >>> 14 | eh << 18) ^ (el >>> 18 | eh << 14) ^ (el << 23 | eh >>> 9);

            // t1 = h + sigma1 + ch + K[i] + W[i]
            var Ki = K[_i];
            var Kih = Ki.high;
            var Kil = Ki.low;
            var t1l = hl + sigma1l;
            var t1h = hh + sigma1h + (t1l >>> 0 < hl >>> 0 ? 1 : 0);
            t1l += chl;
            t1h = t1h + chh + (t1l >>> 0 < chl >>> 0 ? 1 : 0);
            t1l += Kil;
            t1h = t1h + Kih + (t1l >>> 0 < Kil >>> 0 ? 1 : 0);
            t1l += Wil;
            t1h = t1h + Wih + (t1l >>> 0 < Wil >>> 0 ? 1 : 0);

            // t2 = sigma0 + maj
            var t2l = sigma0l + majl;
            var t2h = sigma0h + majh + (t2l >>> 0 < sigma0l >>> 0 ? 1 : 0);

            // Update working variables
            hh = gh;
            hl = gl;
            gh = fh;
            gl = fl;
            fh = eh;
            fl = el;
            el = dl + t1l | 0;
            eh = dh + t1h + (el >>> 0 < dl >>> 0 ? 1 : 0) | 0;
            dh = ch;
            dl = cl;
            ch = bh;
            cl = bl;
            bh = ah;
            bl = al;
            al = t1l + t2l | 0;
            ah = t1h + t2h + (al >>> 0 < t1l >>> 0 ? 1 : 0) | 0;
          }

          // Intermediate hash value
          H0.low = H0l + al;
          H0l = H0.low;
          H0.high = H0h + ah + (H0l >>> 0 < al >>> 0 ? 1 : 0);
          H1.low = H1l + bl;
          H1l = H1.low;
          H1.high = H1h + bh + (H1l >>> 0 < bl >>> 0 ? 1 : 0);
          H2.low = H2l + cl;
          H2l = H2.low;
          H2.high = H2h + ch + (H2l >>> 0 < cl >>> 0 ? 1 : 0);
          H3.low = H3l + dl;
          H3l = H3.low;
          H3.high = H3h + dh + (H3l >>> 0 < dl >>> 0 ? 1 : 0);
          H4.low = H4l + el;
          H4l = H4.low;
          H4.high = H4h + eh + (H4l >>> 0 < el >>> 0 ? 1 : 0);
          H5.low = H5l + fl;
          H5l = H5.low;
          H5.high = H5h + fh + (H5l >>> 0 < fl >>> 0 ? 1 : 0);
          H6.low = H6l + gl;
          H6l = H6.low;
          H6.high = H6h + gh + (H6l >>> 0 < gl >>> 0 ? 1 : 0);
          H7.low = H7l + hl;
          H7l = H7.low;
          H7.high = H7h + hh + (H7l >>> 0 < hl >>> 0 ? 1 : 0);
        };
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          dataWords[(nBitsLeft + 128 >>> 10 << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
          dataWords[(nBitsLeft + 128 >>> 10 << 5) + 31] = nBitsTotal;
          data.sigBytes = dataWords.length * 4;

          // Hash final blocks
          this._process();

          // Convert hash to 32-bit word array before returning
          var hash = this._hash.toX32();

          // Return final computed hash
          return hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return SHA512Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA512('message');
       *     var hash = CryptoJS.SHA512(wordArray);
       */
      var SHA512 = exports('SHA512', Hasher._createHelper(SHA512Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA512(message, key);
       */
      var HmacSHA512 = exports('HmacSHA512', Hasher._createHmacHelper(SHA512Algo));
    }
  };
});

System.register("chunks:///_virtual/tripledes.js", ['./rollupPluginModLoBabelHelpers.js', './core.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, WordArray, BlockCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      WordArray = module.WordArray;
    }, function (module) {
      BlockCipher = module.BlockCipher;
    }],
    execute: function () {
      // Permuted Choice 1 constants
      var PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];

      // Permuted Choice 2 constants
      var PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];

      // Cumulative bit shift constants
      var BIT_SHIFTS = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

      // SBOXes and round permutation constants
      var SBOX_P = [{
        0x0: 0x808200,
        0x10000000: 0x8000,
        0x20000000: 0x808002,
        0x30000000: 0x2,
        0x40000000: 0x200,
        0x50000000: 0x808202,
        0x60000000: 0x800202,
        0x70000000: 0x800000,
        0x80000000: 0x202,
        0x90000000: 0x800200,
        0xa0000000: 0x8200,
        0xb0000000: 0x808000,
        0xc0000000: 0x8002,
        0xd0000000: 0x800002,
        0xe0000000: 0x0,
        0xf0000000: 0x8202,
        0x8000000: 0x0,
        0x18000000: 0x808202,
        0x28000000: 0x8202,
        0x38000000: 0x8000,
        0x48000000: 0x808200,
        0x58000000: 0x200,
        0x68000000: 0x808002,
        0x78000000: 0x2,
        0x88000000: 0x800200,
        0x98000000: 0x8200,
        0xa8000000: 0x808000,
        0xb8000000: 0x800202,
        0xc8000000: 0x800002,
        0xd8000000: 0x8002,
        0xe8000000: 0x202,
        0xf8000000: 0x800000,
        0x1: 0x8000,
        0x10000001: 0x2,
        0x20000001: 0x808200,
        0x30000001: 0x800000,
        0x40000001: 0x808002,
        0x50000001: 0x8200,
        0x60000001: 0x200,
        0x70000001: 0x800202,
        0x80000001: 0x808202,
        0x90000001: 0x808000,
        0xa0000001: 0x800002,
        0xb0000001: 0x8202,
        0xc0000001: 0x202,
        0xd0000001: 0x800200,
        0xe0000001: 0x8002,
        0xf0000001: 0x0,
        0x8000001: 0x808202,
        0x18000001: 0x808000,
        0x28000001: 0x800000,
        0x38000001: 0x200,
        0x48000001: 0x8000,
        0x58000001: 0x800002,
        0x68000001: 0x2,
        0x78000001: 0x8202,
        0x88000001: 0x8002,
        0x98000001: 0x800202,
        0xa8000001: 0x202,
        0xb8000001: 0x808200,
        0xc8000001: 0x800200,
        0xd8000001: 0x0,
        0xe8000001: 0x8200,
        0xf8000001: 0x808002
      }, {
        0x0: 0x40084010,
        0x1000000: 0x4000,
        0x2000000: 0x80000,
        0x3000000: 0x40080010,
        0x4000000: 0x40000010,
        0x5000000: 0x40084000,
        0x6000000: 0x40004000,
        0x7000000: 0x10,
        0x8000000: 0x84000,
        0x9000000: 0x40004010,
        0xa000000: 0x40000000,
        0xb000000: 0x84010,
        0xc000000: 0x80010,
        0xd000000: 0x0,
        0xe000000: 0x4010,
        0xf000000: 0x40080000,
        0x800000: 0x40004000,
        0x1800000: 0x84010,
        0x2800000: 0x10,
        0x3800000: 0x40004010,
        0x4800000: 0x40084010,
        0x5800000: 0x40000000,
        0x6800000: 0x80000,
        0x7800000: 0x40080010,
        0x8800000: 0x80010,
        0x9800000: 0x0,
        0xa800000: 0x4000,
        0xb800000: 0x40080000,
        0xc800000: 0x40000010,
        0xd800000: 0x84000,
        0xe800000: 0x40084000,
        0xf800000: 0x4010,
        0x10000000: 0x0,
        0x11000000: 0x40080010,
        0x12000000: 0x40004010,
        0x13000000: 0x40084000,
        0x14000000: 0x40080000,
        0x15000000: 0x10,
        0x16000000: 0x84010,
        0x17000000: 0x4000,
        0x18000000: 0x4010,
        0x19000000: 0x80000,
        0x1a000000: 0x80010,
        0x1b000000: 0x40000010,
        0x1c000000: 0x84000,
        0x1d000000: 0x40004000,
        0x1e000000: 0x40000000,
        0x1f000000: 0x40084010,
        0x10800000: 0x84010,
        0x11800000: 0x80000,
        0x12800000: 0x40080000,
        0x13800000: 0x4000,
        0x14800000: 0x40004000,
        0x15800000: 0x40084010,
        0x16800000: 0x10,
        0x17800000: 0x40000000,
        0x18800000: 0x40084000,
        0x19800000: 0x40000010,
        0x1a800000: 0x40004010,
        0x1b800000: 0x80010,
        0x1c800000: 0x0,
        0x1d800000: 0x4010,
        0x1e800000: 0x40080010,
        0x1f800000: 0x84000
      }, {
        0x0: 0x104,
        0x100000: 0x0,
        0x200000: 0x4000100,
        0x300000: 0x10104,
        0x400000: 0x10004,
        0x500000: 0x4000004,
        0x600000: 0x4010104,
        0x700000: 0x4010000,
        0x800000: 0x4000000,
        0x900000: 0x4010100,
        0xa00000: 0x10100,
        0xb00000: 0x4010004,
        0xc00000: 0x4000104,
        0xd00000: 0x10000,
        0xe00000: 0x4,
        0xf00000: 0x100,
        0x80000: 0x4010100,
        0x180000: 0x4010004,
        0x280000: 0x0,
        0x380000: 0x4000100,
        0x480000: 0x4000004,
        0x580000: 0x10000,
        0x680000: 0x10004,
        0x780000: 0x104,
        0x880000: 0x4,
        0x980000: 0x100,
        0xa80000: 0x4010000,
        0xb80000: 0x10104,
        0xc80000: 0x10100,
        0xd80000: 0x4000104,
        0xe80000: 0x4010104,
        0xf80000: 0x4000000,
        0x1000000: 0x4010100,
        0x1100000: 0x10004,
        0x1200000: 0x10000,
        0x1300000: 0x4000100,
        0x1400000: 0x100,
        0x1500000: 0x4010104,
        0x1600000: 0x4000004,
        0x1700000: 0x0,
        0x1800000: 0x4000104,
        0x1900000: 0x4000000,
        0x1a00000: 0x4,
        0x1b00000: 0x10100,
        0x1c00000: 0x4010000,
        0x1d00000: 0x104,
        0x1e00000: 0x10104,
        0x1f00000: 0x4010004,
        0x1080000: 0x4000000,
        0x1180000: 0x104,
        0x1280000: 0x4010100,
        0x1380000: 0x0,
        0x1480000: 0x10004,
        0x1580000: 0x4000100,
        0x1680000: 0x100,
        0x1780000: 0x4010004,
        0x1880000: 0x10000,
        0x1980000: 0x4010104,
        0x1a80000: 0x10104,
        0x1b80000: 0x4000004,
        0x1c80000: 0x4000104,
        0x1d80000: 0x4010000,
        0x1e80000: 0x4,
        0x1f80000: 0x10100
      }, {
        0x0: 0x80401000,
        0x10000: 0x80001040,
        0x20000: 0x401040,
        0x30000: 0x80400000,
        0x40000: 0x0,
        0x50000: 0x401000,
        0x60000: 0x80000040,
        0x70000: 0x400040,
        0x80000: 0x80000000,
        0x90000: 0x400000,
        0xa0000: 0x40,
        0xb0000: 0x80001000,
        0xc0000: 0x80400040,
        0xd0000: 0x1040,
        0xe0000: 0x1000,
        0xf0000: 0x80401040,
        0x8000: 0x80001040,
        0x18000: 0x40,
        0x28000: 0x80400040,
        0x38000: 0x80001000,
        0x48000: 0x401000,
        0x58000: 0x80401040,
        0x68000: 0x0,
        0x78000: 0x80400000,
        0x88000: 0x1000,
        0x98000: 0x80401000,
        0xa8000: 0x400000,
        0xb8000: 0x1040,
        0xc8000: 0x80000000,
        0xd8000: 0x400040,
        0xe8000: 0x401040,
        0xf8000: 0x80000040,
        0x100000: 0x400040,
        0x110000: 0x401000,
        0x120000: 0x80000040,
        0x130000: 0x0,
        0x140000: 0x1040,
        0x150000: 0x80400040,
        0x160000: 0x80401000,
        0x170000: 0x80001040,
        0x180000: 0x80401040,
        0x190000: 0x80000000,
        0x1a0000: 0x80400000,
        0x1b0000: 0x401040,
        0x1c0000: 0x80001000,
        0x1d0000: 0x400000,
        0x1e0000: 0x40,
        0x1f0000: 0x1000,
        0x108000: 0x80400000,
        0x118000: 0x80401040,
        0x128000: 0x0,
        0x138000: 0x401000,
        0x148000: 0x400040,
        0x158000: 0x80000000,
        0x168000: 0x80001040,
        0x178000: 0x40,
        0x188000: 0x80000040,
        0x198000: 0x1000,
        0x1a8000: 0x80001000,
        0x1b8000: 0x80400040,
        0x1c8000: 0x1040,
        0x1d8000: 0x80401000,
        0x1e8000: 0x400000,
        0x1f8000: 0x401040
      }, {
        0x0: 0x80,
        0x1000: 0x1040000,
        0x2000: 0x40000,
        0x3000: 0x20000000,
        0x4000: 0x20040080,
        0x5000: 0x1000080,
        0x6000: 0x21000080,
        0x7000: 0x40080,
        0x8000: 0x1000000,
        0x9000: 0x20040000,
        0xa000: 0x20000080,
        0xb000: 0x21040080,
        0xc000: 0x21040000,
        0xd000: 0x0,
        0xe000: 0x1040080,
        0xf000: 0x21000000,
        0x800: 0x1040080,
        0x1800: 0x21000080,
        0x2800: 0x80,
        0x3800: 0x1040000,
        0x4800: 0x40000,
        0x5800: 0x20040080,
        0x6800: 0x21040000,
        0x7800: 0x20000000,
        0x8800: 0x20040000,
        0x9800: 0x0,
        0xa800: 0x21040080,
        0xb800: 0x1000080,
        0xc800: 0x20000080,
        0xd800: 0x21000000,
        0xe800: 0x1000000,
        0xf800: 0x40080,
        0x10000: 0x40000,
        0x11000: 0x80,
        0x12000: 0x20000000,
        0x13000: 0x21000080,
        0x14000: 0x1000080,
        0x15000: 0x21040000,
        0x16000: 0x20040080,
        0x17000: 0x1000000,
        0x18000: 0x21040080,
        0x19000: 0x21000000,
        0x1a000: 0x1040000,
        0x1b000: 0x20040000,
        0x1c000: 0x40080,
        0x1d000: 0x20000080,
        0x1e000: 0x0,
        0x1f000: 0x1040080,
        0x10800: 0x21000080,
        0x11800: 0x1000000,
        0x12800: 0x1040000,
        0x13800: 0x20040080,
        0x14800: 0x20000000,
        0x15800: 0x1040080,
        0x16800: 0x80,
        0x17800: 0x21040000,
        0x18800: 0x40080,
        0x19800: 0x21040080,
        0x1a800: 0x0,
        0x1b800: 0x21000000,
        0x1c800: 0x1000080,
        0x1d800: 0x40000,
        0x1e800: 0x20040000,
        0x1f800: 0x20000080
      }, {
        0x0: 0x10000008,
        0x100: 0x2000,
        0x200: 0x10200000,
        0x300: 0x10202008,
        0x400: 0x10002000,
        0x500: 0x200000,
        0x600: 0x200008,
        0x700: 0x10000000,
        0x800: 0x0,
        0x900: 0x10002008,
        0xa00: 0x202000,
        0xb00: 0x8,
        0xc00: 0x10200008,
        0xd00: 0x202008,
        0xe00: 0x2008,
        0xf00: 0x10202000,
        0x80: 0x10200000,
        0x180: 0x10202008,
        0x280: 0x8,
        0x380: 0x200000,
        0x480: 0x202008,
        0x580: 0x10000008,
        0x680: 0x10002000,
        0x780: 0x2008,
        0x880: 0x200008,
        0x980: 0x2000,
        0xa80: 0x10002008,
        0xb80: 0x10200008,
        0xc80: 0x0,
        0xd80: 0x10202000,
        0xe80: 0x202000,
        0xf80: 0x10000000,
        0x1000: 0x10002000,
        0x1100: 0x10200008,
        0x1200: 0x10202008,
        0x1300: 0x2008,
        0x1400: 0x200000,
        0x1500: 0x10000000,
        0x1600: 0x10000008,
        0x1700: 0x202000,
        0x1800: 0x202008,
        0x1900: 0x0,
        0x1a00: 0x8,
        0x1b00: 0x10200000,
        0x1c00: 0x2000,
        0x1d00: 0x10002008,
        0x1e00: 0x10202000,
        0x1f00: 0x200008,
        0x1080: 0x8,
        0x1180: 0x202000,
        0x1280: 0x200000,
        0x1380: 0x10000008,
        0x1480: 0x10002000,
        0x1580: 0x2008,
        0x1680: 0x10202008,
        0x1780: 0x10200000,
        0x1880: 0x10202000,
        0x1980: 0x10200008,
        0x1a80: 0x2000,
        0x1b80: 0x202008,
        0x1c80: 0x200008,
        0x1d80: 0x0,
        0x1e80: 0x10000000,
        0x1f80: 0x10002008
      }, {
        0x0: 0x100000,
        0x10: 0x2000401,
        0x20: 0x400,
        0x30: 0x100401,
        0x40: 0x2100401,
        0x50: 0x0,
        0x60: 0x1,
        0x70: 0x2100001,
        0x80: 0x2000400,
        0x90: 0x100001,
        0xa0: 0x2000001,
        0xb0: 0x2100400,
        0xc0: 0x2100000,
        0xd0: 0x401,
        0xe0: 0x100400,
        0xf0: 0x2000000,
        0x8: 0x2100001,
        0x18: 0x0,
        0x28: 0x2000401,
        0x38: 0x2100400,
        0x48: 0x100000,
        0x58: 0x2000001,
        0x68: 0x2000000,
        0x78: 0x401,
        0x88: 0x100401,
        0x98: 0x2000400,
        0xa8: 0x2100000,
        0xb8: 0x100001,
        0xc8: 0x400,
        0xd8: 0x2100401,
        0xe8: 0x1,
        0xf8: 0x100400,
        0x100: 0x2000000,
        0x110: 0x100000,
        0x120: 0x2000401,
        0x130: 0x2100001,
        0x140: 0x100001,
        0x150: 0x2000400,
        0x160: 0x2100400,
        0x170: 0x100401,
        0x180: 0x401,
        0x190: 0x2100401,
        0x1a0: 0x100400,
        0x1b0: 0x1,
        0x1c0: 0x0,
        0x1d0: 0x2100000,
        0x1e0: 0x2000001,
        0x1f0: 0x400,
        0x108: 0x100400,
        0x118: 0x2000401,
        0x128: 0x2100001,
        0x138: 0x1,
        0x148: 0x2000000,
        0x158: 0x100000,
        0x168: 0x401,
        0x178: 0x2100400,
        0x188: 0x2000001,
        0x198: 0x2100000,
        0x1a8: 0x0,
        0x1b8: 0x2100401,
        0x1c8: 0x100401,
        0x1d8: 0x400,
        0x1e8: 0x2000400,
        0x1f8: 0x100001
      }, {
        0x0: 0x8000820,
        0x1: 0x20000,
        0x2: 0x8000000,
        0x3: 0x20,
        0x4: 0x20020,
        0x5: 0x8020820,
        0x6: 0x8020800,
        0x7: 0x800,
        0x8: 0x8020000,
        0x9: 0x8000800,
        0xa: 0x20800,
        0xb: 0x8020020,
        0xc: 0x820,
        0xd: 0x0,
        0xe: 0x8000020,
        0xf: 0x20820,
        0x80000000: 0x800,
        0x80000001: 0x8020820,
        0x80000002: 0x8000820,
        0x80000003: 0x8000000,
        0x80000004: 0x8020000,
        0x80000005: 0x20800,
        0x80000006: 0x20820,
        0x80000007: 0x20,
        0x80000008: 0x8000020,
        0x80000009: 0x820,
        0x8000000a: 0x20020,
        0x8000000b: 0x8020800,
        0x8000000c: 0x0,
        0x8000000d: 0x8020020,
        0x8000000e: 0x8000800,
        0x8000000f: 0x20000,
        0x10: 0x20820,
        0x11: 0x8020800,
        0x12: 0x20,
        0x13: 0x800,
        0x14: 0x8000800,
        0x15: 0x8000020,
        0x16: 0x8020020,
        0x17: 0x20000,
        0x18: 0x0,
        0x19: 0x20020,
        0x1a: 0x8020000,
        0x1b: 0x8000820,
        0x1c: 0x8020820,
        0x1d: 0x20800,
        0x1e: 0x820,
        0x1f: 0x8000000,
        0x80000010: 0x20000,
        0x80000011: 0x800,
        0x80000012: 0x8020020,
        0x80000013: 0x20820,
        0x80000014: 0x20,
        0x80000015: 0x8020000,
        0x80000016: 0x8000000,
        0x80000017: 0x8000820,
        0x80000018: 0x8020820,
        0x80000019: 0x8000020,
        0x8000001a: 0x8000800,
        0x8000001b: 0x0,
        0x8000001c: 0x20800,
        0x8000001d: 0x820,
        0x8000001e: 0x20020,
        0x8000001f: 0x8020800
      }];

      // Masks that select the SBOX input
      var SBOX_MASK = [0xf8000001, 0x1f800000, 0x01f80000, 0x001f8000, 0x0001f800, 0x00001f80, 0x000001f8, 0x8000001f];

      // Swap bits across the left and right words
      function exchangeLR(offset, mask) {
        var t = (this._lBlock >>> offset ^ this._rBlock) & mask;
        this._rBlock ^= t;
        this._lBlock ^= t << offset;
      }
      function exchangeRL(offset, mask) {
        var t = (this._rBlock >>> offset ^ this._lBlock) & mask;
        this._lBlock ^= t;
        this._rBlock ^= t << offset;
      }

      /**
       * DES block cipher algorithm.
       */
      var DESAlgo = exports('DESAlgo', /*#__PURE__*/function (_BlockCipher) {
        _inheritsLoose(DESAlgo, _BlockCipher);
        function DESAlgo(xformMode, key, cfg) {
          var _this;
          _this = _BlockCipher.call(this, xformMode, key, cfg) || this;

          // blickSize is an instance field and should set in constructor.
          // Both DESAlgo and TripleDESAlgo.
          _this.blockSize = 64 / 32;
          return _this;
        }
        var _proto = DESAlgo.prototype;
        _proto._doReset = function _doReset() {
          // Shortcuts
          var key = this._key;
          var keyWords = key.words;

          // Select 56 bits according to PC1
          var keyBits = [];
          for (var i = 0; i < 56; i += 1) {
            var keyBitPos = PC1[i] - 1;
            keyBits[i] = keyWords[keyBitPos >>> 5] >>> 31 - keyBitPos % 32 & 1;
          }

          // Assemble 16 subkeys
          this._subKeys = [];
          var subKeys = this._subKeys;
          for (var nSubKey = 0; nSubKey < 16; nSubKey += 1) {
            // Create subkey
            subKeys[nSubKey] = [];
            var subKey = subKeys[nSubKey];

            // Shortcut
            var bitShift = BIT_SHIFTS[nSubKey];

            // Select 48 bits according to PC2
            for (var _i = 0; _i < 24; _i += 1) {
              // Select from the left 28 key bits
              subKey[_i / 6 | 0] |= keyBits[(PC2[_i] - 1 + bitShift) % 28] << 31 - _i % 6;

              // Select from the right 28 key bits
              subKey[4 + (_i / 6 | 0)] |= keyBits[28 + (PC2[_i + 24] - 1 + bitShift) % 28] << 31 - _i % 6;
            }

            // Since each subkey is applied to an expanded 32-bit input,
            // the subkey can be broken into 8 values scaled to 32-bits,
            // which allows the key to be used without expansion
            subKey[0] = subKey[0] << 1 | subKey[0] >>> 31;
            for (var _i2 = 1; _i2 < 7; _i2 += 1) {
              subKey[_i2] >>>= (_i2 - 1) * 4 + 3;
            }
            subKey[7] = subKey[7] << 5 | subKey[7] >>> 27;
          }

          // Compute inverse subkeys
          this._invSubKeys = [];
          var invSubKeys = this._invSubKeys;
          for (var _i3 = 0; _i3 < 16; _i3 += 1) {
            invSubKeys[_i3] = subKeys[15 - _i3];
          }
        };
        _proto.encryptBlock = function encryptBlock(M, offset) {
          this._doCryptBlock(M, offset, this._subKeys);
        };
        _proto.decryptBlock = function decryptBlock(M, offset) {
          this._doCryptBlock(M, offset, this._invSubKeys);
        };
        _proto._doCryptBlock = function _doCryptBlock(M, offset, subKeys) {
          var _M = M;

          // Get input
          this._lBlock = M[offset];
          this._rBlock = M[offset + 1];

          // Initial permutation
          exchangeLR.call(this, 4, 0x0f0f0f0f);
          exchangeLR.call(this, 16, 0x0000ffff);
          exchangeRL.call(this, 2, 0x33333333);
          exchangeRL.call(this, 8, 0x00ff00ff);
          exchangeLR.call(this, 1, 0x55555555);

          // Rounds
          for (var round = 0; round < 16; round += 1) {
            // Shortcuts
            var subKey = subKeys[round];
            var lBlock = this._lBlock;
            var rBlock = this._rBlock;

            // Feistel function
            var f = 0;
            for (var i = 0; i < 8; i += 1) {
              f |= SBOX_P[i][((rBlock ^ subKey[i]) & SBOX_MASK[i]) >>> 0];
            }
            this._lBlock = rBlock;
            this._rBlock = lBlock ^ f;
          }

          // Undo swap from last round
          var t = this._lBlock;
          this._lBlock = this._rBlock;
          this._rBlock = t;

          // Final permutation
          exchangeLR.call(this, 1, 0x55555555);
          exchangeRL.call(this, 8, 0x00ff00ff);
          exchangeRL.call(this, 2, 0x33333333);
          exchangeLR.call(this, 16, 0x0000ffff);
          exchangeLR.call(this, 4, 0x0f0f0f0f);

          // Set output
          _M[offset] = this._lBlock;
          _M[offset + 1] = this._rBlock;
        };
        return DESAlgo;
      }(BlockCipher));
      DESAlgo.keySize = 64 / 32;
      DESAlgo.ivSize = 64 / 32;
      // blickSize is an instance field and should set in constructor.

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.DES.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.DES.decrypt(ciphertext, key, cfg);
       */
      var DES = exports('DES', BlockCipher._createHelper(DESAlgo));

      /**
       * Triple-DES block cipher algorithm.
       */
      var TripleDESAlgo = exports('TripleDESAlgo', /*#__PURE__*/function (_BlockCipher2) {
        _inheritsLoose(TripleDESAlgo, _BlockCipher2);
        function TripleDESAlgo() {
          return _BlockCipher2.apply(this, arguments) || this;
        }
        var _proto2 = TripleDESAlgo.prototype;
        _proto2._doReset = function _doReset() {
          // Shortcuts
          var key = this._key;
          var keyWords = key.words;
          // Make sure the key length is valid (64, 128 or >= 192 bit)
          if (keyWords.length !== 2 && keyWords.length !== 4 && keyWords.length < 6) {
            throw new Error('Invalid key length - 3DES requires the key length to be 64, 128, 192 or >192.');
          }

          // Extend the key according to the keying options defined in 3DES standard
          var key1 = keyWords.slice(0, 2);
          var key2 = keyWords.length < 4 ? keyWords.slice(0, 2) : keyWords.slice(2, 4);
          var key3 = keyWords.length < 6 ? keyWords.slice(0, 2) : keyWords.slice(4, 6);

          // Create DES instances
          this._des1 = DESAlgo.createEncryptor(WordArray.create(key1));
          this._des2 = DESAlgo.createEncryptor(WordArray.create(key2));
          this._des3 = DESAlgo.createEncryptor(WordArray.create(key3));
        };
        _proto2.encryptBlock = function encryptBlock(M, offset) {
          this._des1.encryptBlock(M, offset);
          this._des2.decryptBlock(M, offset);
          this._des3.encryptBlock(M, offset);
        };
        _proto2.decryptBlock = function decryptBlock(M, offset) {
          this._des3.decryptBlock(M, offset);
          this._des2.encryptBlock(M, offset);
          this._des1.decryptBlock(M, offset);
        };
        return TripleDESAlgo;
      }(BlockCipher));
      TripleDESAlgo.keySize = 192 / 32;
      TripleDESAlgo.ivSize = 64 / 32;
      // blickSize is an instance field and should set in constructor.

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.TripleDES.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.TripleDES.decrypt(ciphertext, key, cfg);
       */
      var TripleDES = exports('TripleDES', BlockCipher._createHelper(TripleDESAlgo));
    }
  };
});

System.register("chunks:///_virtual/writer_buffer.js", ['./cjs-loader.mjs', './writer.js', './minimal2.js'], function (exports, module) {
  var loader, __cjsMetaURL$1, __cjsMetaURL$2;
  return {
    setters: [function (module) {
      loader = module.default;
    }, function (module) {
      __cjsMetaURL$1 = module.__cjsMetaURL;
    }, function (module) {
      __cjsMetaURL$2 = module.__cjsMetaURL;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = BufferWriter;

        // extends Writer
        var Writer = require("./writer");
        (BufferWriter.prototype = Object.create(Writer.prototype)).constructor = BufferWriter;
        var util = require("./util/minimal");

        /**
         * Constructs a new buffer writer instance.
         * @classdesc Wire format writer using node buffers.
         * @extends Writer
         * @constructor
         */
        function BufferWriter() {
          Writer.call(this);
        }
        BufferWriter._configure = function () {
          /**
           * Allocates a buffer of the specified size.
           * @function
           * @param {number} size Buffer size
           * @returns {Buffer} Buffer
           */
          BufferWriter.alloc = util._Buffer_allocUnsafe;
          BufferWriter.writeBytesBuffer = util.Buffer && util.Buffer.prototype instanceof Uint8Array && util.Buffer.prototype.set.name === "set" ? function writeBytesBuffer_set(val, buf, pos) {
            buf.set(val, pos); // faster than copy (requires node >= 4 where Buffers extend Uint8Array and set is properly inherited)
            // also works for plain array values
          }
          /* istanbul ignore next */ : function writeBytesBuffer_copy(val, buf, pos) {
            if (val.copy)
              // Buffer values
              val.copy(buf, pos, 0, val.length);else for (var i = 0; i < val.length;)
            // plain array values
            buf[pos++] = val[i++];
          };
        };

        /**
         * @override
         */
        BufferWriter.prototype.bytes = function write_bytes_buffer(value) {
          if (util.isString(value)) value = util._Buffer_from(value, "base64");
          var len = value.length >>> 0;
          this.uint32(len);
          if (len) this._push(BufferWriter.writeBytesBuffer, len, value);
          return this;
        };
        function writeStringBuffer(val, buf, pos) {
          if (val.length < 40)
            // plain js is faster for short strings (probably due to redundant assertions)
            util.utf8.write(val, buf, pos);else if (buf.utf8Write) buf.utf8Write(val, pos);else buf.write(val, pos);
        }

        /**
         * @override
         */
        BufferWriter.prototype.string = function write_string_buffer(value) {
          var len = util.Buffer.byteLength(value);
          this.uint32(len);
          if (len) this._push(writeStringBuffer, len, value);
          return this;
        };

        /**
         * Finishes the write operation.
         * @name BufferWriter#finish
         * @function
         * @returns {Buffer} Finished buffer
         */

        BufferWriter._configure();

        // #endregion ORIGINAL CODE

        module.exports;
      }, function () {
        return {
          './writer': __cjsMetaURL$1,
          './util/minimal': __cjsMetaURL$2
        };
      });
    }
  };
});

System.register("chunks:///_virtual/writer.js", ['./cjs-loader.mjs', './minimal2.js'], function (exports, module) {
  var loader, __cjsMetaURL$1;
  return {
    setters: [function (module) {
      loader = module.default;
    }, function (module) {
      __cjsMetaURL$1 = module.__cjsMetaURL;
    }],
    execute: function () {
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports, require, module, __filename, __dirname) {
        module.exports = Writer;
        var util = require("./util/minimal");
        var BufferWriter; // cyclic

        var LongBits = util.LongBits,
          base64 = util.base64,
          utf8 = util.utf8;

        /**
         * Constructs a new writer operation instance.
         * @classdesc Scheduled writer operation.
         * @constructor
         * @param {function(*, Uint8Array, number)} fn Function to call
         * @param {number} len Value byte length
         * @param {*} val Value to write
         * @ignore
         */
        function Op(fn, len, val) {
          /**
           * Function to call.
           * @type {function(Uint8Array, number, *)}
           */
          this.fn = fn;

          /**
           * Value byte length.
           * @type {number}
           */
          this.len = len;

          /**
           * Next operation.
           * @type {Writer.Op|undefined}
           */
          this.next = undefined;

          /**
           * Value to write.
           * @type {*}
           */
          this.val = val; // type varies
        }

        /* istanbul ignore next */
        function noop() {} // eslint-disable-line no-empty-function

        /**
         * Constructs a new writer state instance.
         * @classdesc Copied writer state.
         * @memberof Writer
         * @constructor
         * @param {Writer} writer Writer to copy state from
         * @ignore
         */
        function State(writer) {
          /**
           * Current head.
           * @type {Writer.Op}
           */
          this.head = writer.head;

          /**
           * Current tail.
           * @type {Writer.Op}
           */
          this.tail = writer.tail;

          /**
           * Current buffer length.
           * @type {number}
           */
          this.len = writer.len;

          /**
           * Next state.
           * @type {State|null}
           */
          this.next = writer.states;
        }

        /**
         * Constructs a new writer instance.
         * @classdesc Wire format writer using `Uint8Array` if available, otherwise `Array`.
         * @constructor
         */
        function Writer() {
          /**
           * Current length.
           * @type {number}
           */
          this.len = 0;

          /**
           * Operations head.
           * @type {Object}
           */
          this.head = new Op(noop, 0, 0);

          /**
           * Operations tail
           * @type {Object}
           */
          this.tail = this.head;

          /**
           * Linked forked states.
           * @type {Object|null}
           */
          this.states = null;

          // When a value is written, the writer calculates its byte length and puts it into a linked
          // list of operations to perform when finish() is called. This both allows us to allocate
          // buffers of the exact required size and reduces the amount of work we have to do compared
          // to first calculating over objects and then encoding over objects. In our case, the encoding
          // part is just a linked list walk calling operations with already prepared values.
        }

        var create = function create() {
          return util.Buffer ? function create_buffer_setup() {
            return (Writer.create = function create_buffer() {
              return new BufferWriter();
            })();
          }
          /* istanbul ignore next */ : function create_array() {
            return new Writer();
          };
        };

        /**
         * Creates a new writer.
         * @function
         * @returns {BufferWriter|Writer} A {@link BufferWriter} when Buffers are supported, otherwise a {@link Writer}
         */
        Writer.create = create();

        /**
         * Allocates a buffer of the specified size.
         * @param {number} size Buffer size
         * @returns {Uint8Array} Buffer
         */
        Writer.alloc = function alloc(size) {
          return new util.Array(size);
        };

        // Use Uint8Array buffer pool in the browser, just like node does with buffers
        /* istanbul ignore else */
        if (util.Array !== Array) Writer.alloc = util.pool(Writer.alloc, util.Array.prototype.subarray);

        /**
         * Pushes a new operation to the queue.
         * @param {function(Uint8Array, number, *)} fn Function to call
         * @param {number} len Value byte length
         * @param {number} val Value to write
         * @returns {Writer} `this`
         * @private
         */
        Writer.prototype._push = function push(fn, len, val) {
          this.tail = this.tail.next = new Op(fn, len, val);
          this.len += len;
          return this;
        };
        function writeByte(val, buf, pos) {
          buf[pos] = val & 255;
        }
        function writeVarint32(val, buf, pos) {
          while (val > 127) {
            buf[pos++] = val & 127 | 128;
            val >>>= 7;
          }
          buf[pos] = val;
        }

        /**
         * Constructs a new varint writer operation instance.
         * @classdesc Scheduled varint writer operation.
         * @extends Op
         * @constructor
         * @param {number} len Value byte length
         * @param {number} val Value to write
         * @ignore
         */
        function VarintOp(len, val) {
          this.len = len;
          this.next = undefined;
          this.val = val;
        }
        VarintOp.prototype = Object.create(Op.prototype);
        VarintOp.prototype.fn = writeVarint32;

        /**
         * Writes an unsigned 32 bit value as a varint.
         * @param {number} value Value to write
         * @returns {Writer} `this`
         */
        Writer.prototype.uint32 = function write_uint32(value) {
          // here, the call to this.push has been inlined and a varint specific Op subclass is used.
          // uint32 is by far the most frequently used operation and benefits significantly from this.
          this.len += (this.tail = this.tail.next = new VarintOp((value = value >>> 0) < 128 ? 1 : value < 16384 ? 2 : value < 2097152 ? 3 : value < 268435456 ? 4 : 5, value)).len;
          return this;
        };

        /**
         * Writes a signed 32 bit value as a varint.
         * @function
         * @param {number} value Value to write
         * @returns {Writer} `this`
         */
        Writer.prototype.int32 = function write_int32(value) {
          return value < 0 ? this._push(writeVarint64, 10, LongBits.fromNumber(value)) // 10 bytes per spec
          : this.uint32(value);
        };

        /**
         * Writes a 32 bit value as a varint, zig-zag encoded.
         * @param {number} value Value to write
         * @returns {Writer} `this`
         */
        Writer.prototype.sint32 = function write_sint32(value) {
          return this.uint32((value << 1 ^ value >> 31) >>> 0);
        };
        function writeVarint64(val, buf, pos) {
          while (val.hi) {
            buf[pos++] = val.lo & 127 | 128;
            val.lo = (val.lo >>> 7 | val.hi << 25) >>> 0;
            val.hi >>>= 7;
          }
          while (val.lo > 127) {
            buf[pos++] = val.lo & 127 | 128;
            val.lo = val.lo >>> 7;
          }
          buf[pos++] = val.lo;
        }

        /**
         * Writes an unsigned 64 bit value as a varint.
         * @param {Long|number|string} value Value to write
         * @returns {Writer} `this`
         * @throws {TypeError} If `value` is a string and no long library is present.
         */
        Writer.prototype.uint64 = function write_uint64(value) {
          var bits = LongBits.from(value);
          return this._push(writeVarint64, bits.length(), bits);
        };

        /**
         * Writes a signed 64 bit value as a varint.
         * @function
         * @param {Long|number|string} value Value to write
         * @returns {Writer} `this`
         * @throws {TypeError} If `value` is a string and no long library is present.
         */
        Writer.prototype.int64 = Writer.prototype.uint64;

        /**
         * Writes a signed 64 bit value as a varint, zig-zag encoded.
         * @param {Long|number|string} value Value to write
         * @returns {Writer} `this`
         * @throws {TypeError} If `value` is a string and no long library is present.
         */
        Writer.prototype.sint64 = function write_sint64(value) {
          var bits = LongBits.from(value).zzEncode();
          return this._push(writeVarint64, bits.length(), bits);
        };

        /**
         * Writes a boolish value as a varint.
         * @param {boolean} value Value to write
         * @returns {Writer} `this`
         */
        Writer.prototype.bool = function write_bool(value) {
          return this._push(writeByte, 1, value ? 1 : 0);
        };
        function writeFixed32(val, buf, pos) {
          buf[pos] = val & 255;
          buf[pos + 1] = val >>> 8 & 255;
          buf[pos + 2] = val >>> 16 & 255;
          buf[pos + 3] = val >>> 24;
        }

        /**
         * Writes an unsigned 32 bit value as fixed 32 bits.
         * @param {number} value Value to write
         * @returns {Writer} `this`
         */
        Writer.prototype.fixed32 = function write_fixed32(value) {
          return this._push(writeFixed32, 4, value >>> 0);
        };

        /**
         * Writes a signed 32 bit value as fixed 32 bits.
         * @function
         * @param {number} value Value to write
         * @returns {Writer} `this`
         */
        Writer.prototype.sfixed32 = Writer.prototype.fixed32;

        /**
         * Writes an unsigned 64 bit value as fixed 64 bits.
         * @param {Long|number|string} value Value to write
         * @returns {Writer} `this`
         * @throws {TypeError} If `value` is a string and no long library is present.
         */
        Writer.prototype.fixed64 = function write_fixed64(value) {
          var bits = LongBits.from(value);
          return this._push(writeFixed32, 4, bits.lo)._push(writeFixed32, 4, bits.hi);
        };

        /**
         * Writes a signed 64 bit value as fixed 64 bits.
         * @function
         * @param {Long|number|string} value Value to write
         * @returns {Writer} `this`
         * @throws {TypeError} If `value` is a string and no long library is present.
         */
        Writer.prototype.sfixed64 = Writer.prototype.fixed64;

        /**
         * Writes a float (32 bit).
         * @function
         * @param {number} value Value to write
         * @returns {Writer} `this`
         */
        Writer.prototype["float"] = function write_float(value) {
          return this._push(util["float"].writeFloatLE, 4, value);
        };

        /**
         * Writes a double (64 bit float).
         * @function
         * @param {number} value Value to write
         * @returns {Writer} `this`
         */
        Writer.prototype["double"] = function write_double(value) {
          return this._push(util["float"].writeDoubleLE, 8, value);
        };
        var writeBytes = util.Array.prototype.set ? function writeBytes_set(val, buf, pos) {
          buf.set(val, pos); // also works for plain array values
        }
        /* istanbul ignore next */ : function writeBytes_for(val, buf, pos) {
          for (var i = 0; i < val.length; ++i) buf[pos + i] = val[i];
        };

        /**
         * Writes a sequence of bytes.
         * @param {Uint8Array|string} value Buffer or base64 encoded string to write
         * @returns {Writer} `this`
         */
        Writer.prototype.bytes = function write_bytes(value) {
          var len = value.length >>> 0;
          if (!len) return this._push(writeByte, 1, 0);
          if (util.isString(value)) {
            var buf = Writer.alloc(len = base64.length(value));
            base64.decode(value, buf, 0);
            value = buf;
          }
          return this.uint32(len)._push(writeBytes, len, value);
        };

        /**
         * Writes a string.
         * @param {string} value Value to write
         * @returns {Writer} `this`
         */
        Writer.prototype.string = function write_string(value) {
          var len = utf8.length(value);
          return len ? this.uint32(len)._push(utf8.write, len, value) : this._push(writeByte, 1, 0);
        };

        /**
         * Forks this writer's state by pushing it to a stack.
         * Calling {@link Writer#reset|reset} or {@link Writer#ldelim|ldelim} resets the writer to the previous state.
         * @returns {Writer} `this`
         */
        Writer.prototype.fork = function fork() {
          this.states = new State(this);
          this.head = this.tail = new Op(noop, 0, 0);
          this.len = 0;
          return this;
        };

        /**
         * Resets this instance to the last state.
         * @returns {Writer} `this`
         */
        Writer.prototype.reset = function reset() {
          if (this.states) {
            this.head = this.states.head;
            this.tail = this.states.tail;
            this.len = this.states.len;
            this.states = this.states.next;
          } else {
            this.head = this.tail = new Op(noop, 0, 0);
            this.len = 0;
          }
          return this;
        };

        /**
         * Resets to the last state and appends the fork state's current write length as a varint followed by its operations.
         * @returns {Writer} `this`
         */
        Writer.prototype.ldelim = function ldelim() {
          var head = this.head,
            tail = this.tail,
            len = this.len;
          this.reset().uint32(len);
          if (len) {
            this.tail.next = head.next; // skip noop
            this.tail = tail;
            this.len += len;
          }
          return this;
        };

        /**
         * Finishes the write operation.
         * @returns {Uint8Array} Finished buffer
         */
        Writer.prototype.finish = function finish() {
          var head = this.head.next,
            // skip noop
            buf = this.constructor.alloc(this.len),
            pos = 0;
          while (head) {
            head.fn(head.val, buf, pos);
            pos += head.len;
            head = head.next;
          }
          // this.head = this.tail = null;
          return buf;
        };
        Writer._configure = function (BufferWriter_) {
          BufferWriter = BufferWriter_;
          Writer.create = create();
          BufferWriter._configure();
        };

        // #endregion ORIGINAL CODE

        module.exports;
      }, function () {
        return {
          './util/minimal': __cjsMetaURL$1
        };
      });
    }
  };
});

System.register("chunks:///_virtual/x64-core.js", ['./rollupPluginModLoBabelHelpers.js', './core.js'], function (exports) {
  var _inheritsLoose, Base, WordArray;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      Base = module.Base;
      WordArray = module.WordArray;
    }],
    execute: function () {
      var X32WordArray = WordArray;

      /**
       * A 64-bit word.
       */
      var X64Word = exports('X64Word', /*#__PURE__*/function (_Base) {
        _inheritsLoose(X64Word, _Base);
        /**
         * Initializes a newly created 64-bit word.
         *
         * @param {number} high The high 32 bits.
         * @param {number} low The low 32 bits.
         *
         * @example
         *
         *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
         */
        function X64Word(high, low) {
          var _this;
          _this = _Base.call(this) || this;
          _this.high = high;
          _this.low = low;
          return _this;
        }
        return X64Word;
      }(Base));

      /**
       * An array of 64-bit words.
       *
       * @property {Array} words The array of CryptoJS.x64.Word objects.
       * @property {number} sigBytes The number of significant bytes in this word array.
       */
      var X64WordArray = exports('X64WordArray', /*#__PURE__*/function (_Base2) {
        _inheritsLoose(X64WordArray, _Base2);
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.x64.WordArray.create();
         *
         *     var wordArray = CryptoJS.x64.WordArray.create([
         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
         *     ]);
         *
         *     var wordArray = CryptoJS.x64.WordArray.create([
         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
         *     ], 10);
         */
        function X64WordArray(words, sigBytes) {
          var _this2;
          if (words === void 0) {
            words = [];
          }
          if (sigBytes === void 0) {
            sigBytes = words.length * 8;
          }
          _this2 = _Base2.call(this) || this;
          _this2.words = words;
          _this2.sigBytes = sigBytes;
          return _this2;
        }

        /**
         * Converts this 64-bit word array to a 32-bit word array.
         *
         * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
         *
         * @example
         *
         *     var x32WordArray = x64WordArray.toX32();
         */
        var _proto = X64WordArray.prototype;
        _proto.toX32 = function toX32() {
          // Shortcuts
          var x64Words = this.words;
          var x64WordsLength = x64Words.length;

          // Convert
          var x32Words = [];
          for (var i = 0; i < x64WordsLength; i += 1) {
            var x64Word = x64Words[i];
            x32Words.push(x64Word.high);
            x32Words.push(x64Word.low);
          }
          return X32WordArray.create(x32Words, this.sigBytes);
        }

        /**
         * Creates a copy of this word array.
         *
         * @return {X64WordArray} The clone.
         *
         * @example
         *
         *     var clone = x64WordArray.clone();
         */;
        _proto.clone = function clone() {
          var clone = _Base2.prototype.clone.call(this);

          // Clone "words" array
          clone.words = this.words.slice(0);
          var words = clone.words;

          // Clone each X64Word object
          var wordsLength = words.length;
          for (var i = 0; i < wordsLength; i += 1) {
            words[i] = words[i].clone();
          }
          return clone;
        };
        return X64WordArray;
      }(Base));
    }
  };
});

} }; });