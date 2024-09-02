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
      var qt = exports('HapticFeedback', /*#__PURE__*/function (_te2) {
        _inheritsLoose(qt, _te2);
        function qt(e, t) {
          var _this16;
          _this16 = _te2.call(this, e, {
            impactOccurred: "web_app_trigger_haptic_feedback",
            notificationOccurred: "web_app_trigger_haptic_feedback",
            selectionChanged: "web_app_trigger_haptic_feedback"
          }) || this, _this16.postEvent = t;
          return _this16;
        }
        /**
         * A method tells that an impact occurred. The Telegram app may play the
         * appropriate haptics based on style value passed.
         * @param style - impact style.
         */
        var _proto10 = qt.prototype;
        _proto10.impactOccurred = function impactOccurred(e) {
          this.postEvent("web_app_trigger_haptic_feedback", {
            type: "impact",
            impact_style: e
          });
        }
        /**
         * A method tells that a task or action has succeeded, failed, or produced
         * a warning. The Telegram app may play the appropriate haptics based on
         * type value passed.
         * @param type - notification type.
         */;
        _proto10.notificationOccurred = function notificationOccurred(e) {
          this.postEvent("web_app_trigger_haptic_feedback", {
            type: "notification",
            notification_type: e
          });
        }
        /**
         * A method tells that the user has changed a selection. The Telegram app
         * may play the appropriate haptics.
         *
         * Do not use this feedback when the user makes or confirms a selection;
         * use it only when the selection changes.
         */;
        _proto10.selectionChanged = function selectionChanged() {
          this.postEvent("web_app_trigger_haptic_feedback", {
            type: "selection_change"
          });
        };
        return qt;
      }(te));
      var as = exports('initHapticFeedback', l(function (_ref20) {
        var s = _ref20.version,
          e = _ref20.postEvent;
        return new qt(s, e);
      }));
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

System.register("chunks:///_virtual/index4.js", ['./cjs-loader.mjs'], function (exports, module) {
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

System.register("chunks:///_virtual/index6.js", ['./cjs-loader.mjs'], function (exports, module) {
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

System.register("chunks:///_virtual/index7.js", ['./cjs-loader.mjs'], function (exports, module) {
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

System.register("chunks:///_virtual/index8.js", ['./cjs-loader.mjs'], function (exports, module) {
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

System.register("chunks:///_virtual/index9.js", ['./cjs-loader.mjs'], function (exports, module) {
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

System.register("chunks:///_virtual/minimal2.js", ['./cjs-loader.mjs', './index3.js', './index6.js', './index8.js', './index7.js', './index4.js', './index5.js', './index9.js', './longbits.js'], function (exports, module) {
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

System.register("chunks:///_virtual/mixpanel.cjs.js", ['./cjs-loader.mjs'], function (exports, module) {
  var loader;
  return {
    setters: [function (module) {
      loader = module.default;
    }],
    execute: function () {
      exports('default', void 0);
      function _regeneratorRuntime() {
        /*! regenerator-runtime -- Copyright (c) 2014-present, Facebook, Inc. -- license (MIT): https://github.com/facebook/regenerator/blob/main/LICENSE */_regeneratorRuntime = function _regeneratorRuntime() {
          return e;
        };
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
          define = function define(t, e, r) {
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
            value: function value(t, n) {
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
          if (o === t) return r.delegate = null, "throw" === n && e.iterator["return"] && (r.method = "return", r.arg = t, maybeInvokeDelegate(e, r), "throw" === r.method) || "return" !== n && (r.method = "throw", r.arg = new TypeError("The iterator does not provide a '" + n + "' method")), y;
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
          reset: function reset(e) {
            if (this.prev = 0, this.next = 0, this.sent = this._sent = t, this.done = !1, this.delegate = null, this.method = "next", this.arg = t, this.tryEntries.forEach(resetTryEntry), !e) for (var r in this) "t" === r.charAt(0) && n.call(this, r) && !isNaN(+r.slice(1)) && (this[r] = t);
          },
          stop: function stop() {
            this.done = !0;
            var t = this.tryEntries[0].completion;
            if ("throw" === t.type) throw t.arg;
            return this.rval;
          },
          dispatchException: function dispatchException(e) {
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
          abrupt: function abrupt(t, e) {
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
          complete: function complete(t, e) {
            if ("throw" === t.type) throw t.arg;
            return "break" === t.type || "continue" === t.type ? this.next = t.arg : "return" === t.type ? (this.rval = this.arg = t.arg, this.method = "return", this.next = "end") : "normal" === t.type && e && (this.next = e), y;
          },
          finish: function finish(t) {
            for (var e = this.tryEntries.length - 1; e >= 0; --e) {
              var r = this.tryEntries[e];
              if (r.finallyLoc === t) return this.complete(r.completion, r.afterLoc), resetTryEntry(r), y;
            }
          },
          "catch": function _catch(t) {
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
          delegateYield: function delegateYield(e, r, n) {
            return this.delegate = {
              iterator: values(e),
              resultName: r,
              nextLoc: n
            }, "next" === this.method && (this.arg = t), y;
          }
        }, e;
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
      var _cjsExports;
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports$1, require, module, __filename, __dirname) {
        var NodeType;
        (function (NodeType) {
          NodeType[NodeType["Document"] = 0] = "Document";
          NodeType[NodeType["DocumentType"] = 1] = "DocumentType";
          NodeType[NodeType["Element"] = 2] = "Element";
          NodeType[NodeType["Text"] = 3] = "Text";
          NodeType[NodeType["CDATA"] = 4] = "CDATA";
          NodeType[NodeType["Comment"] = 5] = "Comment";
        })(NodeType || (NodeType = {}));
        function isElement(n) {
          return n.nodeType === n.ELEMENT_NODE;
        }
        function isShadowRoot(n) {
          var host = n === null || n === void 0 ? void 0 : n.host;
          return Boolean((host === null || host === void 0 ? void 0 : host.shadowRoot) === n);
        }
        function isNativeShadowDom(shadowRoot) {
          return Object.prototype.toString.call(shadowRoot) === '[object ShadowRoot]';
        }
        function fixBrowserCompatibilityIssuesInCSS(cssText) {
          if (cssText.includes(' background-clip: text;') && !cssText.includes(' -webkit-background-clip: text;')) {
            cssText = cssText.replace(' background-clip: text;', ' -webkit-background-clip: text; background-clip: text;');
          }
          return cssText;
        }
        function escapeImportStatement(rule) {
          var cssText = rule.cssText;
          if (cssText.split('"').length < 3) return cssText;
          var statement = ['@import', "url(" + JSON.stringify(rule.href) + ")"];
          if (rule.layerName === '') {
            statement.push("layer");
          } else if (rule.layerName) {
            statement.push("layer(" + rule.layerName + ")");
          }
          if (rule.supportsText) {
            statement.push("supports(" + rule.supportsText + ")");
          }
          if (rule.media.length) {
            statement.push(rule.media.mediaText);
          }
          return statement.join(' ') + ';';
        }
        function stringifyStylesheet(s) {
          try {
            var rules = s.rules || s.cssRules;
            return rules ? fixBrowserCompatibilityIssuesInCSS(Array.from(rules, stringifyRule).join('')) : null;
          } catch (error) {
            return null;
          }
        }
        function stringifyRule(rule) {
          var importStringified;
          if (isCSSImportRule(rule)) {
            try {
              importStringified = stringifyStylesheet(rule.styleSheet) || escapeImportStatement(rule);
            } catch (error) {}
          } else if (isCSSStyleRule(rule) && rule.selectorText.includes(':')) {
            return fixSafariColons(rule.cssText);
          }
          return importStringified || rule.cssText;
        }
        function fixSafariColons(cssStringified) {
          var regex = /(\[(?:[\w-]+)[^\\])(:(?:[\w-]+)\])/gm;
          return cssStringified.replace(regex, '$1\\$2');
        }
        function isCSSImportRule(rule) {
          return 'styleSheet' in rule;
        }
        function isCSSStyleRule(rule) {
          return 'selectorText' in rule;
        }
        var Mirror = /*#__PURE__*/function () {
          function Mirror() {
            this.idNodeMap = new Map();
            this.nodeMetaMap = new WeakMap();
          }
          var _proto = Mirror.prototype;
          _proto.getId = function getId(n) {
            var _a;
            if (!n) return -1;
            var id = (_a = this.getMeta(n)) === null || _a === void 0 ? void 0 : _a.id;
            return id !== null && id !== void 0 ? id : -1;
          };
          _proto.getNode = function getNode(id) {
            return this.idNodeMap.get(id) || null;
          };
          _proto.getIds = function getIds() {
            return Array.from(this.idNodeMap.keys());
          };
          _proto.getMeta = function getMeta(n) {
            return this.nodeMetaMap.get(n) || null;
          };
          _proto.removeNodeFromMap = function removeNodeFromMap(n) {
            var _this2 = this;
            var id = this.getId(n);
            this.idNodeMap["delete"](id);
            if (n.childNodes) {
              n.childNodes.forEach(function (childNode) {
                return _this2.removeNodeFromMap(childNode);
              });
            }
          };
          _proto.has = function has(id) {
            return this.idNodeMap.has(id);
          };
          _proto.hasNode = function hasNode(node) {
            return this.nodeMetaMap.has(node);
          };
          _proto.add = function add(n, meta) {
            var id = meta.id;
            this.idNodeMap.set(id, n);
            this.nodeMetaMap.set(n, meta);
          };
          _proto.replace = function replace(id, n) {
            var oldNode = this.getNode(id);
            if (oldNode) {
              var meta = this.nodeMetaMap.get(oldNode);
              if (meta) this.nodeMetaMap.set(n, meta);
            }
            this.idNodeMap.set(id, n);
          };
          _proto.reset = function reset() {
            this.idNodeMap = new Map();
            this.nodeMetaMap = new WeakMap();
          };
          return Mirror;
        }();
        function createMirror() {
          return new Mirror();
        }
        function maskInputValue(_ref) {
          var element = _ref.element,
            maskInputOptions = _ref.maskInputOptions,
            tagName = _ref.tagName,
            type = _ref.type,
            value = _ref.value,
            maskInputFn = _ref.maskInputFn;
          var text = value || '';
          var actualType = type && toLowerCase(type);
          if (maskInputOptions[tagName.toLowerCase()] || actualType && maskInputOptions[actualType]) {
            if (maskInputFn) {
              text = maskInputFn(text, element);
            } else {
              text = '*'.repeat(text.length);
            }
          }
          return text;
        }
        function toLowerCase(str) {
          return str.toLowerCase();
        }
        var ORIGINAL_ATTRIBUTE_NAME = '__rrweb_original__';
        function is2DCanvasBlank(canvas) {
          var ctx = canvas.getContext('2d');
          if (!ctx) return true;
          var chunkSize = 50;
          for (var x = 0; x < canvas.width; x += chunkSize) {
            for (var y = 0; y < canvas.height; y += chunkSize) {
              var getImageData = ctx.getImageData;
              var originalGetImageData = ORIGINAL_ATTRIBUTE_NAME in getImageData ? getImageData[ORIGINAL_ATTRIBUTE_NAME] : getImageData;
              var pixelBuffer = new Uint32Array(originalGetImageData.call(ctx, x, y, Math.min(chunkSize, canvas.width - x), Math.min(chunkSize, canvas.height - y)).data.buffer);
              if (pixelBuffer.some(function (pixel) {
                return pixel !== 0;
              })) return false;
            }
          }
          return true;
        }
        function getInputType(element) {
          var type = element.type;
          return element.hasAttribute('data-rr-is-password') ? 'password' : type ? toLowerCase(type) : null;
        }
        function extractFileExtension(path, baseURL) {
          var _a;
          var url;
          try {
            url = new URL(path, baseURL !== null && baseURL !== void 0 ? baseURL : window.location.href);
          } catch (err) {
            return null;
          }
          var regex = /\.([0-9a-z]+)(?:$)/i;
          var match = url.pathname.match(regex);
          return (_a = match === null || match === void 0 ? void 0 : match[1]) !== null && _a !== void 0 ? _a : null;
        }
        var _id = 1;
        var tagNameRegex = new RegExp('[^a-z0-9-_:]');
        var IGNORED_NODE = -2;
        function genId() {
          return _id++;
        }
        function getValidTagName(element) {
          if (element instanceof HTMLFormElement) {
            return 'form';
          }
          var processedTagName = toLowerCase(element.tagName);
          if (tagNameRegex.test(processedTagName)) {
            return 'div';
          }
          return processedTagName;
        }
        function extractOrigin(url) {
          var origin = '';
          if (url.indexOf('//') > -1) {
            origin = url.split('/').slice(0, 3).join('/');
          } else {
            origin = url.split('/')[0];
          }
          origin = origin.split('?')[0];
          return origin;
        }
        var canvasService;
        var canvasCtx;
        var URL_IN_CSS_REF = /url\((?:(')([^']*)'|(")(.*?)"|([^)]*))\)/gm;
        var URL_PROTOCOL_MATCH = /^(?:[a-z+]+:)?\/\//i;
        var URL_WWW_MATCH = /^www\..*/i;
        var DATA_URI = /^(data:)([^,]*),(.*)/i;
        function absoluteToStylesheet(cssText, href) {
          return (cssText || '').replace(URL_IN_CSS_REF, function (origin, quote1, path1, quote2, path2, path3) {
            var filePath = path1 || path2 || path3;
            var maybeQuote = quote1 || quote2 || '';
            if (!filePath) {
              return origin;
            }
            if (URL_PROTOCOL_MATCH.test(filePath) || URL_WWW_MATCH.test(filePath)) {
              return "url(" + maybeQuote + filePath + maybeQuote + ")";
            }
            if (DATA_URI.test(filePath)) {
              return "url(" + maybeQuote + filePath + maybeQuote + ")";
            }
            if (filePath[0] === '/') {
              return "url(" + maybeQuote + (extractOrigin(href) + filePath) + maybeQuote + ")";
            }
            var stack = href.split('/');
            var parts = filePath.split('/');
            stack.pop();
            for (var _iterator = _createForOfIteratorHelperLoose(parts), _step; !(_step = _iterator()).done;) {
              var part = _step.value;
              if (part === '.') {
                continue;
              } else if (part === '..') {
                stack.pop();
              } else {
                stack.push(part);
              }
            }
            return "url(" + maybeQuote + stack.join('/') + maybeQuote + ")";
          });
        }
        var SRCSET_NOT_SPACES = /^[^ \t\n\r\u000c]+/;
        var SRCSET_COMMAS_OR_SPACES = /^[, \t\n\r\u000c]+/;
        function getAbsoluteSrcsetString(doc, attributeValue) {
          if (attributeValue.trim() === '') {
            return attributeValue;
          }
          var pos = 0;
          function collectCharacters(regEx) {
            var chars;
            var match = regEx.exec(attributeValue.substring(pos));
            if (match) {
              chars = match[0];
              pos += chars.length;
              return chars;
            }
            return '';
          }
          var output = [];
          while (true) {
            collectCharacters(SRCSET_COMMAS_OR_SPACES);
            if (pos >= attributeValue.length) {
              break;
            }
            var url = collectCharacters(SRCSET_NOT_SPACES);
            if (url.slice(-1) === ',') {
              url = absoluteToDoc(doc, url.substring(0, url.length - 1));
              output.push(url);
            } else {
              var descriptorsStr = '';
              url = absoluteToDoc(doc, url);
              var inParens = false;
              while (true) {
                var c = attributeValue.charAt(pos);
                if (c === '') {
                  output.push((url + descriptorsStr).trim());
                  break;
                } else if (!inParens) {
                  if (c === ',') {
                    pos += 1;
                    output.push((url + descriptorsStr).trim());
                    break;
                  } else if (c === '(') {
                    inParens = true;
                  }
                } else {
                  if (c === ')') {
                    inParens = false;
                  }
                }
                descriptorsStr += c;
                pos += 1;
              }
            }
          }
          return output.join(', ');
        }
        function absoluteToDoc(doc, attributeValue) {
          if (!attributeValue || attributeValue.trim() === '') {
            return attributeValue;
          }
          var a = doc.createElement('a');
          a.href = attributeValue;
          return a.href;
        }
        function isSVGElement(el) {
          return Boolean(el.tagName === 'svg' || el.ownerSVGElement);
        }
        function getHref() {
          var a = document.createElement('a');
          a.href = '';
          return a.href;
        }
        function transformAttribute(doc, tagName, name, value) {
          if (!value) {
            return value;
          }
          if (name === 'src' || name === 'href' && !(tagName === 'use' && value[0] === '#')) {
            return absoluteToDoc(doc, value);
          } else if (name === 'xlink:href' && value[0] !== '#') {
            return absoluteToDoc(doc, value);
          } else if (name === 'background' && (tagName === 'table' || tagName === 'td' || tagName === 'th')) {
            return absoluteToDoc(doc, value);
          } else if (name === 'srcset') {
            return getAbsoluteSrcsetString(doc, value);
          } else if (name === 'style') {
            return absoluteToStylesheet(value, getHref());
          } else if (tagName === 'object' && name === 'data') {
            return absoluteToDoc(doc, value);
          }
          return value;
        }
        function ignoreAttribute(tagName, name, _value) {
          return (tagName === 'video' || tagName === 'audio') && name === 'autoplay';
        }
        function _isBlockedElement(element, blockClass, blockSelector) {
          try {
            if (typeof blockClass === 'string') {
              if (element.classList.contains(blockClass)) {
                return true;
              }
            } else {
              for (var eIndex = element.classList.length; eIndex--;) {
                var className = element.classList[eIndex];
                if (blockClass.test(className)) {
                  return true;
                }
              }
            }
            if (blockSelector) {
              return element.matches(blockSelector);
            }
          } catch (e) {}
          return false;
        }
        function classMatchesRegex(node, regex, checkAncestors) {
          if (!node) return false;
          if (node.nodeType !== node.ELEMENT_NODE) {
            if (!checkAncestors) return false;
            return classMatchesRegex(node.parentNode, regex, checkAncestors);
          }
          for (var eIndex = node.classList.length; eIndex--;) {
            var className = node.classList[eIndex];
            if (regex.test(className)) {
              return true;
            }
          }
          if (!checkAncestors) return false;
          return classMatchesRegex(node.parentNode, regex, checkAncestors);
        }
        function needMaskingText(node, maskTextClass, maskTextSelector, checkAncestors) {
          try {
            var el = node.nodeType === node.ELEMENT_NODE ? node : node.parentElement;
            if (el === null) return false;
            if (typeof maskTextClass === 'string') {
              if (checkAncestors) {
                if (el.closest("." + maskTextClass)) return true;
              } else {
                if (el.classList.contains(maskTextClass)) return true;
              }
            } else {
              if (classMatchesRegex(el, maskTextClass, checkAncestors)) return true;
            }
            if (maskTextSelector) {
              if (checkAncestors) {
                if (el.closest(maskTextSelector)) return true;
              } else {
                if (el.matches(maskTextSelector)) return true;
              }
            }
          } catch (e) {}
          return false;
        }
        function onceIframeLoaded(iframeEl, listener, iframeLoadTimeout) {
          var win = iframeEl.contentWindow;
          if (!win) {
            return;
          }
          var fired = false;
          var readyState;
          try {
            readyState = win.document.readyState;
          } catch (error) {
            return;
          }
          if (readyState !== 'complete') {
            var timer = setTimeout(function () {
              if (!fired) {
                listener();
                fired = true;
              }
            }, iframeLoadTimeout);
            iframeEl.addEventListener('load', function () {
              clearTimeout(timer);
              fired = true;
              listener();
            });
            return;
          }
          var blankUrl = 'about:blank';
          if (win.location.href !== blankUrl || iframeEl.src === blankUrl || iframeEl.src === '') {
            setTimeout(listener, 0);
            return iframeEl.addEventListener('load', listener);
          }
          iframeEl.addEventListener('load', listener);
        }
        function onceStylesheetLoaded(link, listener, styleSheetLoadTimeout) {
          var fired = false;
          var styleSheetLoaded;
          try {
            styleSheetLoaded = link.sheet;
          } catch (error) {
            return;
          }
          if (styleSheetLoaded) return;
          var timer = setTimeout(function () {
            if (!fired) {
              listener();
              fired = true;
            }
          }, styleSheetLoadTimeout);
          link.addEventListener('load', function () {
            clearTimeout(timer);
            fired = true;
            listener();
          });
        }
        function serializeNode(n, options) {
          var doc = options.doc,
            mirror = options.mirror,
            blockClass = options.blockClass,
            blockSelector = options.blockSelector,
            needsMask = options.needsMask,
            inlineStylesheet = options.inlineStylesheet,
            _options$maskInputOpt = options.maskInputOptions,
            maskInputOptions = _options$maskInputOpt === void 0 ? {} : _options$maskInputOpt,
            maskTextFn = options.maskTextFn,
            maskInputFn = options.maskInputFn,
            _options$dataURLOptio = options.dataURLOptions,
            dataURLOptions = _options$dataURLOptio === void 0 ? {} : _options$dataURLOptio,
            inlineImages = options.inlineImages,
            recordCanvas = options.recordCanvas,
            keepIframeSrcFn = options.keepIframeSrcFn,
            _options$newlyAddedEl = options.newlyAddedElement,
            newlyAddedElement = _options$newlyAddedEl === void 0 ? false : _options$newlyAddedEl;
          var rootId = getRootId(doc, mirror);
          switch (n.nodeType) {
            case n.DOCUMENT_NODE:
              if (n.compatMode !== 'CSS1Compat') {
                return {
                  type: NodeType.Document,
                  childNodes: [],
                  compatMode: n.compatMode
                };
              } else {
                return {
                  type: NodeType.Document,
                  childNodes: []
                };
              }
            case n.DOCUMENT_TYPE_NODE:
              return {
                type: NodeType.DocumentType,
                name: n.name,
                publicId: n.publicId,
                systemId: n.systemId,
                rootId: rootId
              };
            case n.ELEMENT_NODE:
              return serializeElementNode(n, {
                doc: doc,
                blockClass: blockClass,
                blockSelector: blockSelector,
                inlineStylesheet: inlineStylesheet,
                maskInputOptions: maskInputOptions,
                maskInputFn: maskInputFn,
                dataURLOptions: dataURLOptions,
                inlineImages: inlineImages,
                recordCanvas: recordCanvas,
                keepIframeSrcFn: keepIframeSrcFn,
                newlyAddedElement: newlyAddedElement,
                rootId: rootId
              });
            case n.TEXT_NODE:
              return serializeTextNode(n, {
                needsMask: needsMask,
                maskTextFn: maskTextFn,
                rootId: rootId
              });
            case n.CDATA_SECTION_NODE:
              return {
                type: NodeType.CDATA,
                textContent: '',
                rootId: rootId
              };
            case n.COMMENT_NODE:
              return {
                type: NodeType.Comment,
                textContent: n.textContent || '',
                rootId: rootId
              };
            default:
              return false;
          }
        }
        function getRootId(doc, mirror) {
          if (!mirror.hasNode(doc)) return undefined;
          var docId = mirror.getId(doc);
          return docId === 1 ? undefined : docId;
        }
        function serializeTextNode(n, options) {
          var _a;
          var needsMask = options.needsMask,
            maskTextFn = options.maskTextFn,
            rootId = options.rootId;
          var parentTagName = n.parentNode && n.parentNode.tagName;
          var textContent = n.textContent;
          var isStyle = parentTagName === 'STYLE' ? true : undefined;
          var isScript = parentTagName === 'SCRIPT' ? true : undefined;
          if (isStyle && textContent) {
            try {
              if (n.nextSibling || n.previousSibling) {} else if ((_a = n.parentNode.sheet) === null || _a === void 0 ? void 0 : _a.cssRules) {
                textContent = stringifyStylesheet(n.parentNode.sheet);
              }
            } catch (err) {
              console.warn("Cannot get CSS styles from text's parentNode. Error: " + err, n);
            }
            textContent = absoluteToStylesheet(textContent, getHref());
          }
          if (isScript) {
            textContent = 'SCRIPT_PLACEHOLDER';
          }
          if (!isStyle && !isScript && textContent && needsMask) {
            textContent = maskTextFn ? maskTextFn(textContent, n.parentElement) : textContent.replace(/[\S]/g, '*');
          }
          return {
            type: NodeType.Text,
            textContent: textContent || '',
            isStyle: isStyle,
            rootId: rootId
          };
        }
        function serializeElementNode(n, options) {
          var doc = options.doc,
            blockClass = options.blockClass,
            blockSelector = options.blockSelector,
            inlineStylesheet = options.inlineStylesheet,
            _options$maskInputOpt2 = options.maskInputOptions,
            maskInputOptions = _options$maskInputOpt2 === void 0 ? {} : _options$maskInputOpt2,
            maskInputFn = options.maskInputFn,
            _options$dataURLOptio2 = options.dataURLOptions,
            dataURLOptions = _options$dataURLOptio2 === void 0 ? {} : _options$dataURLOptio2,
            inlineImages = options.inlineImages,
            recordCanvas = options.recordCanvas,
            keepIframeSrcFn = options.keepIframeSrcFn,
            _options$newlyAddedEl2 = options.newlyAddedElement,
            newlyAddedElement = _options$newlyAddedEl2 === void 0 ? false : _options$newlyAddedEl2,
            rootId = options.rootId;
          var needBlock = _isBlockedElement(n, blockClass, blockSelector);
          var tagName = getValidTagName(n);
          var attributes = {};
          var len = n.attributes.length;
          for (var _i = 0; _i < len; _i++) {
            var attr = n.attributes[_i];
            if (!ignoreAttribute(tagName, attr.name, attr.value)) {
              attributes[attr.name] = transformAttribute(doc, tagName, toLowerCase(attr.name), attr.value);
            }
          }
          if (tagName === 'link' && inlineStylesheet) {
            var stylesheet = Array.from(doc.styleSheets).find(function (s) {
              return s.href === n.href;
            });
            var cssText = null;
            if (stylesheet) {
              cssText = stringifyStylesheet(stylesheet);
            }
            if (cssText) {
              delete attributes.rel;
              delete attributes.href;
              attributes._cssText = absoluteToStylesheet(cssText, stylesheet.href);
            }
          }
          if (tagName === 'style' && n.sheet && !(n.innerText || n.textContent || '').trim().length) {
            var _cssText = stringifyStylesheet(n.sheet);
            if (_cssText) {
              attributes._cssText = absoluteToStylesheet(_cssText, getHref());
            }
          }
          if (tagName === 'input' || tagName === 'textarea' || tagName === 'select') {
            var value = n.value;
            var checked = n.checked;
            if (attributes.type !== 'radio' && attributes.type !== 'checkbox' && attributes.type !== 'submit' && attributes.type !== 'button' && value) {
              attributes.value = maskInputValue({
                element: n,
                type: getInputType(n),
                tagName: tagName,
                value: value,
                maskInputOptions: maskInputOptions,
                maskInputFn: maskInputFn
              });
            } else if (checked) {
              attributes.checked = checked;
            }
          }
          if (tagName === 'option') {
            if (n.selected && !maskInputOptions['select']) {
              attributes.selected = true;
            } else {
              delete attributes.selected;
            }
          }
          if (tagName === 'canvas' && recordCanvas) {
            if (n.__context === '2d') {
              if (!is2DCanvasBlank(n)) {
                attributes.rr_dataURL = n.toDataURL(dataURLOptions.type, dataURLOptions.quality);
              }
            } else if (!('__context' in n)) {
              var canvasDataURL = n.toDataURL(dataURLOptions.type, dataURLOptions.quality);
              var blankCanvas = document.createElement('canvas');
              blankCanvas.width = n.width;
              blankCanvas.height = n.height;
              var blankCanvasDataURL = blankCanvas.toDataURL(dataURLOptions.type, dataURLOptions.quality);
              if (canvasDataURL !== blankCanvasDataURL) {
                attributes.rr_dataURL = canvasDataURL;
              }
            }
          }
          if (tagName === 'img' && inlineImages) {
            if (!canvasService) {
              canvasService = doc.createElement('canvas');
              canvasCtx = canvasService.getContext('2d');
            }
            var image = n;
            var oldValue = image.crossOrigin;
            image.crossOrigin = 'anonymous';
            var recordInlineImage = function recordInlineImage() {
              image.removeEventListener('load', recordInlineImage);
              try {
                canvasService.width = image.naturalWidth;
                canvasService.height = image.naturalHeight;
                canvasCtx.drawImage(image, 0, 0);
                attributes.rr_dataURL = canvasService.toDataURL(dataURLOptions.type, dataURLOptions.quality);
              } catch (err) {
                console.warn("Cannot inline img src=" + image.currentSrc + "! Error: " + err);
              }
              oldValue ? attributes.crossOrigin = oldValue : image.removeAttribute('crossorigin');
            };
            if (image.complete && image.naturalWidth !== 0) recordInlineImage();else image.addEventListener('load', recordInlineImage);
          }
          if (tagName === 'audio' || tagName === 'video') {
            var mediaAttributes = attributes;
            mediaAttributes.rr_mediaState = n.paused ? 'paused' : 'played';
            mediaAttributes.rr_mediaCurrentTime = n.currentTime;
            mediaAttributes.rr_mediaPlaybackRate = n.playbackRate;
            mediaAttributes.rr_mediaMuted = n.muted;
            mediaAttributes.rr_mediaLoop = n.loop;
            mediaAttributes.rr_mediaVolume = n.volume;
          }
          if (!newlyAddedElement) {
            if (n.scrollLeft) {
              attributes.rr_scrollLeft = n.scrollLeft;
            }
            if (n.scrollTop) {
              attributes.rr_scrollTop = n.scrollTop;
            }
          }
          if (needBlock) {
            var _n$getBoundingClientR = n.getBoundingClientRect(),
              width = _n$getBoundingClientR.width,
              height = _n$getBoundingClientR.height;
            attributes = {
              "class": attributes["class"],
              rr_width: width + "px",
              rr_height: height + "px"
            };
          }
          if (tagName === 'iframe' && !keepIframeSrcFn(attributes.src)) {
            if (!n.contentDocument) {
              attributes.rr_src = attributes.src;
            }
            delete attributes.src;
          }
          var isCustomElement;
          try {
            if (customElements.get(tagName)) isCustomElement = true;
          } catch (e) {}
          return {
            type: NodeType.Element,
            tagName: tagName,
            attributes: attributes,
            childNodes: [],
            isSVG: isSVGElement(n) || undefined,
            needBlock: needBlock,
            rootId: rootId,
            isCustom: isCustomElement
          };
        }
        function lowerIfExists(maybeAttr) {
          if (maybeAttr === undefined || maybeAttr === null) {
            return '';
          } else {
            return maybeAttr.toLowerCase();
          }
        }
        function slimDOMExcluded(sn, slimDOMOptions) {
          if (slimDOMOptions.comment && sn.type === NodeType.Comment) {
            return true;
          } else if (sn.type === NodeType.Element) {
            if (slimDOMOptions.script && (sn.tagName === 'script' || sn.tagName === 'link' && (sn.attributes.rel === 'preload' || sn.attributes.rel === 'modulepreload') && sn.attributes.as === 'script' || sn.tagName === 'link' && sn.attributes.rel === 'prefetch' && typeof sn.attributes.href === 'string' && extractFileExtension(sn.attributes.href) === 'js')) {
              return true;
            } else if (slimDOMOptions.headFavicon && (sn.tagName === 'link' && sn.attributes.rel === 'shortcut icon' || sn.tagName === 'meta' && (lowerIfExists(sn.attributes.name).match(/^msapplication-tile(image|color)$/) || lowerIfExists(sn.attributes.name) === 'application-name' || lowerIfExists(sn.attributes.rel) === 'icon' || lowerIfExists(sn.attributes.rel) === 'apple-touch-icon' || lowerIfExists(sn.attributes.rel) === 'shortcut icon'))) {
              return true;
            } else if (sn.tagName === 'meta') {
              if (slimDOMOptions.headMetaDescKeywords && lowerIfExists(sn.attributes.name).match(/^description|keywords$/)) {
                return true;
              } else if (slimDOMOptions.headMetaSocial && (lowerIfExists(sn.attributes.property).match(/^(og|twitter|fb):/) || lowerIfExists(sn.attributes.name).match(/^(og|twitter):/) || lowerIfExists(sn.attributes.name) === 'pinterest')) {
                return true;
              } else if (slimDOMOptions.headMetaRobots && (lowerIfExists(sn.attributes.name) === 'robots' || lowerIfExists(sn.attributes.name) === 'googlebot' || lowerIfExists(sn.attributes.name) === 'bingbot')) {
                return true;
              } else if (slimDOMOptions.headMetaHttpEquiv && sn.attributes['http-equiv'] !== undefined) {
                return true;
              } else if (slimDOMOptions.headMetaAuthorship && (lowerIfExists(sn.attributes.name) === 'author' || lowerIfExists(sn.attributes.name) === 'generator' || lowerIfExists(sn.attributes.name) === 'framework' || lowerIfExists(sn.attributes.name) === 'publisher' || lowerIfExists(sn.attributes.name) === 'progid' || lowerIfExists(sn.attributes.property).match(/^article:/) || lowerIfExists(sn.attributes.property).match(/^product:/))) {
                return true;
              } else if (slimDOMOptions.headMetaVerification && (lowerIfExists(sn.attributes.name) === 'google-site-verification' || lowerIfExists(sn.attributes.name) === 'yandex-verification' || lowerIfExists(sn.attributes.name) === 'csrf-token' || lowerIfExists(sn.attributes.name) === 'p:domain_verify' || lowerIfExists(sn.attributes.name) === 'verify-v1' || lowerIfExists(sn.attributes.name) === 'verification' || lowerIfExists(sn.attributes.name) === 'shopify-checkout-api-token')) {
                return true;
              }
            }
          }
          return false;
        }
        function serializeNodeWithId(n, options) {
          var doc = options.doc,
            mirror = options.mirror,
            blockClass = options.blockClass,
            blockSelector = options.blockSelector,
            maskTextClass = options.maskTextClass,
            maskTextSelector = options.maskTextSelector,
            _options$skipChild = options.skipChild,
            skipChild = _options$skipChild === void 0 ? false : _options$skipChild,
            _options$inlineStyles = options.inlineStylesheet,
            inlineStylesheet = _options$inlineStyles === void 0 ? true : _options$inlineStyles,
            _options$maskInputOpt3 = options.maskInputOptions,
            maskInputOptions = _options$maskInputOpt3 === void 0 ? {} : _options$maskInputOpt3,
            maskTextFn = options.maskTextFn,
            maskInputFn = options.maskInputFn,
            slimDOMOptions = options.slimDOMOptions,
            _options$dataURLOptio3 = options.dataURLOptions,
            dataURLOptions = _options$dataURLOptio3 === void 0 ? {} : _options$dataURLOptio3,
            _options$inlineImages = options.inlineImages,
            inlineImages = _options$inlineImages === void 0 ? false : _options$inlineImages,
            _options$recordCanvas = options.recordCanvas,
            recordCanvas = _options$recordCanvas === void 0 ? false : _options$recordCanvas,
            onSerialize = options.onSerialize,
            onIframeLoad = options.onIframeLoad,
            _options$iframeLoadTi = options.iframeLoadTimeout,
            iframeLoadTimeout = _options$iframeLoadTi === void 0 ? 5000 : _options$iframeLoadTi,
            onStylesheetLoad = options.onStylesheetLoad,
            _options$stylesheetLo = options.stylesheetLoadTimeout,
            stylesheetLoadTimeout = _options$stylesheetLo === void 0 ? 5000 : _options$stylesheetLo,
            _options$keepIframeSr = options.keepIframeSrcFn,
            keepIframeSrcFn = _options$keepIframeSr === void 0 ? function () {
              return false;
            } : _options$keepIframeSr,
            _options$newlyAddedEl3 = options.newlyAddedElement,
            newlyAddedElement = _options$newlyAddedEl3 === void 0 ? false : _options$newlyAddedEl3;
          var needsMask = options.needsMask;
          var _options$preserveWhit = options.preserveWhiteSpace,
            preserveWhiteSpace = _options$preserveWhit === void 0 ? true : _options$preserveWhit;
          if (!needsMask && n.childNodes) {
            var checkAncestors = needsMask === undefined;
            needsMask = needMaskingText(n, maskTextClass, maskTextSelector, checkAncestors);
          }
          var _serializedNode = serializeNode(n, {
            doc: doc,
            mirror: mirror,
            blockClass: blockClass,
            blockSelector: blockSelector,
            needsMask: needsMask,
            inlineStylesheet: inlineStylesheet,
            maskInputOptions: maskInputOptions,
            maskTextFn: maskTextFn,
            maskInputFn: maskInputFn,
            dataURLOptions: dataURLOptions,
            inlineImages: inlineImages,
            recordCanvas: recordCanvas,
            keepIframeSrcFn: keepIframeSrcFn,
            newlyAddedElement: newlyAddedElement
          });
          if (!_serializedNode) {
            console.warn(n, 'not serialized');
            return null;
          }
          var id;
          if (mirror.hasNode(n)) {
            id = mirror.getId(n);
          } else if (slimDOMExcluded(_serializedNode, slimDOMOptions) || !preserveWhiteSpace && _serializedNode.type === NodeType.Text && !_serializedNode.isStyle && !_serializedNode.textContent.replace(/^\s+|\s+$/gm, '').length) {
            id = IGNORED_NODE;
          } else {
            id = genId();
          }
          var serializedNode = Object.assign(_serializedNode, {
            id: id
          });
          mirror.add(n, serializedNode);
          if (id === IGNORED_NODE) {
            return null;
          }
          if (onSerialize) {
            onSerialize(n);
          }
          var recordChild = !skipChild;
          if (serializedNode.type === NodeType.Element) {
            recordChild = recordChild && !serializedNode.needBlock;
            delete serializedNode.needBlock;
            var shadowRoot = n.shadowRoot;
            if (shadowRoot && isNativeShadowDom(shadowRoot)) serializedNode.isShadowHost = true;
          }
          if ((serializedNode.type === NodeType.Document || serializedNode.type === NodeType.Element) && recordChild) {
            if (slimDOMOptions.headWhitespace && serializedNode.type === NodeType.Element && serializedNode.tagName === 'head') {
              preserveWhiteSpace = false;
            }
            var bypassOptions = {
              doc: doc,
              mirror: mirror,
              blockClass: blockClass,
              blockSelector: blockSelector,
              needsMask: needsMask,
              maskTextClass: maskTextClass,
              maskTextSelector: maskTextSelector,
              skipChild: skipChild,
              inlineStylesheet: inlineStylesheet,
              maskInputOptions: maskInputOptions,
              maskTextFn: maskTextFn,
              maskInputFn: maskInputFn,
              slimDOMOptions: slimDOMOptions,
              dataURLOptions: dataURLOptions,
              inlineImages: inlineImages,
              recordCanvas: recordCanvas,
              preserveWhiteSpace: preserveWhiteSpace,
              onSerialize: onSerialize,
              onIframeLoad: onIframeLoad,
              iframeLoadTimeout: iframeLoadTimeout,
              onStylesheetLoad: onStylesheetLoad,
              stylesheetLoadTimeout: stylesheetLoadTimeout,
              keepIframeSrcFn: keepIframeSrcFn
            };
            if (serializedNode.type === NodeType.Element && serializedNode.tagName === 'textarea' && serializedNode.attributes.value !== undefined) ;else {
              for (var _i2 = 0, _Array$from = Array.from(n.childNodes); _i2 < _Array$from.length; _i2++) {
                var childN = _Array$from[_i2];
                var serializedChildNode = serializeNodeWithId(childN, bypassOptions);
                if (serializedChildNode) {
                  serializedNode.childNodes.push(serializedChildNode);
                }
              }
            }
            if (isElement(n) && n.shadowRoot) {
              for (var _i3 = 0, _Array$from2 = Array.from(n.shadowRoot.childNodes); _i3 < _Array$from2.length; _i3++) {
                var _childN = _Array$from2[_i3];
                var _serializedChildNode = serializeNodeWithId(_childN, bypassOptions);
                if (_serializedChildNode) {
                  isNativeShadowDom(n.shadowRoot) && (_serializedChildNode.isShadow = true);
                  serializedNode.childNodes.push(_serializedChildNode);
                }
              }
            }
          }
          if (n.parentNode && isShadowRoot(n.parentNode) && isNativeShadowDom(n.parentNode)) {
            serializedNode.isShadow = true;
          }
          if (serializedNode.type === NodeType.Element && serializedNode.tagName === 'iframe') {
            onceIframeLoaded(n, function () {
              var iframeDoc = n.contentDocument;
              if (iframeDoc && onIframeLoad) {
                var serializedIframeNode = serializeNodeWithId(iframeDoc, {
                  doc: iframeDoc,
                  mirror: mirror,
                  blockClass: blockClass,
                  blockSelector: blockSelector,
                  needsMask: needsMask,
                  maskTextClass: maskTextClass,
                  maskTextSelector: maskTextSelector,
                  skipChild: false,
                  inlineStylesheet: inlineStylesheet,
                  maskInputOptions: maskInputOptions,
                  maskTextFn: maskTextFn,
                  maskInputFn: maskInputFn,
                  slimDOMOptions: slimDOMOptions,
                  dataURLOptions: dataURLOptions,
                  inlineImages: inlineImages,
                  recordCanvas: recordCanvas,
                  preserveWhiteSpace: preserveWhiteSpace,
                  onSerialize: onSerialize,
                  onIframeLoad: onIframeLoad,
                  iframeLoadTimeout: iframeLoadTimeout,
                  onStylesheetLoad: onStylesheetLoad,
                  stylesheetLoadTimeout: stylesheetLoadTimeout,
                  keepIframeSrcFn: keepIframeSrcFn
                });
                if (serializedIframeNode) {
                  onIframeLoad(n, serializedIframeNode);
                }
              }
            }, iframeLoadTimeout);
          }
          if (serializedNode.type === NodeType.Element && serializedNode.tagName === 'link' && typeof serializedNode.attributes.rel === 'string' && (serializedNode.attributes.rel === 'stylesheet' || serializedNode.attributes.rel === 'preload' && typeof serializedNode.attributes.href === 'string' && extractFileExtension(serializedNode.attributes.href) === 'css')) {
            onceStylesheetLoaded(n, function () {
              if (onStylesheetLoad) {
                var serializedLinkNode = serializeNodeWithId(n, {
                  doc: doc,
                  mirror: mirror,
                  blockClass: blockClass,
                  blockSelector: blockSelector,
                  needsMask: needsMask,
                  maskTextClass: maskTextClass,
                  maskTextSelector: maskTextSelector,
                  skipChild: false,
                  inlineStylesheet: inlineStylesheet,
                  maskInputOptions: maskInputOptions,
                  maskTextFn: maskTextFn,
                  maskInputFn: maskInputFn,
                  slimDOMOptions: slimDOMOptions,
                  dataURLOptions: dataURLOptions,
                  inlineImages: inlineImages,
                  recordCanvas: recordCanvas,
                  preserveWhiteSpace: preserveWhiteSpace,
                  onSerialize: onSerialize,
                  onIframeLoad: onIframeLoad,
                  iframeLoadTimeout: iframeLoadTimeout,
                  onStylesheetLoad: onStylesheetLoad,
                  stylesheetLoadTimeout: stylesheetLoadTimeout,
                  keepIframeSrcFn: keepIframeSrcFn
                });
                if (serializedLinkNode) {
                  onStylesheetLoad(n, serializedLinkNode);
                }
              }
            }, stylesheetLoadTimeout);
          }
          return serializedNode;
        }
        function snapshot(n, options) {
          var _ref2 = options || {},
            _ref2$mirror = _ref2.mirror,
            mirror = _ref2$mirror === void 0 ? new Mirror() : _ref2$mirror,
            _ref2$blockClass = _ref2.blockClass,
            blockClass = _ref2$blockClass === void 0 ? 'rr-block' : _ref2$blockClass,
            _ref2$blockSelector = _ref2.blockSelector,
            blockSelector = _ref2$blockSelector === void 0 ? null : _ref2$blockSelector,
            _ref2$maskTextClass = _ref2.maskTextClass,
            maskTextClass = _ref2$maskTextClass === void 0 ? 'rr-mask' : _ref2$maskTextClass,
            _ref2$maskTextSelecto = _ref2.maskTextSelector,
            maskTextSelector = _ref2$maskTextSelecto === void 0 ? null : _ref2$maskTextSelecto,
            _ref2$inlineStyleshee = _ref2.inlineStylesheet,
            inlineStylesheet = _ref2$inlineStyleshee === void 0 ? true : _ref2$inlineStyleshee,
            _ref2$inlineImages = _ref2.inlineImages,
            inlineImages = _ref2$inlineImages === void 0 ? false : _ref2$inlineImages,
            _ref2$recordCanvas = _ref2.recordCanvas,
            recordCanvas = _ref2$recordCanvas === void 0 ? false : _ref2$recordCanvas,
            _ref2$maskAllInputs = _ref2.maskAllInputs,
            maskAllInputs = _ref2$maskAllInputs === void 0 ? false : _ref2$maskAllInputs,
            maskTextFn = _ref2.maskTextFn,
            maskInputFn = _ref2.maskInputFn,
            _ref2$slimDOM = _ref2.slimDOM,
            slimDOM = _ref2$slimDOM === void 0 ? false : _ref2$slimDOM,
            dataURLOptions = _ref2.dataURLOptions,
            preserveWhiteSpace = _ref2.preserveWhiteSpace,
            onSerialize = _ref2.onSerialize,
            onIframeLoad = _ref2.onIframeLoad,
            iframeLoadTimeout = _ref2.iframeLoadTimeout,
            onStylesheetLoad = _ref2.onStylesheetLoad,
            stylesheetLoadTimeout = _ref2.stylesheetLoadTimeout,
            _ref2$keepIframeSrcFn = _ref2.keepIframeSrcFn,
            keepIframeSrcFn = _ref2$keepIframeSrcFn === void 0 ? function () {
              return false;
            } : _ref2$keepIframeSrcFn;
          var maskInputOptions = maskAllInputs === true ? {
            color: true,
            date: true,
            'datetime-local': true,
            email: true,
            month: true,
            number: true,
            range: true,
            search: true,
            tel: true,
            text: true,
            time: true,
            url: true,
            week: true,
            textarea: true,
            select: true,
            password: true
          } : maskAllInputs === false ? {
            password: true
          } : maskAllInputs;
          var slimDOMOptions = slimDOM === true || slimDOM === 'all' ? {
            script: true,
            comment: true,
            headFavicon: true,
            headWhitespace: true,
            headMetaDescKeywords: slimDOM === 'all',
            headMetaSocial: true,
            headMetaRobots: true,
            headMetaHttpEquiv: true,
            headMetaAuthorship: true,
            headMetaVerification: true
          } : slimDOM === false ? {} : slimDOM;
          return serializeNodeWithId(n, {
            doc: n,
            mirror: mirror,
            blockClass: blockClass,
            blockSelector: blockSelector,
            maskTextClass: maskTextClass,
            maskTextSelector: maskTextSelector,
            skipChild: false,
            inlineStylesheet: inlineStylesheet,
            maskInputOptions: maskInputOptions,
            maskTextFn: maskTextFn,
            maskInputFn: maskInputFn,
            slimDOMOptions: slimDOMOptions,
            dataURLOptions: dataURLOptions,
            inlineImages: inlineImages,
            recordCanvas: recordCanvas,
            preserveWhiteSpace: preserveWhiteSpace,
            onSerialize: onSerialize,
            onIframeLoad: onIframeLoad,
            iframeLoadTimeout: iframeLoadTimeout,
            onStylesheetLoad: onStylesheetLoad,
            stylesheetLoadTimeout: stylesheetLoadTimeout,
            keepIframeSrcFn: keepIframeSrcFn,
            newlyAddedElement: false
          });
        }
        function on(type, fn, target) {
          if (target === void 0) {
            target = document;
          }
          var options = {
            capture: true,
            passive: true
          };
          target.addEventListener(type, fn, options);
          return function () {
            return target.removeEventListener(type, fn, options);
          };
        }
        var DEPARTED_MIRROR_ACCESS_WARNING = 'Please stop import mirror directly. Instead of that,' + '\r\n' + 'now you can use replayer.getMirror() to access the mirror instance of a replayer,' + '\r\n' + 'or you can use record.mirror to access the mirror instance during recording.';
        var _mirror = {
          map: {},
          getId: function getId() {
            console.error(DEPARTED_MIRROR_ACCESS_WARNING);
            return -1;
          },
          getNode: function getNode() {
            console.error(DEPARTED_MIRROR_ACCESS_WARNING);
            return null;
          },
          removeNodeFromMap: function removeNodeFromMap() {
            console.error(DEPARTED_MIRROR_ACCESS_WARNING);
          },
          has: function has() {
            console.error(DEPARTED_MIRROR_ACCESS_WARNING);
            return false;
          },
          reset: function reset() {
            console.error(DEPARTED_MIRROR_ACCESS_WARNING);
          }
        };
        if (typeof window !== 'undefined' && window.Proxy && window.Reflect) {
          _mirror = new Proxy(_mirror, {
            get: function get(target, prop, receiver) {
              if (prop === 'map') {
                console.error(DEPARTED_MIRROR_ACCESS_WARNING);
              }
              return Reflect.get(target, prop, receiver);
            }
          });
        }
        function throttle(func, wait, options) {
          if (options === void 0) {
            options = {};
          }
          var timeout = null;
          var previous = 0;
          return function () {
            for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
              args[_key] = arguments[_key];
            }
            var now = Date.now();
            if (!previous && options.leading === false) {
              previous = now;
            }
            var remaining = wait - (now - previous);
            var context = this;
            if (remaining <= 0 || remaining > wait) {
              if (timeout) {
                clearTimeout(timeout);
                timeout = null;
              }
              previous = now;
              func.apply(context, args);
            } else if (!timeout && options.trailing !== false) {
              timeout = setTimeout(function () {
                previous = options.leading === false ? 0 : Date.now();
                timeout = null;
                func.apply(context, args);
              }, remaining);
            }
          };
        }
        function hookSetter(target, key, d, isRevoked, win) {
          if (win === void 0) {
            win = window;
          }
          var original = win.Object.getOwnPropertyDescriptor(target, key);
          win.Object.defineProperty(target, key, isRevoked ? d : {
            set: function set(value) {
              var _this3 = this;
              setTimeout(function () {
                d.set.call(_this3, value);
              }, 0);
              if (original && original.set) {
                original.set.call(this, value);
              }
            }
          });
          return function () {
            return hookSetter(target, key, original || {}, true);
          };
        }
        function patch(source, name, replacement) {
          try {
            if (!(name in source)) {
              return function () {};
            }
            var original = source[name];
            var wrapped = replacement(original);
            if (typeof wrapped === 'function') {
              wrapped.prototype = wrapped.prototype || {};
              Object.defineProperties(wrapped, {
                __rrweb_original__: {
                  enumerable: false,
                  value: original
                }
              });
            }
            source[name] = wrapped;
            return function () {
              source[name] = original;
            };
          } catch (_a) {
            return function () {};
          }
        }
        var nowTimestamp = Date.now;
        if (!/[1-9][0-9]{12}/.test(Date.now().toString())) {
          nowTimestamp = function nowTimestamp() {
            return new Date().getTime();
          };
        }
        function getWindowScroll(win) {
          var _a, _b, _c, _d, _e, _f;
          var doc = win.document;
          return {
            left: doc.scrollingElement ? doc.scrollingElement.scrollLeft : win.pageXOffset !== undefined ? win.pageXOffset : (doc === null || doc === void 0 ? void 0 : doc.documentElement.scrollLeft) || ((_b = (_a = doc === null || doc === void 0 ? void 0 : doc.body) === null || _a === void 0 ? void 0 : _a.parentElement) === null || _b === void 0 ? void 0 : _b.scrollLeft) || ((_c = doc === null || doc === void 0 ? void 0 : doc.body) === null || _c === void 0 ? void 0 : _c.scrollLeft) || 0,
            top: doc.scrollingElement ? doc.scrollingElement.scrollTop : win.pageYOffset !== undefined ? win.pageYOffset : (doc === null || doc === void 0 ? void 0 : doc.documentElement.scrollTop) || ((_e = (_d = doc === null || doc === void 0 ? void 0 : doc.body) === null || _d === void 0 ? void 0 : _d.parentElement) === null || _e === void 0 ? void 0 : _e.scrollTop) || ((_f = doc === null || doc === void 0 ? void 0 : doc.body) === null || _f === void 0 ? void 0 : _f.scrollTop) || 0
          };
        }
        function getWindowHeight() {
          return window.innerHeight || document.documentElement && document.documentElement.clientHeight || document.body && document.body.clientHeight;
        }
        function getWindowWidth() {
          return window.innerWidth || document.documentElement && document.documentElement.clientWidth || document.body && document.body.clientWidth;
        }
        function closestElementOfNode(node) {
          if (!node) {
            return null;
          }
          var el = node.nodeType === node.ELEMENT_NODE ? node : node.parentElement;
          return el;
        }
        function isBlocked(node, blockClass, blockSelector, checkAncestors) {
          if (!node) {
            return false;
          }
          var el = closestElementOfNode(node);
          if (!el) {
            return false;
          }
          try {
            if (typeof blockClass === 'string') {
              if (el.classList.contains(blockClass)) return true;
              if (checkAncestors && el.closest('.' + blockClass) !== null) return true;
            } else {
              if (classMatchesRegex(el, blockClass, checkAncestors)) return true;
            }
          } catch (e) {}
          if (blockSelector) {
            if (el.matches(blockSelector)) return true;
            if (checkAncestors && el.closest(blockSelector) !== null) return true;
          }
          return false;
        }
        function isSerialized(n, mirror) {
          return mirror.getId(n) !== -1;
        }
        function isIgnored(n, mirror) {
          return mirror.getId(n) === IGNORED_NODE;
        }
        function isAncestorRemoved(target, mirror) {
          if (isShadowRoot(target)) {
            return false;
          }
          var id = mirror.getId(target);
          if (!mirror.has(id)) {
            return true;
          }
          if (target.parentNode && target.parentNode.nodeType === target.DOCUMENT_NODE) {
            return false;
          }
          if (!target.parentNode) {
            return true;
          }
          return isAncestorRemoved(target.parentNode, mirror);
        }
        function legacy_isTouchEvent(event) {
          return Boolean(event.changedTouches);
        }
        function polyfill(win) {
          var _this4 = this;
          if (win === void 0) {
            win = window;
          }
          if ('NodeList' in win && !win.NodeList.prototype.forEach) {
            win.NodeList.prototype.forEach = Array.prototype.forEach;
          }
          if ('DOMTokenList' in win && !win.DOMTokenList.prototype.forEach) {
            win.DOMTokenList.prototype.forEach = Array.prototype.forEach;
          }
          if (!Node.prototype.contains) {
            Node.prototype.contains = function () {
              for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
                args[_key2] = arguments[_key2];
              }
              var node = args[0];
              if (!(0 in args)) {
                throw new TypeError('1 argument is required');
              }
              do {
                if (_this4 === node) {
                  return true;
                }
              } while (node = node && node.parentNode);
              return false;
            };
          }
        }
        function isSerializedIframe(n, mirror) {
          return Boolean(n.nodeName === 'IFRAME' && mirror.getMeta(n));
        }
        function isSerializedStylesheet(n, mirror) {
          return Boolean(n.nodeName === 'LINK' && n.nodeType === n.ELEMENT_NODE && n.getAttribute && n.getAttribute('rel') === 'stylesheet' && mirror.getMeta(n));
        }
        function hasShadowRoot(n) {
          return Boolean(n === null || n === void 0 ? void 0 : n.shadowRoot);
        }
        var StyleSheetMirror = /*#__PURE__*/function () {
          function StyleSheetMirror() {
            this.id = 1;
            this.styleIDMap = new WeakMap();
            this.idStyleMap = new Map();
          }
          var _proto2 = StyleSheetMirror.prototype;
          _proto2.getId = function getId(stylesheet) {
            var _a;
            return (_a = this.styleIDMap.get(stylesheet)) !== null && _a !== void 0 ? _a : -1;
          };
          _proto2.has = function has(stylesheet) {
            return this.styleIDMap.has(stylesheet);
          };
          _proto2.add = function add(stylesheet, id) {
            if (this.has(stylesheet)) return this.getId(stylesheet);
            var newId;
            if (id === undefined) {
              newId = this.id++;
            } else newId = id;
            this.styleIDMap.set(stylesheet, newId);
            this.idStyleMap.set(newId, stylesheet);
            return newId;
          };
          _proto2.getStyle = function getStyle(id) {
            return this.idStyleMap.get(id) || null;
          };
          _proto2.reset = function reset() {
            this.styleIDMap = new WeakMap();
            this.idStyleMap = new Map();
            this.id = 1;
          };
          _proto2.generateId = function generateId() {
            return this.id++;
          };
          return StyleSheetMirror;
        }();
        function getShadowHost(n) {
          var _a, _b;
          var shadowHost = null;
          if (((_b = (_a = n.getRootNode) === null || _a === void 0 ? void 0 : _a.call(n)) === null || _b === void 0 ? void 0 : _b.nodeType) === Node.DOCUMENT_FRAGMENT_NODE && n.getRootNode().host) shadowHost = n.getRootNode().host;
          return shadowHost;
        }
        function getRootShadowHost(n) {
          var rootShadowHost = n;
          var shadowHost;
          while (shadowHost = getShadowHost(rootShadowHost)) rootShadowHost = shadowHost;
          return rootShadowHost;
        }
        function shadowHostInDom(n) {
          var doc = n.ownerDocument;
          if (!doc) return false;
          var shadowHost = getRootShadowHost(n);
          return doc.contains(shadowHost);
        }
        function inDom(n) {
          var doc = n.ownerDocument;
          if (!doc) return false;
          return doc.contains(n) || shadowHostInDom(n);
        }
        var EventType$1 = /* @__PURE__ */function (EventType2) {
          EventType2[EventType2["DomContentLoaded"] = 0] = "DomContentLoaded";
          EventType2[EventType2["Load"] = 1] = "Load";
          EventType2[EventType2["FullSnapshot"] = 2] = "FullSnapshot";
          EventType2[EventType2["IncrementalSnapshot"] = 3] = "IncrementalSnapshot";
          EventType2[EventType2["Meta"] = 4] = "Meta";
          EventType2[EventType2["Custom"] = 5] = "Custom";
          EventType2[EventType2["Plugin"] = 6] = "Plugin";
          return EventType2;
        }(EventType$1 || {});
        var IncrementalSource$1 = /* @__PURE__ */function (IncrementalSource2) {
          IncrementalSource2[IncrementalSource2["Mutation"] = 0] = "Mutation";
          IncrementalSource2[IncrementalSource2["MouseMove"] = 1] = "MouseMove";
          IncrementalSource2[IncrementalSource2["MouseInteraction"] = 2] = "MouseInteraction";
          IncrementalSource2[IncrementalSource2["Scroll"] = 3] = "Scroll";
          IncrementalSource2[IncrementalSource2["ViewportResize"] = 4] = "ViewportResize";
          IncrementalSource2[IncrementalSource2["Input"] = 5] = "Input";
          IncrementalSource2[IncrementalSource2["TouchMove"] = 6] = "TouchMove";
          IncrementalSource2[IncrementalSource2["MediaInteraction"] = 7] = "MediaInteraction";
          IncrementalSource2[IncrementalSource2["StyleSheetRule"] = 8] = "StyleSheetRule";
          IncrementalSource2[IncrementalSource2["CanvasMutation"] = 9] = "CanvasMutation";
          IncrementalSource2[IncrementalSource2["Font"] = 10] = "Font";
          IncrementalSource2[IncrementalSource2["Log"] = 11] = "Log";
          IncrementalSource2[IncrementalSource2["Drag"] = 12] = "Drag";
          IncrementalSource2[IncrementalSource2["StyleDeclaration"] = 13] = "StyleDeclaration";
          IncrementalSource2[IncrementalSource2["Selection"] = 14] = "Selection";
          IncrementalSource2[IncrementalSource2["AdoptedStyleSheet"] = 15] = "AdoptedStyleSheet";
          IncrementalSource2[IncrementalSource2["CustomElement"] = 16] = "CustomElement";
          return IncrementalSource2;
        }(IncrementalSource$1 || {});
        var MouseInteractions = /* @__PURE__ */function (MouseInteractions2) {
          MouseInteractions2[MouseInteractions2["MouseUp"] = 0] = "MouseUp";
          MouseInteractions2[MouseInteractions2["MouseDown"] = 1] = "MouseDown";
          MouseInteractions2[MouseInteractions2["Click"] = 2] = "Click";
          MouseInteractions2[MouseInteractions2["ContextMenu"] = 3] = "ContextMenu";
          MouseInteractions2[MouseInteractions2["DblClick"] = 4] = "DblClick";
          MouseInteractions2[MouseInteractions2["Focus"] = 5] = "Focus";
          MouseInteractions2[MouseInteractions2["Blur"] = 6] = "Blur";
          MouseInteractions2[MouseInteractions2["TouchStart"] = 7] = "TouchStart";
          MouseInteractions2[MouseInteractions2["TouchMove_Departed"] = 8] = "TouchMove_Departed";
          MouseInteractions2[MouseInteractions2["TouchEnd"] = 9] = "TouchEnd";
          MouseInteractions2[MouseInteractions2["TouchCancel"] = 10] = "TouchCancel";
          return MouseInteractions2;
        }(MouseInteractions || {});
        var PointerTypes = /* @__PURE__ */function (PointerTypes2) {
          PointerTypes2[PointerTypes2["Mouse"] = 0] = "Mouse";
          PointerTypes2[PointerTypes2["Pen"] = 1] = "Pen";
          PointerTypes2[PointerTypes2["Touch"] = 2] = "Touch";
          return PointerTypes2;
        }(PointerTypes || {});
        var CanvasContext = /* @__PURE__ */function (CanvasContext2) {
          CanvasContext2[CanvasContext2["2D"] = 0] = "2D";
          CanvasContext2[CanvasContext2["WebGL"] = 1] = "WebGL";
          CanvasContext2[CanvasContext2["WebGL2"] = 2] = "WebGL2";
          return CanvasContext2;
        }(CanvasContext || {});
        function isNodeInLinkedList(n) {
          return '__ln' in n;
        }
        var DoubleLinkedList = /*#__PURE__*/function () {
          function DoubleLinkedList() {
            this.length = 0;
            this.head = null;
            this.tail = null;
          }
          var _proto3 = DoubleLinkedList.prototype;
          _proto3.get = function get(position) {
            if (position >= this.length) {
              throw new Error('Position outside of list range');
            }
            var current = this.head;
            for (var index = 0; index < position; index++) {
              current = (current === null || current === void 0 ? void 0 : current.next) || null;
            }
            return current;
          };
          _proto3.addNode = function addNode(n) {
            var node = {
              value: n,
              previous: null,
              next: null
            };
            n.__ln = node;
            if (n.previousSibling && isNodeInLinkedList(n.previousSibling)) {
              var current = n.previousSibling.__ln.next;
              node.next = current;
              node.previous = n.previousSibling.__ln;
              n.previousSibling.__ln.next = node;
              if (current) {
                current.previous = node;
              }
            } else if (n.nextSibling && isNodeInLinkedList(n.nextSibling) && n.nextSibling.__ln.previous) {
              var _current = n.nextSibling.__ln.previous;
              node.previous = _current;
              node.next = n.nextSibling.__ln;
              n.nextSibling.__ln.previous = node;
              if (_current) {
                _current.next = node;
              }
            } else {
              if (this.head) {
                this.head.previous = node;
              }
              node.next = this.head;
              this.head = node;
            }
            if (node.next === null) {
              this.tail = node;
            }
            this.length++;
          };
          _proto3.removeNode = function removeNode(n) {
            var current = n.__ln;
            if (!this.head) {
              return;
            }
            if (!current.previous) {
              this.head = current.next;
              if (this.head) {
                this.head.previous = null;
              } else {
                this.tail = null;
              }
            } else {
              current.previous.next = current.next;
              if (current.next) {
                current.next.previous = current.previous;
              } else {
                this.tail = current.previous;
              }
            }
            if (n.__ln) {
              delete n.__ln;
            }
            this.length--;
          };
          return DoubleLinkedList;
        }();
        var moveKey = function moveKey(id, parentId) {
          return id + "@" + parentId;
        };
        var MutationBuffer = /*#__PURE__*/function () {
          function MutationBuffer() {
            var _this5 = this;
            this.frozen = false;
            this.locked = false;
            this.texts = [];
            this.attributes = [];
            this.attributeMap = new WeakMap();
            this.removes = [];
            this.mapRemoves = [];
            this.movedMap = {};
            this.addedSet = new Set();
            this.movedSet = new Set();
            this.droppedSet = new Set();
            this.processMutations = function (mutations) {
              mutations.forEach(_this5.processMutation);
              _this5.emit();
            };
            this.emit = function () {
              if (_this5.frozen || _this5.locked) {
                return;
              }
              var adds = [];
              var addedIds = new Set();
              var addList = new DoubleLinkedList();
              var getNextId = function getNextId(n) {
                var ns = n;
                var nextId = IGNORED_NODE;
                while (nextId === IGNORED_NODE) {
                  ns = ns && ns.nextSibling;
                  nextId = ns && _this5.mirror.getId(ns);
                }
                return nextId;
              };
              var pushAdd = function pushAdd(n) {
                if (!n.parentNode || !inDom(n) || n.parentNode.tagName === 'TEXTAREA') {
                  return;
                }
                var parentId = isShadowRoot(n.parentNode) ? _this5.mirror.getId(getShadowHost(n)) : _this5.mirror.getId(n.parentNode);
                var nextId = getNextId(n);
                if (parentId === -1 || nextId === -1) {
                  return addList.addNode(n);
                }
                var sn = serializeNodeWithId(n, {
                  doc: _this5.doc,
                  mirror: _this5.mirror,
                  blockClass: _this5.blockClass,
                  blockSelector: _this5.blockSelector,
                  maskTextClass: _this5.maskTextClass,
                  maskTextSelector: _this5.maskTextSelector,
                  skipChild: true,
                  newlyAddedElement: true,
                  inlineStylesheet: _this5.inlineStylesheet,
                  maskInputOptions: _this5.maskInputOptions,
                  maskTextFn: _this5.maskTextFn,
                  maskInputFn: _this5.maskInputFn,
                  slimDOMOptions: _this5.slimDOMOptions,
                  dataURLOptions: _this5.dataURLOptions,
                  recordCanvas: _this5.recordCanvas,
                  inlineImages: _this5.inlineImages,
                  onSerialize: function onSerialize(currentN) {
                    if (isSerializedIframe(currentN, _this5.mirror)) {
                      _this5.iframeManager.addIframe(currentN);
                    }
                    if (isSerializedStylesheet(currentN, _this5.mirror)) {
                      _this5.stylesheetManager.trackLinkElement(currentN);
                    }
                    if (hasShadowRoot(n)) {
                      _this5.shadowDomManager.addShadowRoot(n.shadowRoot, _this5.doc);
                    }
                  },
                  onIframeLoad: function onIframeLoad(iframe, childSn) {
                    _this5.iframeManager.attachIframe(iframe, childSn);
                    _this5.shadowDomManager.observeAttachShadow(iframe);
                  },
                  onStylesheetLoad: function onStylesheetLoad(link, childSn) {
                    _this5.stylesheetManager.attachLinkElement(link, childSn);
                  }
                });
                if (sn) {
                  adds.push({
                    parentId: parentId,
                    nextId: nextId,
                    node: sn
                  });
                  addedIds.add(sn.id);
                }
              };
              while (_this5.mapRemoves.length) {
                _this5.mirror.removeNodeFromMap(_this5.mapRemoves.shift());
              }
              for (var _iterator2 = _createForOfIteratorHelperLoose(_this5.movedSet), _step2; !(_step2 = _iterator2()).done;) {
                var n = _step2.value;
                if (isParentRemoved(_this5.removes, n, _this5.mirror) && !_this5.movedSet.has(n.parentNode)) {
                  continue;
                }
                pushAdd(n);
              }
              for (var _iterator3 = _createForOfIteratorHelperLoose(_this5.addedSet), _step3; !(_step3 = _iterator3()).done;) {
                var _n = _step3.value;
                if (!isAncestorInSet(_this5.droppedSet, _n) && !isParentRemoved(_this5.removes, _n, _this5.mirror)) {
                  pushAdd(_n);
                } else if (isAncestorInSet(_this5.movedSet, _n)) {
                  pushAdd(_n);
                } else {
                  _this5.droppedSet.add(_n);
                }
              }
              var candidate = null;
              while (addList.length) {
                var node = null;
                if (candidate) {
                  var parentId = _this5.mirror.getId(candidate.value.parentNode);
                  var nextId = getNextId(candidate.value);
                  if (parentId !== -1 && nextId !== -1) {
                    node = candidate;
                  }
                }
                if (!node) {
                  var tailNode = addList.tail;
                  while (tailNode) {
                    var _node = tailNode;
                    tailNode = tailNode.previous;
                    if (_node) {
                      var _parentId = _this5.mirror.getId(_node.value.parentNode);
                      var _nextId = getNextId(_node.value);
                      if (_nextId === -1) continue;else if (_parentId !== -1) {
                        node = _node;
                        break;
                      } else {
                        var unhandledNode = _node.value;
                        if (unhandledNode.parentNode && unhandledNode.parentNode.nodeType === Node.DOCUMENT_FRAGMENT_NODE) {
                          var shadowHost = unhandledNode.parentNode.host;
                          var _parentId2 = _this5.mirror.getId(shadowHost);
                          if (_parentId2 !== -1) {
                            node = _node;
                            break;
                          }
                        }
                      }
                    }
                  }
                }
                if (!node) {
                  while (addList.head) {
                    addList.removeNode(addList.head.value);
                  }
                  break;
                }
                candidate = node.previous;
                addList.removeNode(node.value);
                pushAdd(node.value);
              }
              var payload = {
                texts: _this5.texts.map(function (text) {
                  var n = text.node;
                  if (n.parentNode && n.parentNode.tagName === 'TEXTAREA') {
                    _this5.genTextAreaValueMutation(n.parentNode);
                  }
                  return {
                    id: _this5.mirror.getId(n),
                    value: text.value
                  };
                }).filter(function (text) {
                  return !addedIds.has(text.id);
                }).filter(function (text) {
                  return _this5.mirror.has(text.id);
                }),
                attributes: _this5.attributes.map(function (attribute) {
                  var attributes = attribute.attributes;
                  if (typeof attributes.style === 'string') {
                    var diffAsStr = JSON.stringify(attribute.styleDiff);
                    var unchangedAsStr = JSON.stringify(attribute._unchangedStyles);
                    if (diffAsStr.length < attributes.style.length) {
                      if ((diffAsStr + unchangedAsStr).split('var(').length === attributes.style.split('var(').length) {
                        attributes.style = attribute.styleDiff;
                      }
                    }
                  }
                  return {
                    id: _this5.mirror.getId(attribute.node),
                    attributes: attributes
                  };
                }).filter(function (attribute) {
                  return !addedIds.has(attribute.id);
                }).filter(function (attribute) {
                  return _this5.mirror.has(attribute.id);
                }),
                removes: _this5.removes,
                adds: adds
              };
              if (!payload.texts.length && !payload.attributes.length && !payload.removes.length && !payload.adds.length) {
                return;
              }
              _this5.texts = [];
              _this5.attributes = [];
              _this5.attributeMap = new WeakMap();
              _this5.removes = [];
              _this5.addedSet = new Set();
              _this5.movedSet = new Set();
              _this5.droppedSet = new Set();
              _this5.movedMap = {};
              _this5.mutationCb(payload);
            };
            this.genTextAreaValueMutation = function (textarea) {
              var item = _this5.attributeMap.get(textarea);
              if (!item) {
                item = {
                  node: textarea,
                  attributes: {},
                  styleDiff: {},
                  _unchangedStyles: {}
                };
                _this5.attributes.push(item);
                _this5.attributeMap.set(textarea, item);
              }
              item.attributes.value = Array.from(textarea.childNodes, function (cn) {
                return cn.textContent || '';
              }).join('');
            };
            this.processMutation = function (m) {
              if (isIgnored(m.target, _this5.mirror)) {
                return;
              }
              switch (m.type) {
                case 'characterData':
                  {
                    var value = m.target.textContent;
                    if (!isBlocked(m.target, _this5.blockClass, _this5.blockSelector, false) && value !== m.oldValue) {
                      _this5.texts.push({
                        value: needMaskingText(m.target, _this5.maskTextClass, _this5.maskTextSelector, true) && value ? _this5.maskTextFn ? _this5.maskTextFn(value, closestElementOfNode(m.target)) : value.replace(/[\S]/g, '*') : value,
                        node: m.target
                      });
                    }
                    break;
                  }
                case 'attributes':
                  {
                    var target = m.target;
                    var attributeName = m.attributeName;
                    var _value2 = m.target.getAttribute(attributeName);
                    if (attributeName === 'value') {
                      var type = getInputType(target);
                      _value2 = maskInputValue({
                        element: target,
                        maskInputOptions: _this5.maskInputOptions,
                        tagName: target.tagName,
                        type: type,
                        value: _value2,
                        maskInputFn: _this5.maskInputFn
                      });
                    }
                    if (isBlocked(m.target, _this5.blockClass, _this5.blockSelector, false) || _value2 === m.oldValue) {
                      return;
                    }
                    var item = _this5.attributeMap.get(m.target);
                    if (target.tagName === 'IFRAME' && attributeName === 'src' && !_this5.keepIframeSrcFn(_value2)) {
                      if (!target.contentDocument) {
                        attributeName = 'rr_src';
                      } else {
                        return;
                      }
                    }
                    if (!item) {
                      item = {
                        node: m.target,
                        attributes: {},
                        styleDiff: {},
                        _unchangedStyles: {}
                      };
                      _this5.attributes.push(item);
                      _this5.attributeMap.set(m.target, item);
                    }
                    if (attributeName === 'type' && target.tagName === 'INPUT' && (m.oldValue || '').toLowerCase() === 'password') {
                      target.setAttribute('data-rr-is-password', 'true');
                    }
                    if (!ignoreAttribute(target.tagName, attributeName)) {
                      item.attributes[attributeName] = transformAttribute(_this5.doc, toLowerCase(target.tagName), toLowerCase(attributeName), _value2);
                      if (attributeName === 'style') {
                        if (!_this5.unattachedDoc) {
                          try {
                            _this5.unattachedDoc = document.implementation.createHTMLDocument();
                          } catch (e) {
                            _this5.unattachedDoc = _this5.doc;
                          }
                        }
                        var old = _this5.unattachedDoc.createElement('span');
                        if (m.oldValue) {
                          old.setAttribute('style', m.oldValue);
                        }
                        for (var _i4 = 0, _Array$from3 = Array.from(target.style); _i4 < _Array$from3.length; _i4++) {
                          var pname = _Array$from3[_i4];
                          var newValue = target.style.getPropertyValue(pname);
                          var newPriority = target.style.getPropertyPriority(pname);
                          if (newValue !== old.style.getPropertyValue(pname) || newPriority !== old.style.getPropertyPriority(pname)) {
                            if (newPriority === '') {
                              item.styleDiff[pname] = newValue;
                            } else {
                              item.styleDiff[pname] = [newValue, newPriority];
                            }
                          } else {
                            item._unchangedStyles[pname] = [newValue, newPriority];
                          }
                        }
                        for (var _i5 = 0, _Array$from4 = Array.from(old.style); _i5 < _Array$from4.length; _i5++) {
                          var _pname = _Array$from4[_i5];
                          if (target.style.getPropertyValue(_pname) === '') {
                            item.styleDiff[_pname] = false;
                          }
                        }
                      }
                    }
                    break;
                  }
                case 'childList':
                  {
                    if (isBlocked(m.target, _this5.blockClass, _this5.blockSelector, true)) return;
                    if (m.target.tagName === 'TEXTAREA') {
                      _this5.genTextAreaValueMutation(m.target);
                      return;
                    }
                    m.addedNodes.forEach(function (n) {
                      return _this5.genAdds(n, m.target);
                    });
                    m.removedNodes.forEach(function (n) {
                      var nodeId = _this5.mirror.getId(n);
                      var parentId = isShadowRoot(m.target) ? _this5.mirror.getId(m.target.host) : _this5.mirror.getId(m.target);
                      if (isBlocked(m.target, _this5.blockClass, _this5.blockSelector, false) || isIgnored(n, _this5.mirror) || !isSerialized(n, _this5.mirror)) {
                        return;
                      }
                      if (_this5.addedSet.has(n)) {
                        deepDelete(_this5.addedSet, n);
                        _this5.droppedSet.add(n);
                      } else if (_this5.addedSet.has(m.target) && nodeId === -1) ;else if (isAncestorRemoved(m.target, _this5.mirror)) ;else if (_this5.movedSet.has(n) && _this5.movedMap[moveKey(nodeId, parentId)]) {
                        deepDelete(_this5.movedSet, n);
                      } else {
                        _this5.removes.push({
                          parentId: parentId,
                          id: nodeId,
                          isShadow: isShadowRoot(m.target) && isNativeShadowDom(m.target) ? true : undefined
                        });
                      }
                      _this5.mapRemoves.push(n);
                    });
                    break;
                  }
              }
            };
            this.genAdds = function (n, target) {
              if (_this5.processedNodeManager.inOtherBuffer(n, _this5)) return;
              if (_this5.addedSet.has(n) || _this5.movedSet.has(n)) return;
              if (_this5.mirror.hasNode(n)) {
                if (isIgnored(n, _this5.mirror)) {
                  return;
                }
                _this5.movedSet.add(n);
                var targetId = null;
                if (target && _this5.mirror.hasNode(target)) {
                  targetId = _this5.mirror.getId(target);
                }
                if (targetId && targetId !== -1) {
                  _this5.movedMap[moveKey(_this5.mirror.getId(n), targetId)] = true;
                }
              } else {
                _this5.addedSet.add(n);
                _this5.droppedSet["delete"](n);
              }
              if (!isBlocked(n, _this5.blockClass, _this5.blockSelector, false)) {
                n.childNodes.forEach(function (childN) {
                  return _this5.genAdds(childN);
                });
                if (hasShadowRoot(n)) {
                  n.shadowRoot.childNodes.forEach(function (childN) {
                    _this5.processedNodeManager.add(childN, _this5);
                    _this5.genAdds(childN, n);
                  });
                }
              }
            };
          }
          var _proto4 = MutationBuffer.prototype;
          _proto4.init = function init(options) {
            var _this6 = this;
            ['mutationCb', 'blockClass', 'blockSelector', 'maskTextClass', 'maskTextSelector', 'inlineStylesheet', 'maskInputOptions', 'maskTextFn', 'maskInputFn', 'keepIframeSrcFn', 'recordCanvas', 'inlineImages', 'slimDOMOptions', 'dataURLOptions', 'doc', 'mirror', 'iframeManager', 'stylesheetManager', 'shadowDomManager', 'canvasManager', 'processedNodeManager'].forEach(function (key) {
              _this6[key] = options[key];
            });
          };
          _proto4.freeze = function freeze() {
            this.frozen = true;
            this.canvasManager.freeze();
          };
          _proto4.unfreeze = function unfreeze() {
            this.frozen = false;
            this.canvasManager.unfreeze();
            this.emit();
          };
          _proto4.isFrozen = function isFrozen() {
            return this.frozen;
          };
          _proto4.lock = function lock() {
            this.locked = true;
            this.canvasManager.lock();
          };
          _proto4.unlock = function unlock() {
            this.locked = false;
            this.canvasManager.unlock();
            this.emit();
          };
          _proto4.reset = function reset() {
            this.shadowDomManager.reset();
            this.canvasManager.reset();
          };
          return MutationBuffer;
        }();
        function deepDelete(addsSet, n) {
          addsSet["delete"](n);
          n.childNodes.forEach(function (childN) {
            return deepDelete(addsSet, childN);
          });
        }
        function isParentRemoved(removes, n, mirror) {
          if (removes.length === 0) return false;
          return _isParentRemoved(removes, n, mirror);
        }
        function _isParentRemoved(removes, n, mirror) {
          var parentNode = n.parentNode;
          if (!parentNode) {
            return false;
          }
          var parentId = mirror.getId(parentNode);
          if (removes.some(function (r) {
            return r.id === parentId;
          })) {
            return true;
          }
          return _isParentRemoved(removes, parentNode, mirror);
        }
        function isAncestorInSet(set, n) {
          if (set.size === 0) return false;
          return _isAncestorInSet(set, n);
        }
        function _isAncestorInSet(set, n) {
          var parentNode = n.parentNode;
          if (!parentNode) {
            return false;
          }
          if (set.has(parentNode)) {
            return true;
          }
          return _isAncestorInSet(set, parentNode);
        }
        var errorHandler;
        function registerErrorHandler(handler) {
          errorHandler = handler;
        }
        function unregisterErrorHandler() {
          errorHandler = undefined;
        }
        var callbackWrapper = function callbackWrapper(cb) {
          if (!errorHandler) {
            return cb;
          }
          var rrwebWrapped = function rrwebWrapped() {
            try {
              return cb.apply(void 0, arguments);
            } catch (error) {
              if (errorHandler && errorHandler(error) === true) {
                return;
              }
              throw error;
            }
          };
          return rrwebWrapped;
        };
        var mutationBuffers = [];
        function getEventTarget(event) {
          try {
            if ('composedPath' in event) {
              var path = event.composedPath();
              if (path.length) {
                return path[0];
              }
            } else if ('path' in event && event.path.length) {
              return event.path[0];
            }
          } catch (_a) {}
          return event && event.target;
        }
        function initMutationObserver(options, rootEl) {
          var _a, _b;
          var mutationBuffer = new MutationBuffer();
          mutationBuffers.push(mutationBuffer);
          mutationBuffer.init(options);
          var mutationObserverCtor = window.MutationObserver || window.__rrMutationObserver;
          var angularZoneSymbol = (_b = (_a = window === null || window === void 0 ? void 0 : window.Zone) === null || _a === void 0 ? void 0 : _a.__symbol__) === null || _b === void 0 ? void 0 : _b.call(_a, 'MutationObserver');
          if (angularZoneSymbol && window[angularZoneSymbol]) {
            mutationObserverCtor = window[angularZoneSymbol];
          }
          var observer = new mutationObserverCtor(callbackWrapper(mutationBuffer.processMutations.bind(mutationBuffer)));
          observer.observe(rootEl, {
            attributes: true,
            attributeOldValue: true,
            characterData: true,
            characterDataOldValue: true,
            childList: true,
            subtree: true
          });
          return observer;
        }
        function initMoveObserver(_ref3) {
          var mousemoveCb = _ref3.mousemoveCb,
            sampling = _ref3.sampling,
            doc = _ref3.doc,
            mirror = _ref3.mirror;
          if (sampling.mousemove === false) {
            return function () {};
          }
          var threshold = typeof sampling.mousemove === 'number' ? sampling.mousemove : 50;
          var callbackThreshold = typeof sampling.mousemoveCallback === 'number' ? sampling.mousemoveCallback : 500;
          var positions = [];
          var timeBaseline;
          var wrappedCb = throttle(callbackWrapper(function (source) {
            var totalOffset = Date.now() - timeBaseline;
            mousemoveCb(positions.map(function (p) {
              p.timeOffset -= totalOffset;
              return p;
            }), source);
            positions = [];
            timeBaseline = null;
          }), callbackThreshold);
          var updatePosition = callbackWrapper(throttle(callbackWrapper(function (evt) {
            var target = getEventTarget(evt);
            var _ref4 = legacy_isTouchEvent(evt) ? evt.changedTouches[0] : evt,
              clientX = _ref4.clientX,
              clientY = _ref4.clientY;
            if (!timeBaseline) {
              timeBaseline = nowTimestamp();
            }
            positions.push({
              x: clientX,
              y: clientY,
              id: mirror.getId(target),
              timeOffset: nowTimestamp() - timeBaseline
            });
            wrappedCb(typeof DragEvent !== 'undefined' && evt instanceof DragEvent ? IncrementalSource$1.Drag : evt instanceof MouseEvent ? IncrementalSource$1.MouseMove : IncrementalSource$1.TouchMove);
          }), threshold, {
            trailing: false
          }));
          var handlers = [on('mousemove', updatePosition, doc), on('touchmove', updatePosition, doc), on('drag', updatePosition, doc)];
          return callbackWrapper(function () {
            handlers.forEach(function (h) {
              return h();
            });
          });
        }
        function initMouseInteractionObserver(_ref5) {
          var mouseInteractionCb = _ref5.mouseInteractionCb,
            doc = _ref5.doc,
            mirror = _ref5.mirror,
            blockClass = _ref5.blockClass,
            blockSelector = _ref5.blockSelector,
            sampling = _ref5.sampling;
          if (sampling.mouseInteraction === false) {
            return function () {};
          }
          var disableMap = sampling.mouseInteraction === true || sampling.mouseInteraction === undefined ? {} : sampling.mouseInteraction;
          var handlers = [];
          var currentPointerType = null;
          var getHandler = function getHandler(eventKey) {
            return function (event) {
              var target = getEventTarget(event);
              if (isBlocked(target, blockClass, blockSelector, true)) {
                return;
              }
              var pointerType = null;
              var thisEventKey = eventKey;
              if ('pointerType' in event) {
                switch (event.pointerType) {
                  case 'mouse':
                    pointerType = PointerTypes.Mouse;
                    break;
                  case 'touch':
                    pointerType = PointerTypes.Touch;
                    break;
                  case 'pen':
                    pointerType = PointerTypes.Pen;
                    break;
                }
                if (pointerType === PointerTypes.Touch) {
                  if (MouseInteractions[eventKey] === MouseInteractions.MouseDown) {
                    thisEventKey = 'TouchStart';
                  } else if (MouseInteractions[eventKey] === MouseInteractions.MouseUp) {
                    thisEventKey = 'TouchEnd';
                  }
                } else if (pointerType === PointerTypes.Pen) ;
              } else if (legacy_isTouchEvent(event)) {
                pointerType = PointerTypes.Touch;
              }
              if (pointerType !== null) {
                currentPointerType = pointerType;
                if (thisEventKey.startsWith('Touch') && pointerType === PointerTypes.Touch || thisEventKey.startsWith('Mouse') && pointerType === PointerTypes.Mouse) {
                  pointerType = null;
                }
              } else if (MouseInteractions[eventKey] === MouseInteractions.Click) {
                pointerType = currentPointerType;
                currentPointerType = null;
              }
              var e = legacy_isTouchEvent(event) ? event.changedTouches[0] : event;
              if (!e) {
                return;
              }
              var id = mirror.getId(target);
              var clientX = e.clientX,
                clientY = e.clientY;
              callbackWrapper(mouseInteractionCb)(Object.assign({
                type: MouseInteractions[thisEventKey],
                id: id,
                x: clientX,
                y: clientY
              }, pointerType !== null && {
                pointerType: pointerType
              }));
            };
          };
          Object.keys(MouseInteractions).filter(function (key) {
            return Number.isNaN(Number(key)) && !key.endsWith('_Departed') && disableMap[key] !== false;
          }).forEach(function (eventKey) {
            var eventName = toLowerCase(eventKey);
            var handler = getHandler(eventKey);
            if (window.PointerEvent) {
              switch (MouseInteractions[eventKey]) {
                case MouseInteractions.MouseDown:
                case MouseInteractions.MouseUp:
                  eventName = eventName.replace('mouse', 'pointer');
                  break;
                case MouseInteractions.TouchStart:
                case MouseInteractions.TouchEnd:
                  return;
              }
            }
            handlers.push(on(eventName, handler, doc));
          });
          return callbackWrapper(function () {
            handlers.forEach(function (h) {
              return h();
            });
          });
        }
        function initScrollObserver(_ref6) {
          var scrollCb = _ref6.scrollCb,
            doc = _ref6.doc,
            mirror = _ref6.mirror,
            blockClass = _ref6.blockClass,
            blockSelector = _ref6.blockSelector,
            sampling = _ref6.sampling;
          var updatePosition = callbackWrapper(throttle(callbackWrapper(function (evt) {
            var target = getEventTarget(evt);
            if (!target || isBlocked(target, blockClass, blockSelector, true)) {
              return;
            }
            var id = mirror.getId(target);
            if (target === doc && doc.defaultView) {
              var scrollLeftTop = getWindowScroll(doc.defaultView);
              scrollCb({
                id: id,
                x: scrollLeftTop.left,
                y: scrollLeftTop.top
              });
            } else {
              scrollCb({
                id: id,
                x: target.scrollLeft,
                y: target.scrollTop
              });
            }
          }), sampling.scroll || 100));
          return on('scroll', updatePosition, doc);
        }
        function initViewportResizeObserver(_ref7, _ref8) {
          var viewportResizeCb = _ref7.viewportResizeCb;
          var win = _ref8.win;
          var lastH = -1;
          var lastW = -1;
          var updateDimension = callbackWrapper(throttle(callbackWrapper(function () {
            var height = getWindowHeight();
            var width = getWindowWidth();
            if (lastH !== height || lastW !== width) {
              viewportResizeCb({
                width: Number(width),
                height: Number(height)
              });
              lastH = height;
              lastW = width;
            }
          }), 200));
          return on('resize', updateDimension, win);
        }
        var INPUT_TAGS = ['INPUT', 'TEXTAREA', 'SELECT'];
        var lastInputValueMap = new WeakMap();
        function initInputObserver(_ref9) {
          var inputCb = _ref9.inputCb,
            doc = _ref9.doc,
            mirror = _ref9.mirror,
            blockClass = _ref9.blockClass,
            blockSelector = _ref9.blockSelector,
            ignoreClass = _ref9.ignoreClass,
            ignoreSelector = _ref9.ignoreSelector,
            maskInputOptions = _ref9.maskInputOptions,
            maskInputFn = _ref9.maskInputFn,
            sampling = _ref9.sampling,
            userTriggeredOnInput = _ref9.userTriggeredOnInput;
          function eventHandler(event) {
            var target = getEventTarget(event);
            var userTriggered = event.isTrusted;
            var tagName = target && target.tagName;
            if (target && tagName === 'OPTION') {
              target = target.parentElement;
            }
            if (!target || !tagName || INPUT_TAGS.indexOf(tagName) < 0 || isBlocked(target, blockClass, blockSelector, true)) {
              return;
            }
            if (target.classList.contains(ignoreClass) || ignoreSelector && target.matches(ignoreSelector)) {
              return;
            }
            var text = target.value;
            var isChecked = false;
            var type = getInputType(target) || '';
            if (type === 'radio' || type === 'checkbox') {
              isChecked = target.checked;
            } else if (maskInputOptions[tagName.toLowerCase()] || maskInputOptions[type]) {
              text = maskInputValue({
                element: target,
                maskInputOptions: maskInputOptions,
                tagName: tagName,
                type: type,
                value: text,
                maskInputFn: maskInputFn
              });
            }
            cbWithDedup(target, userTriggeredOnInput ? {
              text: text,
              isChecked: isChecked,
              userTriggered: userTriggered
            } : {
              text: text,
              isChecked: isChecked
            });
            var name = target.name;
            if (type === 'radio' && name && isChecked) {
              doc.querySelectorAll("input[type=\"radio\"][name=\"" + name + "\"]").forEach(function (el) {
                if (el !== target) {
                  var _text = el.value;
                  cbWithDedup(el, userTriggeredOnInput ? {
                    text: _text,
                    isChecked: !isChecked,
                    userTriggered: false
                  } : {
                    text: _text,
                    isChecked: !isChecked
                  });
                }
              });
            }
          }
          function cbWithDedup(target, v) {
            var lastInputValue = lastInputValueMap.get(target);
            if (!lastInputValue || lastInputValue.text !== v.text || lastInputValue.isChecked !== v.isChecked) {
              lastInputValueMap.set(target, v);
              var id = mirror.getId(target);
              callbackWrapper(inputCb)(Object.assign(Object.assign({}, v), {
                id: id
              }));
            }
          }
          var events = sampling.input === 'last' ? ['change'] : ['input', 'change'];
          var handlers = events.map(function (eventName) {
            return on(eventName, callbackWrapper(eventHandler), doc);
          });
          var currentWindow = doc.defaultView;
          if (!currentWindow) {
            return function () {
              handlers.forEach(function (h) {
                return h();
              });
            };
          }
          var propertyDescriptor = currentWindow.Object.getOwnPropertyDescriptor(currentWindow.HTMLInputElement.prototype, 'value');
          var hookProperties = [[currentWindow.HTMLInputElement.prototype, 'value'], [currentWindow.HTMLInputElement.prototype, 'checked'], [currentWindow.HTMLSelectElement.prototype, 'value'], [currentWindow.HTMLTextAreaElement.prototype, 'value'], [currentWindow.HTMLSelectElement.prototype, 'selectedIndex'], [currentWindow.HTMLOptionElement.prototype, 'selected']];
          if (propertyDescriptor && propertyDescriptor.set) {
            handlers.push.apply(handlers, hookProperties.map(function (p) {
              return hookSetter(p[0], p[1], {
                set: function set() {
                  callbackWrapper(eventHandler)({
                    target: this,
                    isTrusted: false
                  });
                }
              }, false, currentWindow);
            }));
          }
          return callbackWrapper(function () {
            handlers.forEach(function (h) {
              return h();
            });
          });
        }
        function getNestedCSSRulePositions(rule) {
          var positions = [];
          function recurse(childRule, pos) {
            if (hasNestedCSSRule('CSSGroupingRule') && childRule.parentRule instanceof CSSGroupingRule || hasNestedCSSRule('CSSMediaRule') && childRule.parentRule instanceof CSSMediaRule || hasNestedCSSRule('CSSSupportsRule') && childRule.parentRule instanceof CSSSupportsRule || hasNestedCSSRule('CSSConditionRule') && childRule.parentRule instanceof CSSConditionRule) {
              var rules = Array.from(childRule.parentRule.cssRules);
              var index = rules.indexOf(childRule);
              pos.unshift(index);
            } else if (childRule.parentStyleSheet) {
              var _rules = Array.from(childRule.parentStyleSheet.cssRules);
              var _index = _rules.indexOf(childRule);
              pos.unshift(_index);
            }
            return pos;
          }
          return recurse(rule, positions);
        }
        function getIdAndStyleId(sheet, mirror, styleMirror) {
          var id, styleId;
          if (!sheet) return {};
          if (sheet.ownerNode) id = mirror.getId(sheet.ownerNode);else styleId = styleMirror.getId(sheet);
          return {
            styleId: styleId,
            id: id
          };
        }
        function initStyleSheetObserver(_ref10, _ref11) {
          var styleSheetRuleCb = _ref10.styleSheetRuleCb,
            mirror = _ref10.mirror,
            stylesheetManager = _ref10.stylesheetManager;
          var win = _ref11.win;
          if (!win.CSSStyleSheet || !win.CSSStyleSheet.prototype) {
            return function () {};
          }
          var insertRule = win.CSSStyleSheet.prototype.insertRule;
          win.CSSStyleSheet.prototype.insertRule = new Proxy(insertRule, {
            apply: callbackWrapper(function (target, thisArg, argumentsList) {
              var rule = argumentsList[0],
                index = argumentsList[1];
              var _getIdAndStyleId = getIdAndStyleId(thisArg, mirror, stylesheetManager.styleMirror),
                id = _getIdAndStyleId.id,
                styleId = _getIdAndStyleId.styleId;
              if (id && id !== -1 || styleId && styleId !== -1) {
                styleSheetRuleCb({
                  id: id,
                  styleId: styleId,
                  adds: [{
                    rule: rule,
                    index: index
                  }]
                });
              }
              return target.apply(thisArg, argumentsList);
            })
          });
          var deleteRule = win.CSSStyleSheet.prototype.deleteRule;
          win.CSSStyleSheet.prototype.deleteRule = new Proxy(deleteRule, {
            apply: callbackWrapper(function (target, thisArg, argumentsList) {
              var index = argumentsList[0];
              var _getIdAndStyleId2 = getIdAndStyleId(thisArg, mirror, stylesheetManager.styleMirror),
                id = _getIdAndStyleId2.id,
                styleId = _getIdAndStyleId2.styleId;
              if (id && id !== -1 || styleId && styleId !== -1) {
                styleSheetRuleCb({
                  id: id,
                  styleId: styleId,
                  removes: [{
                    index: index
                  }]
                });
              }
              return target.apply(thisArg, argumentsList);
            })
          });
          var replace;
          if (win.CSSStyleSheet.prototype.replace) {
            replace = win.CSSStyleSheet.prototype.replace;
            win.CSSStyleSheet.prototype.replace = new Proxy(replace, {
              apply: callbackWrapper(function (target, thisArg, argumentsList) {
                var text = argumentsList[0];
                var _getIdAndStyleId3 = getIdAndStyleId(thisArg, mirror, stylesheetManager.styleMirror),
                  id = _getIdAndStyleId3.id,
                  styleId = _getIdAndStyleId3.styleId;
                if (id && id !== -1 || styleId && styleId !== -1) {
                  styleSheetRuleCb({
                    id: id,
                    styleId: styleId,
                    replace: text
                  });
                }
                return target.apply(thisArg, argumentsList);
              })
            });
          }
          var replaceSync;
          if (win.CSSStyleSheet.prototype.replaceSync) {
            replaceSync = win.CSSStyleSheet.prototype.replaceSync;
            win.CSSStyleSheet.prototype.replaceSync = new Proxy(replaceSync, {
              apply: callbackWrapper(function (target, thisArg, argumentsList) {
                var text = argumentsList[0];
                var _getIdAndStyleId4 = getIdAndStyleId(thisArg, mirror, stylesheetManager.styleMirror),
                  id = _getIdAndStyleId4.id,
                  styleId = _getIdAndStyleId4.styleId;
                if (id && id !== -1 || styleId && styleId !== -1) {
                  styleSheetRuleCb({
                    id: id,
                    styleId: styleId,
                    replaceSync: text
                  });
                }
                return target.apply(thisArg, argumentsList);
              })
            });
          }
          var supportedNestedCSSRuleTypes = {};
          if (canMonkeyPatchNestedCSSRule('CSSGroupingRule')) {
            supportedNestedCSSRuleTypes.CSSGroupingRule = win.CSSGroupingRule;
          } else {
            if (canMonkeyPatchNestedCSSRule('CSSMediaRule')) {
              supportedNestedCSSRuleTypes.CSSMediaRule = win.CSSMediaRule;
            }
            if (canMonkeyPatchNestedCSSRule('CSSConditionRule')) {
              supportedNestedCSSRuleTypes.CSSConditionRule = win.CSSConditionRule;
            }
            if (canMonkeyPatchNestedCSSRule('CSSSupportsRule')) {
              supportedNestedCSSRuleTypes.CSSSupportsRule = win.CSSSupportsRule;
            }
          }
          var unmodifiedFunctions = {};
          Object.entries(supportedNestedCSSRuleTypes).forEach(function (_ref12) {
            var typeKey = _ref12[0],
              type = _ref12[1];
            unmodifiedFunctions[typeKey] = {
              insertRule: type.prototype.insertRule,
              deleteRule: type.prototype.deleteRule
            };
            type.prototype.insertRule = new Proxy(unmodifiedFunctions[typeKey].insertRule, {
              apply: callbackWrapper(function (target, thisArg, argumentsList) {
                var rule = argumentsList[0],
                  index = argumentsList[1];
                var _getIdAndStyleId5 = getIdAndStyleId(thisArg.parentStyleSheet, mirror, stylesheetManager.styleMirror),
                  id = _getIdAndStyleId5.id,
                  styleId = _getIdAndStyleId5.styleId;
                if (id && id !== -1 || styleId && styleId !== -1) {
                  styleSheetRuleCb({
                    id: id,
                    styleId: styleId,
                    adds: [{
                      rule: rule,
                      index: [].concat(getNestedCSSRulePositions(thisArg), [index || 0])
                    }]
                  });
                }
                return target.apply(thisArg, argumentsList);
              })
            });
            type.prototype.deleteRule = new Proxy(unmodifiedFunctions[typeKey].deleteRule, {
              apply: callbackWrapper(function (target, thisArg, argumentsList) {
                var index = argumentsList[0];
                var _getIdAndStyleId6 = getIdAndStyleId(thisArg.parentStyleSheet, mirror, stylesheetManager.styleMirror),
                  id = _getIdAndStyleId6.id,
                  styleId = _getIdAndStyleId6.styleId;
                if (id && id !== -1 || styleId && styleId !== -1) {
                  styleSheetRuleCb({
                    id: id,
                    styleId: styleId,
                    removes: [{
                      index: [].concat(getNestedCSSRulePositions(thisArg), [index])
                    }]
                  });
                }
                return target.apply(thisArg, argumentsList);
              })
            });
          });
          return callbackWrapper(function () {
            win.CSSStyleSheet.prototype.insertRule = insertRule;
            win.CSSStyleSheet.prototype.deleteRule = deleteRule;
            replace && (win.CSSStyleSheet.prototype.replace = replace);
            replaceSync && (win.CSSStyleSheet.prototype.replaceSync = replaceSync);
            Object.entries(supportedNestedCSSRuleTypes).forEach(function (_ref13) {
              var typeKey = _ref13[0],
                type = _ref13[1];
              type.prototype.insertRule = unmodifiedFunctions[typeKey].insertRule;
              type.prototype.deleteRule = unmodifiedFunctions[typeKey].deleteRule;
            });
          });
        }
        function initAdoptedStyleSheetObserver(_ref14, host) {
          var mirror = _ref14.mirror,
            stylesheetManager = _ref14.stylesheetManager;
          var _a, _b, _c;
          var hostId = null;
          if (host.nodeName === '#document') hostId = mirror.getId(host);else hostId = mirror.getId(host.host);
          var patchTarget = host.nodeName === '#document' ? (_a = host.defaultView) === null || _a === void 0 ? void 0 : _a.Document : (_c = (_b = host.ownerDocument) === null || _b === void 0 ? void 0 : _b.defaultView) === null || _c === void 0 ? void 0 : _c.ShadowRoot;
          var originalPropertyDescriptor = (patchTarget === null || patchTarget === void 0 ? void 0 : patchTarget.prototype) ? Object.getOwnPropertyDescriptor(patchTarget === null || patchTarget === void 0 ? void 0 : patchTarget.prototype, 'adoptedStyleSheets') : undefined;
          if (hostId === null || hostId === -1 || !patchTarget || !originalPropertyDescriptor) return function () {};
          Object.defineProperty(host, 'adoptedStyleSheets', {
            configurable: originalPropertyDescriptor.configurable,
            enumerable: originalPropertyDescriptor.enumerable,
            get: function get() {
              var _a;
              return (_a = originalPropertyDescriptor.get) === null || _a === void 0 ? void 0 : _a.call(this);
            },
            set: function set(sheets) {
              var _a;
              var result = (_a = originalPropertyDescriptor.set) === null || _a === void 0 ? void 0 : _a.call(this, sheets);
              if (hostId !== null && hostId !== -1) {
                try {
                  stylesheetManager.adoptStyleSheets(sheets, hostId);
                } catch (e) {}
              }
              return result;
            }
          });
          return callbackWrapper(function () {
            Object.defineProperty(host, 'adoptedStyleSheets', {
              configurable: originalPropertyDescriptor.configurable,
              enumerable: originalPropertyDescriptor.enumerable,
              get: originalPropertyDescriptor.get,
              set: originalPropertyDescriptor.set
            });
          });
        }
        function initStyleDeclarationObserver(_ref15, _ref16) {
          var styleDeclarationCb = _ref15.styleDeclarationCb,
            mirror = _ref15.mirror,
            ignoreCSSAttributes = _ref15.ignoreCSSAttributes,
            stylesheetManager = _ref15.stylesheetManager;
          var win = _ref16.win;
          var setProperty = win.CSSStyleDeclaration.prototype.setProperty;
          win.CSSStyleDeclaration.prototype.setProperty = new Proxy(setProperty, {
            apply: callbackWrapper(function (target, thisArg, argumentsList) {
              var _a;
              var property = argumentsList[0],
                value = argumentsList[1],
                priority = argumentsList[2];
              if (ignoreCSSAttributes.has(property)) {
                return setProperty.apply(thisArg, [property, value, priority]);
              }
              var _getIdAndStyleId7 = getIdAndStyleId((_a = thisArg.parentRule) === null || _a === void 0 ? void 0 : _a.parentStyleSheet, mirror, stylesheetManager.styleMirror),
                id = _getIdAndStyleId7.id,
                styleId = _getIdAndStyleId7.styleId;
              if (id && id !== -1 || styleId && styleId !== -1) {
                styleDeclarationCb({
                  id: id,
                  styleId: styleId,
                  set: {
                    property: property,
                    value: value,
                    priority: priority
                  },
                  index: getNestedCSSRulePositions(thisArg.parentRule)
                });
              }
              return target.apply(thisArg, argumentsList);
            })
          });
          var removeProperty = win.CSSStyleDeclaration.prototype.removeProperty;
          win.CSSStyleDeclaration.prototype.removeProperty = new Proxy(removeProperty, {
            apply: callbackWrapper(function (target, thisArg, argumentsList) {
              var _a;
              var property = argumentsList[0];
              if (ignoreCSSAttributes.has(property)) {
                return removeProperty.apply(thisArg, [property]);
              }
              var _getIdAndStyleId8 = getIdAndStyleId((_a = thisArg.parentRule) === null || _a === void 0 ? void 0 : _a.parentStyleSheet, mirror, stylesheetManager.styleMirror),
                id = _getIdAndStyleId8.id,
                styleId = _getIdAndStyleId8.styleId;
              if (id && id !== -1 || styleId && styleId !== -1) {
                styleDeclarationCb({
                  id: id,
                  styleId: styleId,
                  remove: {
                    property: property
                  },
                  index: getNestedCSSRulePositions(thisArg.parentRule)
                });
              }
              return target.apply(thisArg, argumentsList);
            })
          });
          return callbackWrapper(function () {
            win.CSSStyleDeclaration.prototype.setProperty = setProperty;
            win.CSSStyleDeclaration.prototype.removeProperty = removeProperty;
          });
        }
        function initMediaInteractionObserver(_ref17) {
          var mediaInteractionCb = _ref17.mediaInteractionCb,
            blockClass = _ref17.blockClass,
            blockSelector = _ref17.blockSelector,
            mirror = _ref17.mirror,
            sampling = _ref17.sampling,
            doc = _ref17.doc;
          var handler = callbackWrapper(function (type) {
            return throttle(callbackWrapper(function (event) {
              var target = getEventTarget(event);
              if (!target || isBlocked(target, blockClass, blockSelector, true)) {
                return;
              }
              var currentTime = target.currentTime,
                volume = target.volume,
                muted = target.muted,
                playbackRate = target.playbackRate,
                loop = target.loop;
              mediaInteractionCb({
                type: type,
                id: mirror.getId(target),
                currentTime: currentTime,
                volume: volume,
                muted: muted,
                playbackRate: playbackRate,
                loop: loop
              });
            }), sampling.media || 500);
          });
          var handlers = [on('play', handler(0), doc), on('pause', handler(1), doc), on('seeked', handler(2), doc), on('volumechange', handler(3), doc), on('ratechange', handler(4), doc)];
          return callbackWrapper(function () {
            handlers.forEach(function (h) {
              return h();
            });
          });
        }
        function initFontObserver(_ref18) {
          var fontCb = _ref18.fontCb,
            doc = _ref18.doc;
          var win = doc.defaultView;
          if (!win) {
            return function () {};
          }
          var handlers = [];
          var fontMap = new WeakMap();
          var originalFontFace = win.FontFace;
          win.FontFace = function FontFace(family, source, descriptors) {
            var fontFace = new originalFontFace(family, source, descriptors);
            fontMap.set(fontFace, {
              family: family,
              buffer: typeof source !== 'string',
              descriptors: descriptors,
              fontSource: typeof source === 'string' ? source : JSON.stringify(Array.from(new Uint8Array(source)))
            });
            return fontFace;
          };
          var restoreHandler = patch(doc.fonts, 'add', function (original) {
            return function (fontFace) {
              setTimeout(callbackWrapper(function () {
                var p = fontMap.get(fontFace);
                if (p) {
                  fontCb(p);
                  fontMap["delete"](fontFace);
                }
              }), 0);
              return original.apply(this, [fontFace]);
            };
          });
          handlers.push(function () {
            win.FontFace = originalFontFace;
          });
          handlers.push(restoreHandler);
          return callbackWrapper(function () {
            handlers.forEach(function (h) {
              return h();
            });
          });
        }
        function initSelectionObserver(param) {
          var doc = param.doc,
            mirror = param.mirror,
            blockClass = param.blockClass,
            blockSelector = param.blockSelector,
            selectionCb = param.selectionCb;
          var collapsed = true;
          var updateSelection = callbackWrapper(function () {
            var selection = doc.getSelection();
            if (!selection || collapsed && (selection === null || selection === void 0 ? void 0 : selection.isCollapsed)) return;
            collapsed = selection.isCollapsed || false;
            var ranges = [];
            var count = selection.rangeCount || 0;
            for (var _i6 = 0; _i6 < count; _i6++) {
              var range = selection.getRangeAt(_i6);
              var startContainer = range.startContainer,
                startOffset = range.startOffset,
                endContainer = range.endContainer,
                endOffset = range.endOffset;
              var blocked = isBlocked(startContainer, blockClass, blockSelector, true) || isBlocked(endContainer, blockClass, blockSelector, true);
              if (blocked) continue;
              ranges.push({
                start: mirror.getId(startContainer),
                startOffset: startOffset,
                end: mirror.getId(endContainer),
                endOffset: endOffset
              });
            }
            selectionCb({
              ranges: ranges
            });
          });
          updateSelection();
          return on('selectionchange', updateSelection);
        }
        function initCustomElementObserver(_ref19) {
          var doc = _ref19.doc,
            customElementCb = _ref19.customElementCb;
          var win = doc.defaultView;
          if (!win || !win.customElements) return function () {};
          var restoreHandler = patch(win.customElements, 'define', function (original) {
            return function (name, constructor, options) {
              try {
                customElementCb({
                  define: {
                    name: name
                  }
                });
              } catch (e) {
                console.warn("Custom element callback failed for " + name);
              }
              return original.apply(this, [name, constructor, options]);
            };
          });
          return restoreHandler;
        }
        function mergeHooks(o, hooks) {
          var mutationCb = o.mutationCb,
            mousemoveCb = o.mousemoveCb,
            mouseInteractionCb = o.mouseInteractionCb,
            scrollCb = o.scrollCb,
            viewportResizeCb = o.viewportResizeCb,
            inputCb = o.inputCb,
            mediaInteractionCb = o.mediaInteractionCb,
            styleSheetRuleCb = o.styleSheetRuleCb,
            styleDeclarationCb = o.styleDeclarationCb,
            canvasMutationCb = o.canvasMutationCb,
            fontCb = o.fontCb,
            selectionCb = o.selectionCb,
            customElementCb = o.customElementCb;
          o.mutationCb = function () {
            if (hooks.mutation) {
              hooks.mutation.apply(hooks, arguments);
            }
            mutationCb.apply(void 0, arguments);
          };
          o.mousemoveCb = function () {
            if (hooks.mousemove) {
              hooks.mousemove.apply(hooks, arguments);
            }
            mousemoveCb.apply(void 0, arguments);
          };
          o.mouseInteractionCb = function () {
            if (hooks.mouseInteraction) {
              hooks.mouseInteraction.apply(hooks, arguments);
            }
            mouseInteractionCb.apply(void 0, arguments);
          };
          o.scrollCb = function () {
            if (hooks.scroll) {
              hooks.scroll.apply(hooks, arguments);
            }
            scrollCb.apply(void 0, arguments);
          };
          o.viewportResizeCb = function () {
            if (hooks.viewportResize) {
              hooks.viewportResize.apply(hooks, arguments);
            }
            viewportResizeCb.apply(void 0, arguments);
          };
          o.inputCb = function () {
            if (hooks.input) {
              hooks.input.apply(hooks, arguments);
            }
            inputCb.apply(void 0, arguments);
          };
          o.mediaInteractionCb = function () {
            if (hooks.mediaInteaction) {
              hooks.mediaInteaction.apply(hooks, arguments);
            }
            mediaInteractionCb.apply(void 0, arguments);
          };
          o.styleSheetRuleCb = function () {
            if (hooks.styleSheetRule) {
              hooks.styleSheetRule.apply(hooks, arguments);
            }
            styleSheetRuleCb.apply(void 0, arguments);
          };
          o.styleDeclarationCb = function () {
            if (hooks.styleDeclaration) {
              hooks.styleDeclaration.apply(hooks, arguments);
            }
            styleDeclarationCb.apply(void 0, arguments);
          };
          o.canvasMutationCb = function () {
            if (hooks.canvasMutation) {
              hooks.canvasMutation.apply(hooks, arguments);
            }
            canvasMutationCb.apply(void 0, arguments);
          };
          o.fontCb = function () {
            if (hooks.font) {
              hooks.font.apply(hooks, arguments);
            }
            fontCb.apply(void 0, arguments);
          };
          o.selectionCb = function () {
            if (hooks.selection) {
              hooks.selection.apply(hooks, arguments);
            }
            selectionCb.apply(void 0, arguments);
          };
          o.customElementCb = function () {
            if (hooks.customElement) {
              hooks.customElement.apply(hooks, arguments);
            }
            customElementCb.apply(void 0, arguments);
          };
        }
        function initObservers(o, hooks) {
          if (hooks === void 0) {
            hooks = {};
          }
          var currentWindow = o.doc.defaultView;
          if (!currentWindow) {
            return function () {};
          }
          mergeHooks(o, hooks);
          var mutationObserver;
          if (o.recordDOM) {
            mutationObserver = initMutationObserver(o, o.doc);
          }
          var mousemoveHandler = initMoveObserver(o);
          var mouseInteractionHandler = initMouseInteractionObserver(o);
          var scrollHandler = initScrollObserver(o);
          var viewportResizeHandler = initViewportResizeObserver(o, {
            win: currentWindow
          });
          var inputHandler = initInputObserver(o);
          var mediaInteractionHandler = initMediaInteractionObserver(o);
          var styleSheetObserver = function styleSheetObserver() {};
          var adoptedStyleSheetObserver = function adoptedStyleSheetObserver() {};
          var styleDeclarationObserver = function styleDeclarationObserver() {};
          var fontObserver = function fontObserver() {};
          if (o.recordDOM) {
            styleSheetObserver = initStyleSheetObserver(o, {
              win: currentWindow
            });
            adoptedStyleSheetObserver = initAdoptedStyleSheetObserver(o, o.doc);
            styleDeclarationObserver = initStyleDeclarationObserver(o, {
              win: currentWindow
            });
            if (o.collectFonts) {
              fontObserver = initFontObserver(o);
            }
          }
          var selectionObserver = initSelectionObserver(o);
          var customElementObserver = initCustomElementObserver(o);
          var pluginHandlers = [];
          for (var _iterator4 = _createForOfIteratorHelperLoose(o.plugins), _step4; !(_step4 = _iterator4()).done;) {
            var plugin = _step4.value;
            pluginHandlers.push(plugin.observer(plugin.callback, currentWindow, plugin.options));
          }
          return callbackWrapper(function () {
            mutationBuffers.forEach(function (b) {
              return b.reset();
            });
            mutationObserver === null || mutationObserver === void 0 ? void 0 : mutationObserver.disconnect();
            mousemoveHandler();
            mouseInteractionHandler();
            scrollHandler();
            viewportResizeHandler();
            inputHandler();
            mediaInteractionHandler();
            styleSheetObserver();
            adoptedStyleSheetObserver();
            styleDeclarationObserver();
            fontObserver();
            selectionObserver();
            customElementObserver();
            pluginHandlers.forEach(function (h) {
              return h();
            });
          });
        }
        function hasNestedCSSRule(prop) {
          return typeof window[prop] !== 'undefined';
        }
        function canMonkeyPatchNestedCSSRule(prop) {
          return Boolean(typeof window[prop] !== 'undefined' && window[prop].prototype && 'insertRule' in window[prop].prototype && 'deleteRule' in window[prop].prototype);
        }
        var CrossOriginIframeMirror = /*#__PURE__*/function () {
          function CrossOriginIframeMirror(generateIdFn) {
            this.generateIdFn = generateIdFn;
            this.iframeIdToRemoteIdMap = new WeakMap();
            this.iframeRemoteIdToIdMap = new WeakMap();
          }
          var _proto5 = CrossOriginIframeMirror.prototype;
          _proto5.getId = function getId(iframe, remoteId, idToRemoteMap, remoteToIdMap) {
            var idToRemoteIdMap = idToRemoteMap || this.getIdToRemoteIdMap(iframe);
            var remoteIdToIdMap = remoteToIdMap || this.getRemoteIdToIdMap(iframe);
            var id = idToRemoteIdMap.get(remoteId);
            if (!id) {
              id = this.generateIdFn();
              idToRemoteIdMap.set(remoteId, id);
              remoteIdToIdMap.set(id, remoteId);
            }
            return id;
          };
          _proto5.getIds = function getIds(iframe, remoteId) {
            var _this7 = this;
            var idToRemoteIdMap = this.getIdToRemoteIdMap(iframe);
            var remoteIdToIdMap = this.getRemoteIdToIdMap(iframe);
            return remoteId.map(function (id) {
              return _this7.getId(iframe, id, idToRemoteIdMap, remoteIdToIdMap);
            });
          };
          _proto5.getRemoteId = function getRemoteId(iframe, id, map) {
            var remoteIdToIdMap = map || this.getRemoteIdToIdMap(iframe);
            if (typeof id !== 'number') return id;
            var remoteId = remoteIdToIdMap.get(id);
            if (!remoteId) return -1;
            return remoteId;
          };
          _proto5.getRemoteIds = function getRemoteIds(iframe, ids) {
            var _this8 = this;
            var remoteIdToIdMap = this.getRemoteIdToIdMap(iframe);
            return ids.map(function (id) {
              return _this8.getRemoteId(iframe, id, remoteIdToIdMap);
            });
          };
          _proto5.reset = function reset(iframe) {
            if (!iframe) {
              this.iframeIdToRemoteIdMap = new WeakMap();
              this.iframeRemoteIdToIdMap = new WeakMap();
              return;
            }
            this.iframeIdToRemoteIdMap["delete"](iframe);
            this.iframeRemoteIdToIdMap["delete"](iframe);
          };
          _proto5.getIdToRemoteIdMap = function getIdToRemoteIdMap(iframe) {
            var idToRemoteIdMap = this.iframeIdToRemoteIdMap.get(iframe);
            if (!idToRemoteIdMap) {
              idToRemoteIdMap = new Map();
              this.iframeIdToRemoteIdMap.set(iframe, idToRemoteIdMap);
            }
            return idToRemoteIdMap;
          };
          _proto5.getRemoteIdToIdMap = function getRemoteIdToIdMap(iframe) {
            var remoteIdToIdMap = this.iframeRemoteIdToIdMap.get(iframe);
            if (!remoteIdToIdMap) {
              remoteIdToIdMap = new Map();
              this.iframeRemoteIdToIdMap.set(iframe, remoteIdToIdMap);
            }
            return remoteIdToIdMap;
          };
          return CrossOriginIframeMirror;
        }();
        var IframeManager = /*#__PURE__*/function () {
          function IframeManager(options) {
            this.iframes = new WeakMap();
            this.crossOriginIframeMap = new WeakMap();
            this.crossOriginIframeMirror = new CrossOriginIframeMirror(genId);
            this.crossOriginIframeRootIdMap = new WeakMap();
            this.mutationCb = options.mutationCb;
            this.wrappedEmit = options.wrappedEmit;
            this.stylesheetManager = options.stylesheetManager;
            this.recordCrossOriginIframes = options.recordCrossOriginIframes;
            this.crossOriginIframeStyleMirror = new CrossOriginIframeMirror(this.stylesheetManager.styleMirror.generateId.bind(this.stylesheetManager.styleMirror));
            this.mirror = options.mirror;
            if (this.recordCrossOriginIframes) {
              window.addEventListener('message', this.handleMessage.bind(this));
            }
          }
          var _proto6 = IframeManager.prototype;
          _proto6.addIframe = function addIframe(iframeEl) {
            this.iframes.set(iframeEl, true);
            if (iframeEl.contentWindow) this.crossOriginIframeMap.set(iframeEl.contentWindow, iframeEl);
          };
          _proto6.addLoadListener = function addLoadListener(cb) {
            this.loadListener = cb;
          };
          _proto6.attachIframe = function attachIframe(iframeEl, childSn) {
            var _a;
            this.mutationCb({
              adds: [{
                parentId: this.mirror.getId(iframeEl),
                nextId: null,
                node: childSn
              }],
              removes: [],
              texts: [],
              attributes: [],
              isAttachIframe: true
            });
            (_a = this.loadListener) === null || _a === void 0 ? void 0 : _a.call(this, iframeEl);
            if (iframeEl.contentDocument && iframeEl.contentDocument.adoptedStyleSheets && iframeEl.contentDocument.adoptedStyleSheets.length > 0) this.stylesheetManager.adoptStyleSheets(iframeEl.contentDocument.adoptedStyleSheets, this.mirror.getId(iframeEl.contentDocument));
          };
          _proto6.handleMessage = function handleMessage(message) {
            var crossOriginMessageEvent = message;
            if (crossOriginMessageEvent.data.type !== 'rrweb' || crossOriginMessageEvent.origin !== crossOriginMessageEvent.data.origin) return;
            var iframeSourceWindow = message.source;
            if (!iframeSourceWindow) return;
            var iframeEl = this.crossOriginIframeMap.get(message.source);
            if (!iframeEl) return;
            var transformedEvent = this.transformCrossOriginEvent(iframeEl, crossOriginMessageEvent.data.event);
            if (transformedEvent) this.wrappedEmit(transformedEvent, crossOriginMessageEvent.data.isCheckout);
          };
          _proto6.transformCrossOriginEvent = function transformCrossOriginEvent(iframeEl, e) {
            var _this9 = this;
            var _a;
            switch (e.type) {
              case EventType$1.FullSnapshot:
                {
                  this.crossOriginIframeMirror.reset(iframeEl);
                  this.crossOriginIframeStyleMirror.reset(iframeEl);
                  this.replaceIdOnNode(e.data.node, iframeEl);
                  var rootId = e.data.node.id;
                  this.crossOriginIframeRootIdMap.set(iframeEl, rootId);
                  this.patchRootIdOnNode(e.data.node, rootId);
                  return {
                    timestamp: e.timestamp,
                    type: EventType$1.IncrementalSnapshot,
                    data: {
                      source: IncrementalSource$1.Mutation,
                      adds: [{
                        parentId: this.mirror.getId(iframeEl),
                        nextId: null,
                        node: e.data.node
                      }],
                      removes: [],
                      texts: [],
                      attributes: [],
                      isAttachIframe: true
                    }
                  };
                }
              case EventType$1.Meta:
              case EventType$1.Load:
              case EventType$1.DomContentLoaded:
                {
                  return false;
                }
              case EventType$1.Plugin:
                {
                  return e;
                }
              case EventType$1.Custom:
                {
                  this.replaceIds(e.data.payload, iframeEl, ['id', 'parentId', 'previousId', 'nextId']);
                  return e;
                }
              case EventType$1.IncrementalSnapshot:
                {
                  switch (e.data.source) {
                    case IncrementalSource$1.Mutation:
                      {
                        e.data.adds.forEach(function (n) {
                          _this9.replaceIds(n, iframeEl, ['parentId', 'nextId', 'previousId']);
                          _this9.replaceIdOnNode(n.node, iframeEl);
                          var rootId = _this9.crossOriginIframeRootIdMap.get(iframeEl);
                          rootId && _this9.patchRootIdOnNode(n.node, rootId);
                        });
                        e.data.removes.forEach(function (n) {
                          _this9.replaceIds(n, iframeEl, ['parentId', 'id']);
                        });
                        e.data.attributes.forEach(function (n) {
                          _this9.replaceIds(n, iframeEl, ['id']);
                        });
                        e.data.texts.forEach(function (n) {
                          _this9.replaceIds(n, iframeEl, ['id']);
                        });
                        return e;
                      }
                    case IncrementalSource$1.Drag:
                    case IncrementalSource$1.TouchMove:
                    case IncrementalSource$1.MouseMove:
                      {
                        e.data.positions.forEach(function (p) {
                          _this9.replaceIds(p, iframeEl, ['id']);
                        });
                        return e;
                      }
                    case IncrementalSource$1.ViewportResize:
                      {
                        return false;
                      }
                    case IncrementalSource$1.MediaInteraction:
                    case IncrementalSource$1.MouseInteraction:
                    case IncrementalSource$1.Scroll:
                    case IncrementalSource$1.CanvasMutation:
                    case IncrementalSource$1.Input:
                      {
                        this.replaceIds(e.data, iframeEl, ['id']);
                        return e;
                      }
                    case IncrementalSource$1.StyleSheetRule:
                    case IncrementalSource$1.StyleDeclaration:
                      {
                        this.replaceIds(e.data, iframeEl, ['id']);
                        this.replaceStyleIds(e.data, iframeEl, ['styleId']);
                        return e;
                      }
                    case IncrementalSource$1.Font:
                      {
                        return e;
                      }
                    case IncrementalSource$1.Selection:
                      {
                        e.data.ranges.forEach(function (range) {
                          _this9.replaceIds(range, iframeEl, ['start', 'end']);
                        });
                        return e;
                      }
                    case IncrementalSource$1.AdoptedStyleSheet:
                      {
                        this.replaceIds(e.data, iframeEl, ['id']);
                        this.replaceStyleIds(e.data, iframeEl, ['styleIds']);
                        (_a = e.data.styles) === null || _a === void 0 ? void 0 : _a.forEach(function (style) {
                          _this9.replaceStyleIds(style, iframeEl, ['styleId']);
                        });
                        return e;
                      }
                  }
                }
            }
            return false;
          };
          _proto6.replace = function replace(iframeMirror, obj, iframeEl, keys) {
            for (var _iterator5 = _createForOfIteratorHelperLoose(keys), _step5; !(_step5 = _iterator5()).done;) {
              var key = _step5.value;
              if (!Array.isArray(obj[key]) && typeof obj[key] !== 'number') continue;
              if (Array.isArray(obj[key])) {
                obj[key] = iframeMirror.getIds(iframeEl, obj[key]);
              } else {
                obj[key] = iframeMirror.getId(iframeEl, obj[key]);
              }
            }
            return obj;
          };
          _proto6.replaceIds = function replaceIds(obj, iframeEl, keys) {
            return this.replace(this.crossOriginIframeMirror, obj, iframeEl, keys);
          };
          _proto6.replaceStyleIds = function replaceStyleIds(obj, iframeEl, keys) {
            return this.replace(this.crossOriginIframeStyleMirror, obj, iframeEl, keys);
          };
          _proto6.replaceIdOnNode = function replaceIdOnNode(node, iframeEl) {
            var _this10 = this;
            this.replaceIds(node, iframeEl, ['id', 'rootId']);
            if ('childNodes' in node) {
              node.childNodes.forEach(function (child) {
                _this10.replaceIdOnNode(child, iframeEl);
              });
            }
          };
          _proto6.patchRootIdOnNode = function patchRootIdOnNode(node, rootId) {
            var _this11 = this;
            if (node.type !== NodeType.Document && !node.rootId) node.rootId = rootId;
            if ('childNodes' in node) {
              node.childNodes.forEach(function (child) {
                _this11.patchRootIdOnNode(child, rootId);
              });
            }
          };
          return IframeManager;
        }();
        var ShadowDomManager = /*#__PURE__*/function () {
          function ShadowDomManager(options) {
            this.shadowDoms = new WeakSet();
            this.restoreHandlers = [];
            this.mutationCb = options.mutationCb;
            this.scrollCb = options.scrollCb;
            this.bypassOptions = options.bypassOptions;
            this.mirror = options.mirror;
            this.init();
          }
          var _proto7 = ShadowDomManager.prototype;
          _proto7.init = function init() {
            this.reset();
            this.patchAttachShadow(Element, document);
          };
          _proto7.addShadowRoot = function addShadowRoot(shadowRoot, doc) {
            var _this12 = this;
            if (!isNativeShadowDom(shadowRoot)) return;
            if (this.shadowDoms.has(shadowRoot)) return;
            this.shadowDoms.add(shadowRoot);
            var observer = initMutationObserver(Object.assign(Object.assign({}, this.bypassOptions), {
              doc: doc,
              mutationCb: this.mutationCb,
              mirror: this.mirror,
              shadowDomManager: this
            }), shadowRoot);
            this.restoreHandlers.push(function () {
              return observer.disconnect();
            });
            this.restoreHandlers.push(initScrollObserver(Object.assign(Object.assign({}, this.bypassOptions), {
              scrollCb: this.scrollCb,
              doc: shadowRoot,
              mirror: this.mirror
            })));
            setTimeout(function () {
              if (shadowRoot.adoptedStyleSheets && shadowRoot.adoptedStyleSheets.length > 0) _this12.bypassOptions.stylesheetManager.adoptStyleSheets(shadowRoot.adoptedStyleSheets, _this12.mirror.getId(shadowRoot.host));
              _this12.restoreHandlers.push(initAdoptedStyleSheetObserver({
                mirror: _this12.mirror,
                stylesheetManager: _this12.bypassOptions.stylesheetManager
              }, shadowRoot));
            }, 0);
          };
          _proto7.observeAttachShadow = function observeAttachShadow(iframeElement) {
            if (!iframeElement.contentWindow || !iframeElement.contentDocument) return;
            this.patchAttachShadow(iframeElement.contentWindow.Element, iframeElement.contentDocument);
          };
          _proto7.patchAttachShadow = function patchAttachShadow(element, doc) {
            var manager = this;
            this.restoreHandlers.push(patch(element.prototype, 'attachShadow', function (original) {
              return function (option) {
                var shadowRoot = original.call(this, option);
                if (this.shadowRoot && inDom(this)) manager.addShadowRoot(this.shadowRoot, doc);
                return shadowRoot;
              };
            }));
          };
          _proto7.reset = function reset() {
            this.restoreHandlers.forEach(function (handler) {
              try {
                handler();
              } catch (e) {}
            });
            this.restoreHandlers = [];
            this.shadowDoms = new WeakSet();
          };
          return ShadowDomManager;
        }();
        /*! *****************************************************************************
        Copyright (c) Microsoft Corporation.
        
        Permission to use, copy, modify, and/or distribute this software for any
        purpose with or without fee is hereby granted.
        
        THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
        REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
        AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
        INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
        LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
        OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
        PERFORMANCE OF THIS SOFTWARE.
        ***************************************************************************** */
        function __rest(s, e) {
          var t = {};
          for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0) t[p] = s[p];
          if (s != null && typeof Object.getOwnPropertySymbols === "function") for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i])) t[p[i]] = s[p[i]];
          }
          return t;
        }
        function __awaiter(thisArg, _arguments, P, generator) {
          function adopt(value) {
            return value instanceof P ? value : new P(function (resolve) {
              resolve(value);
            });
          }
          return new (P || (P = Promise))(function (resolve, reject) {
            function fulfilled(value) {
              try {
                step(generator.next(value));
              } catch (e) {
                reject(e);
              }
            }
            function rejected(value) {
              try {
                step(generator["throw"](value));
              } catch (e) {
                reject(e);
              }
            }
            function step(result) {
              result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
            }
            step((generator = generator.apply(thisArg, _arguments || [])).next());
          });
        }

        /*
         * base64-arraybuffer 1.0.1 <https://github.com/niklasvh/base64-arraybuffer>
         * Copyright (c) 2021 Niklas von Hertzen <https://hertzen.com>
         * Released under MIT License
         */
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        // Use a lookup table to find the index.
        var lookup = typeof Uint8Array === 'undefined' ? [] : new Uint8Array(256);
        for (var i = 0; i < chars.length; i++) {
          lookup[chars.charCodeAt(i)] = i;
        }
        var encode = function encode(arraybuffer) {
          var bytes = new Uint8Array(arraybuffer),
            i,
            len = bytes.length,
            base64 = '';
          for (i = 0; i < len; i += 3) {
            base64 += chars[bytes[i] >> 2];
            base64 += chars[(bytes[i] & 3) << 4 | bytes[i + 1] >> 4];
            base64 += chars[(bytes[i + 1] & 15) << 2 | bytes[i + 2] >> 6];
            base64 += chars[bytes[i + 2] & 63];
          }
          if (len % 3 === 2) {
            base64 = base64.substring(0, base64.length - 1) + '=';
          } else if (len % 3 === 1) {
            base64 = base64.substring(0, base64.length - 2) + '==';
          }
          return base64;
        };
        var canvasVarMap = new Map();
        function variableListFor(ctx, ctor) {
          var contextMap = canvasVarMap.get(ctx);
          if (!contextMap) {
            contextMap = new Map();
            canvasVarMap.set(ctx, contextMap);
          }
          if (!contextMap.has(ctor)) {
            contextMap.set(ctor, []);
          }
          return contextMap.get(ctor);
        }
        var saveWebGLVar = function saveWebGLVar(value, win, ctx) {
          if (!value || !(isInstanceOfWebGLObject(value, win) || typeof value === 'object')) return;
          var name = value.constructor.name;
          var list = variableListFor(ctx, name);
          var index = list.indexOf(value);
          if (index === -1) {
            index = list.length;
            list.push(value);
          }
          return index;
        };
        function serializeArg(value, win, ctx) {
          if (value instanceof Array) {
            return value.map(function (arg) {
              return serializeArg(arg, win, ctx);
            });
          } else if (value === null) {
            return value;
          } else if (value instanceof Float32Array || value instanceof Float64Array || value instanceof Int32Array || value instanceof Uint32Array || value instanceof Uint8Array || value instanceof Uint16Array || value instanceof Int16Array || value instanceof Int8Array || value instanceof Uint8ClampedArray) {
            var name = value.constructor.name;
            return {
              rr_type: name,
              args: [Object.values(value)]
            };
          } else if (value instanceof ArrayBuffer) {
            var _name = value.constructor.name;
            var base64 = encode(value);
            return {
              rr_type: _name,
              base64: base64
            };
          } else if (value instanceof DataView) {
            var _name2 = value.constructor.name;
            return {
              rr_type: _name2,
              args: [serializeArg(value.buffer, win, ctx), value.byteOffset, value.byteLength]
            };
          } else if (value instanceof HTMLImageElement) {
            var _name3 = value.constructor.name;
            var src = value.src;
            return {
              rr_type: _name3,
              src: src
            };
          } else if (value instanceof HTMLCanvasElement) {
            var _name4 = 'HTMLImageElement';
            var _src2 = value.toDataURL();
            return {
              rr_type: _name4,
              src: _src2
            };
          } else if (value instanceof ImageData) {
            var _name5 = value.constructor.name;
            return {
              rr_type: _name5,
              args: [serializeArg(value.data, win, ctx), value.width, value.height]
            };
          } else if (isInstanceOfWebGLObject(value, win) || typeof value === 'object') {
            var _name6 = value.constructor.name;
            var index = saveWebGLVar(value, win, ctx);
            return {
              rr_type: _name6,
              index: index
            };
          }
          return value;
        }
        var serializeArgs = function serializeArgs(args, win, ctx) {
          return args.map(function (arg) {
            return serializeArg(arg, win, ctx);
          });
        };
        var isInstanceOfWebGLObject = function isInstanceOfWebGLObject(value, win) {
          var webGLConstructorNames = ['WebGLActiveInfo', 'WebGLBuffer', 'WebGLFramebuffer', 'WebGLProgram', 'WebGLRenderbuffer', 'WebGLShader', 'WebGLShaderPrecisionFormat', 'WebGLTexture', 'WebGLUniformLocation', 'WebGLVertexArrayObject', 'WebGLVertexArrayObjectOES'];
          var supportedWebGLConstructorNames = webGLConstructorNames.filter(function (name) {
            return typeof win[name] === 'function';
          });
          return Boolean(supportedWebGLConstructorNames.find(function (name) {
            return value instanceof win[name];
          }));
        };
        function initCanvas2DMutationObserver(cb, win, blockClass, blockSelector) {
          var handlers = [];
          var props2D = Object.getOwnPropertyNames(win.CanvasRenderingContext2D.prototype);
          var _loop = function _loop() {
            var prop = _step6.value;
            try {
              if (typeof win.CanvasRenderingContext2D.prototype[prop] !== 'function') {
                return 1; // continue
              }

              var restoreHandler = patch(win.CanvasRenderingContext2D.prototype, prop, function (original) {
                return function () {
                  var _this13 = this;
                  for (var _len3 = arguments.length, args = new Array(_len3), _key3 = 0; _key3 < _len3; _key3++) {
                    args[_key3] = arguments[_key3];
                  }
                  if (!isBlocked(this.canvas, blockClass, blockSelector, true)) {
                    setTimeout(function () {
                      var recordArgs = serializeArgs(args, win, _this13);
                      cb(_this13.canvas, {
                        type: CanvasContext['2D'],
                        property: prop,
                        args: recordArgs
                      });
                    }, 0);
                  }
                  return original.apply(this, args);
                };
              });
              handlers.push(restoreHandler);
            } catch (_a) {
              var hookHandler = hookSetter(win.CanvasRenderingContext2D.prototype, prop, {
                set: function set(v) {
                  cb(this.canvas, {
                    type: CanvasContext['2D'],
                    property: prop,
                    args: [v],
                    setter: true
                  });
                }
              });
              handlers.push(hookHandler);
            }
          };
          for (var _iterator6 = _createForOfIteratorHelperLoose(props2D), _step6; !(_step6 = _iterator6()).done;) {
            if (_loop()) continue;
          }
          return function () {
            handlers.forEach(function (h) {
              return h();
            });
          };
        }
        function getNormalizedContextName(contextType) {
          return contextType === 'experimental-webgl' ? 'webgl' : contextType;
        }
        function initCanvasContextObserver(win, blockClass, blockSelector, setPreserveDrawingBufferToTrue) {
          var handlers = [];
          try {
            var restoreHandler = patch(win.HTMLCanvasElement.prototype, 'getContext', function (original) {
              return function (contextType) {
                for (var _len4 = arguments.length, args = new Array(_len4 > 1 ? _len4 - 1 : 0), _key4 = 1; _key4 < _len4; _key4++) {
                  args[_key4 - 1] = arguments[_key4];
                }
                if (!isBlocked(this, blockClass, blockSelector, true)) {
                  var ctxName = getNormalizedContextName(contextType);
                  if (!('__context' in this)) this.__context = ctxName;
                  if (setPreserveDrawingBufferToTrue && ['webgl', 'webgl2'].includes(ctxName)) {
                    if (args[0] && typeof args[0] === 'object') {
                      var contextAttributes = args[0];
                      if (!contextAttributes.preserveDrawingBuffer) {
                        contextAttributes.preserveDrawingBuffer = true;
                      }
                    } else {
                      args.splice(0, 1, {
                        preserveDrawingBuffer: true
                      });
                    }
                  }
                }
                return original.apply(this, [contextType].concat(args));
              };
            });
            handlers.push(restoreHandler);
          } catch (_a) {
            console.error('failed to patch HTMLCanvasElement.prototype.getContext');
          }
          return function () {
            handlers.forEach(function (h) {
              return h();
            });
          };
        }
        function patchGLPrototype(prototype, type, cb, blockClass, blockSelector, mirror, win) {
          var handlers = [];
          var props = Object.getOwnPropertyNames(prototype);
          var _loop2 = function _loop2() {
              var prop = _step7.value;
              if (['isContextLost', 'canvas', 'drawingBufferWidth', 'drawingBufferHeight'].includes(prop)) {
                return 0; // continue
              }

              try {
                if (typeof prototype[prop] !== 'function') {
                  return 0; // continue
                }

                var restoreHandler = patch(prototype, prop, function (original) {
                  return function () {
                    for (var _len5 = arguments.length, args = new Array(_len5), _key5 = 0; _key5 < _len5; _key5++) {
                      args[_key5] = arguments[_key5];
                    }
                    var result = original.apply(this, args);
                    saveWebGLVar(result, win, this);
                    if ('tagName' in this.canvas && !isBlocked(this.canvas, blockClass, blockSelector, true)) {
                      var recordArgs = serializeArgs(args, win, this);
                      var mutation = {
                        type: type,
                        property: prop,
                        args: recordArgs
                      };
                      cb(this.canvas, mutation);
                    }
                    return result;
                  };
                });
                handlers.push(restoreHandler);
              } catch (_a) {
                var hookHandler = hookSetter(prototype, prop, {
                  set: function set(v) {
                    cb(this.canvas, {
                      type: type,
                      property: prop,
                      args: [v],
                      setter: true
                    });
                  }
                });
                handlers.push(hookHandler);
              }
            },
            _ret;
          for (var _iterator7 = _createForOfIteratorHelperLoose(props), _step7; !(_step7 = _iterator7()).done;) {
            _ret = _loop2();
            if (_ret === 0) continue;
          }
          return handlers;
        }
        function initCanvasWebGLMutationObserver(cb, win, blockClass, blockSelector, mirror) {
          var handlers = [];
          handlers.push.apply(handlers, patchGLPrototype(win.WebGLRenderingContext.prototype, CanvasContext.WebGL, cb, blockClass, blockSelector, mirror, win));
          if (typeof win.WebGL2RenderingContext !== 'undefined') {
            handlers.push.apply(handlers, patchGLPrototype(win.WebGL2RenderingContext.prototype, CanvasContext.WebGL2, cb, blockClass, blockSelector, mirror, win));
          }
          return function () {
            handlers.forEach(function (h) {
              return h();
            });
          };
        }
        function funcToSource(fn, sourcemapArg) {
          var sourcemap = sourcemapArg === undefined ? null : sourcemapArg;
          var source = fn.toString();
          var lines = source.split('\n');
          lines.pop();
          lines.shift();
          var blankPrefixLength = lines[0].search(/\S/);
          var regex = /(['"])__worker_loader_strict__(['"])/g;
          for (var i = 0, n = lines.length; i < n; ++i) {
            lines[i] = lines[i].substring(blankPrefixLength).replace(regex, '$1use strict$2') + '\n';
          }
          if (sourcemap) {
            lines.push('\/\/# sourceMappingURL=' + sourcemap + '\n');
          }
          return lines;
        }
        function createURL(fn, sourcemapArg) {
          var lines = funcToSource(fn, sourcemapArg);
          var blob = new Blob(lines, {
            type: 'application/javascript'
          });
          return URL.createObjectURL(blob);
        }
        function createInlineWorkerFactory(fn, sourcemapArg) {
          var url;
          return function WorkerFactory(options) {
            url = url || createURL(fn, sourcemapArg);
            return new Worker(url, options);
          };
        }
        var WorkerFactory = createInlineWorkerFactory( /* rollup-plugin-web-worker-loader */function () {
          (function () {
            '__worker_loader_strict__';

            /*! *****************************************************************************
            Copyright (c) Microsoft Corporation.
              Permission to use, copy, modify, and/or distribute this software for any
            purpose with or without fee is hereby granted.
              THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
            REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
            AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
            INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
            LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
            OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
            PERFORMANCE OF THIS SOFTWARE.
            ***************************************************************************** */
            function __awaiter(thisArg, _arguments, P, generator) {
              function adopt(value) {
                return value instanceof P ? value : new P(function (resolve) {
                  resolve(value);
                });
              }
              return new (P || (P = Promise))(function (resolve, reject) {
                function fulfilled(value) {
                  try {
                    step(generator.next(value));
                  } catch (e) {
                    reject(e);
                  }
                }
                function rejected(value) {
                  try {
                    step(generator["throw"](value));
                  } catch (e) {
                    reject(e);
                  }
                }
                function step(result) {
                  result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
                }
                step((generator = generator.apply(thisArg, _arguments || [])).next());
              });
            }

            /*
             * base64-arraybuffer 1.0.1 <https://github.com/niklasvh/base64-arraybuffer>
             * Copyright (c) 2021 Niklas von Hertzen <https://hertzen.com>
             * Released under MIT License
             */
            var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
            // Use a lookup table to find the index.
            var lookup = typeof Uint8Array === 'undefined' ? [] : new Uint8Array(256);
            for (var i = 0; i < chars.length; i++) {
              lookup[chars.charCodeAt(i)] = i;
            }
            var encode = function encode(arraybuffer) {
              var bytes = new Uint8Array(arraybuffer),
                i,
                len = bytes.length,
                base64 = '';
              for (i = 0; i < len; i += 3) {
                base64 += chars[bytes[i] >> 2];
                base64 += chars[(bytes[i] & 3) << 4 | bytes[i + 1] >> 4];
                base64 += chars[(bytes[i + 1] & 15) << 2 | bytes[i + 2] >> 6];
                base64 += chars[bytes[i + 2] & 63];
              }
              if (len % 3 === 2) {
                base64 = base64.substring(0, base64.length - 1) + '=';
              } else if (len % 3 === 1) {
                base64 = base64.substring(0, base64.length - 2) + '==';
              }
              return base64;
            };
            var lastBlobMap = new Map();
            var transparentBlobMap = new Map();
            function getTransparentBlobFor(width, height, dataURLOptions) {
              return __awaiter(this, void 0, void 0, /*#__PURE__*/_regeneratorRuntime().mark(function _callee() {
                var id, offscreen, blob, arrayBuffer, base64;
                return _regeneratorRuntime().wrap(function _callee$(_context) {
                  while (1) switch (_context.prev = _context.next) {
                    case 0:
                      id = width + "-" + height;
                      if (!('OffscreenCanvas' in globalThis)) {
                        _context.next = 17;
                        break;
                      }
                      if (!transparentBlobMap.has(id)) {
                        _context.next = 4;
                        break;
                      }
                      return _context.abrupt("return", transparentBlobMap.get(id));
                    case 4:
                      offscreen = new OffscreenCanvas(width, height);
                      offscreen.getContext('2d');
                      _context.next = 8;
                      return offscreen.convertToBlob(dataURLOptions);
                    case 8:
                      blob = _context.sent;
                      _context.next = 11;
                      return blob.arrayBuffer();
                    case 11:
                      arrayBuffer = _context.sent;
                      base64 = encode(arrayBuffer);
                      transparentBlobMap.set(id, base64);
                      return _context.abrupt("return", base64);
                    case 17:
                      return _context.abrupt("return", '');
                    case 18:
                    case "end":
                      return _context.stop();
                  }
                }, _callee);
              }));
            }
            var worker = self;
            worker.onmessage = function (e) {
              return __awaiter(this, void 0, void 0, /*#__PURE__*/_regeneratorRuntime().mark(function _callee2() {
                var _e$data, id, bitmap, width, height, dataURLOptions, transparentBase64, offscreen, ctx, blob, type, arrayBuffer, base64;
                return _regeneratorRuntime().wrap(function _callee2$(_context2) {
                  while (1) switch (_context2.prev = _context2.next) {
                    case 0:
                      if (!('OffscreenCanvas' in globalThis)) {
                        _context2.next = 31;
                        break;
                      }
                      _e$data = e.data, id = _e$data.id, bitmap = _e$data.bitmap, width = _e$data.width, height = _e$data.height, dataURLOptions = _e$data.dataURLOptions;
                      transparentBase64 = getTransparentBlobFor(width, height, dataURLOptions);
                      offscreen = new OffscreenCanvas(width, height);
                      ctx = offscreen.getContext('2d');
                      ctx.drawImage(bitmap, 0, 0);
                      bitmap.close();
                      _context2.next = 9;
                      return offscreen.convertToBlob(dataURLOptions);
                    case 9:
                      blob = _context2.sent;
                      type = blob.type;
                      _context2.next = 13;
                      return blob.arrayBuffer();
                    case 13:
                      arrayBuffer = _context2.sent;
                      base64 = encode(arrayBuffer);
                      _context2.t0 = !lastBlobMap.has(id);
                      if (!_context2.t0) {
                        _context2.next = 22;
                        break;
                      }
                      _context2.next = 19;
                      return transparentBase64;
                    case 19:
                      _context2.t1 = _context2.sent;
                      _context2.t2 = base64;
                      _context2.t0 = _context2.t1 === _context2.t2;
                    case 22:
                      if (!_context2.t0) {
                        _context2.next = 25;
                        break;
                      }
                      lastBlobMap.set(id, base64);
                      return _context2.abrupt("return", worker.postMessage({
                        id: id
                      }));
                    case 25:
                      if (!(lastBlobMap.get(id) === base64)) {
                        _context2.next = 27;
                        break;
                      }
                      return _context2.abrupt("return", worker.postMessage({
                        id: id
                      }));
                    case 27:
                      worker.postMessage({
                        id: id,
                        type: type,
                        base64: base64,
                        width: width,
                        height: height
                      });
                      lastBlobMap.set(id, base64);
                      _context2.next = 32;
                      break;
                    case 31:
                      return _context2.abrupt("return", worker.postMessage({
                        id: e.data.id
                      }));
                    case 32:
                    case "end":
                      return _context2.stop();
                  }
                }, _callee2);
              }));
            };
          })();
        }, null);
        var CanvasManager = /*#__PURE__*/function () {
          var _proto8 = CanvasManager.prototype;
          _proto8.reset = function reset() {
            this.pendingCanvasMutations.clear();
            this.resetObservers && this.resetObservers();
          };
          _proto8.freeze = function freeze() {
            this.frozen = true;
          };
          _proto8.unfreeze = function unfreeze() {
            this.frozen = false;
          };
          _proto8.lock = function lock() {
            this.locked = true;
          };
          _proto8.unlock = function unlock() {
            this.locked = false;
          };
          function CanvasManager(options) {
            var _this14 = this;
            this.pendingCanvasMutations = new Map();
            this.rafStamps = {
              latestId: 0,
              invokeId: null
            };
            this.frozen = false;
            this.locked = false;
            this.processMutation = function (target, mutation) {
              var newFrame = _this14.rafStamps.invokeId && _this14.rafStamps.latestId !== _this14.rafStamps.invokeId;
              if (newFrame || !_this14.rafStamps.invokeId) _this14.rafStamps.invokeId = _this14.rafStamps.latestId;
              if (!_this14.pendingCanvasMutations.has(target)) {
                _this14.pendingCanvasMutations.set(target, []);
              }
              _this14.pendingCanvasMutations.get(target).push(mutation);
            };
            var _options$sampling = options.sampling,
              sampling = _options$sampling === void 0 ? 'all' : _options$sampling,
              win = options.win,
              blockClass = options.blockClass,
              blockSelector = options.blockSelector,
              recordCanvas = options.recordCanvas,
              dataURLOptions = options.dataURLOptions;
            this.mutationCb = options.mutationCb;
            this.mirror = options.mirror;
            if (recordCanvas && sampling === 'all') this.initCanvasMutationObserver(win, blockClass, blockSelector);
            if (recordCanvas && typeof sampling === 'number') this.initCanvasFPSObserver(sampling, win, blockClass, blockSelector, {
              dataURLOptions: dataURLOptions
            });
          }
          _proto8.initCanvasFPSObserver = function initCanvasFPSObserver(fps, win, blockClass, blockSelector, options) {
            var _this15 = this;
            var canvasContextReset = initCanvasContextObserver(win, blockClass, blockSelector, true);
            var snapshotInProgressMap = new Map();
            var worker = new WorkerFactory();
            worker.onmessage = function (e) {
              var id = e.data.id;
              snapshotInProgressMap.set(id, false);
              if (!('base64' in e.data)) return;
              var _e$data2 = e.data,
                base64 = _e$data2.base64,
                type = _e$data2.type,
                width = _e$data2.width,
                height = _e$data2.height;
              _this15.mutationCb({
                id: id,
                type: CanvasContext['2D'],
                commands: [{
                  property: 'clearRect',
                  args: [0, 0, width, height]
                }, {
                  property: 'drawImage',
                  args: [{
                    rr_type: 'ImageBitmap',
                    args: [{
                      rr_type: 'Blob',
                      data: [{
                        rr_type: 'ArrayBuffer',
                        base64: base64
                      }],
                      type: type
                    }]
                  }, 0, 0]
                }]
              });
            };
            var timeBetweenSnapshots = 1000 / fps;
            var lastSnapshotTime = 0;
            var rafId;
            var getCanvas = function getCanvas() {
              var matchedCanvas = [];
              win.document.querySelectorAll('canvas').forEach(function (canvas) {
                if (!isBlocked(canvas, blockClass, blockSelector, true)) {
                  matchedCanvas.push(canvas);
                }
              });
              return matchedCanvas;
            };
            var takeCanvasSnapshots = function takeCanvasSnapshots(timestamp) {
              if (lastSnapshotTime && timestamp - lastSnapshotTime < timeBetweenSnapshots) {
                rafId = requestAnimationFrame(takeCanvasSnapshots);
                return;
              }
              lastSnapshotTime = timestamp;
              getCanvas().forEach(function (canvas) {
                return __awaiter(_this15, void 0, void 0, /*#__PURE__*/_regeneratorRuntime().mark(function _callee3() {
                  var _a, id, context, bitmap;
                  return _regeneratorRuntime().wrap(function _callee3$(_context3) {
                    while (1) switch (_context3.prev = _context3.next) {
                      case 0:
                        id = this.mirror.getId(canvas);
                        if (!snapshotInProgressMap.get(id)) {
                          _context3.next = 3;
                          break;
                        }
                        return _context3.abrupt("return");
                      case 3:
                        if (!(canvas.width === 0 || canvas.height === 0)) {
                          _context3.next = 5;
                          break;
                        }
                        return _context3.abrupt("return");
                      case 5:
                        snapshotInProgressMap.set(id, true);
                        if (['webgl', 'webgl2'].includes(canvas.__context)) {
                          context = canvas.getContext(canvas.__context);
                          if (((_a = context === null || context === void 0 ? void 0 : context.getContextAttributes()) === null || _a === void 0 ? void 0 : _a.preserveDrawingBuffer) === false) {
                            context.clear(context.COLOR_BUFFER_BIT);
                          }
                        }
                        _context3.next = 9;
                        return createImageBitmap(canvas);
                      case 9:
                        bitmap = _context3.sent;
                        worker.postMessage({
                          id: id,
                          bitmap: bitmap,
                          width: canvas.width,
                          height: canvas.height,
                          dataURLOptions: options.dataURLOptions
                        }, [bitmap]);
                      case 11:
                      case "end":
                        return _context3.stop();
                    }
                  }, _callee3, this);
                }));
              });
              rafId = requestAnimationFrame(takeCanvasSnapshots);
            };
            rafId = requestAnimationFrame(takeCanvasSnapshots);
            this.resetObservers = function () {
              canvasContextReset();
              cancelAnimationFrame(rafId);
            };
          };
          _proto8.initCanvasMutationObserver = function initCanvasMutationObserver(win, blockClass, blockSelector) {
            this.startRAFTimestamping();
            this.startPendingCanvasMutationFlusher();
            var canvasContextReset = initCanvasContextObserver(win, blockClass, blockSelector, false);
            var canvas2DReset = initCanvas2DMutationObserver(this.processMutation.bind(this), win, blockClass, blockSelector);
            var canvasWebGL1and2Reset = initCanvasWebGLMutationObserver(this.processMutation.bind(this), win, blockClass, blockSelector, this.mirror);
            this.resetObservers = function () {
              canvasContextReset();
              canvas2DReset();
              canvasWebGL1and2Reset();
            };
          };
          _proto8.startPendingCanvasMutationFlusher = function startPendingCanvasMutationFlusher() {
            var _this16 = this;
            requestAnimationFrame(function () {
              return _this16.flushPendingCanvasMutations();
            });
          };
          _proto8.startRAFTimestamping = function startRAFTimestamping() {
            var _this17 = this;
            var setLatestRAFTimestamp = function setLatestRAFTimestamp(timestamp) {
              _this17.rafStamps.latestId = timestamp;
              requestAnimationFrame(setLatestRAFTimestamp);
            };
            requestAnimationFrame(setLatestRAFTimestamp);
          };
          _proto8.flushPendingCanvasMutations = function flushPendingCanvasMutations() {
            var _this18 = this;
            this.pendingCanvasMutations.forEach(function (values, canvas) {
              var id = _this18.mirror.getId(canvas);
              _this18.flushPendingCanvasMutationFor(canvas, id);
            });
            requestAnimationFrame(function () {
              return _this18.flushPendingCanvasMutations();
            });
          };
          _proto8.flushPendingCanvasMutationFor = function flushPendingCanvasMutationFor(canvas, id) {
            if (this.frozen || this.locked) {
              return;
            }
            var valuesWithType = this.pendingCanvasMutations.get(canvas);
            if (!valuesWithType || id === -1) return;
            var values = valuesWithType.map(function (value) {
              var rest = __rest(value, ["type"]);
              return rest;
            });
            var type = valuesWithType[0].type;
            this.mutationCb({
              id: id,
              type: type,
              commands: values
            });
            this.pendingCanvasMutations["delete"](canvas);
          };
          return CanvasManager;
        }();
        var StylesheetManager = /*#__PURE__*/function () {
          function StylesheetManager(options) {
            this.trackedLinkElements = new WeakSet();
            this.styleMirror = new StyleSheetMirror();
            this.mutationCb = options.mutationCb;
            this.adoptedStyleSheetCb = options.adoptedStyleSheetCb;
          }
          var _proto9 = StylesheetManager.prototype;
          _proto9.attachLinkElement = function attachLinkElement(linkEl, childSn) {
            if ('_cssText' in childSn.attributes) this.mutationCb({
              adds: [],
              removes: [],
              texts: [],
              attributes: [{
                id: childSn.id,
                attributes: childSn.attributes
              }]
            });
            this.trackLinkElement(linkEl);
          };
          _proto9.trackLinkElement = function trackLinkElement(linkEl) {
            if (this.trackedLinkElements.has(linkEl)) return;
            this.trackedLinkElements.add(linkEl);
            this.trackStylesheetInLinkElement(linkEl);
          };
          _proto9.adoptStyleSheets = function adoptStyleSheets(sheets, hostId) {
            if (sheets.length === 0) return;
            var adoptedStyleSheetData = {
              id: hostId,
              styleIds: []
            };
            var styles = [];
            for (var _iterator8 = _createForOfIteratorHelperLoose(sheets), _step8; !(_step8 = _iterator8()).done;) {
              var sheet = _step8.value;
              var styleId = void 0;
              if (!this.styleMirror.has(sheet)) {
                styleId = this.styleMirror.add(sheet);
                styles.push({
                  styleId: styleId,
                  rules: Array.from(sheet.rules || CSSRule, function (r, index) {
                    return {
                      rule: stringifyRule(r),
                      index: index
                    };
                  })
                });
              } else styleId = this.styleMirror.getId(sheet);
              adoptedStyleSheetData.styleIds.push(styleId);
            }
            if (styles.length > 0) adoptedStyleSheetData.styles = styles;
            this.adoptedStyleSheetCb(adoptedStyleSheetData);
          };
          _proto9.reset = function reset() {
            this.styleMirror.reset();
            this.trackedLinkElements = new WeakSet();
          };
          _proto9.trackStylesheetInLinkElement = function trackStylesheetInLinkElement(linkEl) {};
          return StylesheetManager;
        }();
        var ProcessedNodeManager = /*#__PURE__*/function () {
          function ProcessedNodeManager() {
            this.nodeMap = new WeakMap();
            this.loop = true;
            this.periodicallyClear();
          }
          var _proto10 = ProcessedNodeManager.prototype;
          _proto10.periodicallyClear = function periodicallyClear() {
            var _this19 = this;
            requestAnimationFrame(function () {
              _this19.clear();
              if (_this19.loop) _this19.periodicallyClear();
            });
          };
          _proto10.inOtherBuffer = function inOtherBuffer(node, thisBuffer) {
            var buffers = this.nodeMap.get(node);
            return buffers && Array.from(buffers).some(function (buffer) {
              return buffer !== thisBuffer;
            });
          };
          _proto10.add = function add(node, buffer) {
            this.nodeMap.set(node, (this.nodeMap.get(node) || new Set()).add(buffer));
          };
          _proto10.clear = function clear() {
            this.nodeMap = new WeakMap();
          };
          _proto10.destroy = function destroy() {
            this.loop = false;
          };
          return ProcessedNodeManager;
        }();
        function wrapEvent(e) {
          return Object.assign(Object.assign({}, e), {
            timestamp: nowTimestamp()
          });
        }
        var wrappedEmit;
        var takeFullSnapshot;
        var canvasManager;
        var recording = false;
        var mirror = createMirror();
        function record(options) {
          if (options === void 0) {
            options = {};
          }
          var _options = options,
            emit = _options.emit,
            checkoutEveryNms = _options.checkoutEveryNms,
            checkoutEveryNth = _options.checkoutEveryNth,
            _options$blockClass = _options.blockClass,
            blockClass = _options$blockClass === void 0 ? 'rr-block' : _options$blockClass,
            _options$blockSelecto = _options.blockSelector,
            blockSelector = _options$blockSelecto === void 0 ? null : _options$blockSelecto,
            _options$ignoreClass = _options.ignoreClass,
            ignoreClass = _options$ignoreClass === void 0 ? 'rr-ignore' : _options$ignoreClass,
            _options$ignoreSelect = _options.ignoreSelector,
            ignoreSelector = _options$ignoreSelect === void 0 ? null : _options$ignoreSelect,
            _options$maskTextClas = _options.maskTextClass,
            maskTextClass = _options$maskTextClas === void 0 ? 'rr-mask' : _options$maskTextClas,
            _options$maskTextSele = _options.maskTextSelector,
            maskTextSelector = _options$maskTextSele === void 0 ? null : _options$maskTextSele,
            _options$inlineStyles2 = _options.inlineStylesheet,
            inlineStylesheet = _options$inlineStyles2 === void 0 ? true : _options$inlineStyles2,
            maskAllInputs = _options.maskAllInputs,
            _maskInputOptions = _options.maskInputOptions,
            _slimDOMOptions = _options.slimDOMOptions,
            maskInputFn = _options.maskInputFn,
            maskTextFn = _options.maskTextFn,
            hooks = _options.hooks,
            packFn = _options.packFn,
            _options$sampling2 = _options.sampling,
            sampling = _options$sampling2 === void 0 ? {} : _options$sampling2,
            _options$dataURLOptio4 = _options.dataURLOptions,
            dataURLOptions = _options$dataURLOptio4 === void 0 ? {} : _options$dataURLOptio4,
            mousemoveWait = _options.mousemoveWait,
            _options$recordDOM = _options.recordDOM,
            recordDOM = _options$recordDOM === void 0 ? true : _options$recordDOM,
            _options$recordCanvas2 = _options.recordCanvas,
            recordCanvas = _options$recordCanvas2 === void 0 ? false : _options$recordCanvas2,
            _options$recordCrossO = _options.recordCrossOriginIframes,
            recordCrossOriginIframes = _options$recordCrossO === void 0 ? false : _options$recordCrossO,
            _options$recordAfter = _options.recordAfter,
            recordAfter = _options$recordAfter === void 0 ? options.recordAfter === 'DOMContentLoaded' ? options.recordAfter : 'load' : _options$recordAfter,
            _options$userTriggere = _options.userTriggeredOnInput,
            userTriggeredOnInput = _options$userTriggere === void 0 ? false : _options$userTriggere,
            _options$collectFonts = _options.collectFonts,
            collectFonts = _options$collectFonts === void 0 ? false : _options$collectFonts,
            _options$inlineImages2 = _options.inlineImages,
            inlineImages = _options$inlineImages2 === void 0 ? false : _options$inlineImages2,
            plugins = _options.plugins,
            _options$keepIframeSr2 = _options.keepIframeSrcFn,
            keepIframeSrcFn = _options$keepIframeSr2 === void 0 ? function () {
              return false;
            } : _options$keepIframeSr2,
            _options$ignoreCSSAtt = _options.ignoreCSSAttributes,
            ignoreCSSAttributes = _options$ignoreCSSAtt === void 0 ? new Set([]) : _options$ignoreCSSAtt,
            errorHandler = _options.errorHandler;
          registerErrorHandler(errorHandler);
          var inEmittingFrame = recordCrossOriginIframes ? window.parent === window : true;
          var passEmitsToParent = false;
          if (!inEmittingFrame) {
            try {
              if (window.parent.document) {
                passEmitsToParent = false;
              }
            } catch (e) {
              passEmitsToParent = true;
            }
          }
          if (inEmittingFrame && !emit) {
            throw new Error('emit function is required');
          }
          if (mousemoveWait !== undefined && sampling.mousemove === undefined) {
            sampling.mousemove = mousemoveWait;
          }
          mirror.reset();
          var maskInputOptions = maskAllInputs === true ? {
            color: true,
            date: true,
            'datetime-local': true,
            email: true,
            month: true,
            number: true,
            range: true,
            search: true,
            tel: true,
            text: true,
            time: true,
            url: true,
            week: true,
            textarea: true,
            select: true,
            password: true
          } : _maskInputOptions !== undefined ? _maskInputOptions : {
            password: true
          };
          var slimDOMOptions = _slimDOMOptions === true || _slimDOMOptions === 'all' ? {
            script: true,
            comment: true,
            headFavicon: true,
            headWhitespace: true,
            headMetaSocial: true,
            headMetaRobots: true,
            headMetaHttpEquiv: true,
            headMetaVerification: true,
            headMetaAuthorship: _slimDOMOptions === 'all',
            headMetaDescKeywords: _slimDOMOptions === 'all'
          } : _slimDOMOptions ? _slimDOMOptions : {};
          polyfill();
          var lastFullSnapshotEvent;
          var incrementalSnapshotCount = 0;
          var eventProcessor = function eventProcessor(e) {
            for (var _iterator9 = _createForOfIteratorHelperLoose(plugins || []), _step9; !(_step9 = _iterator9()).done;) {
              var plugin = _step9.value;
              if (plugin.eventProcessor) {
                e = plugin.eventProcessor(e);
              }
            }
            if (packFn && !passEmitsToParent) {
              e = packFn(e);
            }
            return e;
          };
          wrappedEmit = function wrappedEmit(e, isCheckout) {
            var _a;
            if (((_a = mutationBuffers[0]) === null || _a === void 0 ? void 0 : _a.isFrozen()) && e.type !== EventType$1.FullSnapshot && !(e.type === EventType$1.IncrementalSnapshot && e.data.source === IncrementalSource$1.Mutation)) {
              mutationBuffers.forEach(function (buf) {
                return buf.unfreeze();
              });
            }
            if (inEmittingFrame) {
              emit === null || emit === void 0 ? void 0 : emit(eventProcessor(e), isCheckout);
            } else if (passEmitsToParent) {
              var message = {
                type: 'rrweb',
                event: eventProcessor(e),
                origin: window.location.origin,
                isCheckout: isCheckout
              };
              window.parent.postMessage(message, '*');
            }
            if (e.type === EventType$1.FullSnapshot) {
              lastFullSnapshotEvent = e;
              incrementalSnapshotCount = 0;
            } else if (e.type === EventType$1.IncrementalSnapshot) {
              if (e.data.source === IncrementalSource$1.Mutation && e.data.isAttachIframe) {
                return;
              }
              incrementalSnapshotCount++;
              var exceedCount = checkoutEveryNth && incrementalSnapshotCount >= checkoutEveryNth;
              var exceedTime = checkoutEveryNms && e.timestamp - lastFullSnapshotEvent.timestamp > checkoutEveryNms;
              if (exceedCount || exceedTime) {
                takeFullSnapshot(true);
              }
            }
          };
          var wrappedMutationEmit = function wrappedMutationEmit(m) {
            wrappedEmit(wrapEvent({
              type: EventType$1.IncrementalSnapshot,
              data: Object.assign({
                source: IncrementalSource$1.Mutation
              }, m)
            }));
          };
          var wrappedScrollEmit = function wrappedScrollEmit(p) {
            return wrappedEmit(wrapEvent({
              type: EventType$1.IncrementalSnapshot,
              data: Object.assign({
                source: IncrementalSource$1.Scroll
              }, p)
            }));
          };
          var wrappedCanvasMutationEmit = function wrappedCanvasMutationEmit(p) {
            return wrappedEmit(wrapEvent({
              type: EventType$1.IncrementalSnapshot,
              data: Object.assign({
                source: IncrementalSource$1.CanvasMutation
              }, p)
            }));
          };
          var wrappedAdoptedStyleSheetEmit = function wrappedAdoptedStyleSheetEmit(a) {
            return wrappedEmit(wrapEvent({
              type: EventType$1.IncrementalSnapshot,
              data: Object.assign({
                source: IncrementalSource$1.AdoptedStyleSheet
              }, a)
            }));
          };
          var stylesheetManager = new StylesheetManager({
            mutationCb: wrappedMutationEmit,
            adoptedStyleSheetCb: wrappedAdoptedStyleSheetEmit
          });
          var iframeManager = new IframeManager({
            mirror: mirror,
            mutationCb: wrappedMutationEmit,
            stylesheetManager: stylesheetManager,
            recordCrossOriginIframes: recordCrossOriginIframes,
            wrappedEmit: wrappedEmit
          });
          for (var _iterator10 = _createForOfIteratorHelperLoose(plugins || []), _step10; !(_step10 = _iterator10()).done;) {
            var plugin = _step10.value;
            if (plugin.getMirror) plugin.getMirror({
              nodeMirror: mirror,
              crossOriginIframeMirror: iframeManager.crossOriginIframeMirror,
              crossOriginIframeStyleMirror: iframeManager.crossOriginIframeStyleMirror
            });
          }
          var processedNodeManager = new ProcessedNodeManager();
          canvasManager = new CanvasManager({
            recordCanvas: recordCanvas,
            mutationCb: wrappedCanvasMutationEmit,
            win: window,
            blockClass: blockClass,
            blockSelector: blockSelector,
            mirror: mirror,
            sampling: sampling.canvas,
            dataURLOptions: dataURLOptions
          });
          var shadowDomManager = new ShadowDomManager({
            mutationCb: wrappedMutationEmit,
            scrollCb: wrappedScrollEmit,
            bypassOptions: {
              blockClass: blockClass,
              blockSelector: blockSelector,
              maskTextClass: maskTextClass,
              maskTextSelector: maskTextSelector,
              inlineStylesheet: inlineStylesheet,
              maskInputOptions: maskInputOptions,
              dataURLOptions: dataURLOptions,
              maskTextFn: maskTextFn,
              maskInputFn: maskInputFn,
              recordCanvas: recordCanvas,
              inlineImages: inlineImages,
              sampling: sampling,
              slimDOMOptions: slimDOMOptions,
              iframeManager: iframeManager,
              stylesheetManager: stylesheetManager,
              canvasManager: canvasManager,
              keepIframeSrcFn: keepIframeSrcFn,
              processedNodeManager: processedNodeManager
            },
            mirror: mirror
          });
          takeFullSnapshot = function takeFullSnapshot(isCheckout) {
            if (isCheckout === void 0) {
              isCheckout = false;
            }
            if (!recordDOM) {
              return;
            }
            wrappedEmit(wrapEvent({
              type: EventType$1.Meta,
              data: {
                href: window.location.href,
                width: getWindowWidth(),
                height: getWindowHeight()
              }
            }), isCheckout);
            stylesheetManager.reset();
            shadowDomManager.init();
            mutationBuffers.forEach(function (buf) {
              return buf.lock();
            });
            var node = snapshot(document, {
              mirror: mirror,
              blockClass: blockClass,
              blockSelector: blockSelector,
              maskTextClass: maskTextClass,
              maskTextSelector: maskTextSelector,
              inlineStylesheet: inlineStylesheet,
              maskAllInputs: maskInputOptions,
              maskTextFn: maskTextFn,
              slimDOM: slimDOMOptions,
              dataURLOptions: dataURLOptions,
              recordCanvas: recordCanvas,
              inlineImages: inlineImages,
              onSerialize: function onSerialize(n) {
                if (isSerializedIframe(n, mirror)) {
                  iframeManager.addIframe(n);
                }
                if (isSerializedStylesheet(n, mirror)) {
                  stylesheetManager.trackLinkElement(n);
                }
                if (hasShadowRoot(n)) {
                  shadowDomManager.addShadowRoot(n.shadowRoot, document);
                }
              },
              onIframeLoad: function onIframeLoad(iframe, childSn) {
                iframeManager.attachIframe(iframe, childSn);
                shadowDomManager.observeAttachShadow(iframe);
              },
              onStylesheetLoad: function onStylesheetLoad(linkEl, childSn) {
                stylesheetManager.attachLinkElement(linkEl, childSn);
              },
              keepIframeSrcFn: keepIframeSrcFn
            });
            if (!node) {
              return console.warn('Failed to snapshot the document');
            }
            wrappedEmit(wrapEvent({
              type: EventType$1.FullSnapshot,
              data: {
                node: node,
                initialOffset: getWindowScroll(window)
              }
            }), isCheckout);
            mutationBuffers.forEach(function (buf) {
              return buf.unlock();
            });
            if (document.adoptedStyleSheets && document.adoptedStyleSheets.length > 0) stylesheetManager.adoptStyleSheets(document.adoptedStyleSheets, mirror.getId(document));
          };
          try {
            var handlers = [];
            var observe = function observe(doc) {
              var _a;
              return callbackWrapper(initObservers)({
                mutationCb: wrappedMutationEmit,
                mousemoveCb: function mousemoveCb(positions, source) {
                  return wrappedEmit(wrapEvent({
                    type: EventType$1.IncrementalSnapshot,
                    data: {
                      source: source,
                      positions: positions
                    }
                  }));
                },
                mouseInteractionCb: function mouseInteractionCb(d) {
                  return wrappedEmit(wrapEvent({
                    type: EventType$1.IncrementalSnapshot,
                    data: Object.assign({
                      source: IncrementalSource$1.MouseInteraction
                    }, d)
                  }));
                },
                scrollCb: wrappedScrollEmit,
                viewportResizeCb: function viewportResizeCb(d) {
                  return wrappedEmit(wrapEvent({
                    type: EventType$1.IncrementalSnapshot,
                    data: Object.assign({
                      source: IncrementalSource$1.ViewportResize
                    }, d)
                  }));
                },
                inputCb: function inputCb(v) {
                  return wrappedEmit(wrapEvent({
                    type: EventType$1.IncrementalSnapshot,
                    data: Object.assign({
                      source: IncrementalSource$1.Input
                    }, v)
                  }));
                },
                mediaInteractionCb: function mediaInteractionCb(p) {
                  return wrappedEmit(wrapEvent({
                    type: EventType$1.IncrementalSnapshot,
                    data: Object.assign({
                      source: IncrementalSource$1.MediaInteraction
                    }, p)
                  }));
                },
                styleSheetRuleCb: function styleSheetRuleCb(r) {
                  return wrappedEmit(wrapEvent({
                    type: EventType$1.IncrementalSnapshot,
                    data: Object.assign({
                      source: IncrementalSource$1.StyleSheetRule
                    }, r)
                  }));
                },
                styleDeclarationCb: function styleDeclarationCb(r) {
                  return wrappedEmit(wrapEvent({
                    type: EventType$1.IncrementalSnapshot,
                    data: Object.assign({
                      source: IncrementalSource$1.StyleDeclaration
                    }, r)
                  }));
                },
                canvasMutationCb: wrappedCanvasMutationEmit,
                fontCb: function fontCb(p) {
                  return wrappedEmit(wrapEvent({
                    type: EventType$1.IncrementalSnapshot,
                    data: Object.assign({
                      source: IncrementalSource$1.Font
                    }, p)
                  }));
                },
                selectionCb: function selectionCb(p) {
                  wrappedEmit(wrapEvent({
                    type: EventType$1.IncrementalSnapshot,
                    data: Object.assign({
                      source: IncrementalSource$1.Selection
                    }, p)
                  }));
                },
                customElementCb: function customElementCb(c) {
                  wrappedEmit(wrapEvent({
                    type: EventType$1.IncrementalSnapshot,
                    data: Object.assign({
                      source: IncrementalSource$1.CustomElement
                    }, c)
                  }));
                },
                blockClass: blockClass,
                ignoreClass: ignoreClass,
                ignoreSelector: ignoreSelector,
                maskTextClass: maskTextClass,
                maskTextSelector: maskTextSelector,
                maskInputOptions: maskInputOptions,
                inlineStylesheet: inlineStylesheet,
                sampling: sampling,
                recordDOM: recordDOM,
                recordCanvas: recordCanvas,
                inlineImages: inlineImages,
                userTriggeredOnInput: userTriggeredOnInput,
                collectFonts: collectFonts,
                doc: doc,
                maskInputFn: maskInputFn,
                maskTextFn: maskTextFn,
                keepIframeSrcFn: keepIframeSrcFn,
                blockSelector: blockSelector,
                slimDOMOptions: slimDOMOptions,
                dataURLOptions: dataURLOptions,
                mirror: mirror,
                iframeManager: iframeManager,
                stylesheetManager: stylesheetManager,
                shadowDomManager: shadowDomManager,
                processedNodeManager: processedNodeManager,
                canvasManager: canvasManager,
                ignoreCSSAttributes: ignoreCSSAttributes,
                plugins: ((_a = plugins === null || plugins === void 0 ? void 0 : plugins.filter(function (p) {
                  return p.observer;
                })) === null || _a === void 0 ? void 0 : _a.map(function (p) {
                  return {
                    observer: p.observer,
                    options: p.options,
                    callback: function callback(payload) {
                      return wrappedEmit(wrapEvent({
                        type: EventType$1.Plugin,
                        data: {
                          plugin: p.name,
                          payload: payload
                        }
                      }));
                    }
                  };
                })) || []
              }, hooks);
            };
            iframeManager.addLoadListener(function (iframeEl) {
              try {
                handlers.push(observe(iframeEl.contentDocument));
              } catch (error) {
                console.warn(error);
              }
            });
            var init = function init() {
              takeFullSnapshot();
              handlers.push(observe(document));
              recording = true;
            };
            if (document.readyState === 'interactive' || document.readyState === 'complete') {
              init();
            } else {
              handlers.push(on('DOMContentLoaded', function () {
                wrappedEmit(wrapEvent({
                  type: EventType$1.DomContentLoaded,
                  data: {}
                }));
                if (recordAfter === 'DOMContentLoaded') init();
              }));
              handlers.push(on('load', function () {
                wrappedEmit(wrapEvent({
                  type: EventType$1.Load,
                  data: {}
                }));
                if (recordAfter === 'load') init();
              }, window));
            }
            return function () {
              handlers.forEach(function (h) {
                return h();
              });
              processedNodeManager.destroy();
              recording = false;
              unregisterErrorHandler();
            };
          } catch (error) {
            console.warn(error);
          }
        }
        record.addCustomEvent = function (tag, payload) {
          if (!recording) {
            throw new Error('please add custom event after start recording');
          }
          wrappedEmit(wrapEvent({
            type: EventType$1.Custom,
            data: {
              tag: tag,
              payload: payload
            }
          }));
        };
        record.freezePage = function () {
          mutationBuffers.forEach(function (buf) {
            return buf.freeze();
          });
        };
        record.takeFullSnapshot = function (isCheckout) {
          if (!recording) {
            throw new Error('please take full snapshot after start recording');
          }
          takeFullSnapshot(isCheckout);
        };
        record.mirror = mirror;
        var EventType = /* @__PURE__ */function (EventType2) {
          EventType2[EventType2["DomContentLoaded"] = 0] = "DomContentLoaded";
          EventType2[EventType2["Load"] = 1] = "Load";
          EventType2[EventType2["FullSnapshot"] = 2] = "FullSnapshot";
          EventType2[EventType2["IncrementalSnapshot"] = 3] = "IncrementalSnapshot";
          EventType2[EventType2["Meta"] = 4] = "Meta";
          EventType2[EventType2["Custom"] = 5] = "Custom";
          EventType2[EventType2["Plugin"] = 6] = "Plugin";
          return EventType2;
        }(EventType || {});
        var IncrementalSource = /* @__PURE__ */function (IncrementalSource2) {
          IncrementalSource2[IncrementalSource2["Mutation"] = 0] = "Mutation";
          IncrementalSource2[IncrementalSource2["MouseMove"] = 1] = "MouseMove";
          IncrementalSource2[IncrementalSource2["MouseInteraction"] = 2] = "MouseInteraction";
          IncrementalSource2[IncrementalSource2["Scroll"] = 3] = "Scroll";
          IncrementalSource2[IncrementalSource2["ViewportResize"] = 4] = "ViewportResize";
          IncrementalSource2[IncrementalSource2["Input"] = 5] = "Input";
          IncrementalSource2[IncrementalSource2["TouchMove"] = 6] = "TouchMove";
          IncrementalSource2[IncrementalSource2["MediaInteraction"] = 7] = "MediaInteraction";
          IncrementalSource2[IncrementalSource2["StyleSheetRule"] = 8] = "StyleSheetRule";
          IncrementalSource2[IncrementalSource2["CanvasMutation"] = 9] = "CanvasMutation";
          IncrementalSource2[IncrementalSource2["Font"] = 10] = "Font";
          IncrementalSource2[IncrementalSource2["Log"] = 11] = "Log";
          IncrementalSource2[IncrementalSource2["Drag"] = 12] = "Drag";
          IncrementalSource2[IncrementalSource2["StyleDeclaration"] = 13] = "StyleDeclaration";
          IncrementalSource2[IncrementalSource2["Selection"] = 14] = "Selection";
          IncrementalSource2[IncrementalSource2["AdoptedStyleSheet"] = 15] = "AdoptedStyleSheet";
          IncrementalSource2[IncrementalSource2["CustomElement"] = 16] = "CustomElement";
          return IncrementalSource2;
        }(IncrementalSource || {});
        var Config = {
          DEBUG: false,
          LIB_VERSION: '2.55.0'
        };

        /* eslint camelcase: "off", eqeqeq: "off" */

        // since es6 imports are static and we run unit tests from the console, window won't be defined when importing this file
        var win;
        if (typeof window === 'undefined') {
          var loc = {
            hostname: ''
          };
          win = {
            navigator: {
              userAgent: ''
            },
            document: {
              location: loc,
              referrer: ''
            },
            screen: {
              width: 0,
              height: 0
            },
            location: loc
          };
        } else {
          win = window;
        }

        // Maximum allowed session recording length
        var MAX_RECORDING_MS = 24 * 60 * 60 * 1000; // 24 hours

        /*
         * Saved references to long variable names, so that closure compiler can
         * minimize file size.
         */

        var ArrayProto = Array.prototype,
          FuncProto = Function.prototype,
          ObjProto = Object.prototype,
          slice = ArrayProto.slice,
          toString = ObjProto.toString,
          hasOwnProperty = ObjProto.hasOwnProperty,
          windowConsole = win.console,
          navigator = win.navigator,
          document$1 = win.document,
          windowOpera = win.opera,
          screen = win.screen,
          userAgent = navigator.userAgent;
        var nativeBind = FuncProto.bind,
          nativeForEach = ArrayProto.forEach,
          nativeIndexOf = ArrayProto.indexOf,
          nativeMap = ArrayProto.map,
          nativeIsArray = Array.isArray,
          breaker = {};
        var _ = {
          trim: function trim(str) {
            // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/Trim#Polyfill
            return str.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, '');
          }
        };

        // Console override
        var console$1 = {
          /** @type {function(...*)} */
          log: function log() {
            if (Config.DEBUG && !_.isUndefined(windowConsole) && windowConsole) {
              try {
                windowConsole.log.apply(windowConsole, arguments);
              } catch (err) {
                _.each(arguments, function (arg) {
                  windowConsole.log(arg);
                });
              }
            }
          },
          /** @type {function(...*)} */
          warn: function warn() {
            if (Config.DEBUG && !_.isUndefined(windowConsole) && windowConsole) {
              var args = ['Mixpanel warning:'].concat(_.toArray(arguments));
              try {
                windowConsole.warn.apply(windowConsole, args);
              } catch (err) {
                _.each(args, function (arg) {
                  windowConsole.warn(arg);
                });
              }
            }
          },
          /** @type {function(...*)} */
          error: function error() {
            if (Config.DEBUG && !_.isUndefined(windowConsole) && windowConsole) {
              var args = ['Mixpanel error:'].concat(_.toArray(arguments));
              try {
                windowConsole.error.apply(windowConsole, args);
              } catch (err) {
                _.each(args, function (arg) {
                  windowConsole.error(arg);
                });
              }
            }
          },
          /** @type {function(...*)} */
          critical: function critical() {
            if (!_.isUndefined(windowConsole) && windowConsole) {
              var args = ['Mixpanel error:'].concat(_.toArray(arguments));
              try {
                windowConsole.error.apply(windowConsole, args);
              } catch (err) {
                _.each(args, function (arg) {
                  windowConsole.error(arg);
                });
              }
            }
          }
        };
        var log_func_with_prefix = function log_func_with_prefix(func, prefix) {
          return function () {
            arguments[0] = '[' + prefix + '] ' + arguments[0];
            return func.apply(console$1, arguments);
          };
        };
        var console_with_prefix = function console_with_prefix(prefix) {
          return {
            log: log_func_with_prefix(console$1.log, prefix),
            error: log_func_with_prefix(console$1.error, prefix),
            critical: log_func_with_prefix(console$1.critical, prefix)
          };
        };

        // UNDERSCORE
        // Embed part of the Underscore Library
        _.bind = function (func, context) {
          var args, _bound;
          if (nativeBind && func.bind === nativeBind) {
            return nativeBind.apply(func, slice.call(arguments, 1));
          }
          if (!_.isFunction(func)) {
            throw new TypeError();
          }
          args = slice.call(arguments, 2);
          _bound = function bound() {
            if (!(this instanceof _bound)) {
              return func.apply(context, args.concat(slice.call(arguments)));
            }
            var ctor = {};
            ctor.prototype = func.prototype;
            var self = new ctor();
            ctor.prototype = null;
            var result = func.apply(self, args.concat(slice.call(arguments)));
            if (Object(result) === result) {
              return result;
            }
            return self;
          };
          return _bound;
        };

        /**
         * @param {*=} obj
         * @param {function(...*)=} iterator
         * @param {Object=} context
         */
        _.each = function (obj, iterator, context) {
          if (obj === null || obj === undefined) {
            return;
          }
          if (nativeForEach && obj.forEach === nativeForEach) {
            obj.forEach(iterator, context);
          } else if (obj.length === +obj.length) {
            for (var i = 0, l = obj.length; i < l; i++) {
              if (i in obj && iterator.call(context, obj[i], i, obj) === breaker) {
                return;
              }
            }
          } else {
            for (var key in obj) {
              if (hasOwnProperty.call(obj, key)) {
                if (iterator.call(context, obj[key], key, obj) === breaker) {
                  return;
                }
              }
            }
          }
        };
        _.extend = function (obj) {
          _.each(slice.call(arguments, 1), function (source) {
            for (var prop in source) {
              if (source[prop] !== void 0) {
                obj[prop] = source[prop];
              }
            }
          });
          return obj;
        };
        _.isArray = nativeIsArray || function (obj) {
          return toString.call(obj) === '[object Array]';
        };

        // from a comment on http://dbj.org/dbj/?p=286
        // fails on only one very rare and deliberate custom object:
        // var bomb = { toString : undefined, valueOf: function(o) { return "function BOMBA!"; }};
        _.isFunction = function (f) {
          try {
            return /^\s*\bfunction\b/.test(f);
          } catch (x) {
            return false;
          }
        };
        _.isArguments = function (obj) {
          return !!(obj && hasOwnProperty.call(obj, 'callee'));
        };
        _.toArray = function (iterable) {
          if (!iterable) {
            return [];
          }
          if (iterable.toArray) {
            return iterable.toArray();
          }
          if (_.isArray(iterable)) {
            return slice.call(iterable);
          }
          if (_.isArguments(iterable)) {
            return slice.call(iterable);
          }
          return _.values(iterable);
        };
        _.map = function (arr, callback, context) {
          if (nativeMap && arr.map === nativeMap) {
            return arr.map(callback, context);
          } else {
            var results = [];
            _.each(arr, function (item) {
              results.push(callback.call(context, item));
            });
            return results;
          }
        };
        _.keys = function (obj) {
          var results = [];
          if (obj === null) {
            return results;
          }
          _.each(obj, function (value, key) {
            results[results.length] = key;
          });
          return results;
        };
        _.values = function (obj) {
          var results = [];
          if (obj === null) {
            return results;
          }
          _.each(obj, function (value) {
            results[results.length] = value;
          });
          return results;
        };
        _.include = function (obj, target) {
          var found = false;
          if (obj === null) {
            return found;
          }
          if (nativeIndexOf && obj.indexOf === nativeIndexOf) {
            return obj.indexOf(target) != -1;
          }
          _.each(obj, function (value) {
            if (found || (found = value === target)) {
              return breaker;
            }
          });
          return found;
        };
        _.includes = function (str, needle) {
          return str.indexOf(needle) !== -1;
        };

        // Underscore Addons
        _.inherit = function (subclass, superclass) {
          subclass.prototype = new superclass();
          subclass.prototype.constructor = subclass;
          subclass.superclass = superclass.prototype;
          return subclass;
        };
        _.isObject = function (obj) {
          return obj === Object(obj) && !_.isArray(obj);
        };
        _.isEmptyObject = function (obj) {
          if (_.isObject(obj)) {
            for (var key in obj) {
              if (hasOwnProperty.call(obj, key)) {
                return false;
              }
            }
            return true;
          }
          return false;
        };
        _.isUndefined = function (obj) {
          return obj === void 0;
        };
        _.isString = function (obj) {
          return toString.call(obj) == '[object String]';
        };
        _.isDate = function (obj) {
          return toString.call(obj) == '[object Date]';
        };
        _.isNumber = function (obj) {
          return toString.call(obj) == '[object Number]';
        };
        _.isElement = function (obj) {
          return !!(obj && obj.nodeType === 1);
        };
        _.encodeDates = function (obj) {
          _.each(obj, function (v, k) {
            if (_.isDate(v)) {
              obj[k] = _.formatDate(v);
            } else if (_.isObject(v)) {
              obj[k] = _.encodeDates(v); // recurse
            }
          });

          return obj;
        };
        _.timestamp = function () {
          Date.now = Date.now || function () {
            return +new Date();
          };
          return Date.now();
        };
        _.formatDate = function (d) {
          // YYYY-MM-DDTHH:MM:SS in UTC
          function pad(n) {
            return n < 10 ? '0' + n : n;
          }
          return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + 'T' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds());
        };
        _.strip_empty_properties = function (p) {
          var ret = {};
          _.each(p, function (v, k) {
            if (_.isString(v) && v.length > 0) {
              ret[k] = v;
            }
          });
          return ret;
        };

        /*
         * this function returns a copy of object after truncating it.  If
         * passed an Array or Object it will iterate through obj and
         * truncate all the values recursively.
         */
        _.truncate = function (obj, length) {
          var ret;
          if (typeof obj === 'string') {
            ret = obj.slice(0, length);
          } else if (_.isArray(obj)) {
            ret = [];
            _.each(obj, function (val) {
              ret.push(_.truncate(val, length));
            });
          } else if (_.isObject(obj)) {
            ret = {};
            _.each(obj, function (val, key) {
              ret[key] = _.truncate(val, length);
            });
          } else {
            ret = obj;
          }
          return ret;
        };
        _.JSONEncode = function () {
          return function (mixed_val) {
            var value = mixed_val;
            var quote = function quote(string) {
              var escapable = /[\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g; // eslint-disable-line no-control-regex
              var meta = {
                // table of character substitutions
                '\b': '\\b',
                '\t': '\\t',
                '\n': '\\n',
                '\f': '\\f',
                '\r': '\\r',
                '"': '\\"',
                '\\': '\\\\'
              };
              escapable.lastIndex = 0;
              return escapable.test(string) ? '"' + string.replace(escapable, function (a) {
                var c = meta[a];
                return typeof c === 'string' ? c : "\\u" + ('0000' + a.charCodeAt(0).toString(16)).slice(-4);
              }) + '"' : '"' + string + '"';
            };
            var str = function str(key, holder) {
              var gap = '';
              var indent = '    ';
              var i = 0; // The loop counter.
              var k = ''; // The member key.
              var v = ''; // The member value.
              var length = 0;
              var mind = gap;
              var partial = [];
              var value = holder[key];

              // If the value has a toJSON method, call it to obtain a replacement value.
              if (value && typeof value === 'object' && typeof value.toJSON === 'function') {
                value = value.toJSON(key);
              }

              // What happens next depends on the value's type.
              switch (typeof value) {
                case 'string':
                  return quote(value);
                case 'number':
                  // JSON numbers must be finite. Encode non-finite numbers as null.
                  return isFinite(value) ? String(value) : 'null';
                case 'boolean':
                case 'null':
                  // If the value is a boolean or null, convert it to a string. Note:
                  // typeof null does not produce 'null'. The case is included here in
                  // the remote chance that this gets fixed someday.

                  return String(value);
                case 'object':
                  // If the type is 'object', we might be dealing with an object or an array or
                  // null.
                  // Due to a specification blunder in ECMAScript, typeof null is 'object',
                  // so watch out for that case.
                  if (!value) {
                    return 'null';
                  }

                  // Make an array to hold the partial results of stringifying this object value.
                  gap += indent;
                  partial = [];

                  // Is the value an array?
                  if (toString.apply(value) === '[object Array]') {
                    // The value is an array. Stringify every element. Use null as a placeholder
                    // for non-JSON values.

                    length = value.length;
                    for (i = 0; i < length; i += 1) {
                      partial[i] = str(i, value) || 'null';
                    }

                    // Join all of the elements together, separated with commas, and wrap them in
                    // brackets.
                    v = partial.length === 0 ? '[]' : gap ? '[\n' + gap + partial.join(',\n' + gap) + '\n' + mind + ']' : '[' + partial.join(',') + ']';
                    gap = mind;
                    return v;
                  }

                  // Iterate through all of the keys in the object.
                  for (k in value) {
                    if (hasOwnProperty.call(value, k)) {
                      v = str(k, value);
                      if (v) {
                        partial.push(quote(k) + (gap ? ': ' : ':') + v);
                      }
                    }
                  }

                  // Join all of the member texts together, separated with commas,
                  // and wrap them in braces.
                  v = partial.length === 0 ? '{}' : gap ? '{' + partial.join(',') + '' + mind + '}' : '{' + partial.join(',') + '}';
                  gap = mind;
                  return v;
              }
            };

            // Make a fake root object containing our value under the key of ''.
            // Return the result of stringifying the value.
            return str('', {
              '': value
            });
          };
        }();

        /**
         * From https://github.com/douglascrockford/JSON-js/blob/master/json_parse.js
         * Slightly modified to throw a real Error rather than a POJO
         */
        _.JSONDecode = function () {
          var at,
            // The index of the current character
            ch,
            // The current character
            escapee = {
              '"': '"',
              '\\': '\\',
              '/': '/',
              'b': '\b',
              'f': '\f',
              'n': '\n',
              'r': '\r',
              't': '\t'
            },
            text,
            error = function error(m) {
              var e = new SyntaxError(m);
              e.at = at;
              e.text = text;
              throw e;
            },
            next = function next(c) {
              // If a c parameter is provided, verify that it matches the current character.
              if (c && c !== ch) {
                error('Expected \'' + c + '\' instead of \'' + ch + '\'');
              }
              // Get the next character. When there are no more characters,
              // return the empty string.
              ch = text.charAt(at);
              at += 1;
              return ch;
            },
            number = function number() {
              // Parse a number value.
              var number,
                string = '';
              if (ch === '-') {
                string = '-';
                next('-');
              }
              while (ch >= '0' && ch <= '9') {
                string += ch;
                next();
              }
              if (ch === '.') {
                string += '.';
                while (next() && ch >= '0' && ch <= '9') {
                  string += ch;
                }
              }
              if (ch === 'e' || ch === 'E') {
                string += ch;
                next();
                if (ch === '-' || ch === '+') {
                  string += ch;
                  next();
                }
                while (ch >= '0' && ch <= '9') {
                  string += ch;
                  next();
                }
              }
              number = +string;
              if (!isFinite(number)) {
                error('Bad number');
              } else {
                return number;
              }
            },
            string = function string() {
              // Parse a string value.
              var hex,
                i,
                string = '',
                uffff;
              // When parsing for string values, we must look for " and \ characters.
              if (ch === '"') {
                while (next()) {
                  if (ch === '"') {
                    next();
                    return string;
                  }
                  if (ch === '\\') {
                    next();
                    if (ch === 'u') {
                      uffff = 0;
                      for (i = 0; i < 4; i += 1) {
                        hex = parseInt(next(), 16);
                        if (!isFinite(hex)) {
                          break;
                        }
                        uffff = uffff * 16 + hex;
                      }
                      string += String.fromCharCode(uffff);
                    } else if (typeof escapee[ch] === 'string') {
                      string += escapee[ch];
                    } else {
                      break;
                    }
                  } else {
                    string += ch;
                  }
                }
              }
              error('Bad string');
            },
            white = function white() {
              // Skip whitespace.
              while (ch && ch <= ' ') {
                next();
              }
            },
            word = function word() {
              // true, false, or null.
              switch (ch) {
                case 't':
                  next('t');
                  next('r');
                  next('u');
                  next('e');
                  return true;
                case 'f':
                  next('f');
                  next('a');
                  next('l');
                  next('s');
                  next('e');
                  return false;
                case 'n':
                  next('n');
                  next('u');
                  next('l');
                  next('l');
                  return null;
              }
              error('Unexpected "' + ch + '"');
            },
            value,
            // Placeholder for the value function.
            array = function array() {
              // Parse an array value.
              var array = [];
              if (ch === '[') {
                next('[');
                white();
                if (ch === ']') {
                  next(']');
                  return array; // empty array
                }

                while (ch) {
                  array.push(value());
                  white();
                  if (ch === ']') {
                    next(']');
                    return array;
                  }
                  next(',');
                  white();
                }
              }
              error('Bad array');
            },
            object = function object() {
              // Parse an object value.
              var key,
                object = {};
              if (ch === '{') {
                next('{');
                white();
                if (ch === '}') {
                  next('}');
                  return object; // empty object
                }

                while (ch) {
                  key = string();
                  white();
                  next(':');
                  if (Object.hasOwnProperty.call(object, key)) {
                    error('Duplicate key "' + key + '"');
                  }
                  object[key] = value();
                  white();
                  if (ch === '}') {
                    next('}');
                    return object;
                  }
                  next(',');
                  white();
                }
              }
              error('Bad object');
            };
          value = function value() {
            // Parse a JSON value. It could be an object, an array, a string,
            // a number, or a word.
            white();
            switch (ch) {
              case '{':
                return object();
              case '[':
                return array();
              case '"':
                return string();
              case '-':
                return number();
              default:
                return ch >= '0' && ch <= '9' ? number() : word();
            }
          };

          // Return the json_parse function. It will have access to all of the
          // above functions and variables.
          return function (source) {
            var result;
            text = source;
            at = 0;
            ch = ' ';
            result = value();
            white();
            if (ch) {
              error('Syntax error');
            }
            return result;
          };
        }();
        _.base64Encode = function (data) {
          var b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
          var o1,
            o2,
            o3,
            h1,
            h2,
            h3,
            h4,
            bits,
            i = 0,
            ac = 0,
            enc = '',
            tmp_arr = [];
          if (!data) {
            return data;
          }
          data = _.utf8Encode(data);
          do {
            // pack three octets into four hexets
            o1 = data.charCodeAt(i++);
            o2 = data.charCodeAt(i++);
            o3 = data.charCodeAt(i++);
            bits = o1 << 16 | o2 << 8 | o3;
            h1 = bits >> 18 & 0x3f;
            h2 = bits >> 12 & 0x3f;
            h3 = bits >> 6 & 0x3f;
            h4 = bits & 0x3f;

            // use hexets to index into b64, and append result to encoded string
            tmp_arr[ac++] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4);
          } while (i < data.length);
          enc = tmp_arr.join('');
          switch (data.length % 3) {
            case 1:
              enc = enc.slice(0, -2) + '==';
              break;
            case 2:
              enc = enc.slice(0, -1) + '=';
              break;
          }
          return enc;
        };
        _.utf8Encode = function (string) {
          string = (string + '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
          var utftext = '',
            start,
            end;
          var stringl = 0,
            n;
          start = end = 0;
          stringl = string.length;
          for (n = 0; n < stringl; n++) {
            var c1 = string.charCodeAt(n);
            var enc = null;
            if (c1 < 128) {
              end++;
            } else if (c1 > 127 && c1 < 2048) {
              enc = String.fromCharCode(c1 >> 6 | 192, c1 & 63 | 128);
            } else {
              enc = String.fromCharCode(c1 >> 12 | 224, c1 >> 6 & 63 | 128, c1 & 63 | 128);
            }
            if (enc !== null) {
              if (end > start) {
                utftext += string.substring(start, end);
              }
              utftext += enc;
              start = end = n + 1;
            }
          }
          if (end > start) {
            utftext += string.substring(start, string.length);
          }
          return utftext;
        };
        _.UUID = function () {
          // Time-based entropy
          var T = function T() {
            var time = 1 * new Date(); // cross-browser version of Date.now()
            var ticks;
            if (win.performance && win.performance.now) {
              ticks = win.performance.now();
            } else {
              // fall back to busy loop
              ticks = 0;

              // this while loop figures how many browser ticks go by
              // before 1*new Date() returns a new number, ie the amount
              // of ticks that go by per millisecond
              while (time == 1 * new Date()) {
                ticks++;
              }
            }
            return time.toString(16) + Math.floor(ticks).toString(16);
          };

          // Math.Random entropy
          var R = function R() {
            return Math.random().toString(16).replace('.', '');
          };

          // User agent entropy
          // This function takes the user agent string, and then xors
          // together each sequence of 8 bytes.  This produces a final
          // sequence of 8 bytes which it returns as hex.
          var UA = function UA() {
            var ua = userAgent,
              i,
              ch,
              buffer = [],
              ret = 0;
            function xor(result, byte_array) {
              var j,
                tmp = 0;
              for (j = 0; j < byte_array.length; j++) {
                tmp |= buffer[j] << j * 8;
              }
              return result ^ tmp;
            }
            for (i = 0; i < ua.length; i++) {
              ch = ua.charCodeAt(i);
              buffer.unshift(ch & 0xFF);
              if (buffer.length >= 4) {
                ret = xor(ret, buffer);
                buffer = [];
              }
            }
            if (buffer.length > 0) {
              ret = xor(ret, buffer);
            }
            return ret.toString(16);
          };
          return function () {
            var se = (screen.height * screen.width).toString(16);
            return T() + '-' + R() + '-' + UA() + '-' + se + '-' + T();
          };
        }();

        // _.isBlockedUA()
        // This is to block various web spiders from executing our JS and
        // sending false tracking data
        var BLOCKED_UA_STRS = ['ahrefsbot', 'ahrefssiteaudit', 'baiduspider', 'bingbot', 'bingpreview', 'chrome-lighthouse', 'facebookexternal', 'petalbot', 'pinterest', 'screaming frog', 'yahoo! slurp', 'yandexbot',
        // a whole bunch of goog-specific crawlers
        // https://developers.google.com/search/docs/advanced/crawling/overview-google-crawlers
        'adsbot-google', 'apis-google', 'duplexweb-google', 'feedfetcher-google', 'google favicon', 'google web preview', 'google-read-aloud', 'googlebot', 'googleweblight', 'mediapartners-google', 'storebot-google'];
        _.isBlockedUA = function (ua) {
          var i;
          ua = ua.toLowerCase();
          for (i = 0; i < BLOCKED_UA_STRS.length; i++) {
            if (ua.indexOf(BLOCKED_UA_STRS[i]) !== -1) {
              return true;
            }
          }
          return false;
        };

        /**
         * @param {Object=} formdata
         * @param {string=} arg_separator
         */
        _.HTTPBuildQuery = function (formdata, arg_separator) {
          var use_val,
            use_key,
            tmp_arr = [];
          if (_.isUndefined(arg_separator)) {
            arg_separator = '&';
          }
          _.each(formdata, function (val, key) {
            use_val = encodeURIComponent(val.toString());
            use_key = encodeURIComponent(key);
            tmp_arr[tmp_arr.length] = use_key + '=' + use_val;
          });
          return tmp_arr.join(arg_separator);
        };
        _.getQueryParam = function (url, param) {
          // Expects a raw URL

          param = param.replace(/[[]/, '\\[').replace(/[\]]/, '\\]');
          var regexS = '[\\?&]' + param + '=([^&#]*)',
            regex = new RegExp(regexS),
            results = regex.exec(url);
          if (results === null || results && typeof results[1] !== 'string' && results[1].length) {
            return '';
          } else {
            var result = results[1];
            try {
              result = decodeURIComponent(result);
            } catch (err) {
              console$1.error('Skipping decoding for malformed query param: ' + result);
            }
            return result.replace(/\+/g, ' ');
          }
        };

        // _.cookie
        // Methods partially borrowed from quirksmode.org/js/cookies.html
        _.cookie = {
          get: function get(name) {
            var nameEQ = name + '=';
            var ca = document$1.cookie.split(';');
            for (var i = 0; i < ca.length; i++) {
              var c = ca[i];
              while (c.charAt(0) == ' ') {
                c = c.substring(1, c.length);
              }
              if (c.indexOf(nameEQ) === 0) {
                return decodeURIComponent(c.substring(nameEQ.length, c.length));
              }
            }
            return null;
          },
          parse: function parse(name) {
            var cookie;
            try {
              cookie = _.JSONDecode(_.cookie.get(name)) || {};
            } catch (err) {
              // noop
            }
            return cookie;
          },
          set_seconds: function set_seconds(name, value, seconds, is_cross_subdomain, is_secure, is_cross_site, domain_override) {
            var cdomain = '',
              expires = '',
              secure = '';
            if (domain_override) {
              cdomain = '; domain=' + domain_override;
            } else if (is_cross_subdomain) {
              var domain = extract_domain(document$1.location.hostname);
              cdomain = domain ? '; domain=.' + domain : '';
            }
            if (seconds) {
              var date = new Date();
              date.setTime(date.getTime() + seconds * 1000);
              expires = '; expires=' + date.toGMTString();
            }
            if (is_cross_site) {
              is_secure = true;
              secure = '; SameSite=None';
            }
            if (is_secure) {
              secure += '; secure';
            }
            document$1.cookie = name + '=' + encodeURIComponent(value) + expires + '; path=/' + cdomain + secure;
          },
          set: function set(name, value, days, is_cross_subdomain, is_secure, is_cross_site, domain_override) {
            var cdomain = '',
              expires = '',
              secure = '';
            if (domain_override) {
              cdomain = '; domain=' + domain_override;
            } else if (is_cross_subdomain) {
              var domain = extract_domain(document$1.location.hostname);
              cdomain = domain ? '; domain=.' + domain : '';
            }
            if (days) {
              var date = new Date();
              date.setTime(date.getTime() + days * 24 * 60 * 60 * 1000);
              expires = '; expires=' + date.toGMTString();
            }
            if (is_cross_site) {
              is_secure = true;
              secure = '; SameSite=None';
            }
            if (is_secure) {
              secure += '; secure';
            }
            var new_cookie_val = name + '=' + encodeURIComponent(value) + expires + '; path=/' + cdomain + secure;
            document$1.cookie = new_cookie_val;
            return new_cookie_val;
          },
          remove: function remove(name, is_cross_subdomain, domain_override) {
            _.cookie.set(name, '', -1, is_cross_subdomain, false, false, domain_override);
          }
        };
        var _localStorageSupported = null;
        var localStorageSupported = function localStorageSupported(storage, forceCheck) {
          if (_localStorageSupported !== null && !forceCheck) {
            return _localStorageSupported;
          }
          var supported = true;
          try {
            storage = storage || window.localStorage;
            var key = '__mplss_' + cheap_guid(8),
              val = 'xyz';
            storage.setItem(key, val);
            if (storage.getItem(key) !== val) {
              supported = false;
            }
            storage.removeItem(key);
          } catch (err) {
            supported = false;
          }
          _localStorageSupported = supported;
          return supported;
        };

        // _.localStorage
        _.localStorage = {
          is_supported: function is_supported(force_check) {
            var supported = localStorageSupported(null, force_check);
            if (!supported) {
              console$1.error('localStorage unsupported; falling back to cookie store');
            }
            return supported;
          },
          error: function error(msg) {
            console$1.error('localStorage error: ' + msg);
          },
          get: function get(name) {
            try {
              return window.localStorage.getItem(name);
            } catch (err) {
              _.localStorage.error(err);
            }
            return null;
          },
          parse: function parse(name) {
            try {
              return _.JSONDecode(_.localStorage.get(name)) || {};
            } catch (err) {
              // noop
            }
            return null;
          },
          set: function set(name, value) {
            try {
              window.localStorage.setItem(name, value);
            } catch (err) {
              _.localStorage.error(err);
            }
          },
          remove: function remove(name) {
            try {
              window.localStorage.removeItem(name);
            } catch (err) {
              _.localStorage.error(err);
            }
          }
        };
        _.register_event = function () {
          // written by Dean Edwards, 2005
          // with input from Tino Zijdel - crisp@xs4all.nl
          // with input from Carl Sverre - mail@carlsverre.com
          // with input from Mixpanel
          // http://dean.edwards.name/weblog/2005/10/add-event/
          // https://gist.github.com/1930440

          /**
           * @param {Object} element
           * @param {string} type
           * @param {function(...*)} handler
           * @param {boolean=} oldSchool
           * @param {boolean=} useCapture
           */
          var register_event = function register_event(element, type, handler, oldSchool, useCapture) {
            if (!element) {
              console$1.error('No valid element provided to register_event');
              return;
            }
            if (element.addEventListener && !oldSchool) {
              element.addEventListener(type, handler, !!useCapture);
            } else {
              var ontype = 'on' + type;
              var old_handler = element[ontype]; // can be undefined
              element[ontype] = makeHandler(element, handler, old_handler);
            }
          };
          function makeHandler(element, new_handler, old_handlers) {
            var handler = function handler(event) {
              event = event || fixEvent(window.event);

              // this basically happens in firefox whenever another script
              // overwrites the onload callback and doesn't pass the event
              // object to previously defined callbacks.  All the browsers
              // that don't define window.event implement addEventListener
              // so the dom_loaded handler will still be fired as usual.
              if (!event) {
                return undefined;
              }
              var ret = true;
              var old_result, new_result;
              if (_.isFunction(old_handlers)) {
                old_result = old_handlers(event);
              }
              new_result = new_handler.call(element, event);
              if (false === old_result || false === new_result) {
                ret = false;
              }
              return ret;
            };
            return handler;
          }
          function fixEvent(event) {
            if (event) {
              event.preventDefault = fixEvent.preventDefault;
              event.stopPropagation = fixEvent.stopPropagation;
            }
            return event;
          }
          fixEvent.preventDefault = function () {
            this.returnValue = false;
          };
          fixEvent.stopPropagation = function () {
            this.cancelBubble = true;
          };
          return register_event;
        }();
        var TOKEN_MATCH_REGEX = new RegExp('^(\\w*)\\[(\\w+)([=~\\|\\^\\$\\*]?)=?"?([^\\]"]*)"?\\]$');
        _.dom_query = function () {
          /* document.getElementsBySelector(selector)
          - returns an array of element objects from the current document
          matching the CSS selector. Selectors can contain element names,
          class names and ids and can be nested. For example:
           elements = document.getElementsBySelector('div#main p a.external')
           Will return an array of all 'a' elements with 'external' in their
          class attribute that are contained inside 'p' elements that are
          contained inside the 'div' element which has id="main"
           New in version 0.4: Support for CSS2 and CSS3 attribute selectors:
          See http://www.w3.org/TR/css3-selectors/#attribute-selectors
           Version 0.4 - Simon Willison, March 25th 2003
          -- Works in Phoenix 0.5, Mozilla 1.3, Opera 7, Internet Explorer 6, Internet Explorer 5 on Windows
          -- Opera 7 fails
           Version 0.5 - Carl Sverre, Jan 7th 2013
          -- Now uses jQuery-esque `hasClass` for testing class name
          equality.  This fixes a bug related to '-' characters being
          considered not part of a 'word' in regex.
          */

          function getAllChildren(e) {
            // Returns all children of element. Workaround required for IE5/Windows. Ugh.
            return e.all ? e.all : e.getElementsByTagName('*');
          }
          var bad_whitespace = /[\t\r\n]/g;
          function hasClass(elem, selector) {
            var className = ' ' + selector + ' ';
            return (' ' + elem.className + ' ').replace(bad_whitespace, ' ').indexOf(className) >= 0;
          }
          function getElementsBySelector(selector) {
            // Attempt to fail gracefully in lesser browsers
            if (!document$1.getElementsByTagName) {
              return [];
            }
            // Split selector in to tokens
            var tokens = selector.split(' ');
            var token, bits, tagName, found, foundCount, i, j, k, elements, currentContextIndex;
            var currentContext = [document$1];
            for (i = 0; i < tokens.length; i++) {
              token = tokens[i].replace(/^\s+/, '').replace(/\s+$/, '');
              if (token.indexOf('#') > -1) {
                // Token is an ID selector
                bits = token.split('#');
                tagName = bits[0];
                var id = bits[1];
                var element = document$1.getElementById(id);
                if (!element || tagName && element.nodeName.toLowerCase() != tagName) {
                  // element not found or tag with that ID not found, return false
                  return [];
                }
                // Set currentContext to contain just this element
                currentContext = [element];
                continue; // Skip to next token
              }

              if (token.indexOf('.') > -1) {
                // Token contains a class selector
                bits = token.split('.');
                tagName = bits[0];
                var className = bits[1];
                if (!tagName) {
                  tagName = '*';
                }
                // Get elements matching tag, filter them for class selector
                found = [];
                foundCount = 0;
                for (j = 0; j < currentContext.length; j++) {
                  if (tagName == '*') {
                    elements = getAllChildren(currentContext[j]);
                  } else {
                    elements = currentContext[j].getElementsByTagName(tagName);
                  }
                  for (k = 0; k < elements.length; k++) {
                    found[foundCount++] = elements[k];
                  }
                }
                currentContext = [];
                currentContextIndex = 0;
                for (j = 0; j < found.length; j++) {
                  if (found[j].className && _.isString(found[j].className) &&
                  // some SVG elements have classNames which are not strings
                  hasClass(found[j], className)) {
                    currentContext[currentContextIndex++] = found[j];
                  }
                }
                continue; // Skip to next token
              }
              // Code to deal with attribute selectors
              var token_match = token.match(TOKEN_MATCH_REGEX);
              if (token_match) {
                tagName = token_match[1];
                var attrName = token_match[2];
                var attrOperator = token_match[3];
                var attrValue = token_match[4];
                if (!tagName) {
                  tagName = '*';
                }
                // Grab all of the tagName elements within current context
                found = [];
                foundCount = 0;
                for (j = 0; j < currentContext.length; j++) {
                  if (tagName == '*') {
                    elements = getAllChildren(currentContext[j]);
                  } else {
                    elements = currentContext[j].getElementsByTagName(tagName);
                  }
                  for (k = 0; k < elements.length; k++) {
                    found[foundCount++] = elements[k];
                  }
                }
                currentContext = [];
                currentContextIndex = 0;
                var checkFunction; // This function will be used to filter the elements
                switch (attrOperator) {
                  case '=':
                    // Equality
                    checkFunction = function checkFunction(e) {
                      return e.getAttribute(attrName) == attrValue;
                    };
                    break;
                  case '~':
                    // Match one of space seperated words
                    checkFunction = function checkFunction(e) {
                      return e.getAttribute(attrName).match(new RegExp('\\b' + attrValue + '\\b'));
                    };
                    break;
                  case '|':
                    // Match start with value followed by optional hyphen
                    checkFunction = function checkFunction(e) {
                      return e.getAttribute(attrName).match(new RegExp('^' + attrValue + '-?'));
                    };
                    break;
                  case '^':
                    // Match starts with value
                    checkFunction = function checkFunction(e) {
                      return e.getAttribute(attrName).indexOf(attrValue) === 0;
                    };
                    break;
                  case '$':
                    // Match ends with value - fails with "Warning" in Opera 7
                    checkFunction = function checkFunction(e) {
                      return e.getAttribute(attrName).lastIndexOf(attrValue) == e.getAttribute(attrName).length - attrValue.length;
                    };
                    break;
                  case '*':
                    // Match ends with value
                    checkFunction = function checkFunction(e) {
                      return e.getAttribute(attrName).indexOf(attrValue) > -1;
                    };
                    break;
                  default:
                    // Just test for existence of attribute
                    checkFunction = function checkFunction(e) {
                      return e.getAttribute(attrName);
                    };
                }
                currentContext = [];
                currentContextIndex = 0;
                for (j = 0; j < found.length; j++) {
                  if (checkFunction(found[j])) {
                    currentContext[currentContextIndex++] = found[j];
                  }
                }
                // alert('Attribute Selector: '+tagName+' '+attrName+' '+attrOperator+' '+attrValue);
                continue; // Skip to next token
              }
              // If we get here, token is JUST an element (not a class or ID selector)
              tagName = token;
              found = [];
              foundCount = 0;
              for (j = 0; j < currentContext.length; j++) {
                elements = currentContext[j].getElementsByTagName(tagName);
                for (k = 0; k < elements.length; k++) {
                  found[foundCount++] = elements[k];
                }
              }
              currentContext = found;
            }
            return currentContext;
          }
          return function (query) {
            if (_.isElement(query)) {
              return [query];
            } else if (_.isObject(query) && !_.isUndefined(query.length)) {
              return query;
            } else {
              return getElementsBySelector.call(this, query);
            }
          };
        }();
        var CAMPAIGN_KEYWORDS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term'];
        var CLICK_IDS = ['dclid', 'fbclid', 'gclid', 'ko_click_id', 'li_fat_id', 'msclkid', 'ttclid', 'twclid', 'wbraid'];
        _.info = {
          campaignParams: function campaignParams(default_value) {
            var kw = '',
              params = {};
            _.each(CAMPAIGN_KEYWORDS, function (kwkey) {
              kw = _.getQueryParam(document$1.URL, kwkey);
              if (kw.length) {
                params[kwkey] = kw;
              } else if (default_value !== undefined) {
                params[kwkey] = default_value;
              }
            });
            return params;
          },
          clickParams: function clickParams() {
            var id = '',
              params = {};
            _.each(CLICK_IDS, function (idkey) {
              id = _.getQueryParam(document$1.URL, idkey);
              if (id.length) {
                params[idkey] = id;
              }
            });
            return params;
          },
          marketingParams: function marketingParams() {
            return _.extend(_.info.campaignParams(), _.info.clickParams());
          },
          searchEngine: function searchEngine(referrer) {
            if (referrer.search('https?://(.*)google.([^/?]*)') === 0) {
              return 'google';
            } else if (referrer.search('https?://(.*)bing.com') === 0) {
              return 'bing';
            } else if (referrer.search('https?://(.*)yahoo.com') === 0) {
              return 'yahoo';
            } else if (referrer.search('https?://(.*)duckduckgo.com') === 0) {
              return 'duckduckgo';
            } else {
              return null;
            }
          },
          searchInfo: function searchInfo(referrer) {
            var search = _.info.searchEngine(referrer),
              param = search != 'yahoo' ? 'q' : 'p',
              ret = {};
            if (search !== null) {
              ret['$search_engine'] = search;
              var keyword = _.getQueryParam(referrer, param);
              if (keyword.length) {
                ret['mp_keyword'] = keyword;
              }
            }
            return ret;
          },
          /**
           * This function detects which browser is running this script.
           * The order of the checks are important since many user agents
           * include key words used in later checks.
           */
          browser: function browser(user_agent, vendor, opera) {
            vendor = vendor || ''; // vendor is undefined for at least IE9
            if (opera || _.includes(user_agent, ' OPR/')) {
              if (_.includes(user_agent, 'Mini')) {
                return 'Opera Mini';
              }
              return 'Opera';
            } else if (/(BlackBerry|PlayBook|BB10)/i.test(user_agent)) {
              return 'BlackBerry';
            } else if (_.includes(user_agent, 'IEMobile') || _.includes(user_agent, 'WPDesktop')) {
              return 'Internet Explorer Mobile';
            } else if (_.includes(user_agent, 'SamsungBrowser/')) {
              // https://developer.samsung.com/internet/user-agent-string-format
              return 'Samsung Internet';
            } else if (_.includes(user_agent, 'Edge') || _.includes(user_agent, 'Edg/')) {
              return 'Microsoft Edge';
            } else if (_.includes(user_agent, 'FBIOS')) {
              return 'Facebook Mobile';
            } else if (_.includes(user_agent, 'Chrome')) {
              return 'Chrome';
            } else if (_.includes(user_agent, 'CriOS')) {
              return 'Chrome iOS';
            } else if (_.includes(user_agent, 'UCWEB') || _.includes(user_agent, 'UCBrowser')) {
              return 'UC Browser';
            } else if (_.includes(user_agent, 'FxiOS')) {
              return 'Firefox iOS';
            } else if (_.includes(vendor, 'Apple')) {
              if (_.includes(user_agent, 'Mobile')) {
                return 'Mobile Safari';
              }
              return 'Safari';
            } else if (_.includes(user_agent, 'Android')) {
              return 'Android Mobile';
            } else if (_.includes(user_agent, 'Konqueror')) {
              return 'Konqueror';
            } else if (_.includes(user_agent, 'Firefox')) {
              return 'Firefox';
            } else if (_.includes(user_agent, 'MSIE') || _.includes(user_agent, 'Trident/')) {
              return 'Internet Explorer';
            } else if (_.includes(user_agent, 'Gecko')) {
              return 'Mozilla';
            } else {
              return '';
            }
          },
          /**
           * This function detects which browser version is running this script,
           * parsing major and minor version (e.g., 42.1). User agent strings from:
           * http://www.useragentstring.com/pages/useragentstring.php
           */
          browserVersion: function browserVersion(userAgent, vendor, opera) {
            var browser = _.info.browser(userAgent, vendor, opera);
            var versionRegexs = {
              'Internet Explorer Mobile': /rv:(\d+(\.\d+)?)/,
              'Microsoft Edge': /Edge?\/(\d+(\.\d+)?)/,
              'Chrome': /Chrome\/(\d+(\.\d+)?)/,
              'Chrome iOS': /CriOS\/(\d+(\.\d+)?)/,
              'UC Browser': /(UCBrowser|UCWEB)\/(\d+(\.\d+)?)/,
              'Safari': /Version\/(\d+(\.\d+)?)/,
              'Mobile Safari': /Version\/(\d+(\.\d+)?)/,
              'Opera': /(Opera|OPR)\/(\d+(\.\d+)?)/,
              'Firefox': /Firefox\/(\d+(\.\d+)?)/,
              'Firefox iOS': /FxiOS\/(\d+(\.\d+)?)/,
              'Konqueror': /Konqueror:(\d+(\.\d+)?)/,
              'BlackBerry': /BlackBerry (\d+(\.\d+)?)/,
              'Android Mobile': /android\s(\d+(\.\d+)?)/,
              'Samsung Internet': /SamsungBrowser\/(\d+(\.\d+)?)/,
              'Internet Explorer': /(rv:|MSIE )(\d+(\.\d+)?)/,
              'Mozilla': /rv:(\d+(\.\d+)?)/
            };
            var regex = versionRegexs[browser];
            if (regex === undefined) {
              return null;
            }
            var matches = userAgent.match(regex);
            if (!matches) {
              return null;
            }
            return parseFloat(matches[matches.length - 2]);
          },
          os: function os() {
            var a = userAgent;
            if (/Windows/i.test(a)) {
              if (/Phone/.test(a) || /WPDesktop/.test(a)) {
                return 'Windows Phone';
              }
              return 'Windows';
            } else if (/(iPhone|iPad|iPod)/.test(a)) {
              return 'iOS';
            } else if (/Android/.test(a)) {
              return 'Android';
            } else if (/(BlackBerry|PlayBook|BB10)/i.test(a)) {
              return 'BlackBerry';
            } else if (/Mac/i.test(a)) {
              return 'Mac OS X';
            } else if (/Linux/.test(a)) {
              return 'Linux';
            } else if (/CrOS/.test(a)) {
              return 'Chrome OS';
            } else {
              return '';
            }
          },
          device: function device(user_agent) {
            if (/Windows Phone/i.test(user_agent) || /WPDesktop/.test(user_agent)) {
              return 'Windows Phone';
            } else if (/iPad/.test(user_agent)) {
              return 'iPad';
            } else if (/iPod/.test(user_agent)) {
              return 'iPod Touch';
            } else if (/iPhone/.test(user_agent)) {
              return 'iPhone';
            } else if (/(BlackBerry|PlayBook|BB10)/i.test(user_agent)) {
              return 'BlackBerry';
            } else if (/Android/.test(user_agent)) {
              return 'Android';
            } else {
              return '';
            }
          },
          referringDomain: function referringDomain(referrer) {
            var split = referrer.split('/');
            if (split.length >= 3) {
              return split[2];
            }
            return '';
          },
          currentUrl: function currentUrl() {
            return win.location.href;
          },
          properties: function properties(extra_props) {
            if (typeof extra_props !== 'object') {
              extra_props = {};
            }
            return _.extend(_.strip_empty_properties({
              '$os': _.info.os(),
              '$browser': _.info.browser(userAgent, navigator.vendor, windowOpera),
              '$referrer': document$1.referrer,
              '$referring_domain': _.info.referringDomain(document$1.referrer),
              '$device': _.info.device(userAgent)
            }), {
              '$current_url': _.info.currentUrl(),
              '$browser_version': _.info.browserVersion(userAgent, navigator.vendor, windowOpera),
              '$screen_height': screen.height,
              '$screen_width': screen.width,
              'mp_lib': 'web',
              '$lib_version': Config.LIB_VERSION,
              '$insert_id': cheap_guid(),
              'time': _.timestamp() / 1000 // epoch time in seconds
            }, _.strip_empty_properties(extra_props));
          },
          people_properties: function people_properties() {
            return _.extend(_.strip_empty_properties({
              '$os': _.info.os(),
              '$browser': _.info.browser(userAgent, navigator.vendor, windowOpera)
            }), {
              '$browser_version': _.info.browserVersion(userAgent, navigator.vendor, windowOpera)
            });
          },
          mpPageViewProperties: function mpPageViewProperties() {
            return _.strip_empty_properties({
              'current_page_title': document$1.title,
              'current_domain': win.location.hostname,
              'current_url_path': win.location.pathname,
              'current_url_protocol': win.location.protocol,
              'current_url_search': win.location.search
            });
          }
        };
        var cheap_guid = function cheap_guid(maxlen) {
          var guid = Math.random().toString(36).substring(2, 10) + Math.random().toString(36).substring(2, 10);
          return maxlen ? guid.substring(0, maxlen) : guid;
        };

        // naive way to extract domain name (example.com) from full hostname (my.sub.example.com)
        var SIMPLE_DOMAIN_MATCH_REGEX = /[a-z0-9][a-z0-9-]*\.[a-z]+$/i;
        // this next one attempts to account for some ccSLDs, e.g. extracting oxford.ac.uk from www.oxford.ac.uk
        var DOMAIN_MATCH_REGEX = /[a-z0-9][a-z0-9-]+\.[a-z.]{2,6}$/i;
        /**
         * Attempts to extract main domain name from full hostname, using a few blunt heuristics. For
         * common TLDs like .com/.org that always have a simple SLD.TLD structure (example.com), we
         * simply extract the last two .-separated parts of the hostname (SIMPLE_DOMAIN_MATCH_REGEX).
         * For others, we attempt to account for short ccSLD+TLD combos (.ac.uk) with the legacy
         * DOMAIN_MATCH_REGEX (kept to maintain backwards compatibility with existing Mixpanel
         * integrations). The only _reliable_ way to extract domain from hostname is with an up-to-date
         * list like at https://publicsuffix.org/ so for cases that this helper fails at, the SDK
         * offers the 'cookie_domain' config option to set it explicitly.
         * @example
         * extract_domain('my.sub.example.com')
         * // 'example.com'
         */
        var extract_domain = function extract_domain(hostname) {
          var domain_regex = DOMAIN_MATCH_REGEX;
          var parts = hostname.split('.');
          var tld = parts[parts.length - 1];
          if (tld.length > 4 || tld === 'com' || tld === 'org') {
            domain_regex = SIMPLE_DOMAIN_MATCH_REGEX;
          }
          var matches = hostname.match(domain_regex);
          return matches ? matches[0] : '';
        };
        var JSONStringify = null,
          JSONParse = null;
        if (typeof JSON !== 'undefined') {
          JSONStringify = JSON.stringify;
          JSONParse = JSON.parse;
        }
        JSONStringify = JSONStringify || _.JSONEncode;
        JSONParse = JSONParse || _.JSONDecode;

        // EXPORTS (for closure compiler)
        _['toArray'] = _.toArray;
        _['isObject'] = _.isObject;
        _['JSONEncode'] = _.JSONEncode;
        _['JSONDecode'] = _.JSONDecode;
        _['isBlockedUA'] = _.isBlockedUA;
        _['isEmptyObject'] = _.isEmptyObject;
        _['info'] = _.info;
        _['info']['device'] = _.info.device;
        _['info']['browser'] = _.info.browser;
        _['info']['browserVersion'] = _.info.browserVersion;
        _['info']['properties'] = _.info.properties;

        /**
         * GDPR utils
         *
         * The General Data Protection Regulation (GDPR) is a regulation in EU law on data protection
         * and privacy for all individuals within the European Union. It addresses the export of personal
         * data outside the EU. The GDPR aims primarily to give control back to citizens and residents
         * over their personal data and to simplify the regulatory environment for international business
         * by unifying the regulation within the EU.
         *
         * This set of utilities is intended to enable opt in/out functionality in the Mixpanel JS SDK.
         * These functions are used internally by the SDK and are not intended to be publicly exposed.
         */

        /**
         * A function used to track a Mixpanel event (e.g. MixpanelLib.track)
         * @callback trackFunction
         * @param {String} event_name The name of the event. This can be anything the user does - 'Button Click', 'Sign Up', 'Item Purchased', etc.
         * @param {Object} [properties] A set of properties to include with the event you're sending. These describe the user who did the event or details about the event itself.
         * @param {Function} [callback] If provided, the callback function will be called after tracking the event.
         */

        /** Public **/

        var GDPR_DEFAULT_PERSISTENCE_PREFIX = '__mp_opt_in_out_';

        /**
         * Opt the user in to data tracking and cookies/localstorage for the given token
         * @param {string} token - Mixpanel project tracking token
         * @param {Object} [options]
         * @param {trackFunction} [options.track] - function used for tracking a Mixpanel event to record the opt-in action
         * @param {string} [options.trackEventName] - event name to be used for tracking the opt-in action
         * @param {Object} [options.trackProperties] - set of properties to be tracked along with the opt-in action
         * @param {string} [options.persistenceType] Persistence mechanism used - cookie or localStorage
         * @param {string} [options.persistencePrefix=__mp_opt_in_out] - custom prefix to be used in the cookie/localstorage name
         * @param {Number} [options.cookieExpiration] - number of days until the opt-in cookie expires
         * @param {string} [options.cookieDomain] - custom cookie domain
         * @param {boolean} [options.crossSiteCookie] - whether the opt-in cookie is set as cross-site-enabled
         * @param {boolean} [options.crossSubdomainCookie] - whether the opt-in cookie is set as cross-subdomain or not
         * @param {boolean} [options.secureCookie] - whether the opt-in cookie is set as secure or not
         */
        function optIn(token, options) {
          _optInOut(true, token, options);
        }

        /**
         * Opt the user out of data tracking and cookies/localstorage for the given token
         * @param {string} token - Mixpanel project tracking token
         * @param {Object} [options]
         * @param {string} [options.persistenceType] Persistence mechanism used - cookie or localStorage
         * @param {string} [options.persistencePrefix=__mp_opt_in_out] - custom prefix to be used in the cookie/localstorage name
         * @param {Number} [options.cookieExpiration] - number of days until the opt-out cookie expires
         * @param {string} [options.cookieDomain] - custom cookie domain
         * @param {boolean} [options.crossSiteCookie] - whether the opt-in cookie is set as cross-site-enabled
         * @param {boolean} [options.crossSubdomainCookie] - whether the opt-out cookie is set as cross-subdomain or not
         * @param {boolean} [options.secureCookie] - whether the opt-out cookie is set as secure or not
         */
        function optOut(token, options) {
          _optInOut(false, token, options);
        }

        /**
         * Check whether the user has opted in to data tracking and cookies/localstorage for the given token
         * @param {string} token - Mixpanel project tracking token
         * @param {Object} [options]
         * @param {string} [options.persistenceType] Persistence mechanism used - cookie or localStorage
         * @param {string} [options.persistencePrefix=__mp_opt_in_out] - custom prefix to be used in the cookie/localstorage name
         * @returns {boolean} whether the user has opted in to the given opt type
         */
        function hasOptedIn(token, options) {
          return _getStorageValue(token, options) === '1';
        }

        /**
         * Check whether the user has opted out of data tracking and cookies/localstorage for the given token
         * @param {string} token - Mixpanel project tracking token
         * @param {Object} [options]
         * @param {string} [options.persistenceType] Persistence mechanism used - cookie or localStorage
         * @param {string} [options.persistencePrefix=__mp_opt_in_out] - custom prefix to be used in the cookie/localstorage name
         * @param {boolean} [options.ignoreDnt] - flag to ignore browser DNT settings and always return false
         * @returns {boolean} whether the user has opted out of the given opt type
         */
        function hasOptedOut(token, options) {
          if (_hasDoNotTrackFlagOn(options)) {
            console$1.warn('This browser has "Do Not Track" enabled. This will prevent the Mixpanel SDK from sending any data. To ignore the "Do Not Track" browser setting, initialize the Mixpanel instance with the config "ignore_dnt: true"');
            return true;
          }
          var optedOut = _getStorageValue(token, options) === '0';
          if (optedOut) {
            console$1.warn('You are opted out of Mixpanel tracking. This will prevent the Mixpanel SDK from sending any data.');
          }
          return optedOut;
        }

        /**
         * Wrap a MixpanelLib method with a check for whether the user is opted out of data tracking and cookies/localstorage for the given token
         * If the user has opted out, return early instead of executing the method.
         * If a callback argument was provided, execute it passing the 0 error code.
         * @param {function} method - wrapped method to be executed if the user has not opted out
         * @returns {*} the result of executing method OR undefined if the user has opted out
         */
        function addOptOutCheckMixpanelLib(method) {
          return _addOptOutCheck(method, function (name) {
            return this.get_config(name);
          });
        }

        /**
         * Wrap a MixpanelPeople method with a check for whether the user is opted out of data tracking and cookies/localstorage for the given token
         * If the user has opted out, return early instead of executing the method.
         * If a callback argument was provided, execute it passing the 0 error code.
         * @param {function} method - wrapped method to be executed if the user has not opted out
         * @returns {*} the result of executing method OR undefined if the user has opted out
         */
        function addOptOutCheckMixpanelPeople(method) {
          return _addOptOutCheck(method, function (name) {
            return this._get_config(name);
          });
        }

        /**
         * Wrap a MixpanelGroup method with a check for whether the user is opted out of data tracking and cookies/localstorage for the given token
         * If the user has opted out, return early instead of executing the method.
         * If a callback argument was provided, execute it passing the 0 error code.
         * @param {function} method - wrapped method to be executed if the user has not opted out
         * @returns {*} the result of executing method OR undefined if the user has opted out
         */
        function addOptOutCheckMixpanelGroup(method) {
          return _addOptOutCheck(method, function (name) {
            return this._get_config(name);
          });
        }

        /**
         * Clear the user's opt in/out status of data tracking and cookies/localstorage for the given token
         * @param {string} token - Mixpanel project tracking token
         * @param {Object} [options]
         * @param {string} [options.persistenceType] Persistence mechanism used - cookie or localStorage
         * @param {string} [options.persistencePrefix=__mp_opt_in_out] - custom prefix to be used in the cookie/localstorage name
         * @param {Number} [options.cookieExpiration] - number of days until the opt-in cookie expires
         * @param {string} [options.cookieDomain] - custom cookie domain
         * @param {boolean} [options.crossSiteCookie] - whether the opt-in cookie is set as cross-site-enabled
         * @param {boolean} [options.crossSubdomainCookie] - whether the opt-in cookie is set as cross-subdomain or not
         * @param {boolean} [options.secureCookie] - whether the opt-in cookie is set as secure or not
         */
        function clearOptInOut(token, options) {
          options = options || {};
          _getStorage(options).remove(_getStorageKey(token, options), !!options.crossSubdomainCookie, options.cookieDomain);
        }

        /** Private **/

        /**
         * Get storage util
         * @param {Object} [options]
         * @param {string} [options.persistenceType]
         * @returns {object} either _.cookie or _.localstorage
         */
        function _getStorage(options) {
          options = options || {};
          return options.persistenceType === 'localStorage' ? _.localStorage : _.cookie;
        }

        /**
         * Get the name of the cookie that is used for the given opt type (tracking, cookie, etc.)
         * @param {string} token - Mixpanel project tracking token
         * @param {Object} [options]
         * @param {string} [options.persistencePrefix=__mp_opt_in_out] - custom prefix to be used in the cookie/localstorage name
         * @returns {string} the name of the cookie for the given opt type
         */
        function _getStorageKey(token, options) {
          options = options || {};
          return (options.persistencePrefix || GDPR_DEFAULT_PERSISTENCE_PREFIX) + token;
        }

        /**
         * Get the value of the cookie that is used for the given opt type (tracking, cookie, etc.)
         * @param {string} token - Mixpanel project tracking token
         * @param {Object} [options]
         * @param {string} [options.persistencePrefix=__mp_opt_in_out] - custom prefix to be used in the cookie/localstorage name
         * @returns {string} the value of the cookie for the given opt type
         */
        function _getStorageValue(token, options) {
          return _getStorage(options).get(_getStorageKey(token, options));
        }

        /**
         * Check whether the user has set the DNT/doNotTrack setting to true in their browser
         * @param {Object} [options]
         * @param {string} [options.window] - alternate window object to check; used to force various DNT settings in browser tests
         * @param {boolean} [options.ignoreDnt] - flag to ignore browser DNT settings and always return false
         * @returns {boolean} whether the DNT setting is true
         */
        function _hasDoNotTrackFlagOn(options) {
          if (options && options.ignoreDnt) {
            return false;
          }
          var win$1 = options && options.window || win;
          var nav = win$1['navigator'] || {};
          var hasDntOn = false;
          _.each([nav['doNotTrack'],
          // standard
          nav['msDoNotTrack'], win$1['doNotTrack']], function (dntValue) {
            if (_.includes([true, 1, '1', 'yes'], dntValue)) {
              hasDntOn = true;
            }
          });
          return hasDntOn;
        }

        /**
         * Set cookie/localstorage for the user indicating that they are opted in or out for the given opt type
         * @param {boolean} optValue - whether to opt the user in or out for the given opt type
         * @param {string} token - Mixpanel project tracking token
         * @param {Object} [options]
         * @param {trackFunction} [options.track] - function used for tracking a Mixpanel event to record the opt-in action
         * @param {string} [options.trackEventName] - event name to be used for tracking the opt-in action
         * @param {Object} [options.trackProperties] - set of properties to be tracked along with the opt-in action
         * @param {string} [options.persistencePrefix=__mp_opt_in_out] - custom prefix to be used in the cookie/localstorage name
         * @param {Number} [options.cookieExpiration] - number of days until the opt-in cookie expires
         * @param {string} [options.cookieDomain] - custom cookie domain
         * @param {boolean} [options.crossSiteCookie] - whether the opt-in cookie is set as cross-site-enabled
         * @param {boolean} [options.crossSubdomainCookie] - whether the opt-in cookie is set as cross-subdomain or not
         * @param {boolean} [options.secureCookie] - whether the opt-in cookie is set as secure or not
         */
        function _optInOut(optValue, token, options) {
          if (!_.isString(token) || !token.length) {
            console$1.error('gdpr.' + (optValue ? 'optIn' : 'optOut') + ' called with an invalid token');
            return;
          }
          options = options || {};
          _getStorage(options).set(_getStorageKey(token, options), optValue ? 1 : 0, _.isNumber(options.cookieExpiration) ? options.cookieExpiration : null, !!options.crossSubdomainCookie, !!options.secureCookie, !!options.crossSiteCookie, options.cookieDomain);
          if (options.track && optValue) {
            // only track event if opting in (optValue=true)
            options.track(options.trackEventName || '$opt_in', options.trackProperties, {
              'send_immediately': true
            });
          }
        }

        /**
         * Wrap a method with a check for whether the user is opted out of data tracking and cookies/localstorage for the given token
         * If the user has opted out, return early instead of executing the method.
         * If a callback argument was provided, execute it passing the 0 error code.
         * @param {function} method - wrapped method to be executed if the user has not opted out
         * @param {function} getConfigValue - getter function for the Mixpanel API token and other options to be used with opt-out check
         * @returns {*} the result of executing method OR undefined if the user has opted out
         */
        function _addOptOutCheck(method, getConfigValue) {
          return function () {
            var optedOut = false;
            try {
              var token = getConfigValue.call(this, 'token');
              var ignoreDnt = getConfigValue.call(this, 'ignore_dnt');
              var persistenceType = getConfigValue.call(this, 'opt_out_tracking_persistence_type');
              var persistencePrefix = getConfigValue.call(this, 'opt_out_tracking_cookie_prefix');
              var win = getConfigValue.call(this, 'window'); // used to override window during browser tests

              if (token) {
                // if there was an issue getting the token, continue method execution as normal
                optedOut = hasOptedOut(token, {
                  ignoreDnt: ignoreDnt,
                  persistenceType: persistenceType,
                  persistencePrefix: persistencePrefix,
                  window: win
                });
              }
            } catch (err) {
              console$1.error('Unexpected error when checking tracking opt-out status: ' + err);
            }
            if (!optedOut) {
              return method.apply(this, arguments);
            }
            var callback = arguments[arguments.length - 1];
            if (typeof callback === 'function') {
              callback(0);
            }
            return;
          };
        }
        var logger$3 = console_with_prefix('lock');

        /**
         * SharedLock: a mutex built on HTML5 localStorage, to ensure that only one browser
         * window/tab at a time will be able to access shared resources.
         *
         * Based on the Alur and Taubenfeld fast lock
         * (http://www.cs.rochester.edu/research/synchronization/pseudocode/fastlock.html)
         * with an added timeout to ensure there will be eventual progress in the event
         * that a window is closed in the middle of the callback.
         *
         * Implementation based on the original version by David Wolever (https://github.com/wolever)
         * at https://gist.github.com/wolever/5fd7573d1ef6166e8f8c4af286a69432.
         *
         * @example
         * const myLock = new SharedLock('some-key');
         * myLock.withLock(function() {
         *   console.log('I hold the mutex!');
         * });
         *
         * @constructor
         */
        var SharedLock = function SharedLock(key, options) {
          options = options || {};
          this.storageKey = key;
          this.storage = options.storage || window.localStorage;
          this.pollIntervalMS = options.pollIntervalMS || 100;
          this.timeoutMS = options.timeoutMS || 2000;
        };

        // pass in a specific pid to test contention scenarios; otherwise
        // it is chosen randomly for each acquisition attempt
        SharedLock.prototype.withLock = function (lockedCB, errorCB, pid) {
          if (!pid && typeof errorCB !== 'function') {
            pid = errorCB;
            errorCB = null;
          }
          var i = pid || new Date().getTime() + '|' + Math.random();
          var startTime = new Date().getTime();
          var key = this.storageKey;
          var pollIntervalMS = this.pollIntervalMS;
          var timeoutMS = this.timeoutMS;
          var storage = this.storage;
          var keyX = key + ':X';
          var keyY = key + ':Y';
          var keyZ = key + ':Z';
          var reportError = function reportError(err) {
            errorCB && errorCB(err);
          };
          var delay = function delay(cb) {
            if (new Date().getTime() - startTime > timeoutMS) {
              logger$3.error('Timeout waiting for mutex on ' + key + '; clearing lock. [' + i + ']');
              storage.removeItem(keyZ);
              storage.removeItem(keyY);
              loop();
              return;
            }
            setTimeout(function () {
              try {
                cb();
              } catch (err) {
                reportError(err);
              }
            }, pollIntervalMS * (Math.random() + 0.1));
          };
          var waitFor = function waitFor(predicate, cb) {
            if (predicate()) {
              cb();
            } else {
              delay(function () {
                waitFor(predicate, cb);
              });
            }
          };
          var getSetY = function getSetY() {
            var valY = storage.getItem(keyY);
            if (valY && valY !== i) {
              // if Y == i then this process already has the lock (useful for test cases)
              return false;
            } else {
              storage.setItem(keyY, i);
              if (storage.getItem(keyY) === i) {
                return true;
              } else {
                if (!localStorageSupported(storage, true)) {
                  throw new Error('localStorage support dropped while acquiring lock');
                }
                return false;
              }
            }
          };
          var loop = function loop() {
            storage.setItem(keyX, i);
            waitFor(getSetY, function () {
              if (storage.getItem(keyX) === i) {
                criticalSection();
                return;
              }
              delay(function () {
                if (storage.getItem(keyY) !== i) {
                  loop();
                  return;
                }
                waitFor(function () {
                  return !storage.getItem(keyZ);
                }, criticalSection);
              });
            });
          };
          var criticalSection = function criticalSection() {
            storage.setItem(keyZ, '1');
            try {
              lockedCB();
            } finally {
              storage.removeItem(keyZ);
              if (storage.getItem(keyY) === i) {
                storage.removeItem(keyY);
              }
              if (storage.getItem(keyX) === i) {
                storage.removeItem(keyX);
              }
            }
          };
          try {
            if (localStorageSupported(storage, true)) {
              loop();
            } else {
              throw new Error('localStorage support check failed');
            }
          } catch (err) {
            reportError(err);
          }
        };
        var logger$2 = console_with_prefix('batch');

        /**
         * RequestQueue: queue for batching API requests with localStorage backup for retries.
         * Maintains an in-memory queue which represents the source of truth for the current
         * page, but also writes all items out to a copy in the browser's localStorage, which
         * can be read on subsequent pageloads and retried. For batchability, all the request
         * items in the queue should be of the same type (events, people updates, group updates)
         * so they can be sent in a single request to the same API endpoint.
         *
         * LocalStorage keying and locking: In order for reloads and subsequent pageloads of
         * the same site to access the same persisted data, they must share the same localStorage
         * key (for instance based on project token and queue type). Therefore access to the
         * localStorage entry is guarded by an asynchronous mutex (SharedLock) to prevent
         * simultaneously open windows/tabs from overwriting each other's data (which would lead
         * to data loss in some situations).
         * @constructor
         */
        var RequestQueue = function RequestQueue(storageKey, options) {
          options = options || {};
          this.storageKey = storageKey;
          this.storage = options.storage || window.localStorage;
          this.reportError = options.errorReporter || _.bind(logger$2.error, logger$2);
          this.lock = new SharedLock(storageKey, {
            storage: this.storage
          });
          this.usePersistence = options.usePersistence;
          this.pid = options.pid || null; // pass pid to test out storage lock contention scenarios

          this.memQueue = [];
        };

        /**
         * Add one item to queues (memory and localStorage). The queued entry includes
         * the given item along with an auto-generated ID and a "flush-after" timestamp.
         * It is expected that the item will be sent over the network and dequeued
         * before the flush-after time; if this doesn't happen it is considered orphaned
         * (e.g., the original tab where it was enqueued got closed before it could be
         * sent) and the item can be sent by any tab that finds it in localStorage.
         *
         * The final callback param is called with a param indicating success or
         * failure of the enqueue operation; it is asynchronous because the localStorage
         * lock is asynchronous.
         */
        RequestQueue.prototype.enqueue = function (item, flushInterval, cb) {
          var queueEntry = {
            'id': cheap_guid(),
            'flushAfter': new Date().getTime() + flushInterval * 2,
            'payload': item
          };
          if (!this.usePersistence) {
            this.memQueue.push(queueEntry);
            if (cb) {
              cb(true);
            }
          } else {
            this.lock.withLock(_.bind(function lockAcquired() {
              var succeeded;
              try {
                var storedQueue = this.readFromStorage();
                storedQueue.push(queueEntry);
                succeeded = this.saveToStorage(storedQueue);
                if (succeeded) {
                  // only add to in-memory queue when storage succeeds
                  this.memQueue.push(queueEntry);
                }
              } catch (err) {
                this.reportError('Error enqueueing item', item);
                succeeded = false;
              }
              if (cb) {
                cb(succeeded);
              }
            }, this), _.bind(function lockFailure(err) {
              this.reportError('Error acquiring storage lock', err);
              if (cb) {
                cb(false);
              }
            }, this), this.pid);
          }
        };

        /**
         * Read out the given number of queue entries. If this.memQueue
         * has fewer than batchSize items, then look for "orphaned" items
         * in the persisted queue (items where the 'flushAfter' time has
         * already passed).
         */
        RequestQueue.prototype.fillBatch = function (batchSize) {
          var batch = this.memQueue.slice(0, batchSize);
          if (this.usePersistence && batch.length < batchSize) {
            // don't need lock just to read events; localStorage is thread-safe
            // and the worst that could happen is a duplicate send of some
            // orphaned events, which will be deduplicated on the server side
            var storedQueue = this.readFromStorage();
            if (storedQueue.length) {
              // item IDs already in batch; don't duplicate out of storage
              var idsInBatch = {}; // poor man's Set
              _.each(batch, function (item) {
                idsInBatch[item['id']] = true;
              });
              for (var i = 0; i < storedQueue.length; i++) {
                var item = storedQueue[i];
                if (new Date().getTime() > item['flushAfter'] && !idsInBatch[item['id']]) {
                  item.orphaned = true;
                  batch.push(item);
                  if (batch.length >= batchSize) {
                    break;
                  }
                }
              }
            }
          }
          return batch;
        };

        /**
         * Remove items with matching 'id' from array (immutably)
         * also remove any item without a valid id (e.g., malformed
         * storage entries).
         */
        var filterOutIDsAndInvalid = function filterOutIDsAndInvalid(items, idSet) {
          var filteredItems = [];
          _.each(items, function (item) {
            if (item['id'] && !idSet[item['id']]) {
              filteredItems.push(item);
            }
          });
          return filteredItems;
        };

        /**
         * Remove items with matching IDs from both in-memory queue
         * and persisted queue
         */
        RequestQueue.prototype.removeItemsByID = function (ids, cb) {
          var idSet = {}; // poor man's Set
          _.each(ids, function (id) {
            idSet[id] = true;
          });
          this.memQueue = filterOutIDsAndInvalid(this.memQueue, idSet);
          if (!this.usePersistence) {
            if (cb) {
              cb(true);
            }
          } else {
            var removeFromStorage = _.bind(function () {
              var succeeded;
              try {
                var storedQueue = this.readFromStorage();
                storedQueue = filterOutIDsAndInvalid(storedQueue, idSet);
                succeeded = this.saveToStorage(storedQueue);

                // an extra check: did storage report success but somehow
                // the items are still there?
                if (succeeded) {
                  storedQueue = this.readFromStorage();
                  for (var i = 0; i < storedQueue.length; i++) {
                    var item = storedQueue[i];
                    if (item['id'] && !!idSet[item['id']]) {
                      this.reportError('Item not removed from storage');
                      return false;
                    }
                  }
                }
              } catch (err) {
                this.reportError('Error removing items', ids);
                succeeded = false;
              }
              return succeeded;
            }, this);
            this.lock.withLock(function lockAcquired() {
              var succeeded = removeFromStorage();
              if (cb) {
                cb(succeeded);
              }
            }, _.bind(function lockFailure(err) {
              var succeeded = false;
              this.reportError('Error acquiring storage lock', err);
              if (!localStorageSupported(this.storage, true)) {
                // Looks like localStorage writes have stopped working sometime after
                // initialization (probably full), and so nobody can acquire locks
                // anymore. Consider it temporarily safe to remove items without the
                // lock, since nobody's writing successfully anyway.
                succeeded = removeFromStorage();
                if (!succeeded) {
                  // OK, we couldn't even write out the smaller queue. Try clearing it
                  // entirely.
                  try {
                    this.storage.removeItem(this.storageKey);
                  } catch (err) {
                    this.reportError('Error clearing queue', err);
                  }
                }
              }
              if (cb) {
                cb(succeeded);
              }
            }, this), this.pid);
          }
        };

        // internal helper for RequestQueue.updatePayloads
        var updatePayloads = function updatePayloads(existingItems, itemsToUpdate) {
          var newItems = [];
          _.each(existingItems, function (item) {
            var id = item['id'];
            if (id in itemsToUpdate) {
              var newPayload = itemsToUpdate[id];
              if (newPayload !== null) {
                item['payload'] = newPayload;
                newItems.push(item);
              }
            } else {
              // no update
              newItems.push(item);
            }
          });
          return newItems;
        };

        /**
         * Update payloads of given items in both in-memory queue and
         * persisted queue. Items set to null are removed from queues.
         */
        RequestQueue.prototype.updatePayloads = function (itemsToUpdate, cb) {
          this.memQueue = updatePayloads(this.memQueue, itemsToUpdate);
          if (!this.usePersistence) {
            if (cb) {
              cb(true);
            }
          } else {
            this.lock.withLock(_.bind(function lockAcquired() {
              var succeeded;
              try {
                var storedQueue = this.readFromStorage();
                storedQueue = updatePayloads(storedQueue, itemsToUpdate);
                succeeded = this.saveToStorage(storedQueue);
              } catch (err) {
                this.reportError('Error updating items', itemsToUpdate);
                succeeded = false;
              }
              if (cb) {
                cb(succeeded);
              }
            }, this), _.bind(function lockFailure(err) {
              this.reportError('Error acquiring storage lock', err);
              if (cb) {
                cb(false);
              }
            }, this), this.pid);
          }
        };

        /**
         * Read and parse items array from localStorage entry, handling
         * malformed/missing data if necessary.
         */
        RequestQueue.prototype.readFromStorage = function () {
          var storageEntry;
          try {
            storageEntry = this.storage.getItem(this.storageKey);
            if (storageEntry) {
              storageEntry = JSONParse(storageEntry);
              if (!_.isArray(storageEntry)) {
                this.reportError('Invalid storage entry:', storageEntry);
                storageEntry = null;
              }
            }
          } catch (err) {
            this.reportError('Error retrieving queue', err);
            storageEntry = null;
          }
          return storageEntry || [];
        };

        /**
         * Serialize the given items array to localStorage.
         */
        RequestQueue.prototype.saveToStorage = function (queue) {
          try {
            this.storage.setItem(this.storageKey, JSONStringify(queue));
            return true;
          } catch (err) {
            this.reportError('Error saving queue', err);
            return false;
          }
        };

        /**
         * Clear out queues (memory and localStorage).
         */
        RequestQueue.prototype.clear = function () {
          this.memQueue = [];
          if (this.usePersistence) {
            this.storage.removeItem(this.storageKey);
          }
        };

        // maximum interval between request retries after exponential backoff
        var MAX_RETRY_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

        var logger$1 = console_with_prefix('batch');

        /**
         * RequestBatcher: manages the queueing, flushing, retry etc of requests of one
         * type (events, people, groups).
         * Uses RequestQueue to manage the backing store.
         * @constructor
         */
        var RequestBatcher = function RequestBatcher(storageKey, options) {
          this.errorReporter = options.errorReporter;
          this.queue = new RequestQueue(storageKey, {
            errorReporter: _.bind(this.reportError, this),
            storage: options.storage,
            usePersistence: options.usePersistence
          });
          this.libConfig = options.libConfig;
          this.sendRequest = options.sendRequestFunc;
          this.beforeSendHook = options.beforeSendHook;
          this.stopAllBatching = options.stopAllBatchingFunc;

          // seed variable batch size + flush interval with configured values
          this.batchSize = this.libConfig['batch_size'];
          this.flushInterval = this.libConfig['batch_flush_interval_ms'];
          this.stopped = !this.libConfig['batch_autostart'];
          this.consecutiveRemovalFailures = 0;

          // extra client-side dedupe
          this.itemIdsSentSuccessfully = {};

          // Make the flush occur at the interval specified by flushIntervalMs, default behavior will attempt consecutive flushes
          // as long as the queue is not empty. This is useful for high-frequency events like Session Replay where we might end up
          // in a request loop and get ratelimited by the server.
          this.flushOnlyOnInterval = options.flushOnlyOnInterval || false;
        };

        /**
         * Add one item to queue.
         */
        RequestBatcher.prototype.enqueue = function (item, cb) {
          this.queue.enqueue(item, this.flushInterval, cb);
        };

        /**
         * Start flushing batches at the configured time interval. Must call
         * this method upon SDK init in order to send anything over the network.
         */
        RequestBatcher.prototype.start = function () {
          this.stopped = false;
          this.consecutiveRemovalFailures = 0;
          this.flush();
        };

        /**
         * Stop flushing batches. Can be restarted by calling start().
         */
        RequestBatcher.prototype.stop = function () {
          this.stopped = true;
          if (this.timeoutID) {
            clearTimeout(this.timeoutID);
            this.timeoutID = null;
          }
        };

        /**
         * Clear out queue.
         */
        RequestBatcher.prototype.clear = function () {
          this.queue.clear();
        };

        /**
         * Restore batch size configuration to whatever is set in the main SDK.
         */
        RequestBatcher.prototype.resetBatchSize = function () {
          this.batchSize = this.libConfig['batch_size'];
        };

        /**
         * Restore flush interval time configuration to whatever is set in the main SDK.
         */
        RequestBatcher.prototype.resetFlush = function () {
          this.scheduleFlush(this.libConfig['batch_flush_interval_ms']);
        };

        /**
         * Schedule the next flush in the given number of milliseconds.
         */
        RequestBatcher.prototype.scheduleFlush = function (flushMS) {
          this.flushInterval = flushMS;
          if (!this.stopped) {
            // don't schedule anymore if batching has been stopped
            this.timeoutID = setTimeout(_.bind(function () {
              if (!this.stopped) {
                this.flush();
              }
            }, this), this.flushInterval);
          }
        };

        /**
         * Flush one batch to network. Depending on success/failure modes, it will either
         * remove the batch from the queue or leave it in for retry, and schedule the next
         * flush. In cases of most network or API failures, it will back off exponentially
         * when retrying.
         * @param {Object} [options]
         * @param {boolean} [options.sendBeacon] - whether to send batch with
         * navigator.sendBeacon (only useful for sending batches before page unloads, as
         * sendBeacon offers no callbacks or status indications)
         */
        RequestBatcher.prototype.flush = function (options) {
          try {
            if (this.requestInProgress) {
              logger$1.log('Flush: Request already in progress');
              return;
            }
            options = options || {};
            var timeoutMS = this.libConfig['batch_request_timeout_ms'];
            var startTime = new Date().getTime();
            var currentBatchSize = this.batchSize;
            var batch = this.queue.fillBatch(currentBatchSize);
            // if there's more items in the queue than the batch size, attempt
            // to flush again after the current batch is done.
            var attemptSecondaryFlush = batch.length === currentBatchSize;
            var dataForRequest = [];
            var transformedItems = {};
            _.each(batch, function (item) {
              var payload = item['payload'];
              if (this.beforeSendHook && !item.orphaned) {
                payload = this.beforeSendHook(payload);
              }
              if (payload) {
                // mp_sent_by_lib_version prop captures which lib version actually
                // sends each event (regardless of which version originally queued
                // it for sending)
                if (payload['event'] && payload['properties']) {
                  payload['properties'] = _.extend({}, payload['properties'], {
                    'mp_sent_by_lib_version': Config.LIB_VERSION
                  });
                }
                var addPayload = true;
                var itemId = item['id'];
                if (itemId) {
                  if ((this.itemIdsSentSuccessfully[itemId] || 0) > 5) {
                    this.reportError('[dupe] item ID sent too many times, not sending', {
                      item: item,
                      batchSize: batch.length,
                      timesSent: this.itemIdsSentSuccessfully[itemId]
                    });
                    addPayload = false;
                  }
                } else {
                  this.reportError('[dupe] found item with no ID', {
                    item: item
                  });
                }
                if (addPayload) {
                  dataForRequest.push(payload);
                }
              }
              transformedItems[item['id']] = payload;
            }, this);
            if (dataForRequest.length < 1) {
              this.resetFlush();
              return; // nothing to do
            }

            this.requestInProgress = true;
            var batchSendCallback = _.bind(function (res) {
              this.requestInProgress = false;
              try {
                // handle API response in a try-catch to make sure we can reset the
                // flush operation if something goes wrong

                var removeItemsFromQueue = false;
                if (options.unloading) {
                  // update persisted data to include hook transformations
                  this.queue.updatePayloads(transformedItems);
                } else if (_.isObject(res) && res.error === 'timeout' && new Date().getTime() - startTime >= timeoutMS) {
                  this.reportError('Network timeout; retrying');
                  this.flush();
                } else if (_.isObject(res) && (res.httpStatusCode >= 500 || res.httpStatusCode === 429 || res.error === 'timeout')) {
                  // network or API error, or 429 Too Many Requests, retry
                  var retryMS = this.flushInterval * 2;
                  if (res.retryAfter) {
                    retryMS = parseInt(res.retryAfter, 10) * 1000 || retryMS;
                  }
                  retryMS = Math.min(MAX_RETRY_INTERVAL_MS, retryMS);
                  this.reportError('Error; retry in ' + retryMS + ' ms');
                  this.scheduleFlush(retryMS);
                } else if (_.isObject(res) && res.httpStatusCode === 413) {
                  // 413 Payload Too Large
                  if (batch.length > 1) {
                    var halvedBatchSize = Math.max(1, Math.floor(currentBatchSize / 2));
                    this.batchSize = Math.min(this.batchSize, halvedBatchSize, batch.length - 1);
                    this.reportError('413 response; reducing batch size to ' + this.batchSize);
                    this.resetFlush();
                  } else {
                    this.reportError('Single-event request too large; dropping', batch);
                    this.resetBatchSize();
                    removeItemsFromQueue = true;
                  }
                } else {
                  // successful network request+response; remove each item in batch from queue
                  // (even if it was e.g. a 400, in which case retrying won't help)
                  removeItemsFromQueue = true;
                }
                if (removeItemsFromQueue) {
                  this.queue.removeItemsByID(_.map(batch, function (item) {
                    return item['id'];
                  }), _.bind(function (succeeded) {
                    if (succeeded) {
                      this.consecutiveRemovalFailures = 0;
                      if (this.flushOnlyOnInterval && !attemptSecondaryFlush) {
                        this.resetFlush(); // schedule next batch with a delay
                      } else {
                        this.flush(); // handle next batch if the queue isn't empty
                      }
                    } else {
                      this.reportError('Failed to remove items from queue');
                      if (++this.consecutiveRemovalFailures > 5) {
                        this.reportError('Too many queue failures; disabling batching system.');
                        this.stopAllBatching();
                      } else {
                        this.resetFlush();
                      }
                    }
                  }, this));

                  // client-side dedupe
                  _.each(batch, _.bind(function (item) {
                    var itemId = item['id'];
                    if (itemId) {
                      this.itemIdsSentSuccessfully[itemId] = this.itemIdsSentSuccessfully[itemId] || 0;
                      this.itemIdsSentSuccessfully[itemId]++;
                      if (this.itemIdsSentSuccessfully[itemId] > 5) {
                        this.reportError('[dupe] item ID sent too many times', {
                          item: item,
                          batchSize: batch.length,
                          timesSent: this.itemIdsSentSuccessfully[itemId]
                        });
                      }
                    } else {
                      this.reportError('[dupe] found item with no ID while removing', {
                        item: item
                      });
                    }
                  }, this));
                }
              } catch (err) {
                this.reportError('Error handling API response', err);
                this.resetFlush();
              }
            }, this);
            var requestOptions = {
              method: 'POST',
              verbose: true,
              ignore_json_errors: true,
              // eslint-disable-line camelcase
              timeout_ms: timeoutMS // eslint-disable-line camelcase
            };

            if (options.unloading) {
              requestOptions.transport = 'sendBeacon';
            }
            logger$1.log('MIXPANEL REQUEST:', dataForRequest);
            this.sendRequest(dataForRequest, requestOptions, batchSendCallback);
          } catch (err) {
            this.reportError('Error flushing request queue', err);
            this.resetFlush();
          }
        };

        /**
         * Log error to global logger and optional user-defined logger.
         */
        RequestBatcher.prototype.reportError = function (msg, err) {
          logger$1.error.apply(logger$1.error, arguments);
          if (this.errorReporter) {
            try {
              if (!(err instanceof Error)) {
                err = new Error(msg);
              }
              this.errorReporter(msg, err);
            } catch (err) {
              logger$1.error(err);
            }
          }
        };
        var logger = console_with_prefix('recorder');
        var CompressionStream = win['CompressionStream'];
        var RECORDER_BATCHER_LIB_CONFIG = {
          'batch_size': 1000,
          'batch_flush_interval_ms': 10 * 1000,
          'batch_request_timeout_ms': 90 * 1000,
          'batch_autostart': true
        };
        var ACTIVE_SOURCES = new Set([IncrementalSource.MouseMove, IncrementalSource.MouseInteraction, IncrementalSource.Scroll, IncrementalSource.ViewportResize, IncrementalSource.Input, IncrementalSource.TouchMove, IncrementalSource.MediaInteraction, IncrementalSource.Drag, IncrementalSource.Selection]);
        function isUserEvent(ev) {
          return ev.type === EventType.IncrementalSnapshot && ACTIVE_SOURCES.has(ev.data.source);
        }
        var MixpanelRecorder = function MixpanelRecorder(mixpanelInstance) {
          this._mixpanel = mixpanelInstance;

          // internal rrweb stopRecording function
          this._stopRecording = null;
          this.recEvents = [];
          this.seqNo = 0;
          this.replayId = null;
          this.replayStartTime = null;
          this.sendBatchId = null;
          this.idleTimeoutId = null;
          this.maxTimeoutId = null;
          this.recordMaxMs = MAX_RECORDING_MS;
          this._initBatcher();
        };
        MixpanelRecorder.prototype._initBatcher = function () {
          this.batcher = new RequestBatcher('__mprec', {
            libConfig: RECORDER_BATCHER_LIB_CONFIG,
            sendRequestFunc: _.bind(this.flushEventsWithOptOut, this),
            errorReporter: _.bind(this.reportError, this),
            flushOnlyOnInterval: true,
            usePersistence: false
          });
        };

        // eslint-disable-next-line camelcase
        MixpanelRecorder.prototype.get_config = function (configVar) {
          return this._mixpanel.get_config(configVar);
        };
        MixpanelRecorder.prototype.startRecording = function (shouldStopBatcher) {
          if (this._stopRecording !== null) {
            logger.log('Recording already in progress, skipping startRecording.');
            return;
          }
          this.recordMaxMs = this.get_config('record_max_ms');
          if (this.recordMaxMs > MAX_RECORDING_MS) {
            this.recordMaxMs = MAX_RECORDING_MS;
            logger.critical('record_max_ms cannot be greater than ' + MAX_RECORDING_MS + 'ms. Capping value.');
          }
          this.recEvents = [];
          this.seqNo = 0;
          this.replayStartTime = null;
          this.replayId = _.UUID();
          if (shouldStopBatcher) {
            // this is the case when we're starting recording after a reset
            // and don't want to send anything over the network until there's
            // actual user activity
            this.batcher.stop();
          } else {
            this.batcher.start();
          }
          var resetIdleTimeout = _.bind(function () {
            clearTimeout(this.idleTimeoutId);
            this.idleTimeoutId = setTimeout(_.bind(function () {
              logger.log('Idle timeout reached, restarting recording.');
              this.resetRecording();
            }, this), this.get_config('record_idle_timeout_ms'));
          }, this);
          this._stopRecording = record({
            'emit': _.bind(function (ev) {
              this.batcher.enqueue(ev);
              if (isUserEvent(ev)) {
                if (this.batcher.stopped) {
                  // start flushing again after user activity
                  this.batcher.start();
                }
                resetIdleTimeout();
              }
            }, this),
            'blockClass': this.get_config('record_block_class'),
            'blockSelector': this.get_config('record_block_selector'),
            'collectFonts': this.get_config('record_collect_fonts'),
            'inlineImages': this.get_config('record_inline_images'),
            'maskAllInputs': true,
            'maskTextClass': this.get_config('record_mask_text_class'),
            'maskTextSelector': this.get_config('record_mask_text_selector')
          });
          resetIdleTimeout();
          this.maxTimeoutId = setTimeout(_.bind(this.resetRecording, this), this.recordMaxMs);
        };
        MixpanelRecorder.prototype.resetRecording = function () {
          this.stopRecording();
          this.startRecording(true);
        };
        MixpanelRecorder.prototype.stopRecording = function () {
          if (this._stopRecording !== null) {
            this._stopRecording();
            this._stopRecording = null;
          }
          if (this.batcher.stopped) {
            // never got user activity to flush after reset, so just clear the batcher
            this.batcher.clear();
          } else {
            // flush any remaining events from running batcher
            this.batcher.flush();
            this.batcher.stop();
          }
          this.replayId = null;
          clearTimeout(this.idleTimeoutId);
          clearTimeout(this.maxTimeoutId);
        };

        /**
         * Flushes the current batch of events to the server, but passes an opt-out callback to make sure
         * we stop recording and dump any queued events if the user has opted out.
         */
        MixpanelRecorder.prototype.flushEventsWithOptOut = function (data, options, cb) {
          this._flushEvents(data, options, cb, _.bind(this._onOptOut, this));
        };
        MixpanelRecorder.prototype._onOptOut = function (code) {
          // addOptOutCheckMixpanelLib invokes this function with code=0 when the user has opted out
          if (code === 0) {
            this.recEvents = [];
            this.stopRecording();
          }
        };
        MixpanelRecorder.prototype._sendRequest = function (reqParams, reqBody, callback) {
          var onSuccess = _.bind(function (response, responseBody) {
            // Increment sequence counter only if the request was successful to guarantee ordering.
            // RequestBatcher will always flush the next batch after the previous one succeeds.
            if (response.status === 200) {
              this.seqNo++;
            }
            callback({
              status: 0,
              httpStatusCode: response.status,
              responseBody: responseBody,
              retryAfter: response.headers.get('Retry-After')
            });
          }, this);
          win['fetch'](this.get_config('api_host') + '/' + this.get_config('api_routes')['record'] + '?' + new URLSearchParams(reqParams), {
            'method': 'POST',
            'headers': {
              'Authorization': 'Basic ' + btoa(this.get_config('token') + ':'),
              'Content-Type': 'application/octet-stream'
            },
            'body': reqBody
          }).then(function (response) {
            response.json().then(function (responseBody) {
              onSuccess(response, responseBody);
            })["catch"](function (error) {
              callback({
                error: error
              });
            });
          })["catch"](function (error) {
            callback({
              error: error
            });
          });
        };
        MixpanelRecorder.prototype._flushEvents = addOptOutCheckMixpanelLib(function (data, options, callback) {
          var numEvents = data.length;
          if (numEvents > 0) {
            // each rrweb event has a timestamp - leverage those to get time properties
            var batchStartTime = data[0].timestamp;
            if (this.seqNo === 0) {
              this.replayStartTime = batchStartTime;
            }
            var replayLengthMs = data[numEvents - 1].timestamp - this.replayStartTime;
            var reqParams = {
              'distinct_id': String(this._mixpanel.get_distinct_id()),
              'seq': this.seqNo,
              'batch_start_time': batchStartTime / 1000,
              'replay_id': this.replayId,
              'replay_length_ms': replayLengthMs,
              'replay_start_time': this.replayStartTime / 1000
            };
            var eventsJson = _.JSONEncode(data);

            // send ID management props if they exist
            var deviceId = this._mixpanel.get_property('$device_id');
            if (deviceId) {
              reqParams['$device_id'] = deviceId;
            }
            var userId = this._mixpanel.get_property('$user_id');
            if (userId) {
              reqParams['$user_id'] = userId;
            }
            if (CompressionStream) {
              var jsonStream = new Blob([eventsJson], {
                type: 'application/json'
              }).stream();
              var gzipStream = jsonStream.pipeThrough(new CompressionStream('gzip'));
              new Response(gzipStream).blob().then(_.bind(function (compressedBlob) {
                reqParams['format'] = 'gzip';
                this._sendRequest(reqParams, compressedBlob, callback);
              }, this));
            } else {
              reqParams['format'] = 'body';
              this._sendRequest(reqParams, eventsJson, callback);
            }
          }
        });
        MixpanelRecorder.prototype.reportError = function (msg, err) {
          logger.error.apply(logger.error, arguments);
          try {
            if (!err && !(msg instanceof Error)) {
              msg = new Error(msg);
            }
            this.get_config('error_reporter')(msg, err);
          } catch (err) {
            logger.error(err);
          }
        };
        win['__mp_recorder'] = MixpanelRecorder;

        /* eslint camelcase: "off" */

        /**
         * DomTracker Object
         * @constructor
         */
        var DomTracker = function DomTracker() {};

        // interface
        DomTracker.prototype.create_properties = function () {};
        DomTracker.prototype.event_handler = function () {};
        DomTracker.prototype.after_track_handler = function () {};
        DomTracker.prototype.init = function (mixpanel_instance) {
          this.mp = mixpanel_instance;
          return this;
        };

        /**
         * @param {Object|string} query
         * @param {string} event_name
         * @param {Object=} properties
         * @param {function=} user_callback
         */
        DomTracker.prototype.track = function (query, event_name, properties, user_callback) {
          var that = this;
          var elements = _.dom_query(query);
          if (elements.length === 0) {
            console$1.error('The DOM query (' + query + ') returned 0 elements');
            return;
          }
          _.each(elements, function (element) {
            _.register_event(element, this.override_event, function (e) {
              var options = {};
              var props = that.create_properties(properties, this);
              var timeout = that.mp.get_config('track_links_timeout');
              that.event_handler(e, this, options);

              // in case the mixpanel servers don't get back to us in time
              window.setTimeout(that.track_callback(user_callback, props, options, true), timeout);

              // fire the tracking event
              that.mp.track(event_name, props, that.track_callback(user_callback, props, options));
            });
          }, this);
          return true;
        };

        /**
         * @param {function} user_callback
         * @param {Object} props
         * @param {boolean=} timeout_occured
         */
        DomTracker.prototype.track_callback = function (user_callback, props, options, timeout_occured) {
          timeout_occured = timeout_occured || false;
          var that = this;
          return function () {
            // options is referenced from both callbacks, so we can have
            // a 'lock' of sorts to ensure only one fires
            if (options.callback_fired) {
              return;
            }
            options.callback_fired = true;
            if (user_callback && user_callback(timeout_occured, props) === false) {
              // user can prevent the default functionality by
              // returning false from their callback
              return;
            }
            that.after_track_handler(props, options, timeout_occured);
          };
        };
        DomTracker.prototype.create_properties = function (properties, element) {
          var props;
          if (typeof properties === 'function') {
            props = properties(element);
          } else {
            props = _.extend({}, properties);
          }
          return props;
        };

        /**
         * LinkTracker Object
         * @constructor
         * @extends DomTracker
         */
        var LinkTracker = function LinkTracker() {
          this.override_event = 'click';
        };
        _.inherit(LinkTracker, DomTracker);
        LinkTracker.prototype.create_properties = function (properties, element) {
          var props = LinkTracker.superclass.create_properties.apply(this, arguments);
          if (element.href) {
            props['url'] = element.href;
          }
          return props;
        };
        LinkTracker.prototype.event_handler = function (evt, element, options) {
          options.new_tab = evt.which === 2 || evt.metaKey || evt.ctrlKey || element.target === '_blank';
          options.href = element.href;
          if (!options.new_tab) {
            evt.preventDefault();
          }
        };
        LinkTracker.prototype.after_track_handler = function (props, options) {
          if (options.new_tab) {
            return;
          }
          setTimeout(function () {
            window.location = options.href;
          }, 0);
        };

        /**
         * FormTracker Object
         * @constructor
         * @extends DomTracker
         */
        var FormTracker = function FormTracker() {
          this.override_event = 'submit';
        };
        _.inherit(FormTracker, DomTracker);
        FormTracker.prototype.event_handler = function (evt, element, options) {
          options.element = element;
          evt.preventDefault();
        };
        FormTracker.prototype.after_track_handler = function (props, options) {
          setTimeout(function () {
            options.element.submit();
          }, 0);
        };

        /* eslint camelcase: "off" */

        /** @const */
        var SET_ACTION = '$set';
        /** @const */
        var SET_ONCE_ACTION = '$set_once';
        /** @const */
        var UNSET_ACTION = '$unset';
        /** @const */
        var ADD_ACTION = '$add';
        /** @const */
        var APPEND_ACTION = '$append';
        /** @const */
        var UNION_ACTION = '$union';
        /** @const */
        var REMOVE_ACTION = '$remove';
        /** @const */
        var DELETE_ACTION = '$delete';

        // Common internal methods for mixpanel.people and mixpanel.group APIs.
        // These methods shouldn't involve network I/O.
        var apiActions = {
          set_action: function set_action(prop, to) {
            var data = {};
            var $set = {};
            if (_.isObject(prop)) {
              _.each(prop, function (v, k) {
                if (!this._is_reserved_property(k)) {
                  $set[k] = v;
                }
              }, this);
            } else {
              $set[prop] = to;
            }
            data[SET_ACTION] = $set;
            return data;
          },
          unset_action: function unset_action(prop) {
            var data = {};
            var $unset = [];
            if (!_.isArray(prop)) {
              prop = [prop];
            }
            _.each(prop, function (k) {
              if (!this._is_reserved_property(k)) {
                $unset.push(k);
              }
            }, this);
            data[UNSET_ACTION] = $unset;
            return data;
          },
          set_once_action: function set_once_action(prop, to) {
            var data = {};
            var $set_once = {};
            if (_.isObject(prop)) {
              _.each(prop, function (v, k) {
                if (!this._is_reserved_property(k)) {
                  $set_once[k] = v;
                }
              }, this);
            } else {
              $set_once[prop] = to;
            }
            data[SET_ONCE_ACTION] = $set_once;
            return data;
          },
          union_action: function union_action(list_name, values) {
            var data = {};
            var $union = {};
            if (_.isObject(list_name)) {
              _.each(list_name, function (v, k) {
                if (!this._is_reserved_property(k)) {
                  $union[k] = _.isArray(v) ? v : [v];
                }
              }, this);
            } else {
              $union[list_name] = _.isArray(values) ? values : [values];
            }
            data[UNION_ACTION] = $union;
            return data;
          },
          append_action: function append_action(list_name, value) {
            var data = {};
            var $append = {};
            if (_.isObject(list_name)) {
              _.each(list_name, function (v, k) {
                if (!this._is_reserved_property(k)) {
                  $append[k] = v;
                }
              }, this);
            } else {
              $append[list_name] = value;
            }
            data[APPEND_ACTION] = $append;
            return data;
          },
          remove_action: function remove_action(list_name, value) {
            var data = {};
            var $remove = {};
            if (_.isObject(list_name)) {
              _.each(list_name, function (v, k) {
                if (!this._is_reserved_property(k)) {
                  $remove[k] = v;
                }
              }, this);
            } else {
              $remove[list_name] = value;
            }
            data[REMOVE_ACTION] = $remove;
            return data;
          },
          delete_action: function delete_action() {
            var data = {};
            data[DELETE_ACTION] = '';
            return data;
          }
        };

        /* eslint camelcase: "off" */

        /**
         * Mixpanel Group Object
         * @constructor
         */
        var MixpanelGroup = function MixpanelGroup() {};
        _.extend(MixpanelGroup.prototype, apiActions);
        MixpanelGroup.prototype._init = function (mixpanel_instance, group_key, group_id) {
          this._mixpanel = mixpanel_instance;
          this._group_key = group_key;
          this._group_id = group_id;
        };

        /**
         * Set properties on a group.
         *
         * ### Usage:
         *
         *     mixpanel.get_group('company', 'mixpanel').set('Location', '405 Howard');
         *
         *     // or set multiple properties at once
         *     mixpanel.get_group('company', 'mixpanel').set({
         *          'Location': '405 Howard',
         *          'Founded' : 2009,
         *     });
         *     // properties can be strings, integers, dates, or lists
         *
         * @param {Object|String} prop If a string, this is the name of the property. If an object, this is an associative array of names and values.
         * @param {*} [to] A value to set on the given property name
         * @param {Function} [callback] If provided, the callback will be called after the tracking event
         */
        MixpanelGroup.prototype.set = addOptOutCheckMixpanelGroup(function (prop, to, callback) {
          var data = this.set_action(prop, to);
          if (_.isObject(prop)) {
            callback = to;
          }
          return this._send_request(data, callback);
        });

        /**
         * Set properties on a group, only if they do not yet exist.
         * This will not overwrite previous group property values, unlike
         * group.set().
         *
         * ### Usage:
         *
         *     mixpanel.get_group('company', 'mixpanel').set_once('Location', '405 Howard');
         *
         *     // or set multiple properties at once
         *     mixpanel.get_group('company', 'mixpanel').set_once({
         *          'Location': '405 Howard',
         *          'Founded' : 2009,
         *     });
         *     // properties can be strings, integers, lists or dates
         *
         * @param {Object|String} prop If a string, this is the name of the property. If an object, this is an associative array of names and values.
         * @param {*} [to] A value to set on the given property name
         * @param {Function} [callback] If provided, the callback will be called after the tracking event
         */
        MixpanelGroup.prototype.set_once = addOptOutCheckMixpanelGroup(function (prop, to, callback) {
          var data = this.set_once_action(prop, to);
          if (_.isObject(prop)) {
            callback = to;
          }
          return this._send_request(data, callback);
        });

        /**
         * Unset properties on a group permanently.
         *
         * ### Usage:
         *
         *     mixpanel.get_group('company', 'mixpanel').unset('Founded');
         *
         * @param {String} prop The name of the property.
         * @param {Function} [callback] If provided, the callback will be called after the tracking event
         */
        MixpanelGroup.prototype.unset = addOptOutCheckMixpanelGroup(function (prop, callback) {
          var data = this.unset_action(prop);
          return this._send_request(data, callback);
        });

        /**
         * Merge a given list with a list-valued group property, excluding duplicate values.
         *
         * ### Usage:
         *
         *     // merge a value to a list, creating it if needed
         *     mixpanel.get_group('company', 'mixpanel').union('Location', ['San Francisco', 'London']);
         *
         * @param {String} list_name Name of the property.
         * @param {Array} values Values to merge with the given property
         * @param {Function} [callback] If provided, the callback will be called after the tracking event
         */
        MixpanelGroup.prototype.union = addOptOutCheckMixpanelGroup(function (list_name, values, callback) {
          if (_.isObject(list_name)) {
            callback = values;
          }
          var data = this.union_action(list_name, values);
          return this._send_request(data, callback);
        });

        /**
         * Permanently delete a group.
         *
         * ### Usage:
         *
         *     mixpanel.get_group('company', 'mixpanel').delete();
         *
         * @param {Function} [callback] If provided, the callback will be called after the tracking event
         */
        MixpanelGroup.prototype['delete'] = addOptOutCheckMixpanelGroup(function (callback) {
          // bracket notation above prevents a minification error related to reserved words
          var data = this.delete_action();
          return this._send_request(data, callback);
        });

        /**
         * Remove a property from a group. The value will be ignored if doesn't exist.
         *
         * ### Usage:
         *
         *     mixpanel.get_group('company', 'mixpanel').remove('Location', 'London');
         *
         * @param {String} list_name Name of the property.
         * @param {Object} value Value to remove from the given group property
         * @param {Function} [callback] If provided, the callback will be called after the tracking event
         */
        MixpanelGroup.prototype.remove = addOptOutCheckMixpanelGroup(function (list_name, value, callback) {
          var data = this.remove_action(list_name, value);
          return this._send_request(data, callback);
        });
        MixpanelGroup.prototype._send_request = function (data, callback) {
          data['$group_key'] = this._group_key;
          data['$group_id'] = this._group_id;
          data['$token'] = this._get_config('token');
          var date_encoded_data = _.encodeDates(data);
          return this._mixpanel._track_or_batch({
            type: 'groups',
            data: date_encoded_data,
            endpoint: this._get_config('api_host') + '/' + this._get_config('api_routes')['groups'],
            batcher: this._mixpanel.request_batchers.groups
          }, callback);
        };
        MixpanelGroup.prototype._is_reserved_property = function (prop) {
          return prop === '$group_key' || prop === '$group_id';
        };
        MixpanelGroup.prototype._get_config = function (conf) {
          return this._mixpanel.get_config(conf);
        };
        MixpanelGroup.prototype.toString = function () {
          return this._mixpanel.toString() + '.group.' + this._group_key + '.' + this._group_id;
        };

        // MixpanelGroup Exports
        MixpanelGroup.prototype['remove'] = MixpanelGroup.prototype.remove;
        MixpanelGroup.prototype['set'] = MixpanelGroup.prototype.set;
        MixpanelGroup.prototype['set_once'] = MixpanelGroup.prototype.set_once;
        MixpanelGroup.prototype['union'] = MixpanelGroup.prototype.union;
        MixpanelGroup.prototype['unset'] = MixpanelGroup.prototype.unset;
        MixpanelGroup.prototype['toString'] = MixpanelGroup.prototype.toString;

        /* eslint camelcase: "off" */

        /**
         * Mixpanel People Object
         * @constructor
         */
        var MixpanelPeople = function MixpanelPeople() {};
        _.extend(MixpanelPeople.prototype, apiActions);
        MixpanelPeople.prototype._init = function (mixpanel_instance) {
          this._mixpanel = mixpanel_instance;
        };

        /*
        * Set properties on a user record.
        *
        * ### Usage:
        *
        *     mixpanel.people.set('gender', 'm');
        *
        *     // or set multiple properties at once
        *     mixpanel.people.set({
        *         'Company': 'Acme',
        *         'Plan': 'Premium',
        *         'Upgrade date': new Date()
        *     });
        *     // properties can be strings, integers, dates, or lists
        *
        * @param {Object|String} prop If a string, this is the name of the property. If an object, this is an associative array of names and values.
        * @param {*} [to] A value to set on the given property name
        * @param {Function} [callback] If provided, the callback will be called after tracking the event.
        */
        MixpanelPeople.prototype.set = addOptOutCheckMixpanelPeople(function (prop, to, callback) {
          var data = this.set_action(prop, to);
          if (_.isObject(prop)) {
            callback = to;
          }
          // make sure that the referrer info has been updated and saved
          if (this._get_config('save_referrer')) {
            this._mixpanel['persistence'].update_referrer_info(document.referrer);
          }

          // update $set object with default people properties
          data[SET_ACTION] = _.extend({}, _.info.people_properties(), data[SET_ACTION]);
          return this._send_request(data, callback);
        });

        /*
        * Set properties on a user record, only if they do not yet exist.
        * This will not overwrite previous people property values, unlike
        * people.set().
        *
        * ### Usage:
        *
        *     mixpanel.people.set_once('First Login Date', new Date());
        *
        *     // or set multiple properties at once
        *     mixpanel.people.set_once({
        *         'First Login Date': new Date(),
        *         'Starting Plan': 'Premium'
        *     });
        *
        *     // properties can be strings, integers or dates
        *
        * @param {Object|String} prop If a string, this is the name of the property. If an object, this is an associative array of names and values.
        * @param {*} [to] A value to set on the given property name
        * @param {Function} [callback] If provided, the callback will be called after tracking the event.
        */
        MixpanelPeople.prototype.set_once = addOptOutCheckMixpanelPeople(function (prop, to, callback) {
          var data = this.set_once_action(prop, to);
          if (_.isObject(prop)) {
            callback = to;
          }
          return this._send_request(data, callback);
        });

        /*
        * Unset properties on a user record (permanently removes the properties and their values from a profile).
        *
        * ### Usage:
        *
        *     mixpanel.people.unset('gender');
        *
        *     // or unset multiple properties at once
        *     mixpanel.people.unset(['gender', 'Company']);
        *
        * @param {Array|String} prop If a string, this is the name of the property. If an array, this is a list of property names.
        * @param {Function} [callback] If provided, the callback will be called after tracking the event.
        */
        MixpanelPeople.prototype.unset = addOptOutCheckMixpanelPeople(function (prop, callback) {
          var data = this.unset_action(prop);
          return this._send_request(data, callback);
        });

        /*
        * Increment/decrement numeric people analytics properties.
        *
        * ### Usage:
        *
        *     mixpanel.people.increment('page_views', 1);
        *
        *     // or, for convenience, if you're just incrementing a counter by
        *     // 1, you can simply do
        *     mixpanel.people.increment('page_views');
        *
        *     // to decrement a counter, pass a negative number
        *     mixpanel.people.increment('credits_left', -1);
        *
        *     // like mixpanel.people.set(), you can increment multiple
        *     // properties at once:
        *     mixpanel.people.increment({
        *         counter1: 1,
        *         counter2: 6
        *     });
        *
        * @param {Object|String} prop If a string, this is the name of the property. If an object, this is an associative array of names and numeric values.
        * @param {Number} [by] An amount to increment the given property
        * @param {Function} [callback] If provided, the callback will be called after tracking the event.
        */
        MixpanelPeople.prototype.increment = addOptOutCheckMixpanelPeople(function (prop, by, callback) {
          var data = {};
          var $add = {};
          if (_.isObject(prop)) {
            _.each(prop, function (v, k) {
              if (!this._is_reserved_property(k)) {
                if (isNaN(parseFloat(v))) {
                  console$1.error('Invalid increment value passed to mixpanel.people.increment - must be a number');
                  return;
                } else {
                  $add[k] = v;
                }
              }
            }, this);
            callback = by;
          } else {
            // convenience: mixpanel.people.increment('property'); will
            // increment 'property' by 1
            if (_.isUndefined(by)) {
              by = 1;
            }
            $add[prop] = by;
          }
          data[ADD_ACTION] = $add;
          return this._send_request(data, callback);
        });

        /*
        * Append a value to a list-valued people analytics property.
        *
        * ### Usage:
        *
        *     // append a value to a list, creating it if needed
        *     mixpanel.people.append('pages_visited', 'homepage');
        *
        *     // like mixpanel.people.set(), you can append multiple
        *     // properties at once:
        *     mixpanel.people.append({
        *         list1: 'bob',
        *         list2: 123
        *     });
        *
        * @param {Object|String} list_name If a string, this is the name of the property. If an object, this is an associative array of names and values.
        * @param {*} [value] value An item to append to the list
        * @param {Function} [callback] If provided, the callback will be called after tracking the event.
        */
        MixpanelPeople.prototype.append = addOptOutCheckMixpanelPeople(function (list_name, value, callback) {
          if (_.isObject(list_name)) {
            callback = value;
          }
          var data = this.append_action(list_name, value);
          return this._send_request(data, callback);
        });

        /*
        * Remove a value from a list-valued people analytics property.
        *
        * ### Usage:
        *
        *     mixpanel.people.remove('School', 'UCB');
        *
        * @param {Object|String} list_name If a string, this is the name of the property. If an object, this is an associative array of names and values.
        * @param {*} [value] value Item to remove from the list
        * @param {Function} [callback] If provided, the callback will be called after tracking the event.
        */
        MixpanelPeople.prototype.remove = addOptOutCheckMixpanelPeople(function (list_name, value, callback) {
          if (_.isObject(list_name)) {
            callback = value;
          }
          var data = this.remove_action(list_name, value);
          return this._send_request(data, callback);
        });

        /*
        * Merge a given list with a list-valued people analytics property,
        * excluding duplicate values.
        *
        * ### Usage:
        *
        *     // merge a value to a list, creating it if needed
        *     mixpanel.people.union('pages_visited', 'homepage');
        *
        *     // like mixpanel.people.set(), you can append multiple
        *     // properties at once:
        *     mixpanel.people.union({
        *         list1: 'bob',
        *         list2: 123
        *     });
        *
        *     // like mixpanel.people.append(), you can append multiple
        *     // values to the same list:
        *     mixpanel.people.union({
        *         list1: ['bob', 'billy']
        *     });
        *
        * @param {Object|String} list_name If a string, this is the name of the property. If an object, this is an associative array of names and values.
        * @param {*} [value] Value / values to merge with the given property
        * @param {Function} [callback] If provided, the callback will be called after tracking the event.
        */
        MixpanelPeople.prototype.union = addOptOutCheckMixpanelPeople(function (list_name, values, callback) {
          if (_.isObject(list_name)) {
            callback = values;
          }
          var data = this.union_action(list_name, values);
          return this._send_request(data, callback);
        });

        /*
         * Record that you have charged the current user a certain amount
         * of money. Charges recorded with track_charge() will appear in the
         * Mixpanel revenue report.
         *
         * ### Usage:
         *
         *     // charge a user $50
         *     mixpanel.people.track_charge(50);
         *
         *     // charge a user $30.50 on the 2nd of january
         *     mixpanel.people.track_charge(30.50, {
         *         '$time': new Date('jan 1 2012')
         *     });
         *
         * @param {Number} amount The amount of money charged to the current user
         * @param {Object} [properties] An associative array of properties associated with the charge
         * @param {Function} [callback] If provided, the callback will be called when the server responds
         * @deprecated
         */
        MixpanelPeople.prototype.track_charge = addOptOutCheckMixpanelPeople(function (amount, properties, callback) {
          if (!_.isNumber(amount)) {
            amount = parseFloat(amount);
            if (isNaN(amount)) {
              console$1.error('Invalid value passed to mixpanel.people.track_charge - must be a number');
              return;
            }
          }
          return this.append('$transactions', _.extend({
            '$amount': amount
          }, properties), callback);
        });

        /*
         * Permanently clear all revenue report transactions from the
         * current user's people analytics profile.
         *
         * ### Usage:
         *
         *     mixpanel.people.clear_charges();
         *
         * @param {Function} [callback] If provided, the callback will be called after tracking the event.
         * @deprecated
         */
        MixpanelPeople.prototype.clear_charges = function (callback) {
          return this.set('$transactions', [], callback);
        };

        /*
        * Permanently deletes the current people analytics profile from
        * Mixpanel (using the current distinct_id).
        *
        * ### Usage:
        *
        *     // remove the all data you have stored about the current user
        *     mixpanel.people.delete_user();
        *
        */
        MixpanelPeople.prototype.delete_user = function () {
          if (!this._identify_called()) {
            console$1.error('mixpanel.people.delete_user() requires you to call identify() first');
            return;
          }
          var data = {
            '$delete': this._mixpanel.get_distinct_id()
          };
          return this._send_request(data);
        };
        MixpanelPeople.prototype.toString = function () {
          return this._mixpanel.toString() + '.people';
        };
        MixpanelPeople.prototype._send_request = function (data, callback) {
          data['$token'] = this._get_config('token');
          data['$distinct_id'] = this._mixpanel.get_distinct_id();
          var device_id = this._mixpanel.get_property('$device_id');
          var user_id = this._mixpanel.get_property('$user_id');
          var had_persisted_distinct_id = this._mixpanel.get_property('$had_persisted_distinct_id');
          if (device_id) {
            data['$device_id'] = device_id;
          }
          if (user_id) {
            data['$user_id'] = user_id;
          }
          if (had_persisted_distinct_id) {
            data['$had_persisted_distinct_id'] = had_persisted_distinct_id;
          }
          var date_encoded_data = _.encodeDates(data);
          if (!this._identify_called()) {
            this._enqueue(data);
            if (!_.isUndefined(callback)) {
              if (this._get_config('verbose')) {
                callback({
                  status: -1,
                  error: null
                });
              } else {
                callback(-1);
              }
            }
            return _.truncate(date_encoded_data, 255);
          }
          return this._mixpanel._track_or_batch({
            type: 'people',
            data: date_encoded_data,
            endpoint: this._get_config('api_host') + '/' + this._get_config('api_routes')['engage'],
            batcher: this._mixpanel.request_batchers.people
          }, callback);
        };
        MixpanelPeople.prototype._get_config = function (conf_var) {
          return this._mixpanel.get_config(conf_var);
        };
        MixpanelPeople.prototype._identify_called = function () {
          return this._mixpanel._flags.identify_called === true;
        };

        // Queue up engage operations if identify hasn't been called yet.
        MixpanelPeople.prototype._enqueue = function (data) {
          if (SET_ACTION in data) {
            this._mixpanel['persistence']._add_to_people_queue(SET_ACTION, data);
          } else if (SET_ONCE_ACTION in data) {
            this._mixpanel['persistence']._add_to_people_queue(SET_ONCE_ACTION, data);
          } else if (UNSET_ACTION in data) {
            this._mixpanel['persistence']._add_to_people_queue(UNSET_ACTION, data);
          } else if (ADD_ACTION in data) {
            this._mixpanel['persistence']._add_to_people_queue(ADD_ACTION, data);
          } else if (APPEND_ACTION in data) {
            this._mixpanel['persistence']._add_to_people_queue(APPEND_ACTION, data);
          } else if (REMOVE_ACTION in data) {
            this._mixpanel['persistence']._add_to_people_queue(REMOVE_ACTION, data);
          } else if (UNION_ACTION in data) {
            this._mixpanel['persistence']._add_to_people_queue(UNION_ACTION, data);
          } else {
            console$1.error('Invalid call to _enqueue():', data);
          }
        };
        MixpanelPeople.prototype._flush_one_queue = function (action, action_method, callback, queue_to_params_fn) {
          var _this = this;
          var queued_data = _.extend({}, this._mixpanel['persistence'].load_queue(action));
          var action_params = queued_data;
          if (!_.isUndefined(queued_data) && _.isObject(queued_data) && !_.isEmptyObject(queued_data)) {
            _this._mixpanel['persistence']._pop_from_people_queue(action, queued_data);
            _this._mixpanel['persistence'].save();
            if (queue_to_params_fn) {
              action_params = queue_to_params_fn(queued_data);
            }
            action_method.call(_this, action_params, function (response, data) {
              // on bad response, we want to add it back to the queue
              if (response === 0) {
                _this._mixpanel['persistence']._add_to_people_queue(action, queued_data);
              }
              if (!_.isUndefined(callback)) {
                callback(response, data);
              }
            });
          }
        };

        // Flush queued engage operations - order does not matter,
        // and there are network level race conditions anyway
        MixpanelPeople.prototype._flush = function (_set_callback, _add_callback, _append_callback, _set_once_callback, _union_callback, _unset_callback, _remove_callback) {
          var _this = this;
          this._flush_one_queue(SET_ACTION, this.set, _set_callback);
          this._flush_one_queue(SET_ONCE_ACTION, this.set_once, _set_once_callback);
          this._flush_one_queue(UNSET_ACTION, this.unset, _unset_callback, function (queue) {
            return _.keys(queue);
          });
          this._flush_one_queue(ADD_ACTION, this.increment, _add_callback);
          this._flush_one_queue(UNION_ACTION, this.union, _union_callback);

          // we have to fire off each $append individually since there is
          // no concat method server side
          var $append_queue = this._mixpanel['persistence'].load_queue(APPEND_ACTION);
          if (!_.isUndefined($append_queue) && _.isArray($append_queue) && $append_queue.length) {
            var $append_item;
            var append_callback = function append_callback(response, data) {
              if (response === 0) {
                _this._mixpanel['persistence']._add_to_people_queue(APPEND_ACTION, $append_item);
              }
              if (!_.isUndefined(_append_callback)) {
                _append_callback(response, data);
              }
            };
            for (var i = $append_queue.length - 1; i >= 0; i--) {
              $append_queue = this._mixpanel['persistence'].load_queue(APPEND_ACTION);
              $append_item = $append_queue.pop();
              _this._mixpanel['persistence'].save();
              if (!_.isEmptyObject($append_item)) {
                _this.append($append_item, append_callback);
              }
            }
          }

          // same for $remove
          var $remove_queue = this._mixpanel['persistence'].load_queue(REMOVE_ACTION);
          if (!_.isUndefined($remove_queue) && _.isArray($remove_queue) && $remove_queue.length) {
            var $remove_item;
            var remove_callback = function remove_callback(response, data) {
              if (response === 0) {
                _this._mixpanel['persistence']._add_to_people_queue(REMOVE_ACTION, $remove_item);
              }
              if (!_.isUndefined(_remove_callback)) {
                _remove_callback(response, data);
              }
            };
            for (var j = $remove_queue.length - 1; j >= 0; j--) {
              $remove_queue = this._mixpanel['persistence'].load_queue(REMOVE_ACTION);
              $remove_item = $remove_queue.pop();
              _this._mixpanel['persistence'].save();
              if (!_.isEmptyObject($remove_item)) {
                _this.remove($remove_item, remove_callback);
              }
            }
          }
        };
        MixpanelPeople.prototype._is_reserved_property = function (prop) {
          return prop === '$distinct_id' || prop === '$token' || prop === '$device_id' || prop === '$user_id' || prop === '$had_persisted_distinct_id';
        };

        // MixpanelPeople Exports
        MixpanelPeople.prototype['set'] = MixpanelPeople.prototype.set;
        MixpanelPeople.prototype['set_once'] = MixpanelPeople.prototype.set_once;
        MixpanelPeople.prototype['unset'] = MixpanelPeople.prototype.unset;
        MixpanelPeople.prototype['increment'] = MixpanelPeople.prototype.increment;
        MixpanelPeople.prototype['append'] = MixpanelPeople.prototype.append;
        MixpanelPeople.prototype['remove'] = MixpanelPeople.prototype.remove;
        MixpanelPeople.prototype['union'] = MixpanelPeople.prototype.union;
        MixpanelPeople.prototype['track_charge'] = MixpanelPeople.prototype.track_charge;
        MixpanelPeople.prototype['clear_charges'] = MixpanelPeople.prototype.clear_charges;
        MixpanelPeople.prototype['delete_user'] = MixpanelPeople.prototype.delete_user;
        MixpanelPeople.prototype['toString'] = MixpanelPeople.prototype.toString;

        /* eslint camelcase: "off" */

        /*
         * Constants
         */
        /** @const */
        var SET_QUEUE_KEY = '__mps';
        /** @const */
        var SET_ONCE_QUEUE_KEY = '__mpso';
        /** @const */
        var UNSET_QUEUE_KEY = '__mpus';
        /** @const */
        var ADD_QUEUE_KEY = '__mpa';
        /** @const */
        var APPEND_QUEUE_KEY = '__mpap';
        /** @const */
        var REMOVE_QUEUE_KEY = '__mpr';
        /** @const */
        var UNION_QUEUE_KEY = '__mpu';
        // This key is deprecated, but we want to check for it to see whether aliasing is allowed.
        /** @const */
        var PEOPLE_DISTINCT_ID_KEY = '$people_distinct_id';
        /** @const */
        var ALIAS_ID_KEY = '__alias';
        /** @const */
        var EVENT_TIMERS_KEY = '__timers';
        /** @const */
        var RESERVED_PROPERTIES = [SET_QUEUE_KEY, SET_ONCE_QUEUE_KEY, UNSET_QUEUE_KEY, ADD_QUEUE_KEY, APPEND_QUEUE_KEY, REMOVE_QUEUE_KEY, UNION_QUEUE_KEY, PEOPLE_DISTINCT_ID_KEY, ALIAS_ID_KEY, EVENT_TIMERS_KEY];

        /**
         * Mixpanel Persistence Object
         * @constructor
         */
        var MixpanelPersistence = function MixpanelPersistence(config) {
          this['props'] = {};
          this.campaign_params_saved = false;
          if (config['persistence_name']) {
            this.name = 'mp_' + config['persistence_name'];
          } else {
            this.name = 'mp_' + config['token'] + '_mixpanel';
          }
          var storage_type = config['persistence'];
          if (storage_type !== 'cookie' && storage_type !== 'localStorage') {
            console$1.critical('Unknown persistence type ' + storage_type + '; falling back to cookie');
            storage_type = config['persistence'] = 'cookie';
          }
          if (storage_type === 'localStorage' && _.localStorage.is_supported()) {
            this.storage = _.localStorage;
          } else {
            this.storage = _.cookie;
          }
          this.load();
          this.update_config(config);
          this.upgrade();
          this.save();
        };
        MixpanelPersistence.prototype.properties = function () {
          var p = {};
          this.load();

          // Filter out reserved properties
          _.each(this['props'], function (v, k) {
            if (!_.include(RESERVED_PROPERTIES, k)) {
              p[k] = v;
            }
          });
          return p;
        };
        MixpanelPersistence.prototype.load = function () {
          if (this.disabled) {
            return;
          }
          var entry = this.storage.parse(this.name);
          if (entry) {
            this['props'] = _.extend({}, entry);
          }
        };
        MixpanelPersistence.prototype.upgrade = function () {
          var old_cookie, old_localstorage;

          // if transferring from cookie to localStorage or vice-versa, copy existing
          // super properties over to new storage mode
          if (this.storage === _.localStorage) {
            old_cookie = _.cookie.parse(this.name);
            _.cookie.remove(this.name);
            _.cookie.remove(this.name, true);
            if (old_cookie) {
              this.register_once(old_cookie);
            }
          } else if (this.storage === _.cookie) {
            old_localstorage = _.localStorage.parse(this.name);
            _.localStorage.remove(this.name);
            if (old_localstorage) {
              this.register_once(old_localstorage);
            }
          }
        };
        MixpanelPersistence.prototype.save = function () {
          if (this.disabled) {
            return;
          }
          this.storage.set(this.name, _.JSONEncode(this['props']), this.expire_days, this.cross_subdomain, this.secure, this.cross_site, this.cookie_domain);
        };
        MixpanelPersistence.prototype.load_prop = function (key) {
          this.load();
          return this['props'][key];
        };
        MixpanelPersistence.prototype.remove = function () {
          // remove both domain and subdomain cookies
          this.storage.remove(this.name, false, this.cookie_domain);
          this.storage.remove(this.name, true, this.cookie_domain);
        };

        // removes the storage entry and deletes all loaded data
        // forced name for tests
        MixpanelPersistence.prototype.clear = function () {
          this.remove();
          this['props'] = {};
        };

        /**
        * @param {Object} props
        * @param {*=} default_value
        * @param {number=} days
        */
        MixpanelPersistence.prototype.register_once = function (props, default_value, days) {
          if (_.isObject(props)) {
            if (typeof default_value === 'undefined') {
              default_value = 'None';
            }
            this.expire_days = typeof days === 'undefined' ? this.default_expiry : days;
            this.load();
            _.each(props, function (val, prop) {
              if (!this['props'].hasOwnProperty(prop) || this['props'][prop] === default_value) {
                this['props'][prop] = val;
              }
            }, this);
            this.save();
            return true;
          }
          return false;
        };

        /**
        * @param {Object} props
        * @param {number=} days
        */
        MixpanelPersistence.prototype.register = function (props, days) {
          if (_.isObject(props)) {
            this.expire_days = typeof days === 'undefined' ? this.default_expiry : days;
            this.load();
            _.extend(this['props'], props);
            this.save();
            return true;
          }
          return false;
        };
        MixpanelPersistence.prototype.unregister = function (prop) {
          this.load();
          if (prop in this['props']) {
            delete this['props'][prop];
            this.save();
          }
        };
        MixpanelPersistence.prototype.update_search_keyword = function (referrer) {
          this.register(_.info.searchInfo(referrer));
        };

        // EXPORTED METHOD, we test this directly.
        MixpanelPersistence.prototype.update_referrer_info = function (referrer) {
          // If referrer doesn't exist, we want to note the fact that it was type-in traffic.
          this.register_once({
            '$initial_referrer': referrer || '$direct',
            '$initial_referring_domain': _.info.referringDomain(referrer) || '$direct'
          }, '');
        };
        MixpanelPersistence.prototype.get_referrer_info = function () {
          return _.strip_empty_properties({
            '$initial_referrer': this['props']['$initial_referrer'],
            '$initial_referring_domain': this['props']['$initial_referring_domain']
          });
        };
        MixpanelPersistence.prototype.update_config = function (config) {
          this.default_expiry = this.expire_days = config['cookie_expiration'];
          this.set_disabled(config['disable_persistence']);
          this.set_cookie_domain(config['cookie_domain']);
          this.set_cross_site(config['cross_site_cookie']);
          this.set_cross_subdomain(config['cross_subdomain_cookie']);
          this.set_secure(config['secure_cookie']);
        };
        MixpanelPersistence.prototype.set_disabled = function (disabled) {
          this.disabled = disabled;
          if (this.disabled) {
            this.remove();
          } else {
            this.save();
          }
        };
        MixpanelPersistence.prototype.set_cookie_domain = function (cookie_domain) {
          if (cookie_domain !== this.cookie_domain) {
            this.remove();
            this.cookie_domain = cookie_domain;
            this.save();
          }
        };
        MixpanelPersistence.prototype.set_cross_site = function (cross_site) {
          if (cross_site !== this.cross_site) {
            this.cross_site = cross_site;
            this.remove();
            this.save();
          }
        };
        MixpanelPersistence.prototype.set_cross_subdomain = function (cross_subdomain) {
          if (cross_subdomain !== this.cross_subdomain) {
            this.cross_subdomain = cross_subdomain;
            this.remove();
            this.save();
          }
        };
        MixpanelPersistence.prototype.get_cross_subdomain = function () {
          return this.cross_subdomain;
        };
        MixpanelPersistence.prototype.set_secure = function (secure) {
          if (secure !== this.secure) {
            this.secure = secure ? true : false;
            this.remove();
            this.save();
          }
        };
        MixpanelPersistence.prototype._add_to_people_queue = function (queue, data) {
          var q_key = this._get_queue_key(queue),
            q_data = data[queue],
            set_q = this._get_or_create_queue(SET_ACTION),
            set_once_q = this._get_or_create_queue(SET_ONCE_ACTION),
            unset_q = this._get_or_create_queue(UNSET_ACTION),
            add_q = this._get_or_create_queue(ADD_ACTION),
            union_q = this._get_or_create_queue(UNION_ACTION),
            remove_q = this._get_or_create_queue(REMOVE_ACTION, []),
            append_q = this._get_or_create_queue(APPEND_ACTION, []);
          if (q_key === SET_QUEUE_KEY) {
            // Update the set queue - we can override any existing values
            _.extend(set_q, q_data);
            // if there was a pending increment, override it
            // with the set.
            this._pop_from_people_queue(ADD_ACTION, q_data);
            // if there was a pending union, override it
            // with the set.
            this._pop_from_people_queue(UNION_ACTION, q_data);
            this._pop_from_people_queue(UNSET_ACTION, q_data);
          } else if (q_key === SET_ONCE_QUEUE_KEY) {
            // only queue the data if there is not already a set_once call for it.
            _.each(q_data, function (v, k) {
              if (!(k in set_once_q)) {
                set_once_q[k] = v;
              }
            });
            this._pop_from_people_queue(UNSET_ACTION, q_data);
          } else if (q_key === UNSET_QUEUE_KEY) {
            _.each(q_data, function (prop) {
              // undo previously-queued actions on this key
              _.each([set_q, set_once_q, add_q, union_q], function (enqueued_obj) {
                if (prop in enqueued_obj) {
                  delete enqueued_obj[prop];
                }
              });
              _.each(append_q, function (append_obj) {
                if (prop in append_obj) {
                  delete append_obj[prop];
                }
              });
              unset_q[prop] = true;
            });
          } else if (q_key === ADD_QUEUE_KEY) {
            _.each(q_data, function (v, k) {
              // If it exists in the set queue, increment
              // the value
              if (k in set_q) {
                set_q[k] += v;
              } else {
                // If it doesn't exist, update the add
                // queue
                if (!(k in add_q)) {
                  add_q[k] = 0;
                }
                add_q[k] += v;
              }
            }, this);
            this._pop_from_people_queue(UNSET_ACTION, q_data);
          } else if (q_key === UNION_QUEUE_KEY) {
            _.each(q_data, function (v, k) {
              if (_.isArray(v)) {
                if (!(k in union_q)) {
                  union_q[k] = [];
                }
                // We may send duplicates, the server will dedup them.
                union_q[k] = union_q[k].concat(v);
              }
            });
            this._pop_from_people_queue(UNSET_ACTION, q_data);
          } else if (q_key === REMOVE_QUEUE_KEY) {
            remove_q.push(q_data);
            this._pop_from_people_queue(APPEND_ACTION, q_data);
          } else if (q_key === APPEND_QUEUE_KEY) {
            append_q.push(q_data);
            this._pop_from_people_queue(UNSET_ACTION, q_data);
          }
          console$1.log('MIXPANEL PEOPLE REQUEST (QUEUED, PENDING IDENTIFY):');
          console$1.log(data);
          this.save();
        };
        MixpanelPersistence.prototype._pop_from_people_queue = function (queue, data) {
          var q = this['props'][this._get_queue_key(queue)];
          if (!_.isUndefined(q)) {
            _.each(data, function (v, k) {
              if (queue === APPEND_ACTION || queue === REMOVE_ACTION) {
                // list actions: only remove if both k+v match
                // e.g. remove should not override append in a case like
                // append({foo: 'bar'}); remove({foo: 'qux'})
                _.each(q, function (queued_action) {
                  if (queued_action[k] === v) {
                    delete queued_action[k];
                  }
                });
              } else {
                delete q[k];
              }
            }, this);
          }
        };
        MixpanelPersistence.prototype.load_queue = function (queue) {
          return this.load_prop(this._get_queue_key(queue));
        };
        MixpanelPersistence.prototype._get_queue_key = function (queue) {
          if (queue === SET_ACTION) {
            return SET_QUEUE_KEY;
          } else if (queue === SET_ONCE_ACTION) {
            return SET_ONCE_QUEUE_KEY;
          } else if (queue === UNSET_ACTION) {
            return UNSET_QUEUE_KEY;
          } else if (queue === ADD_ACTION) {
            return ADD_QUEUE_KEY;
          } else if (queue === APPEND_ACTION) {
            return APPEND_QUEUE_KEY;
          } else if (queue === REMOVE_ACTION) {
            return REMOVE_QUEUE_KEY;
          } else if (queue === UNION_ACTION) {
            return UNION_QUEUE_KEY;
          } else {
            console$1.error('Invalid queue:', queue);
          }
        };
        MixpanelPersistence.prototype._get_or_create_queue = function (queue, default_val) {
          var key = this._get_queue_key(queue);
          default_val = _.isUndefined(default_val) ? {} : default_val;
          return this['props'][key] || (this['props'][key] = default_val);
        };
        MixpanelPersistence.prototype.set_event_timer = function (event_name, timestamp) {
          var timers = this.load_prop(EVENT_TIMERS_KEY) || {};
          timers[event_name] = timestamp;
          this['props'][EVENT_TIMERS_KEY] = timers;
          this.save();
        };
        MixpanelPersistence.prototype.remove_event_timer = function (event_name) {
          var timers = this.load_prop(EVENT_TIMERS_KEY) || {};
          var timestamp = timers[event_name];
          if (!_.isUndefined(timestamp)) {
            delete this['props'][EVENT_TIMERS_KEY][event_name];
            this.save();
          }
          return timestamp;
        };

        /* eslint camelcase: "off" */

        /*
         * Mixpanel JS Library
         *
         * Copyright 2012, Mixpanel, Inc. All Rights Reserved
         * http://mixpanel.com/
         *
         * Includes portions of Underscore.js
         * http://documentcloud.github.com/underscore/
         * (c) 2011 Jeremy Ashkenas, DocumentCloud Inc.
         * Released under the MIT License.
         */

        // ==ClosureCompiler==
        // @compilation_level ADVANCED_OPTIMIZATIONS
        // @output_file_name mixpanel-2.8.min.js
        // ==/ClosureCompiler==

        /*
        SIMPLE STYLE GUIDE:
         this.x === public function
        this._x === internal - only use within this file
        this.__x === private - only use within the class
         Globals should be all caps
        */

        var init_type; // MODULE or SNIPPET loader
        // allow bundlers to specify how extra code (recorder bundle) should be loaded
        // eslint-disable-next-line no-unused-vars
        var load_extra_bundle = function load_extra_bundle(src, _onload) {
          throw new Error(src + ' not available in this build.');
        };
        var mixpanel_master; // main mixpanel instance / object
        var INIT_MODULE = 0;
        var INIT_SNIPPET = 1;
        var IDENTITY_FUNC = function IDENTITY_FUNC(x) {
          return x;
        };
        var NOOP_FUNC = function NOOP_FUNC() {};

        /** @const */
        var PRIMARY_INSTANCE_NAME = 'mixpanel';
        /** @const */
        var PAYLOAD_TYPE_BASE64 = 'base64';
        /** @const */
        var PAYLOAD_TYPE_JSON = 'json';
        /** @const */
        var DEVICE_ID_PREFIX = '$device:';

        /*
         * Dynamic... constants? Is that an oxymoron?
         */
        // http://hacks.mozilla.org/2009/07/cross-site-xmlhttprequest-with-cors/
        // https://developer.mozilla.org/en-US/docs/DOM/XMLHttpRequest#withCredentials
        var USE_XHR = win.XMLHttpRequest && 'withCredentials' in new XMLHttpRequest();

        // IE<10 does not support cross-origin XHR's but script tags
        // with defer won't block window.onload; ENQUEUE_REQUESTS
        // should only be true for Opera<12
        var ENQUEUE_REQUESTS = !USE_XHR && userAgent.indexOf('MSIE') === -1 && userAgent.indexOf('Mozilla') === -1;

        // save reference to navigator.sendBeacon so it can be minified
        var sendBeacon = null;
        if (navigator['sendBeacon']) {
          sendBeacon = function sendBeacon() {
            // late reference to navigator.sendBeacon to allow patching/spying
            return navigator['sendBeacon'].apply(navigator, arguments);
          };
        }
        var DEFAULT_API_ROUTES = {
          'track': 'track/',
          'engage': 'engage/',
          'groups': 'groups/',
          'record': 'record/'
        };

        /*
         * Module-level globals
         */
        var DEFAULT_CONFIG = {
          'api_host': 'https://api-js.mixpanel.com',
          'api_routes': DEFAULT_API_ROUTES,
          'api_method': 'POST',
          'api_transport': 'XHR',
          'api_payload_format': PAYLOAD_TYPE_BASE64,
          'app_host': 'https://mixpanel.com',
          'cdn': 'https://cdn.mxpnl.com',
          'cross_site_cookie': false,
          'cross_subdomain_cookie': true,
          'error_reporter': NOOP_FUNC,
          'persistence': 'cookie',
          'persistence_name': '',
          'cookie_domain': '',
          'cookie_name': '',
          'loaded': NOOP_FUNC,
          'mp_loader': null,
          'track_marketing': true,
          'track_pageview': false,
          'skip_first_touch_marketing': false,
          'store_google': true,
          'stop_utm_persistence': false,
          'save_referrer': true,
          'test': false,
          'verbose': false,
          'img': false,
          'debug': false,
          'track_links_timeout': 300,
          'cookie_expiration': 365,
          'upgrade': false,
          'disable_persistence': false,
          'disable_cookie': false,
          'secure_cookie': false,
          'ip': true,
          'opt_out_tracking_by_default': false,
          'opt_out_persistence_by_default': false,
          'opt_out_tracking_persistence_type': 'localStorage',
          'opt_out_tracking_cookie_prefix': null,
          'property_blacklist': [],
          'xhr_headers': {},
          // { header: value, header2: value }
          'ignore_dnt': false,
          'batch_requests': true,
          'batch_size': 50,
          'batch_flush_interval_ms': 5000,
          'batch_request_timeout_ms': 90000,
          'batch_autostart': true,
          'hooks': {},
          'record_block_class': new RegExp('^(mp-block|fs-exclude|amp-block|rr-block|ph-no-capture)$'),
          'record_block_selector': 'img, video',
          'record_collect_fonts': false,
          'record_idle_timeout_ms': 30 * 60 * 1000,
          // 30 minutes
          'record_inline_images': false,
          'record_mask_text_class': new RegExp('^(mp-mask|fs-mask|amp-mask|rr-mask|ph-mask)$'),
          'record_mask_text_selector': '*',
          'record_max_ms': MAX_RECORDING_MS,
          'record_sessions_percent': 0,
          'recorder_src': 'https://cdn.mxpnl.com/libs/mixpanel-recorder.min.js'
        };
        var DOM_LOADED = false;

        /**
         * Mixpanel Library Object
         * @constructor
         */
        var MixpanelLib = function MixpanelLib() {};

        /**
         * create_mplib(token:string, config:object, name:string)
         *
         * This function is used by the init method of MixpanelLib objects
         * as well as the main initializer at the end of the JSLib (that
         * initializes document.mixpanel as well as any additional instances
         * declared before this file has loaded).
         */
        var create_mplib = function create_mplib(token, config, name) {
          var instance,
            target = name === PRIMARY_INSTANCE_NAME ? mixpanel_master : mixpanel_master[name];
          if (target && init_type === INIT_MODULE) {
            instance = target;
          } else {
            if (target && !_.isArray(target)) {
              console$1.error('You have already initialized ' + name);
              return;
            }
            instance = new MixpanelLib();
          }
          instance._cached_groups = {}; // cache groups in a pool

          instance._init(token, config, name);
          instance['people'] = new MixpanelPeople();
          instance['people']._init(instance);
          if (!instance.get_config('skip_first_touch_marketing')) {
            // We need null UTM params in the object because
            // UTM parameters act as a tuple. If any UTM param
            // is present, then we set all UTM params including
            // empty ones together
            var utm_params = _.info.campaignParams(null);
            var initial_utm_params = {};
            var has_utm = false;
            _.each(utm_params, function (utm_value, utm_key) {
              initial_utm_params['initial_' + utm_key] = utm_value;
              if (utm_value) {
                has_utm = true;
              }
            });
            if (has_utm) {
              instance['people'].set_once(initial_utm_params);
            }
          }

          // if any instance on the page has debug = true, we set the
          // global debug to be true
          Config.DEBUG = Config.DEBUG || instance.get_config('debug');

          // if target is not defined, we called init after the lib already
          // loaded, so there won't be an array of things to execute
          if (!_.isUndefined(target) && _.isArray(target)) {
            // Crunch through the people queue first - we queue this data up &
            // flush on identify, so it's better to do all these operations first
            instance._execute_array.call(instance['people'], target['people']);
            instance._execute_array(target);
          }
          return instance;
        };

        // Initialization methods

        /**
         * This function initializes a new instance of the Mixpanel tracking object.
         * All new instances are added to the main mixpanel object as sub properties (such as
         * mixpanel.library_name) and also returned by this function. To define a
         * second instance on the page, you would call:
         *
         *     mixpanel.init('new token', { your: 'config' }, 'library_name');
         *
         * and use it like so:
         *
         *     mixpanel.library_name.track(...);
         *
         * @param {String} token   Your Mixpanel API token
         * @param {Object} [config]  A dictionary of config options to override. <a href="https://github.com/mixpanel/mixpanel-js/blob/v2.46.0/src/mixpanel-core.js#L88-L127">See a list of default config options</a>.
         * @param {String} [name]    The name for the new mixpanel instance that you want created
         */
        MixpanelLib.prototype.init = function (token, config, name) {
          if (_.isUndefined(name)) {
            this.report_error('You must name your new library: init(token, config, name)');
            return;
          }
          if (name === PRIMARY_INSTANCE_NAME) {
            this.report_error('You must initialize the main mixpanel object right after you include the Mixpanel js snippet');
            return;
          }
          var instance = create_mplib(token, config, name);
          mixpanel_master[name] = instance;
          instance._loaded();
          return instance;
        };

        // mixpanel._init(token:string, config:object, name:string)
        //
        // This function sets up the current instance of the mixpanel
        // library.  The difference between this method and the init(...)
        // method is this one initializes the actual instance, whereas the
        // init(...) method sets up a new library and calls _init on it.
        //
        MixpanelLib.prototype._init = function (token, config, name) {
          config = config || {};
          this['__loaded'] = true;
          this['config'] = {};
          var variable_features = {};

          // default to JSON payload for standard mixpanel.com API hosts
          if (!('api_payload_format' in config)) {
            var api_host = config['api_host'] || DEFAULT_CONFIG['api_host'];
            if (api_host.match(/\.mixpanel\.com/)) {
              variable_features['api_payload_format'] = PAYLOAD_TYPE_JSON;
            }
          }
          this.set_config(_.extend({}, DEFAULT_CONFIG, variable_features, config, {
            'name': name,
            'token': token,
            'callback_fn': (name === PRIMARY_INSTANCE_NAME ? name : PRIMARY_INSTANCE_NAME + '.' + name) + '._jsc'
          }));
          this['_jsc'] = NOOP_FUNC;
          this.__dom_loaded_queue = [];
          this.__request_queue = [];
          this.__disabled_events = [];
          this._flags = {
            'disable_all_events': false,
            'identify_called': false
          };

          // set up request queueing/batching
          this.request_batchers = {};
          this._batch_requests = this.get_config('batch_requests');
          if (this._batch_requests) {
            if (!_.localStorage.is_supported(true) || !USE_XHR) {
              this._batch_requests = false;
              console$1.log('Turning off Mixpanel request-queueing; needs XHR and localStorage support');
              _.each(this.get_batcher_configs(), function (batcher_config) {
                console$1.log('Clearing batch queue ' + batcher_config.queue_key);
                _.localStorage.remove(batcher_config.queue_key);
              });
            } else {
              this.init_batchers();
              if (sendBeacon && win.addEventListener) {
                // Before page closes or hides (user tabs away etc), attempt to flush any events
                // queued up via navigator.sendBeacon. Since sendBeacon doesn't report success/failure,
                // events will not be removed from the persistent store; if the site is loaded again,
                // the events will be flushed again on startup and deduplicated on the Mixpanel server
                // side.
                // There is no reliable way to capture only page close events, so we lean on the
                // visibilitychange and pagehide events as recommended at
                // https://developer.mozilla.org/en-US/docs/Web/API/Window/unload_event#usage_notes.
                // These events fire when the user clicks away from the current page/tab, so will occur
                // more frequently than page unload, but are the only mechanism currently for capturing
                // this scenario somewhat reliably.
                var flush_on_unload = _.bind(function () {
                  if (!this.request_batchers.events.stopped) {
                    this.request_batchers.events.flush({
                      unloading: true
                    });
                  }
                }, this);
                win.addEventListener('pagehide', function (ev) {
                  if (ev['persisted']) {
                    flush_on_unload();
                  }
                });
                win.addEventListener('visibilitychange', function () {
                  if (document$1['visibilityState'] === 'hidden') {
                    flush_on_unload();
                  }
                });
              }
            }
          }
          this['persistence'] = this['cookie'] = new MixpanelPersistence(this['config']);
          this.unpersisted_superprops = {};
          this._gdpr_init();
          var uuid = _.UUID();
          if (!this.get_distinct_id()) {
            // There is no need to set the distinct id
            // or the device id if something was already stored
            // in the persitence
            this.register_once({
              'distinct_id': DEVICE_ID_PREFIX + uuid,
              '$device_id': uuid
            }, '');
          }
          var track_pageview_option = this.get_config('track_pageview');
          if (track_pageview_option) {
            this._init_url_change_tracking(track_pageview_option);
          }
          if (this.get_config('record_sessions_percent') > 0 && Math.random() * 100 <= this.get_config('record_sessions_percent')) {
            this.start_session_recording();
          }
        };
        MixpanelLib.prototype.start_session_recording = addOptOutCheckMixpanelLib(function () {
          if (!win['MutationObserver']) {
            console$1.critical('Browser does not support MutationObserver; skipping session recording');
            return;
          }
          var handleLoadedRecorder = _.bind(function () {
            this._recorder = this._recorder || new win['__mp_recorder'](this);
            this._recorder['startRecording']();
          }, this);
          if (_.isUndefined(win['__mp_recorder'])) {
            load_extra_bundle(this.get_config('recorder_src'), handleLoadedRecorder);
          } else {
            handleLoadedRecorder();
          }
        });
        MixpanelLib.prototype.stop_session_recording = function () {
          if (this._recorder) {
            this._recorder['stopRecording']();
          } else {
            console$1.critical('Session recorder module not loaded');
          }
        };
        MixpanelLib.prototype.get_session_recording_properties = function () {
          var props = {};
          if (this._recorder) {
            var replay_id = this._recorder['replayId'];
            if (replay_id) {
              props['$mp_replay_id'] = replay_id;
            }
          }
          return props;
        };

        // Private methods

        MixpanelLib.prototype._loaded = function () {
          this.get_config('loaded')(this);
          this._set_default_superprops();
          this['people'].set_once(this['persistence'].get_referrer_info());

          // `store_google` is now deprecated and previously stored UTM parameters are cleared
          // from persistence by default.
          if (this.get_config('store_google') && this.get_config('stop_utm_persistence')) {
            var utm_params = _.info.campaignParams(null);
            _.each(utm_params, function (_utm_value, utm_key) {
              // We need to unregister persisted UTM parameters so old values
              // are not mixed with the new UTM parameters
              this.unregister(utm_key);
            }.bind(this));
          }
        };

        // update persistence with info on referrer, UTM params, etc
        MixpanelLib.prototype._set_default_superprops = function () {
          this['persistence'].update_search_keyword(document$1.referrer);
          // Registering super properties for UTM persistence by 'store_google' is deprecated.
          if (this.get_config('store_google') && !this.get_config('stop_utm_persistence')) {
            this.register(_.info.campaignParams());
          }
          if (this.get_config('save_referrer')) {
            this['persistence'].update_referrer_info(document$1.referrer);
          }
        };
        MixpanelLib.prototype._dom_loaded = function () {
          _.each(this.__dom_loaded_queue, function (item) {
            this._track_dom.apply(this, item);
          }, this);
          if (!this.has_opted_out_tracking()) {
            _.each(this.__request_queue, function (item) {
              this._send_request.apply(this, item);
            }, this);
          }
          delete this.__dom_loaded_queue;
          delete this.__request_queue;
        };
        MixpanelLib.prototype._track_dom = function (DomClass, args) {
          if (this.get_config('img')) {
            this.report_error('You can\'t use DOM tracking functions with img = true.');
            return false;
          }
          if (!DOM_LOADED) {
            this.__dom_loaded_queue.push([DomClass, args]);
            return false;
          }
          var dt = new DomClass().init(this);
          return dt.track.apply(dt, args);
        };
        MixpanelLib.prototype._init_url_change_tracking = function (track_pageview_option) {
          var previous_tracked_url = '';
          var tracked = this.track_pageview();
          if (tracked) {
            previous_tracked_url = _.info.currentUrl();
          }
          if (_.include(['full-url', 'url-with-path-and-query-string', 'url-with-path'], track_pageview_option)) {
            win.addEventListener('popstate', function () {
              win.dispatchEvent(new Event('mp_locationchange'));
            });
            win.addEventListener('hashchange', function () {
              win.dispatchEvent(new Event('mp_locationchange'));
            });
            var nativePushState = win.history.pushState;
            if (typeof nativePushState === 'function') {
              win.history.pushState = function (state, unused, url) {
                nativePushState.call(win.history, state, unused, url);
                win.dispatchEvent(new Event('mp_locationchange'));
              };
            }
            var nativeReplaceState = win.history.replaceState;
            if (typeof nativeReplaceState === 'function') {
              win.history.replaceState = function (state, unused, url) {
                nativeReplaceState.call(win.history, state, unused, url);
                win.dispatchEvent(new Event('mp_locationchange'));
              };
            }
            win.addEventListener('mp_locationchange', function () {
              var current_url = _.info.currentUrl();
              var should_track = false;
              if (track_pageview_option === 'full-url') {
                should_track = current_url !== previous_tracked_url;
              } else if (track_pageview_option === 'url-with-path-and-query-string') {
                should_track = current_url.split('#')[0] !== previous_tracked_url.split('#')[0];
              } else if (track_pageview_option === 'url-with-path') {
                should_track = current_url.split('#')[0].split('?')[0] !== previous_tracked_url.split('#')[0].split('?')[0];
              }
              if (should_track) {
                var tracked = this.track_pageview();
                if (tracked) {
                  previous_tracked_url = current_url;
                }
              }
            }.bind(this));
          }
        };

        /**
         * _prepare_callback() should be called by callers of _send_request for use
         * as the callback argument.
         *
         * If there is no callback, this returns null.
         * If we are going to make XHR/XDR requests, this returns a function.
         * If we are going to use script tags, this returns a string to use as the
         * callback GET param.
         */
        MixpanelLib.prototype._prepare_callback = function (callback, data) {
          if (_.isUndefined(callback)) {
            return null;
          }
          if (USE_XHR) {
            var callback_function = function callback_function(response) {
              callback(response, data);
            };
            return callback_function;
          } else {
            // if the user gives us a callback, we store as a random
            // property on this instances jsc function and update our
            // callback string to reflect that.
            var jsc = this['_jsc'];
            var randomized_cb = '' + Math.floor(Math.random() * 100000000);
            var callback_string = this.get_config('callback_fn') + '[' + randomized_cb + ']';
            jsc[randomized_cb] = function (response) {
              delete jsc[randomized_cb];
              callback(response, data);
            };
            return callback_string;
          }
        };
        MixpanelLib.prototype._send_request = function (url, data, options, callback) {
          var succeeded = true;
          if (ENQUEUE_REQUESTS) {
            this.__request_queue.push(arguments);
            return succeeded;
          }
          var DEFAULT_OPTIONS = {
            method: this.get_config('api_method'),
            transport: this.get_config('api_transport'),
            verbose: this.get_config('verbose')
          };
          var body_data = null;
          if (!callback && (_.isFunction(options) || typeof options === 'string')) {
            callback = options;
            options = null;
          }
          options = _.extend(DEFAULT_OPTIONS, options || {});
          if (!USE_XHR) {
            options.method = 'GET';
          }
          var use_post = options.method === 'POST';
          var use_sendBeacon = sendBeacon && use_post && options.transport.toLowerCase() === 'sendbeacon';

          // needed to correctly format responses
          var verbose_mode = options.verbose;
          if (data['verbose']) {
            verbose_mode = true;
          }
          if (this.get_config('test')) {
            data['test'] = 1;
          }
          if (verbose_mode) {
            data['verbose'] = 1;
          }
          if (this.get_config('img')) {
            data['img'] = 1;
          }
          if (!USE_XHR) {
            if (callback) {
              data['callback'] = callback;
            } else if (verbose_mode || this.get_config('test')) {
              // Verbose output (from verbose mode, or an error in test mode) is a json blob,
              // which by itself is not valid javascript. Without a callback, this verbose output will
              // cause an error when returned via jsonp, so we force a no-op callback param.
              // See the ECMA script spec: http://www.ecma-international.org/ecma-262/5.1/#sec-12.4
              data['callback'] = '(function(){})';
            }
          }
          data['ip'] = this.get_config('ip') ? 1 : 0;
          data['_'] = new Date().getTime().toString();
          if (use_post) {
            body_data = 'data=' + encodeURIComponent(data['data']);
            delete data['data'];
          }
          url += '?' + _.HTTPBuildQuery(data);
          var lib = this;
          if ('img' in data) {
            var img = document$1.createElement('img');
            img.src = url;
            document$1.body.appendChild(img);
          } else if (use_sendBeacon) {
            try {
              succeeded = sendBeacon(url, body_data);
            } catch (e) {
              lib.report_error(e);
              succeeded = false;
            }
            try {
              if (callback) {
                callback(succeeded ? 1 : 0);
              }
            } catch (e) {
              lib.report_error(e);
            }
          } else if (USE_XHR) {
            try {
              var req = new XMLHttpRequest();
              req.open(options.method, url, true);
              var headers = this.get_config('xhr_headers');
              if (use_post) {
                headers['Content-Type'] = 'application/x-www-form-urlencoded';
              }
              _.each(headers, function (headerValue, headerName) {
                req.setRequestHeader(headerName, headerValue);
              });
              if (options.timeout_ms && typeof req.timeout !== 'undefined') {
                req.timeout = options.timeout_ms;
                var start_time = new Date().getTime();
              }

              // send the mp_optout cookie
              // withCredentials cannot be modified until after calling .open on Android and Mobile Safari
              req.withCredentials = true;
              req.onreadystatechange = function () {
                if (req.readyState === 4) {
                  // XMLHttpRequest.DONE == 4, except in safari 4
                  if (req.status === 200) {
                    if (callback) {
                      if (verbose_mode) {
                        var response;
                        try {
                          response = _.JSONDecode(req.responseText);
                        } catch (e) {
                          lib.report_error(e);
                          if (options.ignore_json_errors) {
                            response = req.responseText;
                          } else {
                            return;
                          }
                        }
                        callback(response);
                      } else {
                        callback(Number(req.responseText));
                      }
                    }
                  } else {
                    var error;
                    if (req.timeout && !req.status && new Date().getTime() - start_time >= req.timeout) {
                      error = 'timeout';
                    } else {
                      error = 'Bad HTTP status: ' + req.status + ' ' + req.statusText;
                    }
                    lib.report_error(error);
                    if (callback) {
                      if (verbose_mode) {
                        var response_headers = req['responseHeaders'] || {};
                        callback({
                          status: 0,
                          httpStatusCode: req['status'],
                          error: error,
                          retryAfter: response_headers['Retry-After']
                        });
                      } else {
                        callback(0);
                      }
                    }
                  }
                }
              };
              req.send(body_data);
            } catch (e) {
              lib.report_error(e);
              succeeded = false;
            }
          } else {
            var script = document$1.createElement('script');
            script.type = 'text/javascript';
            script.async = true;
            script.defer = true;
            script.src = url;
            var s = document$1.getElementsByTagName('script')[0];
            s.parentNode.insertBefore(script, s);
          }
          return succeeded;
        };

        /**
         * _execute_array() deals with processing any mixpanel function
         * calls that were called before the Mixpanel library were loaded
         * (and are thus stored in an array so they can be called later)
         *
         * Note: we fire off all the mixpanel function calls && user defined
         * functions BEFORE we fire off mixpanel tracking calls. This is so
         * identify/register/set_config calls can properly modify early
         * tracking calls.
         *
         * @param {Array} array
         */
        MixpanelLib.prototype._execute_array = function (array) {
          var fn_name,
            alias_calls = [],
            other_calls = [],
            tracking_calls = [];
          _.each(array, function (item) {
            if (item) {
              fn_name = item[0];
              if (_.isArray(fn_name)) {
                tracking_calls.push(item); // chained call e.g. mixpanel.get_group().set()
              } else if (typeof item === 'function') {
                item.call(this);
              } else if (_.isArray(item) && fn_name === 'alias') {
                alias_calls.push(item);
              } else if (_.isArray(item) && fn_name.indexOf('track') !== -1 && typeof this[fn_name] === 'function') {
                tracking_calls.push(item);
              } else {
                other_calls.push(item);
              }
            }
          }, this);
          var execute = function execute(calls, context) {
            _.each(calls, function (item) {
              if (_.isArray(item[0])) {
                // chained call
                var caller = context;
                _.each(item, function (call) {
                  caller = caller[call[0]].apply(caller, call.slice(1));
                });
              } else {
                this[item[0]].apply(this, item.slice(1));
              }
            }, context);
          };
          execute(alias_calls, this);
          execute(other_calls, this);
          execute(tracking_calls, this);
        };

        // request queueing utils

        MixpanelLib.prototype.are_batchers_initialized = function () {
          return !!this.request_batchers.events;
        };
        MixpanelLib.prototype.get_batcher_configs = function () {
          var queue_prefix = '__mpq_' + this.get_config('token');
          var api_routes = this.get_config('api_routes');
          this._batcher_configs = this._batcher_configs || {
            events: {
              type: 'events',
              endpoint: '/' + api_routes['track'],
              queue_key: queue_prefix + '_ev'
            },
            people: {
              type: 'people',
              endpoint: '/' + api_routes['engage'],
              queue_key: queue_prefix + '_pp'
            },
            groups: {
              type: 'groups',
              endpoint: '/' + api_routes['groups'],
              queue_key: queue_prefix + '_gr'
            }
          };
          return this._batcher_configs;
        };
        MixpanelLib.prototype.init_batchers = function () {
          if (!this.are_batchers_initialized()) {
            var batcher_for = _.bind(function (attrs) {
              return new RequestBatcher(attrs.queue_key, {
                libConfig: this['config'],
                errorReporter: this.get_config('error_reporter'),
                sendRequestFunc: _.bind(function (data, options, cb) {
                  this._send_request(this.get_config('api_host') + attrs.endpoint, this._encode_data_for_request(data), options, this._prepare_callback(cb, data));
                }, this),
                beforeSendHook: _.bind(function (item) {
                  return this._run_hook('before_send_' + attrs.type, item);
                }, this),
                stopAllBatchingFunc: _.bind(this.stop_batch_senders, this),
                usePersistence: true
              });
            }, this);
            var batcher_configs = this.get_batcher_configs();
            this.request_batchers = {
              events: batcher_for(batcher_configs.events),
              people: batcher_for(batcher_configs.people),
              groups: batcher_for(batcher_configs.groups)
            };
          }
          if (this.get_config('batch_autostart')) {
            this.start_batch_senders();
          }
        };
        MixpanelLib.prototype.start_batch_senders = function () {
          this._batchers_were_started = true;
          if (this.are_batchers_initialized()) {
            this._batch_requests = true;
            _.each(this.request_batchers, function (batcher) {
              batcher.start();
            });
          }
        };
        MixpanelLib.prototype.stop_batch_senders = function () {
          this._batch_requests = false;
          _.each(this.request_batchers, function (batcher) {
            batcher.stop();
            batcher.clear();
          });
        };

        /**
         * push() keeps the standard async-array-push
         * behavior around after the lib is loaded.
         * This is only useful for external integrations that
         * do not wish to rely on our convenience methods
         * (created in the snippet).
         *
         * ### Usage:
         *     mixpanel.push(['register', { a: 'b' }]);
         *
         * @param {Array} item A [function_name, args...] array to be executed
         */
        MixpanelLib.prototype.push = function (item) {
          this._execute_array([item]);
        };

        /**
         * Disable events on the Mixpanel object. If passed no arguments,
         * this function disables tracking of any event. If passed an
         * array of event names, those events will be disabled, but other
         * events will continue to be tracked.
         *
         * Note: this function does not stop other mixpanel functions from
         * firing, such as register() or people.set().
         *
         * @param {Array} [events] An array of event names to disable
         */
        MixpanelLib.prototype.disable = function (events) {
          if (typeof events === 'undefined') {
            this._flags.disable_all_events = true;
          } else {
            this.__disabled_events = this.__disabled_events.concat(events);
          }
        };
        MixpanelLib.prototype._encode_data_for_request = function (data) {
          var encoded_data = _.JSONEncode(data);
          if (this.get_config('api_payload_format') === PAYLOAD_TYPE_BASE64) {
            encoded_data = _.base64Encode(encoded_data);
          }
          return {
            'data': encoded_data
          };
        };

        // internal method for handling track vs batch-enqueue logic
        MixpanelLib.prototype._track_or_batch = function (options, callback) {
          var truncated_data = _.truncate(options.data, 255);
          var endpoint = options.endpoint;
          var batcher = options.batcher;
          var should_send_immediately = options.should_send_immediately;
          var send_request_options = options.send_request_options || {};
          callback = callback || NOOP_FUNC;
          var request_enqueued_or_initiated = true;
          var send_request_immediately = _.bind(function () {
            if (!send_request_options.skip_hooks) {
              truncated_data = this._run_hook('before_send_' + options.type, truncated_data);
            }
            if (truncated_data) {
              console$1.log('MIXPANEL REQUEST:');
              console$1.log(truncated_data);
              return this._send_request(endpoint, this._encode_data_for_request(truncated_data), send_request_options, this._prepare_callback(callback, truncated_data));
            } else {
              return null;
            }
          }, this);
          if (this._batch_requests && !should_send_immediately) {
            batcher.enqueue(truncated_data, function (succeeded) {
              if (succeeded) {
                callback(1, truncated_data);
              } else {
                send_request_immediately();
              }
            });
          } else {
            request_enqueued_or_initiated = send_request_immediately();
          }
          return request_enqueued_or_initiated && truncated_data;
        };

        /**
         * Track an event. This is the most important and
         * frequently used Mixpanel function.
         *
         * ### Usage:
         *
         *     // track an event named 'Registered'
         *     mixpanel.track('Registered', {'Gender': 'Male', 'Age': 21});
         *
         *     // track an event using navigator.sendBeacon
         *     mixpanel.track('Left page', {'duration_seconds': 35}, {transport: 'sendBeacon'});
         *
         * To track link clicks or form submissions, see track_links() or track_forms().
         *
         * @param {String} event_name The name of the event. This can be anything the user does - 'Button Click', 'Sign Up', 'Item Purchased', etc.
         * @param {Object} [properties] A set of properties to include with the event you're sending. These describe the user who did the event or details about the event itself.
         * @param {Object} [options] Optional configuration for this track request.
         * @param {String} [options.transport] Transport method for network request ('xhr' or 'sendBeacon').
         * @param {Boolean} [options.send_immediately] Whether to bypass batching/queueing and send track request immediately.
         * @param {Function} [callback] If provided, the callback function will be called after tracking the event.
         * @returns {Boolean|Object} If the tracking request was successfully initiated/queued, an object
         * with the tracking payload sent to the API server is returned; otherwise false.
         */
        MixpanelLib.prototype.track = addOptOutCheckMixpanelLib(function (event_name, properties, options, callback) {
          if (!callback && typeof options === 'function') {
            callback = options;
            options = null;
          }
          options = options || {};
          var transport = options['transport']; // external API, don't minify 'transport' prop
          if (transport) {
            options.transport = transport; // 'transport' prop name can be minified internally
          }

          var should_send_immediately = options['send_immediately'];
          if (typeof callback !== 'function') {
            callback = NOOP_FUNC;
          }
          if (_.isUndefined(event_name)) {
            this.report_error('No event name provided to mixpanel.track');
            return;
          }
          if (this._event_is_disabled(event_name)) {
            callback(0);
            return;
          }

          // set defaults
          properties = _.extend({}, properties);
          properties['token'] = this.get_config('token');

          // set $duration if time_event was previously called for this event
          var start_timestamp = this['persistence'].remove_event_timer(event_name);
          if (!_.isUndefined(start_timestamp)) {
            var duration_in_ms = new Date().getTime() - start_timestamp;
            properties['$duration'] = parseFloat((duration_in_ms / 1000).toFixed(3));
          }
          this._set_default_superprops();
          var marketing_properties = this.get_config('track_marketing') ? _.info.marketingParams() : {};

          // note: extend writes to the first object, so lets make sure we
          // don't write to the persistence properties object and info
          // properties object by passing in a new object

          // update properties with pageview info and super-properties
          properties = _.extend({}, _.info.properties({
            'mp_loader': this.get_config('mp_loader')
          }), marketing_properties, this['persistence'].properties(), this.unpersisted_superprops, this.get_session_recording_properties(), properties);
          var property_blacklist = this.get_config('property_blacklist');
          if (_.isArray(property_blacklist)) {
            _.each(property_blacklist, function (blacklisted_prop) {
              delete properties[blacklisted_prop];
            });
          } else {
            this.report_error('Invalid value for property_blacklist config: ' + property_blacklist);
          }
          var data = {
            'event': event_name,
            'properties': properties
          };
          var ret = this._track_or_batch({
            type: 'events',
            data: data,
            endpoint: this.get_config('api_host') + '/' + this.get_config('api_routes')['track'],
            batcher: this.request_batchers.events,
            should_send_immediately: should_send_immediately,
            send_request_options: options
          }, callback);
          return ret;
        });

        /**
         * Register the current user into one/many groups.
         *
         * ### Usage:
         *
         *      mixpanel.set_group('company', ['mixpanel', 'google']) // an array of IDs
         *      mixpanel.set_group('company', 'mixpanel')
         *      mixpanel.set_group('company', 128746312)
         *
         * @param {String} group_key Group key
         * @param {Array|String|Number} group_ids An array of group IDs, or a singular group ID
         * @param {Function} [callback] If provided, the callback will be called after tracking the event.
         *
         */
        MixpanelLib.prototype.set_group = addOptOutCheckMixpanelLib(function (group_key, group_ids, callback) {
          if (!_.isArray(group_ids)) {
            group_ids = [group_ids];
          }
          var prop = {};
          prop[group_key] = group_ids;
          this.register(prop);
          return this['people'].set(group_key, group_ids, callback);
        });

        /**
         * Add a new group for this user.
         *
         * ### Usage:
         *
         *      mixpanel.add_group('company', 'mixpanel')
         *
         * @param {String} group_key Group key
         * @param {*} group_id A valid Mixpanel property type
         * @param {Function} [callback] If provided, the callback will be called after tracking the event.
         */
        MixpanelLib.prototype.add_group = addOptOutCheckMixpanelLib(function (group_key, group_id, callback) {
          var old_values = this.get_property(group_key);
          var prop = {};
          if (old_values === undefined) {
            prop[group_key] = [group_id];
            this.register(prop);
          } else {
            if (old_values.indexOf(group_id) === -1) {
              old_values.push(group_id);
              prop[group_key] = old_values;
              this.register(prop);
            }
          }
          return this['people'].union(group_key, group_id, callback);
        });

        /**
         * Remove a group from this user.
         *
         * ### Usage:
         *
         *      mixpanel.remove_group('company', 'mixpanel')
         *
         * @param {String} group_key Group key
         * @param {*} group_id A valid Mixpanel property type
         * @param {Function} [callback] If provided, the callback will be called after tracking the event.
         */
        MixpanelLib.prototype.remove_group = addOptOutCheckMixpanelLib(function (group_key, group_id, callback) {
          var old_value = this.get_property(group_key);
          // if the value doesn't exist, the persistent store is unchanged
          if (old_value !== undefined) {
            var idx = old_value.indexOf(group_id);
            if (idx > -1) {
              old_value.splice(idx, 1);
              this.register({
                group_key: old_value
              });
            }
            if (old_value.length === 0) {
              this.unregister(group_key);
            }
          }
          return this['people'].remove(group_key, group_id, callback);
        });

        /**
         * Track an event with specific groups.
         *
         * ### Usage:
         *
         *      mixpanel.track_with_groups('purchase', {'product': 'iphone'}, {'University': ['UCB', 'UCLA']})
         *
         * @param {String} event_name The name of the event (see `mixpanel.track()`)
         * @param {Object=} properties A set of properties to include with the event you're sending (see `mixpanel.track()`)
         * @param {Object=} groups An object mapping group name keys to one or more values
         * @param {Function} [callback] If provided, the callback will be called after tracking the event.
         */
        MixpanelLib.prototype.track_with_groups = addOptOutCheckMixpanelLib(function (event_name, properties, groups, callback) {
          var tracking_props = _.extend({}, properties || {});
          _.each(groups, function (v, k) {
            if (v !== null && v !== undefined) {
              tracking_props[k] = v;
            }
          });
          return this.track(event_name, tracking_props, callback);
        });
        MixpanelLib.prototype._create_map_key = function (group_key, group_id) {
          return group_key + '_' + JSON.stringify(group_id);
        };
        MixpanelLib.prototype._remove_group_from_cache = function (group_key, group_id) {
          delete this._cached_groups[this._create_map_key(group_key, group_id)];
        };

        /**
         * Look up reference to a Mixpanel group
         *
         * ### Usage:
         *
         *       mixpanel.get_group(group_key, group_id)
         *
         * @param {String} group_key Group key
         * @param {Object} group_id A valid Mixpanel property type
         * @returns {Object} A MixpanelGroup identifier
         */
        MixpanelLib.prototype.get_group = function (group_key, group_id) {
          var map_key = this._create_map_key(group_key, group_id);
          var group = this._cached_groups[map_key];
          if (group === undefined || group._group_key !== group_key || group._group_id !== group_id) {
            group = new MixpanelGroup();
            group._init(this, group_key, group_id);
            this._cached_groups[map_key] = group;
          }
          return group;
        };

        /**
         * Track a default Mixpanel page view event, which includes extra default event properties to
         * improve page view data.
         *
         * ### Usage:
         *
         *     // track a default $mp_web_page_view event
         *     mixpanel.track_pageview();
         *
         *     // track a page view event with additional event properties
         *     mixpanel.track_pageview({'ab_test_variant': 'card-layout-b'});
         *
         *     // example approach to track page views on different page types as event properties
         *     mixpanel.track_pageview({'page': 'pricing'});
         *     mixpanel.track_pageview({'page': 'homepage'});
         *
         *     // UNCOMMON: Tracking a page view event with a custom event_name option. NOT expected to be used for
         *     // individual pages on the same site or product. Use cases for custom event_name may be page
         *     // views on different products or internal applications that are considered completely separate
         *     mixpanel.track_pageview({'page': 'customer-search'}, {'event_name': '[internal] Admin Page View'});
         *
         * ### Notes:
         *
         * The `config.track_pageview` option for <a href="#mixpanelinit">mixpanel.init()</a>
         * may be turned on for tracking page loads automatically.
         *
         *     // track only page loads
         *     mixpanel.init(PROJECT_TOKEN, {track_pageview: true});
         *
         *     // track when the URL changes in any manner
         *     mixpanel.init(PROJECT_TOKEN, {track_pageview: 'full-url'});
         *
         *     // track when the URL changes, ignoring any changes in the hash part
         *     mixpanel.init(PROJECT_TOKEN, {track_pageview: 'url-with-path-and-query-string'});
         *
         *     // track when the path changes, ignoring any query parameter or hash changes
         *     mixpanel.init(PROJECT_TOKEN, {track_pageview: 'url-with-path'});
         *
         * @param {Object} [properties] An optional set of additional properties to send with the page view event
         * @param {Object} [options] Page view tracking options
         * @param {String} [options.event_name] - Alternate name for the tracking event
         * @returns {Boolean|Object} If the tracking request was successfully initiated/queued, an object
         * with the tracking payload sent to the API server is returned; otherwise false.
         */
        MixpanelLib.prototype.track_pageview = addOptOutCheckMixpanelLib(function (properties, options) {
          if (typeof properties !== 'object') {
            properties = {};
          }
          options = options || {};
          var event_name = options['event_name'] || '$mp_web_page_view';
          var default_page_properties = _.extend(_.info.mpPageViewProperties(), _.info.campaignParams(), _.info.clickParams());
          var event_properties = _.extend({}, default_page_properties, properties);
          return this.track(event_name, event_properties);
        });

        /**
         * Track clicks on a set of document elements. Selector must be a
         * valid query. Elements must exist on the page at the time track_links is called.
         *
         * ### Usage:
         *
         *     // track click for link id #nav
         *     mixpanel.track_links('#nav', 'Clicked Nav Link');
         *
         * ### Notes:
         *
         * This function will wait up to 300 ms for the Mixpanel
         * servers to respond. If they have not responded by that time
         * it will head to the link without ensuring that your event
         * has been tracked.  To configure this timeout please see the
         * set_config() documentation below.
         *
         * If you pass a function in as the properties argument, the
         * function will receive the DOMElement that triggered the
         * event as an argument.  You are expected to return an object
         * from the function; any properties defined on this object
         * will be sent to mixpanel as event properties.
         *
         * @type {Function}
         * @param {Object|String} query A valid DOM query, element or jQuery-esque list
         * @param {String} event_name The name of the event to track
         * @param {Object|Function} [properties] A properties object or function that returns a dictionary of properties when passed a DOMElement
         */
        MixpanelLib.prototype.track_links = function () {
          return this._track_dom.call(this, LinkTracker, arguments);
        };

        /**
         * Track form submissions. Selector must be a valid query.
         *
         * ### Usage:
         *
         *     // track submission for form id 'register'
         *     mixpanel.track_forms('#register', 'Created Account');
         *
         * ### Notes:
         *
         * This function will wait up to 300 ms for the mixpanel
         * servers to respond, if they have not responded by that time
         * it will head to the link without ensuring that your event
         * has been tracked.  To configure this timeout please see the
         * set_config() documentation below.
         *
         * If you pass a function in as the properties argument, the
         * function will receive the DOMElement that triggered the
         * event as an argument.  You are expected to return an object
         * from the function; any properties defined on this object
         * will be sent to mixpanel as event properties.
         *
         * @type {Function}
         * @param {Object|String} query A valid DOM query, element or jQuery-esque list
         * @param {String} event_name The name of the event to track
         * @param {Object|Function} [properties] This can be a set of properties, or a function that returns a set of properties after being passed a DOMElement
         */
        MixpanelLib.prototype.track_forms = function () {
          return this._track_dom.call(this, FormTracker, arguments);
        };

        /**
         * Time an event by including the time between this call and a
         * later 'track' call for the same event in the properties sent
         * with the event.
         *
         * ### Usage:
         *
         *     // time an event named 'Registered'
         *     mixpanel.time_event('Registered');
         *     mixpanel.track('Registered', {'Gender': 'Male', 'Age': 21});
         *
         * When called for a particular event name, the next track call for that event
         * name will include the elapsed time between the 'time_event' and 'track'
         * calls. This value is stored as seconds in the '$duration' property.
         *
         * @param {String} event_name The name of the event.
         */
        MixpanelLib.prototype.time_event = function (event_name) {
          if (_.isUndefined(event_name)) {
            this.report_error('No event name provided to mixpanel.time_event');
            return;
          }
          if (this._event_is_disabled(event_name)) {
            return;
          }
          this['persistence'].set_event_timer(event_name, new Date().getTime());
        };
        var REGISTER_DEFAULTS = {
          'persistent': true
        };
        /**
         * Helper to parse options param for register methods, maintaining
         * legacy support for plain "days" param instead of options object
         * @param {Number|Object} [days_or_options] 'days' option (Number), or Options object for register methods
         * @returns {Object} options object
         */
        var options_for_register = function options_for_register(days_or_options) {
          var options;
          if (_.isObject(days_or_options)) {
            options = days_or_options;
          } else if (!_.isUndefined(days_or_options)) {
            options = {
              'days': days_or_options
            };
          } else {
            options = {};
          }
          return _.extend({}, REGISTER_DEFAULTS, options);
        };

        /**
         * Register a set of super properties, which are included with all
         * events. This will overwrite previous super property values.
         *
         * ### Usage:
         *
         *     // register 'Gender' as a super property
         *     mixpanel.register({'Gender': 'Female'});
         *
         *     // register several super properties when a user signs up
         *     mixpanel.register({
         *         'Email': 'jdoe@example.com',
         *         'Account Type': 'Free'
         *     });
         *
         *     // register only for the current pageload
         *     mixpanel.register({'Name': 'Pat'}, {persistent: false});
         *
         * @param {Object} properties An associative array of properties to store about the user
         * @param {Number|Object} [days_or_options] Options object or number of days since the user's last visit to store the super properties (only valid for persisted props)
         * @param {boolean} [days_or_options.days] - number of days since the user's last visit to store the super properties (only valid for persisted props)
         * @param {boolean} [days_or_options.persistent=true] - whether to put in persistent storage (cookie/localStorage)
         */
        MixpanelLib.prototype.register = function (props, days_or_options) {
          var options = options_for_register(days_or_options);
          if (options['persistent']) {
            this['persistence'].register(props, options['days']);
          } else {
            _.extend(this.unpersisted_superprops, props);
          }
        };

        /**
         * Register a set of super properties only once. This will not
         * overwrite previous super property values, unlike register().
         *
         * ### Usage:
         *
         *     // register a super property for the first time only
         *     mixpanel.register_once({
         *         'First Login Date': new Date().toISOString()
         *     });
         *
         *     // register once, only for the current pageload
         *     mixpanel.register_once({
         *         'First interaction time': new Date().toISOString()
         *     }, 'None', {persistent: false});
         *
         * ### Notes:
         *
         * If default_value is specified, current super properties
         * with that value will be overwritten.
         *
         * @param {Object} properties An associative array of properties to store about the user
         * @param {*} [default_value] Value to override if already set in super properties (ex: 'False') Default: 'None'
         * @param {Number|Object} [days_or_options] Options object or number of days since the user's last visit to store the super properties (only valid for persisted props)
         * @param {boolean} [days_or_options.days] - number of days since the user's last visit to store the super properties (only valid for persisted props)
         * @param {boolean} [days_or_options.persistent=true] - whether to put in persistent storage (cookie/localStorage)
         */
        MixpanelLib.prototype.register_once = function (props, default_value, days_or_options) {
          var options = options_for_register(days_or_options);
          if (options['persistent']) {
            this['persistence'].register_once(props, default_value, options['days']);
          } else {
            if (typeof default_value === 'undefined') {
              default_value = 'None';
            }
            _.each(props, function (val, prop) {
              if (!this.unpersisted_superprops.hasOwnProperty(prop) || this.unpersisted_superprops[prop] === default_value) {
                this.unpersisted_superprops[prop] = val;
              }
            }, this);
          }
        };

        /**
         * Delete a super property stored with the current user.
         *
         * @param {String} property The name of the super property to remove
         * @param {Object} [options]
         * @param {boolean} [options.persistent=true] - whether to look in persistent storage (cookie/localStorage)
         */
        MixpanelLib.prototype.unregister = function (property, options) {
          options = options_for_register(options);
          if (options['persistent']) {
            this['persistence'].unregister(property);
          } else {
            delete this.unpersisted_superprops[property];
          }
        };
        MixpanelLib.prototype._register_single = function (prop, value) {
          var props = {};
          props[prop] = value;
          this.register(props);
        };

        /**
         * Identify a user with a unique ID to track user activity across
         * devices, tie a user to their events, and create a user profile.
         * If you never call this method, unique visitors are tracked using
         * a UUID generated the first time they visit the site.
         *
         * Call identify when you know the identity of the current user,
         * typically after login or signup. We recommend against using
         * identify for anonymous visitors to your site.
         *
         * ### Notes:
         * If your project has
         * <a href="https://help.mixpanel.com/hc/en-us/articles/360039133851">ID Merge</a>
         * enabled, the identify method will connect pre- and
         * post-authentication events when appropriate.
         *
         * If your project does not have ID Merge enabled, identify will
         * change the user's local distinct_id to the unique ID you pass.
         * Events tracked prior to authentication will not be connected
         * to the same user identity. If ID Merge is disabled, alias can
         * be used to connect pre- and post-registration events.
         *
         * @param {String} [unique_id] A string that uniquely identifies a user. If not provided, the distinct_id currently in the persistent store (cookie or localStorage) will be used.
         */
        MixpanelLib.prototype.identify = function (new_distinct_id, _set_callback, _add_callback, _append_callback, _set_once_callback, _union_callback, _unset_callback, _remove_callback) {
          // Optional Parameters
          //  _set_callback:function  A callback to be run if and when the People set queue is flushed
          //  _add_callback:function  A callback to be run if and when the People add queue is flushed
          //  _append_callback:function  A callback to be run if and when the People append queue is flushed
          //  _set_once_callback:function  A callback to be run if and when the People set_once queue is flushed
          //  _union_callback:function  A callback to be run if and when the People union queue is flushed
          //  _unset_callback:function  A callback to be run if and when the People unset queue is flushed

          var previous_distinct_id = this.get_distinct_id();
          if (new_distinct_id && previous_distinct_id !== new_distinct_id) {
            // we allow the following condition if previous distinct_id is same as new_distinct_id
            // so that you can force flush people updates for anonymous profiles.
            if (typeof new_distinct_id === 'string' && new_distinct_id.indexOf(DEVICE_ID_PREFIX) === 0) {
              this.report_error('distinct_id cannot have $device: prefix');
              return -1;
            }
            this.register({
              '$user_id': new_distinct_id
            });
          }
          if (!this.get_property('$device_id')) {
            // The persisted distinct id might not actually be a device id at all
            // it might be a distinct id of the user from before
            var device_id = previous_distinct_id;
            this.register_once({
              '$had_persisted_distinct_id': true,
              '$device_id': device_id
            }, '');
          }

          // identify only changes the distinct id if it doesn't match either the existing or the alias;
          // if it's new, blow away the alias as well.
          if (new_distinct_id !== previous_distinct_id && new_distinct_id !== this.get_property(ALIAS_ID_KEY)) {
            this.unregister(ALIAS_ID_KEY);
            this.register({
              'distinct_id': new_distinct_id
            });
          }
          this._flags.identify_called = true;
          // Flush any queued up people requests
          this['people']._flush(_set_callback, _add_callback, _append_callback, _set_once_callback, _union_callback, _unset_callback, _remove_callback);

          // send an $identify event any time the distinct_id is changing - logic on the server
          // will determine whether or not to do anything with it.
          if (new_distinct_id !== previous_distinct_id) {
            this.track('$identify', {
              'distinct_id': new_distinct_id,
              '$anon_distinct_id': previous_distinct_id
            }, {
              skip_hooks: true
            });
          }
        };

        /**
         * Clears super properties and generates a new random distinct_id for this instance.
         * Useful for clearing data when a user logs out.
         */
        MixpanelLib.prototype.reset = function () {
          this['persistence'].clear();
          this._flags.identify_called = false;
          var uuid = _.UUID();
          this.register_once({
            'distinct_id': DEVICE_ID_PREFIX + uuid,
            '$device_id': uuid
          }, '');
        };

        /**
         * Returns the current distinct id of the user. This is either the id automatically
         * generated by the library or the id that has been passed by a call to identify().
         *
         * ### Notes:
         *
         * get_distinct_id() can only be called after the Mixpanel library has finished loading.
         * init() has a loaded function available to handle this automatically. For example:
         *
         *     // set distinct_id after the mixpanel library has loaded
         *     mixpanel.init('YOUR PROJECT TOKEN', {
         *         loaded: function(mixpanel) {
         *             distinct_id = mixpanel.get_distinct_id();
         *         }
         *     });
         */
        MixpanelLib.prototype.get_distinct_id = function () {
          return this.get_property('distinct_id');
        };

        /**
         * The alias method creates an alias which Mixpanel will use to
         * remap one id to another. Multiple aliases can point to the
         * same identifier.
         *
         * The following is a valid use of alias:
         *
         *     mixpanel.alias('new_id', 'existing_id');
         *     // You can add multiple id aliases to the existing ID
         *     mixpanel.alias('newer_id', 'existing_id');
         *
         * Aliases can also be chained - the following is a valid example:
         *
         *     mixpanel.alias('new_id', 'existing_id');
         *     // chain newer_id - new_id - existing_id
         *     mixpanel.alias('newer_id', 'new_id');
         *
         * Aliases cannot point to multiple identifiers - the following
         * example will not work:
         *
         *     mixpanel.alias('new_id', 'existing_id');
         *     // this is invalid as 'new_id' already points to 'existing_id'
         *     mixpanel.alias('new_id', 'newer_id');
         *
         * ### Notes:
         *
         * If your project does not have
         * <a href="https://help.mixpanel.com/hc/en-us/articles/360039133851">ID Merge</a>
         * enabled, the best practice is to call alias once when a unique
         * ID is first created for a user (e.g., when a user first registers
         * for an account). Do not use alias multiple times for a single
         * user without ID Merge enabled.
         *
         * @param {String} alias A unique identifier that you want to use for this user in the future.
         * @param {String} [original] The current identifier being used for this user.
         */
        MixpanelLib.prototype.alias = function (alias, original) {
          // If the $people_distinct_id key exists in persistence, there has been a previous
          // mixpanel.people.identify() call made for this user. It is VERY BAD to make an alias with
          // this ID, as it will duplicate users.
          if (alias === this.get_property(PEOPLE_DISTINCT_ID_KEY)) {
            this.report_error('Attempting to create alias for existing People user - aborting.');
            return -2;
          }
          var _this = this;
          if (_.isUndefined(original)) {
            original = this.get_distinct_id();
          }
          if (alias !== original) {
            this._register_single(ALIAS_ID_KEY, alias);
            return this.track('$create_alias', {
              'alias': alias,
              'distinct_id': original
            }, {
              skip_hooks: true
            }, function () {
              // Flush the people queue
              _this.identify(alias);
            });
          } else {
            this.report_error('alias matches current distinct_id - skipping api call.');
            this.identify(alias);
            return -1;
          }
        };

        /**
         * Provide a string to recognize the user by. The string passed to
         * this method will appear in the Mixpanel Streams product rather
         * than an automatically generated name. Name tags do not have to
         * be unique.
         *
         * This value will only be included in Streams data.
         *
         * @param {String} name_tag A human readable name for the user
         * @deprecated
         */
        MixpanelLib.prototype.name_tag = function (name_tag) {
          this._register_single('mp_name_tag', name_tag);
        };

        /**
         * Update the configuration of a mixpanel library instance.
         *
         * The default config is:
         *
         *     {
         *       // host for requests (customizable for e.g. a local proxy)
         *       api_host: 'https://api-js.mixpanel.com',
         *
         *       // endpoints for different types of requests
         *       api_routes: {
         *         track: 'track/',
         *         engage: 'engage/',
         *         groups: 'groups/',
         *       }
         *
         *       // HTTP method for tracking requests
         *       api_method: 'POST'
         *
         *       // transport for sending requests ('XHR' or 'sendBeacon')
         *       // NB: sendBeacon should only be used for scenarios such as
         *       // page unload where a "best-effort" attempt to send is
         *       // acceptable; the sendBeacon API does not support callbacks
         *       // or any way to know the result of the request. Mixpanel
         *       // tracking via sendBeacon will not support any event-
         *       // batching or retry mechanisms.
         *       api_transport: 'XHR'
         *
         *       // request-batching/queueing/retry
         *       batch_requests: true,
         *
         *       // maximum number of events/updates to send in a single
         *       // network request
         *       batch_size: 50,
         *
         *       // milliseconds to wait between sending batch requests
         *       batch_flush_interval_ms: 5000,
         *
         *       // milliseconds to wait for network responses to batch requests
         *       // before they are considered timed-out and retried
         *       batch_request_timeout_ms: 90000,
         *
         *       // override value for cookie domain, only useful for ensuring
         *       // correct cross-subdomain cookies on unusual domains like
         *       // subdomain.mainsite.avocat.fr; NB this cannot be used to
         *       // set cookies on a different domain than the current origin
         *       cookie_domain: ''
         *
         *       // super properties cookie expiration (in days)
         *       cookie_expiration: 365
         *
         *       // if true, cookie will be set with SameSite=None; Secure
         *       // this is only useful in special situations, like embedded
         *       // 3rd-party iframes that set up a Mixpanel instance
         *       cross_site_cookie: false
         *
         *       // super properties span subdomains
         *       cross_subdomain_cookie: true
         *
         *       // debug mode
         *       debug: false
         *
         *       // if this is true, the mixpanel cookie or localStorage entry
         *       // will be deleted, and no user persistence will take place
         *       disable_persistence: false
         *
         *       // if this is true, Mixpanel will automatically determine
         *       // City, Region and Country data using the IP address of
         *       //the client
         *       ip: true
         *
         *       // opt users out of tracking by this Mixpanel instance by default
         *       opt_out_tracking_by_default: false
         *
         *       // opt users out of browser data storage by this Mixpanel instance by default
         *       opt_out_persistence_by_default: false
         *
         *       // persistence mechanism used by opt-in/opt-out methods - cookie
         *       // or localStorage - falls back to cookie if localStorage is unavailable
         *       opt_out_tracking_persistence_type: 'localStorage'
         *
         *       // customize the name of cookie/localStorage set by opt-in/opt-out methods
         *       opt_out_tracking_cookie_prefix: null
         *
         *       // type of persistent store for super properties (cookie/
         *       // localStorage) if set to 'localStorage', any existing
         *       // mixpanel cookie value with the same persistence_name
         *       // will be transferred to localStorage and deleted
         *       persistence: 'cookie'
         *
         *       // name for super properties persistent store
         *       persistence_name: ''
         *
         *       // names of properties/superproperties which should never
         *       // be sent with track() calls
         *       property_blacklist: []
         *
         *       // if this is true, mixpanel cookies will be marked as
         *       // secure, meaning they will only be transmitted over https
         *       secure_cookie: false
         *
         *       // disables enriching user profiles with first touch marketing data
         *       skip_first_touch_marketing: false
         *
         *       // the amount of time track_links will
         *       // wait for Mixpanel's servers to respond
         *       track_links_timeout: 300
         *
         *       // adds any UTM parameters and click IDs present on the page to any events fired
         *       track_marketing: true
         *
         *       // enables automatic page view tracking using default page view events through
         *       // the track_pageview() method
         *       track_pageview: false
         *
         *       // if you set upgrade to be true, the library will check for
         *       // a cookie from our old js library and import super
         *       // properties from it, then the old cookie is deleted
         *       // The upgrade config option only works in the initialization,
         *       // so make sure you set it when you create the library.
         *       upgrade: false
         *
         *       // extra HTTP request headers to set for each API request, in
         *       // the format {'Header-Name': value}
         *       xhr_headers: {}
         *
         *       // whether to ignore or respect the web browser's Do Not Track setting
         *       ignore_dnt: false
         *     }
         *
         *
         * @param {Object} config A dictionary of new configuration values to update
         */
        MixpanelLib.prototype.set_config = function (config) {
          if (_.isObject(config)) {
            _.extend(this['config'], config);
            var new_batch_size = config['batch_size'];
            if (new_batch_size) {
              _.each(this.request_batchers, function (batcher) {
                batcher.resetBatchSize();
              });
            }
            if (!this.get_config('persistence_name')) {
              this['config']['persistence_name'] = this['config']['cookie_name'];
            }
            if (!this.get_config('disable_persistence')) {
              this['config']['disable_persistence'] = this['config']['disable_cookie'];
            }
            if (this['persistence']) {
              this['persistence'].update_config(this['config']);
            }
            Config.DEBUG = Config.DEBUG || this.get_config('debug');
          }
        };

        /**
         * returns the current config object for the library.
         */
        MixpanelLib.prototype.get_config = function (prop_name) {
          return this['config'][prop_name];
        };

        /**
         * Fetch a hook function from config, with safe default, and run it
         * against the given arguments
         * @param {string} hook_name which hook to retrieve
         * @returns {any|null} return value of user-provided hook, or null if nothing was returned
         */
        MixpanelLib.prototype._run_hook = function (hook_name) {
          var ret = (this['config']['hooks'][hook_name] || IDENTITY_FUNC).apply(this, slice.call(arguments, 1));
          if (typeof ret === 'undefined') {
            this.report_error(hook_name + ' hook did not return a value');
            ret = null;
          }
          return ret;
        };

        /**
         * Returns the value of the super property named property_name. If no such
         * property is set, get_property() will return the undefined value.
         *
         * ### Notes:
         *
         * get_property() can only be called after the Mixpanel library has finished loading.
         * init() has a loaded function available to handle this automatically. For example:
         *
         *     // grab value for 'user_id' after the mixpanel library has loaded
         *     mixpanel.init('YOUR PROJECT TOKEN', {
         *         loaded: function(mixpanel) {
         *             user_id = mixpanel.get_property('user_id');
         *         }
         *     });
         *
         * @param {String} property_name The name of the super property you want to retrieve
         */
        MixpanelLib.prototype.get_property = function (property_name) {
          return this['persistence'].load_prop([property_name]);
        };
        MixpanelLib.prototype.toString = function () {
          var name = this.get_config('name');
          if (name !== PRIMARY_INSTANCE_NAME) {
            name = PRIMARY_INSTANCE_NAME + '.' + name;
          }
          return name;
        };
        MixpanelLib.prototype._event_is_disabled = function (event_name) {
          return _.isBlockedUA(userAgent) || this._flags.disable_all_events || _.include(this.__disabled_events, event_name);
        };

        // perform some housekeeping around GDPR opt-in/out state
        MixpanelLib.prototype._gdpr_init = function () {
          var is_localStorage_requested = this.get_config('opt_out_tracking_persistence_type') === 'localStorage';

          // try to convert opt-in/out cookies to localStorage if possible
          if (is_localStorage_requested && _.localStorage.is_supported()) {
            if (!this.has_opted_in_tracking() && this.has_opted_in_tracking({
              'persistence_type': 'cookie'
            })) {
              this.opt_in_tracking({
                'enable_persistence': false
              });
            }
            if (!this.has_opted_out_tracking() && this.has_opted_out_tracking({
              'persistence_type': 'cookie'
            })) {
              this.opt_out_tracking({
                'clear_persistence': false
              });
            }
            this.clear_opt_in_out_tracking({
              'persistence_type': 'cookie',
              'enable_persistence': false
            });
          }

          // check whether the user has already opted out - if so, clear & disable persistence
          if (this.has_opted_out_tracking()) {
            this._gdpr_update_persistence({
              'clear_persistence': true
            });

            // check whether we should opt out by default
            // note: we don't clear persistence here by default since opt-out default state is often
            //       used as an initial state while GDPR information is being collected
          } else if (!this.has_opted_in_tracking() && (this.get_config('opt_out_tracking_by_default') || _.cookie.get('mp_optout'))) {
            _.cookie.remove('mp_optout');
            this.opt_out_tracking({
              'clear_persistence': this.get_config('opt_out_persistence_by_default')
            });
          }
        };

        /**
         * Enable or disable persistence based on options
         * only enable/disable if persistence is not already in this state
         * @param {boolean} [options.clear_persistence] If true, will delete all data stored by the sdk in persistence and disable it
         * @param {boolean} [options.enable_persistence] If true, will re-enable sdk persistence
         */
        MixpanelLib.prototype._gdpr_update_persistence = function (options) {
          var disabled;
          if (options && options['clear_persistence']) {
            disabled = true;
          } else if (options && options['enable_persistence']) {
            disabled = false;
          } else {
            return;
          }
          if (!this.get_config('disable_persistence') && this['persistence'].disabled !== disabled) {
            this['persistence'].set_disabled(disabled);
          }
          if (disabled) {
            this.stop_batch_senders();
          } else {
            // only start batchers after opt-in if they have previously been started
            // in order to avoid unintentionally starting up batching for the first time
            if (this._batchers_were_started) {
              this.start_batch_senders();
            }
          }
        };

        // call a base gdpr function after constructing the appropriate token and options args
        MixpanelLib.prototype._gdpr_call_func = function (func, options) {
          options = _.extend({
            'track': _.bind(this.track, this),
            'persistence_type': this.get_config('opt_out_tracking_persistence_type'),
            'cookie_prefix': this.get_config('opt_out_tracking_cookie_prefix'),
            'cookie_expiration': this.get_config('cookie_expiration'),
            'cross_site_cookie': this.get_config('cross_site_cookie'),
            'cross_subdomain_cookie': this.get_config('cross_subdomain_cookie'),
            'cookie_domain': this.get_config('cookie_domain'),
            'secure_cookie': this.get_config('secure_cookie'),
            'ignore_dnt': this.get_config('ignore_dnt')
          }, options);

          // check if localStorage can be used for recording opt out status, fall back to cookie if not
          if (!_.localStorage.is_supported()) {
            options['persistence_type'] = 'cookie';
          }
          return func(this.get_config('token'), {
            track: options['track'],
            trackEventName: options['track_event_name'],
            trackProperties: options['track_properties'],
            persistenceType: options['persistence_type'],
            persistencePrefix: options['cookie_prefix'],
            cookieDomain: options['cookie_domain'],
            cookieExpiration: options['cookie_expiration'],
            crossSiteCookie: options['cross_site_cookie'],
            crossSubdomainCookie: options['cross_subdomain_cookie'],
            secureCookie: options['secure_cookie'],
            ignoreDnt: options['ignore_dnt']
          });
        };

        /**
         * Opt the user in to data tracking and cookies/localstorage for this Mixpanel instance
         *
         * ### Usage:
         *
         *     // opt user in
         *     mixpanel.opt_in_tracking();
         *
         *     // opt user in with specific event name, properties, cookie configuration
         *     mixpanel.opt_in_tracking({
         *         track_event_name: 'User opted in',
         *         track_event_properties: {
         *             'Email': 'jdoe@example.com'
         *         },
         *         cookie_expiration: 30,
         *         secure_cookie: true
         *     });
         *
         * @param {Object} [options] A dictionary of config options to override
         * @param {function} [options.track] Function used for tracking a Mixpanel event to record the opt-in action (default is this Mixpanel instance's track method)
         * @param {string} [options.track_event_name=$opt_in] Event name to be used for tracking the opt-in action
         * @param {Object} [options.track_properties] Set of properties to be tracked along with the opt-in action
         * @param {boolean} [options.enable_persistence=true] If true, will re-enable sdk persistence
         * @param {string} [options.persistence_type=localStorage] Persistence mechanism used - cookie or localStorage - falls back to cookie if localStorage is unavailable
         * @param {string} [options.cookie_prefix=__mp_opt_in_out] Custom prefix to be used in the cookie/localstorage name
         * @param {Number} [options.cookie_expiration] Number of days until the opt-in cookie expires (overrides value specified in this Mixpanel instance's config)
         * @param {string} [options.cookie_domain] Custom cookie domain (overrides value specified in this Mixpanel instance's config)
         * @param {boolean} [options.cross_site_cookie] Whether the opt-in cookie is set as cross-site-enabled (overrides value specified in this Mixpanel instance's config)
         * @param {boolean} [options.cross_subdomain_cookie] Whether the opt-in cookie is set as cross-subdomain or not (overrides value specified in this Mixpanel instance's config)
         * @param {boolean} [options.secure_cookie] Whether the opt-in cookie is set as secure or not (overrides value specified in this Mixpanel instance's config)
         */
        MixpanelLib.prototype.opt_in_tracking = function (options) {
          options = _.extend({
            'enable_persistence': true
          }, options);
          this._gdpr_call_func(optIn, options);
          this._gdpr_update_persistence(options);
        };

        /**
         * Opt the user out of data tracking and cookies/localstorage for this Mixpanel instance
         *
         * ### Usage:
         *
         *     // opt user out
         *     mixpanel.opt_out_tracking();
         *
         *     // opt user out with different cookie configuration from Mixpanel instance
         *     mixpanel.opt_out_tracking({
         *         cookie_expiration: 30,
         *         secure_cookie: true
         *     });
         *
         * @param {Object} [options] A dictionary of config options to override
         * @param {boolean} [options.delete_user=true] If true, will delete the currently identified user's profile and clear all charges after opting the user out
         * @param {boolean} [options.clear_persistence=true] If true, will delete all data stored by the sdk in persistence
         * @param {string} [options.persistence_type=localStorage] Persistence mechanism used - cookie or localStorage - falls back to cookie if localStorage is unavailable
         * @param {string} [options.cookie_prefix=__mp_opt_in_out] Custom prefix to be used in the cookie/localstorage name
         * @param {Number} [options.cookie_expiration] Number of days until the opt-in cookie expires (overrides value specified in this Mixpanel instance's config)
         * @param {string} [options.cookie_domain] Custom cookie domain (overrides value specified in this Mixpanel instance's config)
         * @param {boolean} [options.cross_site_cookie] Whether the opt-in cookie is set as cross-site-enabled (overrides value specified in this Mixpanel instance's config)
         * @param {boolean} [options.cross_subdomain_cookie] Whether the opt-in cookie is set as cross-subdomain or not (overrides value specified in this Mixpanel instance's config)
         * @param {boolean} [options.secure_cookie] Whether the opt-in cookie is set as secure or not (overrides value specified in this Mixpanel instance's config)
         */
        MixpanelLib.prototype.opt_out_tracking = function (options) {
          options = _.extend({
            'clear_persistence': true,
            'delete_user': true
          }, options);

          // delete user and clear charges since these methods may be disabled by opt-out
          if (options['delete_user'] && this['people'] && this['people']._identify_called()) {
            this['people'].delete_user();
            this['people'].clear_charges();
          }
          this._gdpr_call_func(optOut, options);
          this._gdpr_update_persistence(options);
        };

        /**
         * Check whether the user has opted in to data tracking and cookies/localstorage for this Mixpanel instance
         *
         * ### Usage:
         *
         *     var has_opted_in = mixpanel.has_opted_in_tracking();
         *     // use has_opted_in value
         *
         * @param {Object} [options] A dictionary of config options to override
         * @param {string} [options.persistence_type=localStorage] Persistence mechanism used - cookie or localStorage - falls back to cookie if localStorage is unavailable
         * @param {string} [options.cookie_prefix=__mp_opt_in_out] Custom prefix to be used in the cookie/localstorage name
         * @returns {boolean} current opt-in status
         */
        MixpanelLib.prototype.has_opted_in_tracking = function (options) {
          return this._gdpr_call_func(hasOptedIn, options);
        };

        /**
         * Check whether the user has opted out of data tracking and cookies/localstorage for this Mixpanel instance
         *
         * ### Usage:
         *
         *     var has_opted_out = mixpanel.has_opted_out_tracking();
         *     // use has_opted_out value
         *
         * @param {Object} [options] A dictionary of config options to override
         * @param {string} [options.persistence_type=localStorage] Persistence mechanism used - cookie or localStorage - falls back to cookie if localStorage is unavailable
         * @param {string} [options.cookie_prefix=__mp_opt_in_out] Custom prefix to be used in the cookie/localstorage name
         * @returns {boolean} current opt-out status
         */
        MixpanelLib.prototype.has_opted_out_tracking = function (options) {
          return this._gdpr_call_func(hasOptedOut, options);
        };

        /**
         * Clear the user's opt in/out status of data tracking and cookies/localstorage for this Mixpanel instance
         *
         * ### Usage:
         *
         *     // clear user's opt-in/out status
         *     mixpanel.clear_opt_in_out_tracking();
         *
         *     // clear user's opt-in/out status with specific cookie configuration - should match
         *     // configuration used when opt_in_tracking/opt_out_tracking methods were called.
         *     mixpanel.clear_opt_in_out_tracking({
         *         cookie_expiration: 30,
         *         secure_cookie: true
         *     });
         *
         * @param {Object} [options] A dictionary of config options to override
         * @param {boolean} [options.enable_persistence=true] If true, will re-enable sdk persistence
         * @param {string} [options.persistence_type=localStorage] Persistence mechanism used - cookie or localStorage - falls back to cookie if localStorage is unavailable
         * @param {string} [options.cookie_prefix=__mp_opt_in_out] Custom prefix to be used in the cookie/localstorage name
         * @param {Number} [options.cookie_expiration] Number of days until the opt-in cookie expires (overrides value specified in this Mixpanel instance's config)
         * @param {string} [options.cookie_domain] Custom cookie domain (overrides value specified in this Mixpanel instance's config)
         * @param {boolean} [options.cross_site_cookie] Whether the opt-in cookie is set as cross-site-enabled (overrides value specified in this Mixpanel instance's config)
         * @param {boolean} [options.cross_subdomain_cookie] Whether the opt-in cookie is set as cross-subdomain or not (overrides value specified in this Mixpanel instance's config)
         * @param {boolean} [options.secure_cookie] Whether the opt-in cookie is set as secure or not (overrides value specified in this Mixpanel instance's config)
         */
        MixpanelLib.prototype.clear_opt_in_out_tracking = function (options) {
          options = _.extend({
            'enable_persistence': true
          }, options);
          this._gdpr_call_func(clearOptInOut, options);
          this._gdpr_update_persistence(options);
        };
        MixpanelLib.prototype.report_error = function (msg, err) {
          console$1.error.apply(console$1.error, arguments);
          try {
            if (!err && !(msg instanceof Error)) {
              msg = new Error(msg);
            }
            this.get_config('error_reporter')(msg, err);
          } catch (err) {
            console$1.error(err);
          }
        };

        // EXPORTS (for closure compiler)

        // MixpanelLib Exports
        MixpanelLib.prototype['init'] = MixpanelLib.prototype.init;
        MixpanelLib.prototype['reset'] = MixpanelLib.prototype.reset;
        MixpanelLib.prototype['disable'] = MixpanelLib.prototype.disable;
        MixpanelLib.prototype['time_event'] = MixpanelLib.prototype.time_event;
        MixpanelLib.prototype['track'] = MixpanelLib.prototype.track;
        MixpanelLib.prototype['track_links'] = MixpanelLib.prototype.track_links;
        MixpanelLib.prototype['track_forms'] = MixpanelLib.prototype.track_forms;
        MixpanelLib.prototype['track_pageview'] = MixpanelLib.prototype.track_pageview;
        MixpanelLib.prototype['register'] = MixpanelLib.prototype.register;
        MixpanelLib.prototype['register_once'] = MixpanelLib.prototype.register_once;
        MixpanelLib.prototype['unregister'] = MixpanelLib.prototype.unregister;
        MixpanelLib.prototype['identify'] = MixpanelLib.prototype.identify;
        MixpanelLib.prototype['alias'] = MixpanelLib.prototype.alias;
        MixpanelLib.prototype['name_tag'] = MixpanelLib.prototype.name_tag;
        MixpanelLib.prototype['set_config'] = MixpanelLib.prototype.set_config;
        MixpanelLib.prototype['get_config'] = MixpanelLib.prototype.get_config;
        MixpanelLib.prototype['get_property'] = MixpanelLib.prototype.get_property;
        MixpanelLib.prototype['get_distinct_id'] = MixpanelLib.prototype.get_distinct_id;
        MixpanelLib.prototype['toString'] = MixpanelLib.prototype.toString;
        MixpanelLib.prototype['opt_out_tracking'] = MixpanelLib.prototype.opt_out_tracking;
        MixpanelLib.prototype['opt_in_tracking'] = MixpanelLib.prototype.opt_in_tracking;
        MixpanelLib.prototype['has_opted_out_tracking'] = MixpanelLib.prototype.has_opted_out_tracking;
        MixpanelLib.prototype['has_opted_in_tracking'] = MixpanelLib.prototype.has_opted_in_tracking;
        MixpanelLib.prototype['clear_opt_in_out_tracking'] = MixpanelLib.prototype.clear_opt_in_out_tracking;
        MixpanelLib.prototype['get_group'] = MixpanelLib.prototype.get_group;
        MixpanelLib.prototype['set_group'] = MixpanelLib.prototype.set_group;
        MixpanelLib.prototype['add_group'] = MixpanelLib.prototype.add_group;
        MixpanelLib.prototype['remove_group'] = MixpanelLib.prototype.remove_group;
        MixpanelLib.prototype['track_with_groups'] = MixpanelLib.prototype.track_with_groups;
        MixpanelLib.prototype['start_batch_senders'] = MixpanelLib.prototype.start_batch_senders;
        MixpanelLib.prototype['stop_batch_senders'] = MixpanelLib.prototype.stop_batch_senders;
        MixpanelLib.prototype['start_session_recording'] = MixpanelLib.prototype.start_session_recording;
        MixpanelLib.prototype['stop_session_recording'] = MixpanelLib.prototype.stop_session_recording;
        MixpanelLib.prototype['get_session_recording_properties'] = MixpanelLib.prototype.get_session_recording_properties;
        MixpanelLib.prototype['DEFAULT_API_ROUTES'] = DEFAULT_API_ROUTES;

        // MixpanelPersistence Exports
        MixpanelPersistence.prototype['properties'] = MixpanelPersistence.prototype.properties;
        MixpanelPersistence.prototype['update_search_keyword'] = MixpanelPersistence.prototype.update_search_keyword;
        MixpanelPersistence.prototype['update_referrer_info'] = MixpanelPersistence.prototype.update_referrer_info;
        MixpanelPersistence.prototype['get_cross_subdomain'] = MixpanelPersistence.prototype.get_cross_subdomain;
        MixpanelPersistence.prototype['clear'] = MixpanelPersistence.prototype.clear;
        var instances = {};
        var extend_mp = function extend_mp() {
          // add all the sub mixpanel instances
          _.each(instances, function (instance, name) {
            if (name !== PRIMARY_INSTANCE_NAME) {
              mixpanel_master[name] = instance;
            }
          });

          // add private functions as _
          mixpanel_master['_'] = _;
        };
        var override_mp_init_func = function override_mp_init_func() {
          // we override the snippets init function to handle the case where a
          // user initializes the mixpanel library after the script loads & runs
          mixpanel_master['init'] = function (token, config, name) {
            if (name) {
              // initialize a sub library
              if (!mixpanel_master[name]) {
                mixpanel_master[name] = instances[name] = create_mplib(token, config, name);
                mixpanel_master[name]._loaded();
              }
              return mixpanel_master[name];
            } else {
              var instance = mixpanel_master;
              if (instances[PRIMARY_INSTANCE_NAME]) {
                // main mixpanel lib already initialized
                instance = instances[PRIMARY_INSTANCE_NAME];
              } else if (token) {
                // intialize the main mixpanel lib
                instance = create_mplib(token, config, PRIMARY_INSTANCE_NAME);
                instance._loaded();
                instances[PRIMARY_INSTANCE_NAME] = instance;
              }
              mixpanel_master = instance;
              if (init_type === INIT_SNIPPET) {
                win[PRIMARY_INSTANCE_NAME] = mixpanel_master;
              }
              extend_mp();
            }
          };
        };
        var add_dom_loaded_handler = function add_dom_loaded_handler() {
          // Cross browser DOM Loaded support
          function dom_loaded_handler() {
            // function flag since we only want to execute this once
            if (dom_loaded_handler.done) {
              return;
            }
            dom_loaded_handler.done = true;
            DOM_LOADED = true;
            ENQUEUE_REQUESTS = false;
            _.each(instances, function (inst) {
              inst._dom_loaded();
            });
          }
          function do_scroll_check() {
            try {
              document$1.documentElement.doScroll('left');
            } catch (e) {
              setTimeout(do_scroll_check, 1);
              return;
            }
            dom_loaded_handler();
          }
          if (document$1.addEventListener) {
            if (document$1.readyState === 'complete') {
              // safari 4 can fire the DOMContentLoaded event before loading all
              // external JS (including this file). you will see some copypasta
              // on the internet that checks for 'complete' and 'loaded', but
              // 'loaded' is an IE thing
              dom_loaded_handler();
            } else {
              document$1.addEventListener('DOMContentLoaded', dom_loaded_handler, false);
            }
          } else if (document$1.attachEvent) {
            // IE
            document$1.attachEvent('onreadystatechange', dom_loaded_handler);

            // check to make sure we arn't in a frame
            var toplevel = false;
            try {
              toplevel = win.frameElement === null;
            } catch (e) {
              // noop
            }
            if (document$1.documentElement.doScroll && toplevel) {
              do_scroll_check();
            }
          }

          // fallback handler, always will work
          _.register_event(win, 'load', dom_loaded_handler, true);
        };
        function init_as_module(bundle_loader) {
          load_extra_bundle = bundle_loader;
          init_type = INIT_MODULE;
          mixpanel_master = new MixpanelLib();
          override_mp_init_func();
          mixpanel_master['init']();
          add_dom_loaded_handler();
          return mixpanel_master;
        }

        // For loading separate bundles asynchronously via script tag

        // For builds that have everything in one bundle, no extra work.
        function loadNoop(_src, onload) {
          onload();
        }

        /* eslint camelcase: "off" */

        var mixpanel = init_as_module(loadNoop);
        module.exports = mixpanel;

        // #endregion ORIGINAL CODE

        _cjsExports = exports('default', module.exports);
      }, {});
    }
  };
});

System.register("chunks:///_virtual/mixpanel.cjs.mjs_cjs=&original=.js", ['./mixpanel.cjs.js', './cjs-loader.mjs'], function (exports, module) {
  var __cjsMetaURL, loader;
  return {
    setters: [function (module) {
      __cjsMetaURL = module.__cjsMetaURL;
      var _setter = {};
      _setter.__cjsMetaURL = module.__cjsMetaURL;
      _setter.default = module.default;
      exports(_setter);
    }, function (module) {
      loader = module.default;
    }],
    execute: function () {
      // I am the facade module who provides access to the CommonJS module './mixpanel.cjs.js'~
      if (!__cjsMetaURL) {
        loader.throwInvalidWrapper('./mixpanel.cjs.js', module.meta.url);
      }
      loader.require(__cjsMetaURL);
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