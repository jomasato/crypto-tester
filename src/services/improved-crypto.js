// src/services/improved-crypto.js

import { v4 as uuidv4 } from 'uuid';
// secrets.js-grempeの代わりに使用する改良版シャミア秘密分散の実装
// このモジュールは外部ライブラリに依存せず、より安全な実装を提供します

/**
 * 暗号化用のランダムキーを生成
 * @returns {Promise<string>} 生成されたキー（Hex形式）
 */
export const generateEncryptionKey = async () => {
  // Web Crypto APIを使用して256ビット(32バイト)のランダムキーを生成
  const key = await window.crypto.getRandomValues(new Uint8Array(32));
  // 16進数文字列に変換
  return Array.from(key)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

/**
 * 暗号化キーをインポート
 * @param {string} keyHex - 16進数形式のキー
 * @returns {Promise<CryptoKey>} Cryptoキーオブジェクト
 */
export const importKey = async (keyHex) => {
  // 16進数から配列バッファに変換
  const keyData = new Uint8Array(
    keyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
  );
  
  // AES-GCMキーとしてインポート
  return await window.crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM', length: 256 },
    false, // extractable
    ['encrypt', 'decrypt'] // 使用目的
  );
};

/**
 * データをキーで暗号化
 * @param {any} data - 暗号化するデータ
 * @param {string} keyHex - 暗号化キー（16進数）
 * @returns {Promise<Object>} 暗号化されたデータ（iv含む）
 */
export const encryptWithKey = async (data, keyHex) => {
  // データをJSON文字列に変換
  const dataString = JSON.stringify(data);
  const dataBuffer = new TextEncoder().encode(dataString);
  
  // キーをインポート
  const key = await importKey(keyHex);
  
  // 初期化ベクトル（IV）を生成
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  // 暗号化を実行
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    dataBuffer
  );
  
  // バイナリデータを16進数に変換
  const encryptedHex = Array.from(new Uint8Array(encryptedBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  const ivHex = Array.from(iv)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  // 暗号化データとIVを返す
  return {
    encryptedData: encryptedHex,
    iv: ivHex
  };
};

/**
 * 暗号化されたデータをキーで復号
 * @param {Object} encryptedObj - 暗号化されたデータオブジェクト（encryptedData, iv）
 * @param {string} keyHex - 復号キー（16進数）
 * @returns {Promise<any>} 復号されたデータ
 */
export const decryptWithKey = async (encryptedObj, keyHex) => {
  try {
    const { encryptedData, iv } = encryptedObj;
    
    // 16進数からバイナリデータに変換
    const encryptedBuffer = new Uint8Array(
      encryptedData.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    ).buffer;
    
    const ivBuffer = new Uint8Array(
      iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    );
    
    // キーをインポート
    const key = await importKey(keyHex);
    
    // 復号を実行
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBuffer },
      key,
      encryptedBuffer
    );
    
    // バッファをJSONに変換
    const decryptedText = new TextDecoder().decode(decryptedBuffer);
    return JSON.parse(decryptedText);
  } catch (error) {
    console.error('復号化に失敗しました:', error);
    throw new Error('復号化に失敗しました');
  }
};

/**
 * RSA鍵ペアを生成
 * @returns {Promise<Object>} キーペア（publicKey, privateKey）
 */
export const generateKeyPair = async () => {
  try {
    // RSA-OAEPキーペアを生成
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true, // キーをエクスポート可能に設定
      ['encrypt', 'decrypt']
    );
    
    // 秘密鍵をエクスポート（PKCS#8形式）
    const privateKeyBuffer = await window.crypto.subtle.exportKey(
      'pkcs8',
      keyPair.privateKey
    );
    
    // 公開鍵をエクスポート（SPKI形式）
    const publicKeyBuffer = await window.crypto.subtle.exportKey(
      'spki',
      keyPair.publicKey
    );
    
    // バイナリデータを16進数に変換
    const privateKeyHex = Array.from(new Uint8Array(privateKeyBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    const publicKeyHex = Array.from(new Uint8Array(publicKeyBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    return {
      privateKey: privateKeyHex,
      publicKey: publicKeyHex
    };
  } catch (error) {
    console.error('キーペア生成に失敗しました:', error);
    throw new Error('キーペア生成に失敗しました');
  }
};

/**
 * 16進数の公開鍵をインポート
 * @param {string} publicKeyHex - 16進数形式の公開鍵
 * @returns {Promise<CryptoKey>} インポートされた公開鍵
 */
export const importPublicKey = async (publicKeyHex) => {
  try {
    // 16進数から配列バッファに変換
    const keyData = new Uint8Array(
      publicKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    ).buffer;
    
    // SPKI形式からRSA-OAEP公開鍵をインポート
    return await window.crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false, // extractable
      ['encrypt'] // 使用目的
    );
  } catch (error) {
    console.error('公開鍵のインポートに失敗しました:', error);
    throw new Error('公開鍵のインポートに失敗しました');
  }
};

/**
 * 16進数の秘密鍵をインポート
 * @param {string} privateKeyHex - 16進数形式の秘密鍵
 * @returns {Promise<CryptoKey>} インポートされた秘密鍵
 */
export const importPrivateKey = async (privateKeyHex) => {
  try {
    // 16進数から配列バッファに変換
    const keyData = new Uint8Array(
      privateKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    ).buffer;
    
    // PKCS#8形式からRSA-OAEP秘密鍵をインポート
    return await window.crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false, // extractable
      ['decrypt'] // 使用目的
    );
  } catch (error) {
    console.error('秘密鍵のインポートに失敗しました:', error);
    throw new Error('秘密鍵のインポートに失敗しました');
  }
};

/**
 * 公開鍵でデータを暗号化
 * @param {any} data - 暗号化するデータ
 * @param {string} publicKeyHex - 16進数形式の公開鍵
 * @returns {Promise<string>} 暗号化されたデータ（16進数）
 */
export const encryptWithPublicKey = async (data, publicKeyHex) => {
  try {
    // 公開鍵をインポート
    const publicKey = await importPublicKey(publicKeyHex);
    
    // データをJSON文字列に変換
    const dataString = JSON.stringify(data);
    const dataBuffer = new TextEncoder().encode(dataString);
    
    // RSA-OAEPで暗号化
    const encryptedBuffer = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      dataBuffer
    );
    
    // バイナリデータを16進数に変換
    return Array.from(new Uint8Array(encryptedBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  } catch (error) {
    console.error('公開鍵暗号化に失敗しました:', error);
    throw new Error('公開鍵暗号化に失敗しました');
  }
};

/**
 * 秘密鍵でデータを復号
 * @param {string} encryptedHex - 暗号化されたデータ（16進数）
 * @param {string} privateKeyHex - 16進数形式の秘密鍵
 * @returns {Promise<any>} 復号されたデータ
 */
export const decryptWithPrivateKey = async (encryptedHex, privateKeyHex) => {
  try {
    // 秘密鍵をインポート
    const privateKey = await importPrivateKey(privateKeyHex);
    
    // 16進数からバイナリデータに変換
    const encryptedBuffer = new Uint8Array(
      encryptedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    ).buffer;
    
    // RSA-OAEPで復号
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      encryptedBuffer
    );
    
    // バッファをJSONに変換
    const decryptedText = new TextDecoder().decode(decryptedBuffer);
    return JSON.parse(decryptedText);
  } catch (error) {
    console.error('秘密鍵復号に失敗しました:', error);
    throw new Error('秘密鍵復号に失敗しました');
  }
};

/**
 * GF(256)上の有限体演算のための補助関数
 */
const gf256 = {
  // 掛け算
  mul: (a, b) => {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if ((b & 1) !== 0) {
        p ^= a;
      }
      const highBit = a & 0x80;
      a = (a << 1) & 0xff;
      if (highBit !== 0) {
        a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
      }
      b >>= 1;
    }
    return p;
  },
  
  // 割り算（テーブルベースの逆元を使用）
  div: (a, b) => {
    if (b === 0) {
      throw new Error('0で割ることはできません');
    }
    if (a === 0) return 0;
    
    // GF(256)の逆元テーブル
    const inverseTable = [
      0x00, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5, 0xc7, 
      0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f, 0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40, 0xee, 0xb2, 
      0x3a, 0x6e, 0x5a, 0xf1, 0x55, 0x4d, 0xa8, 0xc9, 0xc1, 0x0a, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2, 
      0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20, 0x6f, 0x77, 0xbb, 0x59, 0x19, 
      0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69, 0xa7, 0x64, 0xab, 0x13, 0x54, 0x25, 0xe9, 0x09, 
      0xed, 0x5c, 0x05, 0xca, 0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e, 0x22, 0xf0, 0x51, 0xec, 0x61, 0x17, 
      0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4, 0x47, 0x91, 0xdf, 0x33, 0x93, 0x21, 0x3b, 
      0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c, 0xb6, 0x70, 0xd0, 0x06, 0xa1, 0xfa, 0x81, 0x82, 
      0x83, 0x7e, 0x7f, 0x80, 0x96, 0x73, 0xbe, 0x56, 0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x02, 0xb9, 0xa4, 
      0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72, 0x2a, 0x14, 0x9f, 0x88, 0xf9, 0xdc, 0x89, 0x9a, 
      0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48, 0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62, 
      0x0c, 0xe0, 0x1f, 0xef, 0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57, 
      0x0b, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0x0f, 0xa9, 0x27, 0x53, 0x04, 0x1b, 0xfc, 0xac, 0xe6, 
      0x7a, 0x07, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea, 0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b, 
      0xb1, 0x0d, 0xd6, 0xeb, 0xc6, 0x0e, 0xcf, 0xad, 0x08, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3, 
      0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8c, 0xdd, 0x9c, 0x7d, 0xa0, 0xcd, 0x1a, 0x41, 0x1c
    ];
    
    return gf256.mul(a, inverseTable[b]);
  }
};

/**
 * 多項式を評価する関数（効率化）
 * @param {Array} coeffs - 多項式の係数
 * @param {number} x - 評価するx値
 * @returns {number} 評価結果
 */
const evaluatePolynomial = (coeffs, x) => {
  let result = coeffs[0];
  for (let i = 1; i < coeffs.length; i++) {
    result = gf256.mul(result, x) ^ coeffs[i];
  }
  return result;
};

/**
 * ラグランジュ補間法で多項式を復元（最適化）
 * @param {Array} points - (x, y)座標の配列
 * @returns {number} f(0)の値
 */
const lagrangeInterpolation = (points) => {
  const k = points.length;
  let result = 0;
  
  // 各ポイントに対してラグランジュ係数を計算
  for (let i = 0; i < k; i++) {
    const [xi, yi] = points[i];
    if (yi === 0) continue; // 最適化: yiが0なら項は0になる
    
    // この項の分子と分母を計算
    let numerator = 1;
    let denominator = 1;
    
    for (let j = 0; j < k; j++) {
      if (i === j) continue;
      
      const [xj] = points[j];
      numerator = gf256.mul(numerator, xj);
      denominator = gf256.mul(denominator, xj ^ xi);
    }
    
    // 係数を計算してf(0)に加算
    const term = gf256.mul(yi, gf256.div(numerator, denominator));
    result ^= term;
  }
  
  return result;
}

/**
 * バイト配列を16進数文字列に変換
 * @param {Uint8Array} bytes - バイト配列
 * @returns {string} 16進数文字列
 */
const bytesToHex = (bytes) => {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};


/**
 * シャミア秘密分散法で秘密を複数のシェアに分割（修正版）
 * @param {string} secret - 分割する秘密情報
 * @param {number} totalShares - 総シェア数
 * @param {number} threshold - 必要なシェア数
 * @returns {Array} シェアの配列
 */
export const createShares = (secret, totalShares, threshold) => {
    try {
      // 入力検証
      if (threshold < 2) {
        throw new Error('しきい値は2以上である必要があります');
      }
      if (totalShares < threshold) {
        throw new Error('総シェア数はしきい値以上である必要があります');
      }
  
      // 秘密情報をバイト配列に変換
      const secretBytes = new TextEncoder().encode(secret);
      
      // エンコーディング情報の保存（復元時に必要）
      const encoding = 'utf-8';
      
      // シェアのリスト
      const shares = [];
      
      // バイトごとに処理
      for (let byteIndex = 0; byteIndex < secretBytes.length; byteIndex++) {
        // 各バイトに対して多項式を作成
        const coeffs = new Uint8Array(threshold);
        
        // a_0はシークレットのバイト値
        coeffs[0] = secretBytes[byteIndex];
        
        // a_1からa_{t-1}は乱数
        window.crypto.getRandomValues(coeffs.subarray(1));
        
        // 各参加者にシェアを生成
        for (let x = 1; x <= totalShares; x++) {
          // インデックスは1から始まる
          const y = evaluatePolynomial(coeffs, x);
          
          if (shares[x - 1] === undefined) {
            shares[x - 1] = {
              x,
              y: [y]
            };
          } else {
            shares[x - 1].y.push(y);
          }
        }
      }
      
      // シェアをエンコード
      const encodedShares = shares.map(share => {
        // xとyをエンコード
        const xByte = String.fromCharCode(share.x);
        const yHex = bytesToHex(new Uint8Array(share.y));
        
        // プレフィックス(80)を追加 - オリジナルライブラリとの互換性のため
        return {
          id: `share-${uuidv4()}`,
          value: `80${share.x.toString(16).padStart(2, '0')}${yHex}`,
          encoding // エンコーディング情報を追加
        };
      });
      
      return encodedShares;
    } catch (error) {
      console.error('シェア作成に失敗しました:', error);
      throw new Error('シェア作成に失敗しました: ' + error.message);
    }
  };
  
  /**
   * シェアを結合して秘密を復元（修正版）
   * @param {Array} shares - シェアの配列
   * @returns {string} 復元された秘密情報
   */
  export const combineShares = (shares) => {
    try {
      // シェアの値だけを抽出
      const shareValues = shares.map(share => share.value || share);
      
      // エンコーディング情報を取得（最初のシェアから）
      const encoding = shares[0].encoding || 'utf-8';
      
      // シェアをデコード
      const decodedShares = shareValues.map(shareValue => {
        // 形式チェック
        if (!shareValue.startsWith('80')) {
          throw new Error('不正なシェア形式です');
        }
        
        // xとyを抽出
        const x = parseInt(shareValue.substring(2, 4), 16);
        const yHex = shareValue.substring(4);
        const yBytes = hexToBytes(yHex);
        
        return {
          x,
          y: Array.from(yBytes)
        };
      });
      
      // 秘密の長さは全てのシェアのy配列の長さと同じ
      const secretLength = decodedShares[0].y.length;
      
      // 結果のバイト配列
      const result = new Uint8Array(secretLength);
      
      // バイトごとに復元
      for (let byteIndex = 0; byteIndex < secretLength; byteIndex++) {
        // 各シェアから対応するバイトのポイントを収集
        const points = decodedShares.map(share => [
          share.x,
          share.y[byteIndex]
        ]);
        
        // ラグランジュ補間法でf(0)を求める
        result[byteIndex] = lagrangeInterpolation(points);
      }
      
      // バイト配列を文字列に変換（指定されたエンコーディングで）
      return new TextDecoder(encoding).decode(result);
    } catch (error) {
      console.error('シェア結合に失敗しました:', error);
      
      // デバッグ情報を追加
      console.debug('シェアの数:', shares.length);
      if (shares.length > 0) {
        console.debug('最初のシェア:', shares[0]);
      }
      
      throw new Error('シェア結合に失敗しました: ' + error.message);
    }
  };
/**
 * パスワードから暗号化キーを派生（PBKDF2）- バックアップ実装付き
 * @param {string} password - ユーザーパスワード
 * @param {Uint8Array} salt - ソルト（新規の場合は省略可）
 * @returns {Promise<Object>} 派生キーとソルト
 */
export const deriveKeyFromPassword = async (password, salt = null) => {
  try {
    // ソルトがない場合は新しく生成
    if (!salt) {
      salt = window.crypto.getRandomValues(new Uint8Array(16));
    }
    
    // パスワードからキーマテリアルを作成
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    // Web Crypto API が利用可能かチェック
    if (window.crypto && window.crypto.subtle) {
      try {
        const keyMaterial = await window.crypto.subtle.importKey(
          'raw',
          passwordBuffer,
          { name: 'PBKDF2' },
          false,
          ['deriveBits', 'deriveKey']
        );
        
        // PBKDF2を使ってキーを派生
        const derivedKey = await window.crypto.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt,
            iterations: 100000, // 適切な反復回数
            hash: 'SHA-256'
          },
          keyMaterial,
          { name: 'AES-GCM', length: 256 },
          true, // エクスポート可能に設定
          ['encrypt', 'decrypt']
        );
        
        // 派生キーをエクスポート
        const exportedKey = await window.crypto.subtle.exportKey('raw', derivedKey);
        const keyHex = Array.from(new Uint8Array(exportedKey))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
        
        // ソルトを16進数に変換
        const saltHex = Array.from(salt)
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
        
        return {
          derivedKey,
          key: keyHex,
          salt: saltHex
        };
      } catch (cryptoError) {
        console.warn('Web Crypto APIでの鍵派生に失敗しました - フォールバック実装を使用します:', cryptoError);
        return fallbackDeriveKey(password, salt);
      }
    } else {
      console.warn('Web Crypto APIが利用できません - フォールバック実装を使用します');
      return fallbackDeriveKey(password, salt);
    }
  } catch (error) {
    console.error('鍵派生に失敗しました:', error);
    // 最終手段としてフォールバック
    return fallbackDeriveKey(password, salt);
  }
};

/**
 * パスワードからキーを派生するフォールバック実装
 * 注: これは暗号学的に安全なPBKDF2ではありませんが、Web Crypto APIが使用できない場合の代替です
 * @param {string} password - パスワード
 * @param {Uint8Array} salt - ソルト
 * @returns {Promise<Object>} 派生キーと関連情報
 */
const fallbackDeriveKey = (password, salt) => {
  return new Promise(resolve => {
    // 簡易的なキー派生（本番環境では使用しないでください）
    const encoder = new TextEncoder();
    const saltHex = Array.from(salt)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    // パスワードとソルトを結合して繰り返しハッシュ化する簡易実装
    let key = password + saltHex;
    
    // 単純なハッシュ反復（これは例示目的です - 本番環境では使用しないでください）
    for (let i = 0; i < 1000; i++) {
      // 単純な文字列ハッシュ
      let hash = 0;
      for (let j = 0; j < key.length; j++) {
        hash = ((hash << 5) - hash) + key.charCodeAt(j);
        hash |= 0; // 32ビット整数に変換
      }
      key = hash.toString(16);
    }
    
    // 256ビット（32バイト）のキーを生成
    let derivedKeyArray = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      derivedKeyArray[i] = parseInt(key.substr((i * 2) % key.length, 2) || '0', 16);
    }
    
    const keyHex = Array.from(derivedKeyArray)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    resolve({
      derivedKey: null, // Web Crypto APIのオブジェクトはありません
      key: keyHex,
      salt: saltHex,
      isWebCrypto: false
    });
  });
};

/**
 * 暗号化キーを安全にストレージに保存
 * @param {string} masterKey - マスター暗号化キー
 * @param {string} password - パスワード
 * @returns {Promise<boolean>} 成功した場合はtrue
 */
export const storeEncryptionKeySecurely = async (masterKey, password) => {
    try {
      // パスワードからキーを派生
      const { derivedKey, salt, key, isWebCrypto } = await deriveKeyFromPassword(password);
      
      // Web Crypto APIが利用可能かどうかで処理を分岐
      let encryptedKeyHex;
      let ivHex;
      
      if (derivedKey && window.crypto.subtle) {
        // 初期化ベクトル（IV）を生成
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // マスターキーをバッファに変換（文字列の場合）
        let masterKeyBuffer;
        if (typeof masterKey === 'string') {
          masterKeyBuffer = new TextEncoder().encode(masterKey);
        } else {
          // すでにバイナリ形式の場合
          masterKeyBuffer = masterKey;
        }
        
        // Web Crypto APIでマスターキーを暗号化
        const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv
          },
          derivedKey,
          masterKeyBuffer
        );
        
        // バイナリデータを16進数に変換
        encryptedKeyHex = Array.from(new Uint8Array(encryptedKeyBuffer))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
        
        ivHex = Array.from(iv)
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      } else {
      // フォールバック: 簡易暗号化（本番環境では使用しないでください）
      console.warn('フォールバック暗号化を使用しています - 本番環境では推奨されません');
      
      // 簡易IV生成
      const iv = new Uint8Array(12);
      for (let i = 0; i < 12; i++) {
        iv[i] = Math.floor(Math.random() * 256);
      }
      
      // 単純なXORベースの暗号化（これは例示目的です - 本番環境では使用しないでください）
      const masterKeyBytes = new TextEncoder().encode(masterKey);
      const keyBytes = hexToBytes(key);
      const encryptedBytes = new Uint8Array(masterKeyBytes.length);
      
      for (let i = 0; i < masterKeyBytes.length; i++) {
        encryptedBytes[i] = masterKeyBytes[i] ^ keyBytes[i % keyBytes.length] ^ iv[i % iv.length];
      }
      
      encryptedKeyHex = bytesToHex(encryptedBytes);
      ivHex = bytesToHex(iv);
    }
    
    // 暗号化データを保存形式に変換
    const secureData = {
        encryptedKey: encryptedKeyHex,
        iv: ivHex,
        salt: Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join(''),
        version: 2,
        algorithm: derivedKey ? 'AES-GCM' : 'XOR-FALLBACK',
        iterations: derivedKey ? 100000 : 1000,
        createdAt: new Date().toISOString(),
        // 重要: キーのエンコーディング情報を保存
        keyEncoding: 'utf8'
      };
    
      return await saveToSecureStorage('masterKey', secureData);
    } catch (error) {
      console.error('暗号化キーの保存に失敗しました:', error);
      throw new Error('暗号化キーの保存に失敗しました');
    }
  };

/**
 * 16進数文字列をバイト配列に変換
 * @param {string} hex - 16進数文字列
 * @returns {Uint8Array} バイト配列
 */
const hexToBytes = (hex) => {
  if (!hex || hex.length % 2 !== 0) {
    return new Uint8Array(0);
  }
  
  return new Uint8Array(
    hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
  );
};

/**
 * 安全なストレージに保存（IndexedDBプライマリ、バックアプオプション付き）
 * @param {string} key - 保存するキー名
 * @param {any} data - 保存するデータ
 * @returns {Promise<boolean>} 成功した場合はtrue
 */
export const saveToSecureStorage = (key, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      // 最初にIndexedDBに保存を試みる
      const savedToIndexedDB = await saveToIndexedDB(key, data);
      
      if (savedToIndexedDB) {
        return resolve(true);
      }
      
      // IndexedDBが失敗した場合の代替手段（メモリ内の一時ストレージ）
      const secureBackupStorage = getSecureBackupStorage();
      secureBackupStorage[key] = data;
      
      resolve(true);
    } catch (error) {
      reject(error);
    }
  });
};

/**
 * IndexedDBにデータを保存
 * @param {string} key - 保存するキー名
 * @param {any} data - 保存するデータ
 * @returns {Promise<boolean>} 成功した場合はtrue
 */
const saveToIndexedDB = (key, data) => {
  return new Promise((resolve, reject) => {
    try {
      const request = indexedDB.open('SecureStorage', 2);
      
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('secureData')) {
          db.createObjectStore('secureData', { keyPath: 'id' });
        }
      };
      
      request.onsuccess = (event) => {
        try {
          const db = event.target.result;
          const transaction = db.transaction(['secureData'], 'readwrite');
          const objectStore = transaction.objectStore('secureData');
          
          const storeRequest = objectStore.put({
            id: key,
            data,
            updatedAt: new Date().toISOString()
          });
          
          storeRequest.onsuccess = () => resolve(true);
          storeRequest.onerror = () => {
            console.warn('IndexedDBへの保存に失敗しました - バックアップストレージを使用します');
            resolve(false);
          };
        } catch (txError) {
          console.warn('IndexedDB transaction error:', txError);
          resolve(false);
        }
      };
      
      request.onerror = () => {
        console.warn('IndexedDBを開くことができませんでした - バックアップストレージを使用します');
        resolve(false);
      };
    } catch (error) {
      console.warn('IndexedDB操作エラー:', error);
      resolve(false);
    }
  });
};

/**
 * セキュアなバックアップストレージを取得（メモリ内）
 * @returns {Object} バックアップストレージオブジェクト
 */
const getSecureBackupStorage = () => {
  // メモリ内のストレージ（ページリロード時に消去されます）
  if (!window._secureBackupStorage) {
    window._secureBackupStorage = {};
  }
  return window._secureBackupStorage;
};

/**
 * 安全なストレージからデータを取得
 * @param {string} key - 取得するキー名
 * @returns {Promise<any>} 取得したデータ
 */
export const getFromSecureStorage = async (key) => {
  try {
    // 最初にIndexedDBから取得を試みる
    const dataFromIndexedDB = await getFromIndexedDB(key);
    if (dataFromIndexedDB) {
      return dataFromIndexedDB;
    }
    
    // IndexedDBが失敗した場合、バックアップストレージから取得
    const secureBackupStorage = getSecureBackupStorage();
    if (secureBackupStorage[key]) {
      return secureBackupStorage[key];
    }
    
    return null;
  } catch (error) {
    console.error('ストレージからの取得に失敗しました:', error);
    throw new Error('ストレージからの取得に失敗しました');
  }
};

/**
 * IndexedDBからデータを取得
 * @param {string} key - 取得するキー名
 * @returns {Promise<any>} 取得したデータ
 */
const getFromIndexedDB = (key) => {
  return new Promise((resolve, reject) => {
    try {
      const request = indexedDB.open('SecureStorage', 2);
      
      request.onsuccess = (event) => {
        try {
          const db = event.target.result;
          const transaction = db.transaction(['secureData'], 'readonly');
          const objectStore = transaction.objectStore('secureData');
          
          const getRequest = objectStore.get(key);
          
          getRequest.onsuccess = () => {
            if (getRequest.result) {
              resolve(getRequest.result.data);
            } else {
              resolve(null);
            }
          };
          
          getRequest.onerror = () => resolve(null);
        } catch (txError) {
          console.warn('IndexedDB transaction error:', txError);
          resolve(null);
        }
      };
      
      request.onerror = () => resolve(null);
    } catch (error) {
      console.warn('IndexedDB操作エラー:', error);
      resolve(null);
    }
  });
};

/**
 * 暗号化されたマスターキーを取得して復号
 * @param {string} password - パスワード
 * @returns {Promise<string>} 復号されたマスターキー
 */
export const retrieveEncryptionKeySecurely = async (password) => {
    try {
      // 暗号化されたキーデータを取得
      const secureData = await getFromSecureStorage('masterKey');
      
      if (!secureData) {
        throw new Error('暗号化キーが見つかりません');
      }
      
      // 16進数からバイナリデータに変換
      const encryptedKeyBytes = hexToBytes(secureData.encryptedKey);
      const ivBytes = hexToBytes(secureData.iv);
      const saltBytes = hexToBytes(secureData.salt);
      
      // アルゴリズムとエンコーディングを確認
      const algorithm = secureData.algorithm || 'AES-GCM';
      const keyEncoding = secureData.keyEncoding || 'utf8';
      
      // Web Crypto APIが利用可能であれば使用
      if (algorithm === 'AES-GCM' && window.crypto && window.crypto.subtle) {
        try {
          // パスワードからキーを派生
          const { derivedKey } = await deriveKeyFromPassword(password, saltBytes);
          
          // マスターキーを復号化
          const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: ivBytes
            },
            derivedKey,
            encryptedKeyBytes
          );
          
          // バッファを文字列に変換 (エンコーディングを指定)
          return new TextDecoder(keyEncoding).decode(decryptedBuffer);
        } catch (cryptoError) {
          console.warn('Web Crypto APIでの復号に失敗しました:', cryptoError);
          // デバッグ情報
          console.debug('暗号化データ長:', encryptedKeyBytes.length);
          console.debug('IV長:', ivBytes.length);
          console.debug('ソルト長:', saltBytes.length);
        }
      }
      
      // フォールバック復号（失敗した場合）
      console.warn('フォールバック復号を使用しています');
      
      // パスワードからキーを派生
      const { key } = await deriveKeyFromPassword(password, saltBytes);
      const keyBytes = hexToBytes(key);
      
      // 単純なXORベースの復号
      const decryptedBytes = new Uint8Array(encryptedKeyBytes.length);
      for (let i = 0; i < encryptedKeyBytes.length; i++) {
        decryptedBytes[i] = encryptedKeyBytes[i] ^ keyBytes[i % keyBytes.length] ^ ivBytes[i % ivBytes.length];
      }
      
      // エンコーディングを指定して文字列に変換
      return new TextDecoder(keyEncoding).decode(decryptedBytes);
    } catch (error) {
      console.error('暗号化キーの取得に失敗しました:', error);
      throw new Error('暗号化キーの取得に失敗しました - パスワードが正しくないか、キーが存在しません');
    }
  };

/**
 * リカバリーデータを生成
 * @param {string} encryptionKey - マスター暗号化キー
 * @param {number} totalGuardians - 総ガーディアン数
 * @param {number} requiredShares - リカバリーに必要なシェア数
 * @returns {Object} 生成されたリカバリーデータ
 */
export const generateRecoveryData = (encryptionKey, totalGuardians, requiredShares) => {
  // シェアを作成
  const shares = createShares(encryptionKey, totalGuardians, requiredShares);
  
  // 公開リカバリーデータ
  const publicRecoveryData = {
    version: 2,
    createdAt: new Date().toISOString(),
    requiredShares,
    totalShares: totalGuardians,
    algorithm: 'shamir-secret-sharing',
    library: 'custom-implementation'
  };
  
  // バイト配列に変換
  const publicDataBytes = new TextEncoder().encode(
    JSON.stringify(publicRecoveryData)
  );
  
  return {
    shares,
    publicRecoveryData: publicDataBytes
  };
};