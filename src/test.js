import { v4 as uuidv4 } from 'uuid';

/**
 * GF(256)の演算を直接計算する実装
 * テーブル参照ではなく、毎回計算することで信頼性を高める
 */
const GF256 = {
  // 加算と減算はXOR
  add: (a, b) => a ^ b,
  sub: (a, b) => a ^ b,
  
  // 乗算（シンプルで信頼性の高い実装）
  mul: function(a, b) {
    a = a & 0xff; // 8ビットに制限
    b = b & 0xff;
    
    if (a === 0 || b === 0) return 0;
    
    let result = 0;
    let temp_a = a;
    
    // シフトと加算による乗算
    for (let i = 0; i < 8; i++) {
      if (b & 1) {
        result ^= temp_a; // 現在のaをXOR
      }
      
      // aを2倍（シフト）し、必要ならGF(256)の既約多項式でXOR
      const highBit = temp_a & 0x80;
      temp_a = (temp_a << 1) & 0xff;
      if (highBit) {
        temp_a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
      }
      
      b >>= 1; // bを右シフト
    }
    
    return result;
  },
  
  // 除算（逆元を使用）
  div: function(a, b) {
    a = a & 0xff;
    b = b & 0xff;
    
    if (b === 0) throw new Error('0による除算はできません');
    if (a === 0) return 0;
    
    // b の逆元を計算
    const b_inv = this.inverse(b);
    
    // a / b = a * (b^-1)
    return this.mul(a, b_inv);
  },
  
  // 逆元計算（拡張ユークリッドアルゴリズム）
  inverse: function(a) {
    if (a === 0) throw new Error('0の逆元は存在しません');
    
    // 拡張ユークリッドアルゴリズムによるGF(256)での逆元計算
    let t = 0, newt = 1;
    let r = 0x11b, newr = a; // 0x11b = x^8 + x^4 + x^3 + x + 1
    
    while (newr !== 0) {
      const quotient = this.polyDiv(r, newr);
      
      [t, newt] = [newt, t ^ this.polyMul(quotient, newt)];
      [r, newr] = [newr, r ^ this.polyMul(quotient, newr)];
    }
    
    if (r > 1) {
      throw new Error('多項式は可逆ではありません');
    }
    
    return t;
  },
  
  // 多項式除算（GF(2)上）- 逆元計算用
  polyDiv: function(a, b) {
    if (b === 0) throw new Error('0による多項式除算はできません');
    
    let result = 0;
    let degree_diff = this.degree(a) - this.degree(b);
    
    if (degree_diff < 0) return 0;
    
    for (let i = degree_diff; i >= 0; i--) {
      if (a & (1 << (i + this.degree(b)))) {
        result |= 1 << i;
        a ^= b << i;
      }
    }
    
    return result;
  },
  
  // 多項式乗算（GF(2)上）- 逆元計算用
  polyMul: function(a, b) {
    let result = 0;
    
    while (a > 0) {
      if (a & 1) {
        result ^= b;
      }
      b <<= 1;
      a >>= 1;
    }
    
    return result;
  },
  
  // 多項式の次数
  degree: function(a) {
    let degree = -1;
    
    for (let i = 0; i < 32; i++) {
      if (a & (1 << i)) {
        degree = i;
      }
    }
    
    return degree;
  }
};

/**
 * 多項式を評価する関数（修正版）
 * @param {Uint8Array|Array} coeffs - 多項式の係数（低次から高次）
 * @param {number} x - 評価するx値
 * @returns {number} 評価結果
 */
const evaluatePolynomial = (coeffs, x) => {
  // x=0の場合は定数項を返す
  if (x === 0) return coeffs[0];
  
  // ホーナー法を用いた効率的な多項式評価
  let result = coeffs[0];
  for (let i = 1; i < coeffs.length; i++) {
    result = GF256.add(GF256.mul(result, x), coeffs[i]);
  }
  return result;
};

/**
 * ラグランジュ補間法で多項式を復元（修正版）
 * @param {Array} points - (x, y)座標の配列
 * @returns {number} f(0)の値
 */
const lagrangeInterpolation = (points) => {
  console.log('ラグランジュ補間開始 - ポイント:', JSON.stringify(points));
  
  if (points.length === 0) {
    throw new Error('ポイントが必要です');
  }
  
  // f(0)を求める
  let result = 0;
  
  for (let i = 0; i < points.length; i++) {
    const [xi, yi] = points[i];
    console.log(`ポイント[${i}]: (${xi}, ${yi})`);
    
    // このポイントのラグランジュ基底多項式の値を計算
    let basis = 1;
    
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      
      const [xj] = points[j];
      
      // 分子: (0 - xj) = xj (GF(256)では -xj = xj)
      const num = xj;
      
      // 分母: (xi - xj)
      const denom = GF256.sub(xi, xj);
      
      if (denom === 0) {
        throw new Error(`重複するx座標: xi=${xi}, xj=${xj}`);
      }
      
      // 除算
      const term = GF256.div(num, denom);
      console.log(`  j=${j}: xj=${xj}, 分子=${num}, 分母=${denom}, 項=${term}`);
      
      // 基底多項式に掛ける
      basis = GF256.mul(basis, term);
    }
    
    console.log(`  基底多項式 L_${i}(0) = ${basis}`);
    
    // yi * Li(0)
    const term = GF256.mul(yi, basis);
    console.log(`  項の寄与: ${yi} * ${basis} = ${term}`);
    
    // 累積結果に加算
    result = GF256.add(result, term);
    console.log(`  現在の結果: ${result}`);
  }
  
  console.log(`最終結果: ${result}`);
  return result;
};

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
 * 16進数文字列をバイト配列に変換
 * @param {string} hex - 16進数文字列
 * @returns {Uint8Array} バイト配列
 */
export const hexToBytes = (hex) => {
  if (!hex || typeof hex !== 'string' || hex.length % 2 !== 0) {
    console.error('Invalid hex string:', hex);
    return new Uint8Array(0);
  }
  
  try {
    return new Uint8Array(
      hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    );
  } catch (e) {
    console.error('Error converting hex to bytes:', e);
    return new Uint8Array(0);
  }
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
    console.log('秘密のバイト配列:', Array.from(secretBytes));
    
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
      
      console.log(`バイトインデックス ${byteIndex}, 元の値: ${secretBytes[byteIndex]}, 係数:`, Array.from(coeffs));
      
      // 各参加者にシェアを生成
      for (let x = 1; x <= totalShares; x++) {
        // インデックスは1から始まる
        const y = evaluatePolynomial(coeffs, x);
        console.log(`参加者 ${x}, バイト ${byteIndex}, 多項式結果: ${y}`);
        
        if (shares[x - 1] === undefined) {
          shares[x - 1] = {
            x,
            y: [y]  // 通常の配列として保持
          };
        } else {
          shares[x - 1].y.push(y);
        }
      }
    }
    
    // シェアをエンコード - 復元側と互換性のある形式に
    const encodedShares = shares.map(share => {
      // xは16進数で2桁にエンコード
      const xHex = share.x.toString(16).padStart(2, '0');
      
      // yはUint8Arrayに変換してから16進数にエンコード
      const yHex = bytesToHex(new Uint8Array(share.y));
      console.log(`シェアID: share-${share.x}, X: ${xHex}, Y(Hex): ${yHex}`);
      
      // プレフィックス(80)を追加 - オリジナルライブラリとの互換性のため
      return {
        id: `share-${uuidv4()}`,
        value: `80${xHex}${yHex}`,
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
    console.log('シェア値:', shareValues);
    
    // エンコーディング情報を取得（最初のシェアから）
    const encoding = shares[0].encoding || 'utf-8';
    console.log('使用するエンコーディング:', encoding);
    
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
        y: Array.from(yBytes) // 一貫性のためにArray.fromを使用
      };
    });
    
    console.log('デコードされたシェア:', JSON.stringify(decodedShares));
    
    // シェアの有効性チェック
    if (decodedShares.length === 0) {
      throw new Error('有効なシェアがありません');
    }
    
    // 全シェアのyの長さが同じか確認
    const yLengths = decodedShares.map(share => share.y.length);
    const allSameLength = yLengths.every(length => length === yLengths[0]);
    if (!allSameLength) {
      throw new Error('シェアのバイト長が一致しません');
    }
    
    // 秘密の長さは全てのシェアのy配列の長さと同じ
    const secretLength = decodedShares[0].y.length;
    
    // 結果のバイト配列
    const result = new Uint8Array(secretLength);
    console.log('初期化された結果バイト配列:', result);
    
    // バイトごとに復元
    for (let byteIndex = 0; byteIndex < secretLength; byteIndex++) {
      // 各シェアから対応するバイトのポイントを収集
      const points = decodedShares.map(share => [
        share.x,
        share.y[byteIndex]
      ]);
      
      // ポイントをログ
      console.log(`バイト ${byteIndex}, ポイント:`, JSON.stringify(points));
      
      // ラグランジュ補間法でf(0)を求める
      result[byteIndex] = lagrangeInterpolation(points);
      
      // 結果をログ
      console.log(`バイト ${byteIndex}, 補間結果: ${result[byteIndex]}`);
    }
    
    // 復元されたバイト配列をログ出力
    console.log('復元されたバイト配列:', Array.from(result).map(b => b.toString(16).padStart(2, '0')).join(' '));
    
    try {
      // バイト配列を文字列に変換
      const decoded = new TextDecoder(encoding).decode(result);
      console.log('デコード結果:', decoded);
      return decoded;
    } catch (decodeError) {
      console.error('TextDecoderでのデコードに失敗:', decodeError);
      
      // エラーとともに16進数表現も添えて再スロー
      const hexString = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('');
      throw new Error(`デコードに失敗しました: ${decodeError.message}。データ(16進数): ${hexString}`);
    }
  } catch (error) {
    console.error('シェア結合に失敗しました:', error);
    throw new Error('シェア結合に失敗しました: ' + error.message);
  }
};

// テスト関数
function testSimple() {
  // 基本演算のテスト
  console.log("--- GF(256)基本演算テスト ---");
  console.log("加算: 3 + 7 =", GF256.add(3, 7));
  console.log("乗算: 3 * 7 =", GF256.mul(3, 7));
  console.log("除算: 21 / 7 =", GF256.div(21, 7));
  
  // 逆元テスト
  console.log("\n--- 逆元テスト ---");
  for (let i = 1; i <= 5; i++) {
    const inv = GF256.inverse(i);
    console.log(`${i}の逆元 = ${inv}, 検証: ${i} * ${inv} = ${GF256.mul(i, inv)}`);
  }
  
  // シャミア分散法テスト
  console.log("\n--- シャミア秘密分散テスト ---");
  // シンプルな秘密（'A'のASCIIコード = 65）
  const secret = "A";
  // シェアを作成
  const shares = createShares(secret, 5, 3);
  console.log("作成されたシェア:", shares);
  
  // シェアから秘密を復元
  const recovered = combineShares(shares.slice(0, 3));
  console.log("復元された秘密:", recovered);
  
  return recovered === secret;
}

// テスト実行（必要に応じてコメントアウト解除）
console.log("テスト結果:", testSimple() ? "成功" : "失敗");