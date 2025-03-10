// src/crypto-tester.js
import React, { useState, useEffect } from 'react';
import * as crypto from './services/improved-crypto';

function CryptoTester() {
  // 各機能のテスト状態
  const [symmetricTestState, setSymmetricTestState] = useState({
    key: '',
    message: '',
    encrypted: null,
    decrypted: null,
    status: '',
    success: null
  });

  const [asymmetricTestState, setAsymmetricTestState] = useState({
    keyPair: null,
    message: '',
    encrypted: null,
    decrypted: null,
    status: '',
    success: null
  });

  const [shamirTestState, setShamirTestState] = useState({
    secret: '',
    totalShares: 5,
    threshold: 3,
    shares: [],
    selectedShares: [],
    recovered: null,
    status: '',
    success: null
  });

  const [keyStorageTestState, setKeyStorageTestState] = useState({
    key: '',
    password: '',
    storedSuccessfully: null,
    retrievedKey: null,
    status: '',
    success: null
  });

  // 対称暗号テスト関数
  const testSymmetricEncryption = async () => {
    try {
      setSymmetricTestState(prev => ({ ...prev, status: 'テスト実行中...', success: null }));
      
      // キーがなければ生成
      const key = symmetricTestState.key || await crypto.generateEncryptionKey();
      
      // 暗号化
      const encrypted = await crypto.encryptWithKey(
        { text: symmetricTestState.message || 'テストメッセージ' }, 
        key
      );
      
      // 復号
      const decrypted = await crypto.decryptWithKey(encrypted, key);
      
      setSymmetricTestState({
        key,
        message: symmetricTestState.message || 'テストメッセージ',
        encrypted,
        decrypted,
        status: '成功: 対称暗号化テスト完了',
        success: true
      });
    } catch (error) {
      console.error('対称暗号化テスト失敗:', error);
      setSymmetricTestState(prev => ({
        ...prev,
        status: `失敗: ${error.message}`,
        success: false
      }));
    }
  };

  // 非対称暗号テスト関数
  const testAsymmetricEncryption = async () => {
    try {
      setAsymmetricTestState(prev => ({ ...prev, status: 'テスト実行中...', success: null }));
      
      // キーペアがなければ生成
      const keyPair = asymmetricTestState.keyPair || await crypto.generateKeyPair();
      
      // 暗号化
      const encrypted = await crypto.encryptWithPublicKey(
        { text: asymmetricTestState.message || 'テストメッセージ' },
        keyPair.publicKey
      );
      
      // 復号
      const decrypted = await crypto.decryptWithPrivateKey(encrypted, keyPair.privateKey);
      
      setAsymmetricTestState({
        keyPair,
        message: asymmetricTestState.message || 'テストメッセージ',
        encrypted,
        decrypted,
        status: '成功: 非対称暗号化テスト完了',
        success: true
      });
    } catch (error) {
      console.error('非対称暗号化テスト失敗:', error);
      setAsymmetricTestState(prev => ({
        ...prev,
        status: `失敗: ${error.message}`,
        success: false
      }));
    }
  };

  // シャミア秘密分散テスト関数
  const testShamirSecretSharing = () => {
    try {
      setShamirTestState(prev => ({ ...prev, status: 'テスト実行中...', success: null }));
      
      // シェアを作成
      const secret = shamirTestState.secret || 'シャミア秘密分散のテスト';
      const shares = crypto.createShares(
        secret,
        shamirTestState.totalShares,
        shamirTestState.threshold
      );
      console.log('生成されたシェア:', shares);
      
      setShamirTestState(prev => ({
        ...prev,
        secret,
        shares,
        selectedShares: [],
        recovered: null,
        status: `成功: ${shares.length}個のシェアを作成しました`,
        success: true
      }));
    } catch (error) {
      console.error('シャミア秘密分散テスト失敗:', error);
      setShamirTestState(prev => ({
        ...prev,
        status: `失敗: ${error.message}`,
        success: false
      }));
    }
  };

  // シェア選択時の処理
  const toggleShareSelection = (shareId) => {
    setShamirTestState(prev => {
      const selected = prev.selectedShares.includes(shareId)
        ? prev.selectedShares.filter(id => id !== shareId)
        : [...prev.selectedShares, shareId];
      
      return { ...prev, selectedShares: selected };
    });
  };

  // 選択したシェアから秘密を復元
  const recoverSecretFromShares = () => {
    try {
      const selectedShares = shamirTestState.shares.filter(share => 
        shamirTestState.selectedShares.includes(share.id)
      );
      
      if (selectedShares.length < shamirTestState.threshold) {
        setShamirTestState(prev => ({
          ...prev,
          status: `失敗: 必要なシェア数(${shamirTestState.threshold})に達していません`,
          success: false
        }));
        return;
      }
      
      const recovered = crypto.combineShares(selectedShares);
      
      setShamirTestState(prev => ({
        ...prev,
        recovered,
        status: '成功: 秘密情報を復元しました',
        success: true
      }));
    } catch (error) {
      console.error('秘密復元失敗:', error);
      setShamirTestState(prev => ({
        ...prev,
        status: `失敗: ${error.message}`,
        success: false
      }));
    }
  };

  // キー保存テスト関数
  const testKeyStorage = async () => {
    try {
      setKeyStorageTestState(prev => ({ ...prev, status: 'テスト実行中...', success: null }));
      
      // キーがなければ生成
      const key = keyStorageTestState.key || await crypto.generateEncryptionKey();
      const password = keyStorageTestState.password || 'テストパスワード';
      
      // キーを保存
      await crypto.storeEncryptionKeySecurely(key, password);
      
      setKeyStorageTestState(prev => ({
        ...prev,
        key,
        password,
        storedSuccessfully: true,
        status: '成功: 暗号化キーを保存しました',
        success: true
      }));
    } catch (error) {
      console.error('キー保存テスト失敗:', error);
      setKeyStorageTestState(prev => ({
        ...prev,
        status: `失敗: ${error.message}`,
        success: false
      }));
    }
  };

  // 保存したキーを取得
  const retrieveStoredKey = async () => {
    try {
      setKeyStorageTestState(prev => ({ ...prev, status: 'キー取得中...', success: null }));
      
      const password = keyStorageTestState.password || 'テストパスワード';
      const retrievedKey = await crypto.retrieveEncryptionKeySecurely(password);
      
      setKeyStorageTestState(prev => ({
        ...prev,
        retrievedKey,
        status: '成功: 暗号化キーを取得しました',
        success: true
      }));
    } catch (error) {
      console.error('キー取得テスト失敗:', error);
      setKeyStorageTestState(prev => ({
        ...prev,
        status: `失敗: ${error.message}`,
        success: false
      }));
    }
  };

  return (
    <div className="crypto-tester">
      <h1>暗号化機能テスト</h1>
      
      {/* 対称暗号テスト */}
      <section className="test-section">
        <h2>対称暗号テスト (AES-GCM)</h2>
        <div className="test-controls">
          <div className="form-group">
            <label>メッセージ:</label>
            <input
              type="text"
              value={symmetricTestState.message}
              onChange={(e) => setSymmetricTestState(prev => ({ ...prev, message: e.target.value }))}
              placeholder="暗号化するメッセージを入力"
            />
          </div>
          <button onClick={testSymmetricEncryption}>テスト実行</button>
        </div>
        
        {symmetricTestState.success !== null && (
          <div className={`test-result ${symmetricTestState.success ? 'success' : 'error'}`}>
            <p><strong>ステータス:</strong> {symmetricTestState.status}</p>
            {symmetricTestState.success && (
              <>
                <p><strong>暗号化キー:</strong> {symmetricTestState.key.substring(0, 15)}...</p>
                <p><strong>暗号化データ:</strong> {JSON.stringify(symmetricTestState.encrypted).substring(0, 30)}...</p>
                <p><strong>復号データ:</strong> {JSON.stringify(symmetricTestState.decrypted)}</p>
              </>
            )}
          </div>
        )}
      </section>
      
      {/* 非対称暗号テスト */}
      <section className="test-section">
        <h2>非対称暗号テスト (RSA-OAEP)</h2>
        <div className="test-controls">
          <div className="form-group">
            <label>メッセージ:</label>
            <input
              type="text"
              value={asymmetricTestState.message}
              onChange={(e) => setAsymmetricTestState(prev => ({ ...prev, message: e.target.value }))}
              placeholder="暗号化するメッセージを入力"
            />
          </div>
          <button onClick={testAsymmetricEncryption}>テスト実行</button>
        </div>
        
        {asymmetricTestState.success !== null && (
          <div className={`test-result ${asymmetricTestState.success ? 'success' : 'error'}`}>
            <p><strong>ステータス:</strong> {asymmetricTestState.status}</p>
            {asymmetricTestState.success && (
              <>
                <p><strong>公開鍵:</strong> {asymmetricTestState.keyPair.publicKey.substring(0, 15)}...</p>
                <p><strong>秘密鍵:</strong> {asymmetricTestState.keyPair.privateKey.substring(0, 15)}...</p>
                <p><strong>暗号化データ:</strong> {asymmetricTestState.encrypted.substring(0, 30)}...</p>
                <p><strong>復号データ:</strong> {JSON.stringify(asymmetricTestState.decrypted)}</p>
              </>
            )}
          </div>
        )}
      </section>
      
      {/* シャミア秘密分散テスト */}
      <section className="test-section">
        <h2>シャミア秘密分散テスト</h2>
        <div className="test-controls">
          <div className="form-group">
            <label>秘密情報:</label>
            <input
              type="text"
              value={shamirTestState.secret}
              onChange={(e) => setShamirTestState(prev => ({ ...prev, secret: e.target.value }))}
              placeholder="分散する秘密情報を入力"
            />
          </div>
          <div className="form-group">
            <label>総シェア数:</label>
            <input
              type="number"
              min="2"
              max="10"
              value={shamirTestState.totalShares}
              onChange={(e) => setShamirTestState(prev => ({ ...prev, totalShares: parseInt(e.target.value) }))}
            />
          </div>
          <div className="form-group">
            <label>必要シェア数:</label>
            <input
              type="number"
              min="2"
              max={shamirTestState.totalShares}
              value={shamirTestState.threshold}
              onChange={(e) => setShamirTestState(prev => ({ ...prev, threshold: parseInt(e.target.value) }))}
            />
          </div>
          <button onClick={testShamirSecretSharing}>シェア作成</button>
        </div>
        
        {shamirTestState.shares.length > 0 && (
          <div className={`test-result ${shamirTestState.success ? 'success' : 'error'}`}>
            <p><strong>ステータス:</strong> {shamirTestState.status}</p>
            <div className="shares-container">
              <h3>シェア一覧 (復元に{shamirTestState.threshold}個必要):</h3>
              <ul className="shares-list">
                {shamirTestState.shares.map((share, index) => (
                  <li key={share.id}>
                    <label>
                      <input
                        type="checkbox"
                        checked={shamirTestState.selectedShares.includes(share.id)}
                        onChange={() => toggleShareSelection(share.id)}
                      />
                      シェア {index + 1}: {share.value.substring(0, 15)}...
                    </label>
                  </li>
                ))}
              </ul>
              <button 
                onClick={recoverSecretFromShares}
                disabled={shamirTestState.selectedShares.length < shamirTestState.threshold}
              >
                選択したシェアから秘密を復元
              </button>
              
              {shamirTestState.recovered && (
                <div className="recovery-result">
                  <p><strong>復元された秘密:</strong> {shamirTestState.recovered}</p>
                  <p><strong>一致:</strong> {shamirTestState.recovered === shamirTestState.secret ? '✅ はい' : '❌ いいえ'}</p>
                </div>
              )}
            </div>
          </div>
        )}
      </section>
      
      {/* キー保存テスト */}
      <section className="test-section">
        <h2>暗号化キー保存テスト</h2>
        <div className="test-controls">
          <div className="form-group">
            <label>パスワード:</label>
            <input
              type="password"
              value={keyStorageTestState.password}
              onChange={(e) => setKeyStorageTestState(prev => ({ ...prev, password: e.target.value }))}
              placeholder="保存に使用するパスワード"
            />
          </div>
          <button onClick={testKeyStorage}>キー生成・保存</button>
          <button 
            onClick={retrieveStoredKey}
            disabled={!keyStorageTestState.storedSuccessfully}
          >
            保存したキーを取得
          </button>
        </div>
        
        {keyStorageTestState.success !== null && (
          <div className={`test-result ${keyStorageTestState.success ? 'success' : 'error'}`}>
            <p><strong>ステータス:</strong> {keyStorageTestState.status}</p>
            {keyStorageTestState.key && (
              <p><strong>生成・保存したキー:</strong> {keyStorageTestState.key.substring(0, 15)}...</p>
            )}
            {keyStorageTestState.retrievedKey && (
              <>
                <p><strong>取得したキー:</strong> {keyStorageTestState.retrievedKey.substring(0, 15)}...</p>
                <p><strong>一致:</strong> {keyStorageTestState.retrievedKey === keyStorageTestState.key ? '✅ はい' : '❌ いいえ'}</p>
              </>
            )}
          </div>
        )}
      </section>

      <style>{`
        .crypto-tester {
          font-family: Arial, sans-serif;
          max-width: 800px;
          margin: 0 auto;
          padding: 20px;
        }
        
        .test-section {
          margin-bottom: 30px;
          border: 1px solid #ddd;
          padding: 20px;
          border-radius: 5px;
        }
        
        .test-controls {
          margin-bottom: 15px;
        }
        
        .form-group {
          margin-bottom: 10px;
        }
        
        label {
          display: block;
          margin-bottom: 5px;
          font-weight: bold;
        }
        
        input[type="text"],
        input[type="password"],
        input[type="number"] {
          width: 100%;
          padding: 8px;
          border: 1px solid #ddd;
          border-radius: 4px;
          box-sizing: border-box;
        }
        
        button {
          background-color: #4CAF50;
          color: white;
          padding: 8px 15px;
          margin-right: 10px;
          margin-top: 10px;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }
        
        button:disabled {
          background-color: #cccccc;
          cursor: not-allowed;
        }
        
        .test-result {
          margin-top: 15px;
          padding: 15px;
          border-radius: 4px;
        }
        
        .success {
          background-color: #f0f8e6;
          border: 1px solid #dff2bf;
        }
        
        .error {
          background-color: #ffecec;
          border: 1px solid #f5aca6;
        }
        
        .shares-list {
          list-style-type: none;
          padding: 0;
        }
        
        .shares-list li {
          margin-bottom: 5px;
        }
        
        .recovery-result {
          margin-top: 15px;
          padding: 10px;
          background-color: #e8f4f8;
          border: 1px solid #b8e6ff;
          border-radius: 4px;
        }
      `}</style>
    </div>
  );
}

export default CryptoTester;