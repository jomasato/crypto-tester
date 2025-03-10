// src/App.js
import React from 'react';
import CryptoTester from './crypto-tester';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <h1>暗号化機能テストアプリ</h1>
        <p>このアプリは暗号化機能の動作確認を行うためのものです。</p>
      </header>
      <main>
        <CryptoTester />
      </main>
      <footer>
        <p>セキュアアプリケーションデモ</p>
      </footer>
    </div>
  );
}

export default App;