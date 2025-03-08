// src/index.js
import React from 'react';
import { createRoot } from 'react-dom/client';

import App from './App';
import CryptoTester from './crypto-tester';

// React 18のcreateRootメソッドを使用
const rootElement = document.getElementById('root');
const root = createRoot(rootElement);

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

