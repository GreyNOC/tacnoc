import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.js';
import { StoreProvider } from './store.js';
import './styles.css';

const root = document.getElementById('root');
if (!root) throw new Error('root element missing');

createRoot(root).render(
  <React.StrictMode>
    <StoreProvider>
      <App />
    </StoreProvider>
  </React.StrictMode>,
);
