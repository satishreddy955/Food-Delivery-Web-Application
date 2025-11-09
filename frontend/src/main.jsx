import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import App from './App';
import './index.css';
import StoreContextProvider from './Context/StoreContext';

// Import the admin app and login page
import AdminApp from './admin/AdminApp';
import AdminLogin from './admin/AdminLogin';

const root = ReactDOM.createRoot(document.getElementById('root'));

root.render(
  <BrowserRouter>
    <StoreContextProvider>
      <Routes>
        {/* Frontend routes */}
        <Route path="/*" element={<App />} />

        {/* Admin login route */}
        <Route path="/admin-login" element={<AdminLogin />} />

        {/* Protected admin routes */}
        <Route
          path="/admin/*"
          element={
            localStorage.getItem("isAdmin") === "true"
              ? <AdminApp />
              : <Navigate to="/admin-login" />
          }
        />
      </Routes>
    </StoreContextProvider>
  </BrowserRouter>
);
