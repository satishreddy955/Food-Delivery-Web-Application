import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar/Navbar';
import './App.css';
import Home from './pages/Home/Home';
import Cart from './pages/Cart/Cart';
import { Routes, Route, Navigate } from 'react-router-dom';
import Footer from './components/Footer/Footer';
import LoginPopup from './components/LoginPopup/LoginPopup';
import PlaceOrder from './pages/placeOrder/placeOrder';
import Verify from './Verify/Verify';
import MyOrders from './pages/MyOrders/MyOrders';
import SearchResults from "./pages/SearchResults/SearchResults";
import Profile from './pages/Profile/Profile';

function App() {
  const [showLogin, setShowLogin] = useState(false);
  const [token, setToken] = useState(null);

  useEffect(() => {
    const savedToken = localStorage.getItem("token");
    if (!savedToken) {
      setShowLogin(true);
      setToken(null);  // reset if not logged in
    } else {
      setToken(savedToken);
      setShowLogin(false);
    }
  }, [token]); // run when token changes

  return (
    <>
      {showLogin && !token ? (
        <LoginPopup setShowLogin={setShowLogin} />
      ) : (
        <div className="app1">
          <Navbar setShowLogin={setShowLogin} />
          <Routes>
            <Route path="/" element={<Navigate to="/home" replace />} /> 
            <Route path="/home" element={<Home />} />
            <Route path="/cart" element={<Cart />} />
            <Route path="/order" element={<PlaceOrder />} />
            <Route path="/verify" element={<Verify />} />
            <Route path="/myorders" element={<MyOrders />} />
            <Route path="/search" element={<SearchResults />} />
            <Route path="/profile" element={<Profile setToken={setToken} setShowLogin={setShowLogin}/>}/>

          </Routes>
          <Footer />
        </div>
      )}
    </>
  );
}

export default App;
