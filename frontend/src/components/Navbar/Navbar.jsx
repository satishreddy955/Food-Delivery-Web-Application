import React, { useContext, useState } from 'react'
import './Navbar.css'
import { assets } from '../../assets/assets'
import { Link, useNavigate } from 'react-router-dom'
import { StoreContext } from '../../Context/StoreContext'

const Navbar = ({ setShowLogin }) => {
  const [menu, setMenu] = useState("home");
  const { getTotalCartAmount, token } = useContext(StoreContext);
  const navigate = useNavigate();

  const [showSearch, setShowSearch] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");


  // Handle search submit
  const handleSearch = (e) => {
    if (e.key === "Enter" && searchQuery.trim() !== "") {
      navigate(`/search?query=${searchQuery}`);
      setShowSearch(false);
      setSearchQuery("");
    }
  };

  return (
    <div className='navbar'>
      <Link to='/home'><h1 className="logo-text">TOMATO</h1></Link>
      
      <ul className="navbar-menu">
        <Link to="/home" onClick={() => setMenu("home")} className={`${menu === "home" ? "active" : ""}`}>home</Link>
        <a href='#explore-menu' onClick={() => setMenu("menu")} className={`${menu === "menu" ? "active" : ""}`}>menu</a>
        <a href='#app-download' onClick={() => setMenu("mob-app")} className={`${menu === "mob-app" ? "active" : ""}`}>mobile app</a>
        <a href='#footer' onClick={() => setMenu("contact")} className={`${menu === "contact" ? "active" : ""}`}>contact us</a>
      </ul>

      <div className="navbar-right">
        {/* Search Icon */}
        <div className="navbar-search">
          <img
            src={assets.search_icon}
            alt="search"
            onClick={() => setShowSearch(!showSearch)}
            style={{ cursor: "pointer" }}
          />
          {showSearch && (
            <div className="search-box">
              <input
                type="text"
                placeholder="Search for food..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={handleSearch}
              />
            </div>
          )}
        </div>

        <Link to='/cart' className='navbar-search-icon'>
          <img src={assets.basket_icon} alt="" />
          <div className={getTotalCartAmount() > 0 ? "dot" : ""}></div>
        </Link>

        {!token ? (
          <></>
        ) : (
          <div className='navbar-profile'>
            <img
              src={assets.profile_icon}
              alt="profile"
              onClick={() => navigate('/profile')}   // ✅ Redirect directly
              style={{ cursor: "pointer" }}
            />
          </div>

        )}
      </div>
    </div>
  )
}

export default Navbar
