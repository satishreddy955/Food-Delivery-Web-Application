import React from "react";
import "./Navbar.css";
import { assets } from "../../assets/assets";
import { useNavigate } from "react-router-dom";

const Navbar = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem("isAdmin"); // ✅ Clear admin session
    navigate("/admin-login"); // ✅ Redirect back to login page
  };

  return (
    <div className="navbar">
      <img className="logo" src={assets.logo} alt="Logo" />

      <div className="navbar-right">
        <img className="profile" src={assets.profile_image} alt="Profile" />
        <button className="logout-btn" onClick={handleLogout}>
          Logout
        </button>
      </div>
    </div>
  );
};

export default Navbar;
