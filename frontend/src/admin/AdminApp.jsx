import React from "react";
import Navbar from "./Components/Navbar/Navbar";
import Sidebar from "./Components/Sidebar/Sidebar";
import { Route, Routes, Navigate, useNavigate } from "react-router-dom";
import Add from "./pages/Add/Add";
import List from "./pages/List/List";
import Orders from "./pages/Orders/Orders";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import "./AdminApp.css";

const AdminApp = () => {
  const navigate = useNavigate();

  // ✅ Logout handler
  const handleLogout = () => {
    localStorage.removeItem("isAdmin"); // clear admin session
    navigate("/admin/login"); // redirect to login
  };

  // ✅ Protect admin routes
  const isAdmin = localStorage.getItem("isAdmin") === "true";
  if (!isAdmin) {
    return <Navigate to="/admin/login" replace />;
  }

  return (
    <div>
      <ToastContainer />
      
      {/* ✅ Pass logout handler to Navbar */}
      <Navbar onLogout={handleLogout} />

      <hr />
      <div className="app-content">
        <Sidebar />
        <Routes>
          {/* Default redirect when hitting /admin */}
          {/* <Route path="/" element={<Navigate to="add" />} /> */}
          <Route path="add" element={<Add />} />
          <Route path="list" element={<List />} />
          <Route path="orders" element={<Orders />} />
        </Routes>
      </div>
    </div>
  );
};

export default AdminApp;
