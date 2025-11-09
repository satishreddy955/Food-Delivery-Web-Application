import React, { useContext, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { StoreContext } from "../../Context/StoreContext";
import axios from "axios";
import { assets } from "../../assets/assets";
import "./Profile.css";

const Profile = ({ setToken,setShowLogin }) => {
  const { url, token, setUser, user, currency } = useContext(StoreContext);
  const navigate = useNavigate();
  const [orders, setOrders] = useState([]);

  // ✅ Fetch order history
  const fetchOrders = async () => {
    try {
      const response = await axios.post(
        `${url}/api/order/userorders`,
        {},
        { headers: { token } }
      );
      setOrders(response.data.data);
    } catch (err) {
      console.error("Error fetching orders:", err);
    }
  };

  // ✅ Logout
  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setToken(null);     // update App.js state
    setUser(null);      // clear context
    setShowLogin(true);
  };

  useEffect(() => {
    if (token) {
      fetchOrders();
    }
  }, [token]);

  if (!token) {
    return (
      <div className="profile-container">
        <h2>Please login to view your profile</h2>
      </div>
    );
  }

  return (
    <div className="profile-container">
      <h2>My Profile</h2>

      {/* ✅ User details */}
      <div className="user-details">
        <p><strong>Name:</strong> {user?.name || "Guest"}</p>
        <p><strong>Email:</strong> {user?.email || "Not available"}</p>
      </div>

      {/* ✅ Orders */}
      <h3>My Orders</h3>
      <div className="orders-list">
        {orders.length === 0 ? (
          <p>No orders found</p>
        ) : (
          orders.map((order, index) => (
            <div key={index} className="order-card">
              <img src={assets.parcel_icon} alt="order" />
              <p>
                {order.items.map((item, idx) =>
                  idx === order.items.length - 1
                    ? `${item.name} x ${item.quantity}`
                    : `${item.name} x ${item.quantity}, `
                )}
              </p>
              <p>{currency}{order.amount}.00</p>
              <p>Items: {order.items.length}</p>
              <p>
                <span>&#x25cf;</span> <b>{order.status}</b>
              </p>
              <button onClick={fetchOrders}>Track Order</button>
            </div>
          ))
        )}
      </div>

      {/* ✅ Logout at bottom */}
      <button className="logout-btn" onClick={logout}>Logout</button>
    </div>
  );
};

export default Profile;
