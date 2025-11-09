import React, { useContext } from 'react';
import './Cart.css';
import { StoreContext } from '../../Context/StoreContext';
import { useNavigate } from 'react-router-dom';

const Cart = () => {
  const { cartItems, food_list, addToCart, removeFromCart, removeItem, getTotalCartAmount, url } =
    useContext(StoreContext);
  const navigate = useNavigate();

  const cartIsEmpty = getTotalCartAmount() === 0;
  const deliveryFee = cartIsEmpty ? 0 : 50;

  const subtotal = getTotalCartAmount();
  const total = subtotal + deliveryFee;

  return (
    <div className="cart">
      <div className="cart-items">
        <div className="cart-items-title">
          <p>Item</p>
          <p>Title</p>
          <p>Price</p>
          <p>Quantity</p>
          <p>Total</p>
          <p>Actions</p>
        </div>
        <hr />

        {food_list.map((item) => {
          if (cartItems[item._id] > 0) {
            return (
              <React.Fragment key={item._id}>
                <div className="cart-items-title cart-items-item">
                  <img src={`${url}/images/${item.image}`} alt={item.name} />
                  <p>{item.name}</p>
                  <p>₹{item.price}</p>

                  {/* Quantity Controls */}
                  <div className="quantity-controls">
                    <button onClick={() => removeFromCart(item._id)}>-</button>
                    <span>{cartItems[item._id]}</span>
                    <button onClick={() => addToCart(item._id)}>+</button>
                  </div>

                  <p>₹{(item.price * cartItems[item._id]).toFixed(2)}</p>

                  {/* Remove item completely */}
                  <button className="remove-btn" onClick={() => removeItem(item._id)}>
                    Remove
                  </button>
                </div>
                <hr />
              </React.Fragment>
            );
          }
          return null;
        })}

        {cartIsEmpty && (
          <div className="empty-cart">
            <p>Your cart is empty.</p>
            <button onClick={() => navigate('/home')}>Continue Shopping</button>
          </div>
        )}
      </div>

      <div className="cart-bottom">
        <div className="cart-total">
          <h2>Cart Total</h2>
          <div>
            <div className="cart-total-details">
              <p>Subtotal</p>
              <p>₹{subtotal.toFixed(2)}</p>
            </div>
            <hr />
            <div className="cart-total-details">
              <p>Delivery Fee</p>
              <p>₹{deliveryFee.toFixed(2)}</p>
            </div>
            <hr />
            <div className="cart-total-details">
              <b>Total</b>
              <b>₹{total.toFixed(2)}</b>
            </div>
            <button
              disabled={cartIsEmpty}
              onClick={() => navigate('/order')}
              style={{ opacity: cartIsEmpty ? 0.6 : 1 }}
            >
              PROCEED TO CHECK OUT
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Cart;
