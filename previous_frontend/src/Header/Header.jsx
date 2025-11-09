import React from 'react'
import './Header.css'
import { Link } from 'react-router-dom'

const Header = () => {
  return (
    <div className='header'>
        <div className="header-contents">
            <h2>Order your favourite food here</h2>
            <p>Choose from a diverse menu featuring a delecatable arrary of dishes crafted with the 
                finest ingredients and culinary expertise. Our mission is to satisfy your cravings 
                and elavate your experience, oner delicious meal at a time.
            </p>
           <a href='#explore-menu'> <button >View Menu</button></a>
        </div>
    </div>
  )
}

export default Header