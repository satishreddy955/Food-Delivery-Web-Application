import React from 'react'
import { menu_list } from '../../../assets/assets'
import './ExploreMenu.css'

const ExploreMenu = ({category,setCategory}) => {
  return (
    <div className='explore-menu' id="explore-menu">
        <h1>Explore Menu</h1>
        <p className='explore-menu-text'>Choose from a diverse menu featuring a delecatable arrary of dishes. 
            Our mission is to satisfy your cravings and elavate your experience,
             oner delicious meal at a time.</p>
        <div className='explore-menu-list'>
            {menu_list.map((item,index) =>(
                <div onClick={()=>setCategory(prev=>prev===item.menu_name?"All":item.menu_name)} key={index} className='explore-menu-list-item'>
                    <img className={category===item.menu_name?"active":""}src={item.menu_image} alt={item.menu_name}/>
                    <p>{item.menu_name}</p>
                </div>
            ))}
        </div>
        <hr/>
    </div>
  )
}

export default ExploreMenu