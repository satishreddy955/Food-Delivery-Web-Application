import React, { useState } from 'react'
import Header from '../../Header/Header'
import ExploreMenu from '../../components/Navbar/Explore Menu/ExploreMenu'
import FoodDisplay from '../../FoodDisplay/FoodDisplay'
import AppDownload from '../../components/AppDownload/AppDownload'

const Home = () => {

  const [category,setCategory] = useState("All")
  return (
    <div>
      <Header/>  
      <ExploreMenu category={category} setCategory={setCategory}/>
      <FoodDisplay category={category}/>
      <AppDownload/>
    </div>
  )
}

export default Home