import React, { useEffect, useState } from 'react'
import './List.css'
import { url, currency } from '../../assets/assets'
import axios from 'axios';
import { toast } from 'react-toastify';

const List = () => {

  const [list, setList] = useState([]);
  const [editFood, setEditFood] = useState(null); // food being edited
  const [formData, setFormData] = useState({ name: "", description: "", price: "", category: "", image: null });

  const fetchList = async () => {
    const response = await axios.get(`${url}/api/food/list`)
    if (response.data.success) {
      setList(response.data.data);
    }
    else {
      toast.error("Error")
    }
  }

  const removeFood = async (foodId) => {
    const response = await axios.post(`${url}/api/food/remove`, { id: foodId })
    await fetchList();
    if (response.data.success) {
      toast.success(response.data.message);
    }
    else {
      toast.error("Error")
    }
  }

  const startEdit = (food) => {
    setEditFood(food);
    setFormData({
      name: food.name,
      description: food.description,
      price: food.price,
      category: food.category,
      image: null
    });
  }

  const handleChange = (e) => {
    const { name, value, files } = e.target;
    if (name === "image") {
      setFormData({ ...formData, image: files[0] });
    } else {
      setFormData({ ...formData, [name]: value });
    }
  }

  const updateFood = async () => {
    try {
      const data = new FormData();
      data.append("id", editFood._id);
      data.append("name", formData.name);
      data.append("description", formData.description);
      data.append("price", formData.price);
      data.append("category", formData.category);
      if (formData.image) {
        data.append("image", formData.image);
      }

      const response = await axios.post(`${url}/api/food/update`, data);
      if (response.data.success) {
        toast.success(response.data.message);
        setEditFood(null);
        fetchList();
      } else {
        toast.error("Update failed");
      }
    } catch (error) {
      console.error(error);
      toast.error("Error updating food");
    }
  }

  useEffect(() => {
    fetchList();
  }, [])

  return (
    <div className='list flex-col'>
      <p className='list-title'>All Foods List</p>
      <div className='list-table'>
        <div className="list-table-format title">
          <b>Image</b>
          <b>Name</b>
          <b>Category</b>
          <b>Price</b>
          <b>Action</b>
        </div>
        {list.map((item, index) => {
          return (
            <div key={index} className='list-table-format'>
              <img src={`${url}/images/` + item.image} alt="" />
              <p>{item.name}</p>
              <p>{item.category}</p>
              <p>{currency}{item.price}</p>
              <div style={{ display: "flex", gap: "10px" }}>
                <button className='cursor' onClick={() => removeFood(item._id)}>Remove</button>
                <button className='cursor' onClick={() => startEdit(item)}>Edit</button>
              </div>
            </div>
          )
        })}
      </div>

      {/* Edit Modal */}
      {editFood && (
        <div className="edit-modal">
          <div className="edit-box">
            <h3>Edit Food</h3>
            <input type="text" name="name" value={formData.name} onChange={handleChange} placeholder="Name" />
            <input type="text" name="description" value={formData.description} onChange={handleChange} placeholder="Description" />
            <input type="number" name="price" value={formData.price} onChange={handleChange} placeholder="Price" />
            <input type="text" name="category" value={formData.category} onChange={handleChange} placeholder="Category" />
            <input type="file" name="image" onChange={handleChange} />
            <div style={{ display: "flex", gap: "10px", marginTop: "10px" }}>
              <button onClick={updateFood}>Update</button>
              <button onClick={() => setEditFood(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default List
