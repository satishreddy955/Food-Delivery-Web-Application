import React, { useContext } from "react";
import { useLocation } from "react-router-dom";
import { StoreContext } from "../../Context/StoreContext";
import FoodItem from "../../components/FoodItem/FoodItem";
import "./SearchResults.css";

const SearchResults = () => {
  const { food_list } = useContext(StoreContext);
  const location = useLocation();
  const query = new URLSearchParams(location.search).get("query") || "";

  // Normalize query for case + space insensitive search
  const normalizedQuery = query.toLowerCase().replace(/\s+/g, "");

  // Filter items by name OR category
  const filteredItems = food_list.filter(item => {
    const nameMatch = item.name.toLowerCase().replace(/\s+/g, "").includes(normalizedQuery);
    const categoryMatch = item.category.toLowerCase().replace(/\s+/g, "").includes(normalizedQuery);
    return nameMatch || categoryMatch;
  });

  return (
    <div className="search-results-page">
      <h2>Search Results for "{query}"</h2>
      {filteredItems.length > 0 ? (
        <div className="results-grid">
          {filteredItems.map(item => (
            <FoodItem
              key={item._id}
              id={item._id}
              image={item.image}
              name={item.name}
              desc={item.description}
              price={item.price}
            />
          ))}
        </div>
      ) : (
        <p>No items found for "{query}".</p>
      )}
    </div>
  );
};

export default SearchResults;
