import React, { useContext, useState } from "react";
import "./LoginPopup.css";
import { assets } from "../../assets/assets";
import { StoreContext } from "../../Context/StoreContext";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const LoginPopup = ({ setShowLogin }) => {
  const { url, setToken, setUser } = useContext(StoreContext);
  const [currState, setCurrState] = useState("Sign Up"); // "Sign Up" | "Login" | "ForgotPassword"
  const [data, setData] = useState({
    name: "",
    email: "",
    password: "",
  });

  // OTP + password states
  const [otp, setOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [otpSent, setOtpSent] = useState(false); // for forgot password
  const [signupOtpSent, setSignupOtpSent] = useState(false); // for signup

  const navigate = useNavigate();

  const onChangehandler = (event) => {
    const { name, value } = event.target;
    setData((prev) => ({ ...prev, [name]: value }));
  };

  // ---------------- LOGIN / SIGNUP HANDLER ----------------
  const onLoginOrSignup = async (event) => {
    event.preventDefault();
    let newUrl = url;

    if (currState === "Login") {
      newUrl += "/api/user/login";
    } else if (currState === "Sign Up") {
      if (!signupOtpSent) {
        alert("Please send OTP to your email first.");
        return;
      }
      if (!otp) {
        alert("Please enter the OTP before creating account.");
        return;
      }
      newUrl += "/api/user/register";
    }

    try {
      const payload =
        currState === "Sign Up" ? { ...data, otp } : data;

      const response = await axios.post(newUrl, payload);
      if (response.data.success) {
        const { token, user } = response.data;

        setToken(token);
        localStorage.setItem("token", token);

        if (user) {
          setUser(user);
          localStorage.setItem("user", JSON.stringify(user));
        } else {
          const fallbackUser = { name: data.name || "User", email: data.email };
          setUser(fallbackUser);
          localStorage.setItem("user", JSON.stringify(fallbackUser));
        }

        setShowLogin(false);
        navigate("/home");
      } else {
        alert(response.data.message);
      }
    } catch (error) {
      console.error("Error:", error);
      alert("Something went wrong, please try again.");
    }
  };

  // ---------------- SIGNUP OTP HANDLER ----------------
  const handleSendSignupOtp = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${url}/api/user/send-register-otp`, {
        email: data.email,
      });
      if (res.data.success) {
        alert("OTP sent to your email!");
        setSignupOtpSent(true);
      } else {
        alert(res.data.message);
      }
    } catch (err) {
      console.error(err);
      alert("Error sending OTP");
    }
  };

  // ---------------- FORGOT PASSWORD HANDLERS ----------------
  const handleSendResetOtp = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${url}/api/user/send-reset-otp`, {
        email: data.email,
      });
      if (res.data.success) {
        alert("OTP sent to your email!");
        setOtpSent(true);
      } else {
        alert(res.data.message);
      }
    } catch (err) {
      console.error(err);
      alert("Error sending OTP");
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${url}/api/user/reset-password`, {
        email: data.email,
        otp,
        newPassword,
      });
      if (res.data.success) {
        alert("Password reset successful! Please login.");
        setCurrState("Login");
        setOtp("");
        setNewPassword("");
        setOtpSent(false);
      } else {
        alert(res.data.message);
      }
    } catch (err) {
      console.error(err);
      alert("Error resetting password");
    }
  };

  // ---------------- FORM SUBMIT HANDLER SELECTION ----------------
  const getFormHandler = () => {
    if (currState === "ForgotPassword") {
      return otpSent ? handleResetPassword : handleSendResetOtp;
    }
    if (currState === "Sign Up" && !signupOtpSent) {
      return handleSendSignupOtp;
    }
    return onLoginOrSignup;
  };

  return (
    <div className="login-popup">
      <form onSubmit={getFormHandler()} className="login-popup-container">
        <div className="login-popup-title">
          <h2>
            {currState === "ForgotPassword" ? "Forgot Password" : currState}
          </h2>
          <img
            src={assets.cross_icon}
            onClick={() => setShowLogin(false)}
            alt="close"
          />
        </div>

        <div className="login-popup-inputs">
          {currState === "Sign Up" && (
            <input
              name="name"
              onChange={onChangehandler}
              value={data.name}
              type="text"
              placeholder="Your Name"
              required
            />
          )}

          {(currState === "Login" ||
            currState === "Sign Up" ||
            currState === "ForgotPassword") && (
            <input
              type="email"
              placeholder="Your Email"
              required
              name="email"
              onChange={onChangehandler}
              value={data.email}
            />
          )}

          {(currState === "Sign Up" || currState === "Login") && (
            <input
              type="password"
              placeholder="Password"
              required
              name="password"
              onChange={onChangehandler}
              value={data.password}
            />
          )}

          {/* Forgot Password fields */}
          {currState === "ForgotPassword" && otpSent && (
            <>
              <input
                type="text"
                placeholder="Enter OTP"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                required
              />
              <input
                type="password"
                placeholder="New Password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
              />
            </>
          )}

          {/* Sign Up OTP field */}
          {currState === "Sign Up" && signupOtpSent && (
            <input
              type="text"
              placeholder="Enter OTP to verify email"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              required
            />
          )}
        </div>

        <button type="submit">
          {currState === "Sign Up"
            ? !signupOtpSent
              ? "Send OTP"
              : "Create Account"
            : currState === "Login"
            ? "Login"
            : otpSent
            ? "Reset Password"
            : "Send OTP"}
        </button>

        {currState !== "ForgotPassword" && (
          <div className="login-popup-condition">
            <input type="checkbox" required />
            <p>
              By continuing, I agree to the terms of use & privacy policy.
            </p>
          </div>
        )}

        {/* Switch links */}
        {currState === "Login" ? (
          <p>
            Don’t have an account?{" "}
            <span onClick={() => setCurrState("Sign Up")}>Sign up here</span>
            <br />
            <span
              style={{ color: "blue", cursor: "pointer" }}
              onClick={() => setCurrState("ForgotPassword")}
            >
              Forgot Password?
            </span>
          </p>
        ) : currState === "Sign Up" ? (
          <p>
            Already registered?{" "}
            <span onClick={() => setCurrState("Login")}>Login here</span>
          </p>
        ) : (
          <p>
            Back to{" "}
            <span onClick={() => setCurrState("Login")}>Login</span>
          </p>
        )}
      </form>
    </div>
  );
};

export default LoginPopup;