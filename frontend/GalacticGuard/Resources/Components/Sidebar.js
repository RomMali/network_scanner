import React from "react";
import "./../styles/Sidebar.css";

const Sidebar = () => {
    return (
        <div className="sidebar">
            <div className="logo-section">
                <h2>GalacticGuard</h2>
                <button className="login-btn">Login / Exit</button>
            </div>

            <
            >
                <ul>
                    <li>Dashboard</li>
                    <li>Analytics</li>
                    <li>Reports</li>
                </ul>
            </nav>

            <div className="bottom-section">
                <p>Notifications</p>
                <p>Settings</p>
            </div>
        </div>
    );
};

export default Sidebar;
