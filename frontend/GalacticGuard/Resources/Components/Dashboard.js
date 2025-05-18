import React from "react";
import Sidebar from "./Sidebar";
import "./../styles/Dashboard.css";

const Dashboard = () => {
    return (
        <div className="dashboard-container">
            <Sidebar />
            <div className="dashboard-content">
                <h1>Dashboard Analytics</h1>
                <div className="charts-container">
                    <div className="chart">Chart 1</div>
                    <div className="chart">Chart 2</div>
                    <div className="chart">Chart 3</div>
                    <div className="chart">Chart 4</div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
