using MySqlConnector;

namespace GalacticGuard.DB
{
    public class Init
    {
        private string connectionString = "server=localhost;user=root;password=RomMali130507!;database=galacticguard";

        public void InitializeDatabase()
        {
            using var connection = new MySqlConnection(connectionString);
            connection.Open();

            var createUsersTable = @"CREATE TABLE IF NOT EXISTS Users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE,
                email VARCHAR(100) UNIQUE,
                password_hash VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );";

            var createLastPassesTable = @"CREATE TABLE IF NOT EXISTS LastPasses (
                user_id INT,
                pass1 VARCHAR(20) NOT NULL,
                pass2 VARCHAR(20) NOT NULL,
                pass3 VARCHAR(20) NOT NULL,
                FOREIGN KEY (user_id) REFERENCES Users(id)
            );";

            using var command = new MySqlCommand(createUsersTable, connection);
            command.ExecuteNonQuery();

            command.CommandText = createLastPassesTable;
            command.ExecuteNonQuery();
        }
    }
}
