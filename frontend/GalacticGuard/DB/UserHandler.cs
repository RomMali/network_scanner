using MySqlConnector;
using GalacticGuard.Models;
using GalacticGuard.Utils;


namespace GalacticGuard.DB
{
    public class UserHandler
    {
        private readonly string connectionString = "server=localhost;user=root;password=RomMali130507!;database=galacticguard";

        public void CreateUser(string username, string email, string passwordHash)
        {
            try
            {
                using var connection = new MySqlConnection(connectionString);
                connection.Open();

                string sql = "INSERT INTO Users (username, email, password_hash) VALUES (@username, @email, @passwordHash)";
                using var command = new MySqlCommand(sql, connection);
                command.Parameters.AddWithValue("@username", username);
                command.Parameters.AddWithValue("@email", email);
                command.Parameters.AddWithValue("@passwordHash", passwordHash);
                command.ExecuteNonQuery();

                Logger.Info("Creating user " + username, nameof(UserHandler));
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to create user: {ex.Message}", nameof(UserHandler));
            }
        }

        public User? GetUserById(int userId)
        {
            using var connection = new MySqlConnection(connectionString);
            connection.Open();

            string sql = "SELECT id, username, email, password_hash, created_at FROM users WHERE id = @id";
            using var command = new MySqlCommand(sql, connection);
            command.Parameters.AddWithValue("@id", userId);

            using var reader = command.ExecuteReader();
            if (reader.Read())
            {
                return new User
                {
                    Id = reader.GetInt32("id"),
                    Username = reader.GetString("username"),
                    Email = reader.GetString("email"),
                    PasswordHash = reader.GetString("password_hash"),
                    CreatedAt = reader.GetDateTime("created_at")
                };
            }
            return null;
        }

        public void DeleteUser(int userId)
        {
            using var connection = new MySqlConnection(connectionString);
            connection.Open();

            string sql = "DELETE FROM users WHERE id = @id";
            using var command = new MySqlCommand(sql, connection);
            command.Parameters.AddWithValue("@id", userId);
            command.ExecuteNonQuery();
        }
    }
}
