using MySqlConnector;
using GalacticGuard.Utils;

namespace GalacticGuard.DB
{
    public class LastPassHandler
    {
        private readonly string connectionString = "server=localhost;user=root;password=RomMali130507!;database=galacticguard";

        public void AddLastPasses(int userId, string pass1, string pass2, string pass3)
        {
            try
            {
                using var connection = new MySqlConnection(connectionString);
                connection.Open();

                string sql = "INSERT INTO LastPasses (user_id, pass1, pass2, pass3) VALUES (@userId, @pass1, @pass2, @pass3)";
                using var command = new MySqlCommand(sql, connection);
                command.Parameters.AddWithValue("@userId", userId);
                command.Parameters.AddWithValue("@pass1", pass1);
                command.Parameters.AddWithValue("@pass2", pass2);
                command.Parameters.AddWithValue("@pass3", pass3);
                command.ExecuteNonQuery();

                Logger.Info($"Last passes added for user ID {userId}.", nameof(LastPassHandler));
            }
            catch (Exception ex)
            {
                Logger.Error($"Error adding last passes for user ID {userId}: {ex.Message}", nameof(LastPassHandler));
            }
        }
    }
}
