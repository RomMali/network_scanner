using GalacticGuard.Utils;

namespace GalacticGuard.DB
{
    internal class DBHandler
    {
        public static UserHandler Users { get; private set; }
        public static LastPassHandler LastPasses { get; private set; }

        static DBHandler()
        {
            Logger.Info("Initializing DBHandler...", nameof(DBHandler));
            Users = new UserHandler();
            LastPasses = new LastPassHandler();
            Logger.Info("DBHandler initialized.", nameof(DBHandler));
        }
    }
}
