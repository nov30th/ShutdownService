using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Threading;

namespace ShutdownService
{
    public partial class Service1 : ServiceBase
    {
        private Thread _localThread;

        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            _localThread = new Thread(Start);
            _localThread.IsBackground = true;
            _localThread.Start();

        }

        protected override void OnStop()
        {
            _localThread.Abort();
        }

        private void Start()
        {
            var serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            serverSocket.Bind(new IPEndPoint(0, 1234));
            serverSocket.Listen(10);

            Socket clientSocket = serverSocket.Accept();


            EventLog log = new EventLog("System");
            // 首先应判断日志来源是否存在，一个日志来源只能与一个事件绑定
            if (!EventLog.SourceExists("HOHO Shutdown Service"))
            {
                EventLog.CreateEventSource("HOHO Shutdown Service", "System");
            }

            IPEndPoint clientipe = (IPEndPoint)clientSocket.RemoteEndPoint;
            log.Source = "HOHO Shutdown Service";
            log.WriteEntry($@"收到来自{clientipe.Address.ToString()}的关机端口扫描，正在关机...", EventLogEntryType.Information);

            Thread.Sleep(2000);

            Shutdown();
        }

        public enum ExitWindows : uint
        {
            EWX_LOGOFF = 0x00,
            EWX_SHUTDOWN = 0x01,
            EWX_REBOOT = 0x02,
            EWX_POWEROFF = 0x08,
            EWX_RESTARTAPPS = 0x40,
            EWX_FORCE = 0x04,
            EWX_FORCEIFHUNG = 0x10,
        }

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        public static extern bool ExitWindowsEx(ExitWindows uFlags,
        int dwReason);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true,
        CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string lpSystemName,
        string lpName,
        out long lpLuid);

        [System.Runtime.InteropServices.StructLayout(
        System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 1)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public long Luid;
            public int Attributes;
        }

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        int BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);

        //为了关闭系统设定安全权限
        public void AdjustToken()
        {
            const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
            const uint TOKEN_QUERY = 0x8;
            const int SE_PRIVILEGE_ENABLED = 0x2;
            const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";

            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                return;
            }

            IntPtr procHandle = GetCurrentProcess();

            //取得令牌
            IntPtr tokenHandle;
            OpenProcessToken(procHandle,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle);
            //取得LUID
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.Attributes = SE_PRIVILEGE_ENABLED;
            tp.PrivilegeCount = 1;
            LookupPrivilegeValue(null, SE_SHUTDOWN_NAME, out tp.Luid);
            //设定权限
            AdjustTokenPrivileges(
 tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }

        private void Shutdown()
        {
            AdjustToken();
            ExitWindowsEx(ExitWindows.EWX_POWEROFF | ExitWindows.EWX_FORCE, 0);
        }
    }
}
