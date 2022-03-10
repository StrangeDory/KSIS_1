using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace KSIS_lab1
{

    class Program
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint destIP, uint srcIP, byte[] macAddress, ref uint macAddressLength);

        [DllImport("mpr.dll", CharSet = CharSet.Auto)]

        public static extern int WNetEnumResource(IntPtr hEnum, ref int lpcCount, IntPtr lpBuffer, ref int lpBufferSize);

        [DllImport("mpr.dll", CharSet = CharSet.Auto)]
        public static extern int WNetOpenEnum(RESOURCE_SCOPE dwScope, RESOURCE_TYPE dwType, RESOURCE_USAGE dwUsage,
            [MarshalAs(UnmanagedType.AsAny)][In] Object lpNetResource, out IntPtr lphEnum);


        [DllImport("mpr.dll", CharSet = CharSet.Auto)]
        public static extern int WNetCloseEnum(IntPtr hEnum);

        //declare the structures to hold info

        public enum RESOURCE_SCOPE
        {
            RESOURCE_CONNECTED = 0x00000001,
            RESOURCE_GLOBALNET = 0x00000002,
            RESOURCE_REMEMBERED = 0x00000003,
            RESOURCE_RECENT = 0x00000004,
            RESOURCE_CONTEXT = 0x00000005
        }

        public enum RESOURCE_TYPE
        {
            RESOURCETYPE_ANY = 0x00000000,
            RESOURCETYPE_DISK = 0x00000001,
            RESOURCETYPE_PRINT = 0x00000002,
            RESOURCETYPE_RESERVED = 0x00000008,
        }

        public enum RESOURCE_USAGE
        {
            RESOURCEUSAGE_CONNECTABLE = 0x00000001,
            RESOURCEUSAGE_CONTAINER = 0x00000002,
            RESOURCEUSAGE_NOLOCALDEVICE = 0x00000004,
            RESOURCEUSAGE_SIBLING = 0x00000008,
            RESOURCEUSAGE_ATTACHED = 0x00000010,
            RESOURCEUSAGE_ALL = (RESOURCEUSAGE_CONNECTABLE | RESOURCEUSAGE_CONTAINER | RESOURCEUSAGE_ATTACHED),
        }

        public enum RESOURCE_DISPLAYTYPE
        {
            RESOURCEDISPLAYTYPE_GENERIC = 0x00000000,
            RESOURCEDISPLAYTYPE_DOMAIN = 0x00000001,
            RESOURCEDISPLAYTYPE_SERVER = 0x00000002,
            RESOURCEDISPLAYTYPE_SHARE = 0x00000003,
            RESOURCEDISPLAYTYPE_FILE = 0x00000004,
            RESOURCEDISPLAYTYPE_GROUP = 0x00000005,
            RESOURCEDISPLAYTYPE_NETWORK = 0x00000006,
            RESOURCEDISPLAYTYPE_ROOT = 0x00000007,
            RESOURCEDISPLAYTYPE_SHAREADMIN = 0x00000008,
            RESOURCEDISPLAYTYPE_DIRECTORY = 0x00000009,
            RESOURCEDISPLAYTYPE_TREE = 0x0000000A,
            RESOURCEDISPLAYTYPE_NDSCONTAINER = 0x0000000B
        }

        public struct NETRESOURCE
        {
            public RESOURCE_SCOPE dwScope;
            public RESOURCE_TYPE dwType;
            public RESOURCE_DISPLAYTYPE dwDisplayType;
            public RESOURCE_USAGE dwUsage;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPTStr)] public string lpLocalName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPTStr)] public string lpRemoteName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPTStr)] public string lpComment;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPTStr)] public string lpProvider;
        }

        private unsafe void DisplayStruct(int i, NETRESOURCE lpnrLocal)
        {
            Console.Write("NETRESOURCE[" + i +"] DisplayType: ");
            switch (lpnrLocal.dwDisplayType)
            {
                case (RESOURCE_DISPLAYTYPE.RESOURCEDISPLAYTYPE_GENERIC):
                    Console.Write("generic\n");
                    break;
                case (RESOURCE_DISPLAYTYPE.RESOURCEDISPLAYTYPE_DOMAIN):
                    Console.Write("domain\n");
                    break;
                case (RESOURCE_DISPLAYTYPE.RESOURCEDISPLAYTYPE_SERVER):
                    Console.Write("server\n");
                    break;
                case (RESOURCE_DISPLAYTYPE.RESOURCEDISPLAYTYPE_SHARE):
                    Console.Write("share\n");
                    break;
                case (RESOURCE_DISPLAYTYPE.RESOURCEDISPLAYTYPE_FILE):
                    Console.Write("file\n");
                    break;
                case (RESOURCE_DISPLAYTYPE.RESOURCEDISPLAYTYPE_GROUP):
                    Console.Write("group\n");
                    break;
                case (RESOURCE_DISPLAYTYPE.RESOURCEDISPLAYTYPE_NETWORK):
                    Console.Write("network\n");
                    break;
                default:
                    Console.Write("unknown display type %d\n", lpnrLocal.dwDisplayType);
                    break;
            }
            Console.WriteLine("NETRESOURCE["+ i+ "] Localname: "+ (lpnrLocal.lpLocalName != null ? lpnrLocal.lpLocalName : "(null)"));
            Console.WriteLine("NETRESOURCE["+ i+ "] Remotename: "+ lpnrLocal.lpRemoteName);
            Console.WriteLine("NETRESOURCE["+ i+ "] Comment: "+ (lpnrLocal.lpComment != null ? lpnrLocal.lpComment : "(null)"));
            Console.WriteLine("NETRESOURCE["+ i+ "] Provider: "+ (lpnrLocal.lpProvider != null ? lpnrLocal.lpProvider : "(null)"));
            Console.WriteLine();
        }

        public unsafe bool WNETOE(Object o)
        {
            int iRet;
            IntPtr ptrHandle = new IntPtr();
            try
            {
                iRet = WNetOpenEnum(
                    RESOURCE_SCOPE.RESOURCE_GLOBALNET,
                    RESOURCE_TYPE.RESOURCETYPE_ANY,
                    RESOURCE_USAGE.RESOURCEUSAGE_ALL,
                    o,
                    out ptrHandle);
                if (iRet != 0)
                {
                    return false;
                }

                int entries;
                int buffer = 16384;
                var ptrBuffer = Marshal.AllocHGlobal(buffer);
                NETRESOURCE nr;
                for (; ; )
                {
                    entries = -1;
                    buffer = 16384;
                    iRet = WNetEnumResource(ptrHandle, ref entries, ptrBuffer, ref buffer);

                    if ((iRet != 0) || (entries < 1))
                    {
                        break;
                    }

                    //int ptr = Convert.ToInt32(ptrBuffer);
                    for (int i = 0; i < entries; i++)
                    {
                        nr = (NETRESOURCE)Marshal.PtrToStructure(ptrBuffer, typeof(NETRESOURCE));
                        DisplayStruct(i, nr);
                        if (RESOURCE_USAGE.RESOURCEUSAGE_CONTAINER == (nr.dwUsage & RESOURCE_USAGE.RESOURCEUSAGE_CONTAINER))
                            if (!WNETOE(nr))
                                Console.WriteLine("EnumerateFunc returned FALSE");
                    }

                }
                Marshal.FreeHGlobal(ptrBuffer);
                iRet = WNetCloseEnum(ptrHandle);
            }
            catch (Exception e) {
                return false;
            }
            return true;
        }

        public static byte[] GetMacAddress(IPAddress address)
        {
            byte[] mac = new byte[6];
            uint len = (uint)mac.Length;
            byte[] addressBytes = address.GetAddressBytes();
            uint dest = ((uint)addressBytes[3] << 24)
              + ((uint)addressBytes[2] << 16)
              + ((uint)addressBytes[1] << 8)
              + ((uint)addressBytes[0]);
            if (SendARP(dest, 0, mac, ref len) != 0)
            {
                Console.WriteLine("ARP запрос не прошёл.");
            }
            return mac;
        }

        public void GetLocalAddress()
        {
            if (!NetworkInterface.GetIsNetworkAvailable())
            {
                Console.WriteLine("Сетевое соединение недоступно!");
                return;
            }
            string name = Dns.GetHostName();
            var host = Dns.GetHostEntry(name);
            string pubIp;
            try
            {
                pubIp = new WebClient().DownloadString("https://api.ipify.org");
            }
            catch
            {
                pubIp = "Компьютер не подключён к сети!";
            }
            Console.WriteLine(name + "    " + pubIp);
            Console.WriteLine();
            Console.WriteLine(" IP-address \t Mac-address \t Name");
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    byte[] mac = GetMacAddress(ip);
                    PhysicalAddress physicalAddress = new PhysicalAddress(mac);
                    Console.WriteLine(ip.ToString() + "\t" + physicalAddress.ToString() + "\t" + GetName(physicalAddress.ToString()));
                }
            }
        }

        public string GetName(string physicalAddress)
        {
            string name = string.Empty;
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus == OperationalStatus.Up && nic.GetPhysicalAddress().GetAddressBytes().Length != 0)
                    if (physicalAddress == nic.GetPhysicalAddress().ToString())
                        return nic.Name; 
            }
            return name;
        }

        public static IPAddress GetSubnetMask(IPAddress address)
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (UnicastIPAddressInformation unicastIPAddressInformation in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (unicastIPAddressInformation.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        if (address.Equals(unicastIPAddressInformation.Address))
                        {
                            return unicastIPAddressInformation.IPv4Mask;
                        }
                    }
                }
            }
            throw new ArgumentException(string.Format("Can't find subnetmask for IP address ", address));
        }

        public void GetStartFinishAddr(IPAddress ip, out byte[] start, out byte[] finish)
        {
            IPAddress mask = GetSubnetMask(ip);
            Console.WriteLine(mask.ToString());
            UInt32 numIP = Convert.ToUInt32(ip.Address);
            UInt32 numMask = Convert.ToUInt32(mask.Address);
            UInt32 numNetAddress = numIP & numMask;
            start = BitConverter.GetBytes(numNetAddress);
            UInt32 numReverseMask = ~numMask;
            numNetAddress = numIP | numReverseMask;
            finish = BitConverter.GetBytes(numNetAddress);
            finish[3]--;
        }

        public int GetDiapazone(byte[] start, byte[] finish)
        {
            int i = 0;
            while (start[i] == finish[i])
                i++;
            int diapazone = finish[i]-start[i]+1;
            i++;
            while (i<4)
            {
                diapazone *= 256;
                i++;
            }
            return diapazone;
        }

        public byte[] increment(byte[] mas, int count)
        {
            for(int i = 0; i < count; i++)
            {
                if (mas[3] != 255)
                    mas[3]++;
                else
                {
                    mas[3] = 0;
                    if (mas[2] != 255)
                        mas[2]++;
                    else
                    {
                        mas[2] = 0;
                        if (mas[1] != 255)
                            mas[1]++;
                    }
                }
            }
            return mas;
        }

        byte[] startIP;
        List<IPAddress> nodes = new List<IPAddress>();
        public void AnalyseNodeAsync(IPAddress ip)
        {
            byte[] finishIP;
                GetStartFinishAddr(ip, out startIP, out finishIP);

            int diapazone = GetDiapazone(startIP, finishIP);
            int count = diapazone / 8;
            ManualResetEvent[] handles = new ManualResetEvent[count];
            for (int i = 0; i < count; i++) //Parallel.foreach
            {
                int index = i;
                handles[index] = new ManualResetEvent(false);
                new Thread(delegate () { PingAsinc(index*8, handles[index]); }).Start();
            }
            WaitHandle.WaitAll(handles);
            Console.WriteLine();
            for (int p = 0; p < nodes.Count; p++)
            {
                byte[] mac = GetMacAddress(nodes[p]);
                PhysicalAddress physicalAddress = new PhysicalAddress(mac);
                Console.WriteLine(nodes[p].ToString() + "\t" + physicalAddress.ToString());
            }
            Console.WriteLine();
            if (!WNETOE(null))
            {
                Console.WriteLine("Call to EnumerateFunc failed");
            }
        }

        public void PingAsinc(object? obj, object? handle)
        {
            int begin = (int)obj;
            int end = begin + 8;
            byte[] copy = new byte[4];
            for (int i = 0; i < 4; i++)
                copy[i] = startIP[i];
            Ping ping = new Ping();
            string data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            byte[] buffer = Encoding.ASCII.GetBytes(data);
            int timeout = 100;
            PingOptions options = new PingOptions(64, true);
            copy = increment(copy, begin);
            for (int i = begin; i < end; i++)
            {
                string local = String.Empty;
                copy = increment(copy, 1);
                foreach (var elem in copy)
                    local += elem.ToString() + '.';
                local = local.Remove(local.Length - 1);
                PingReply reply;
                try
                {
                    reply = ping.Send(local, timeout, buffer, options);
                }
                catch
                {
                    continue;
                }
                //Console.WriteLine(local);
                if (reply.Status == IPStatus.Success)
                {
                    if (!(nodes.Contains(IPAddress.Parse(local))))
                        nodes.Add(IPAddress.Parse(local));
                }
            }
            ((ManualResetEvent)handle).Set();
        }

        static void Main(string[] args)
        {
            var proc = new Program();
            proc.GetLocalAddress();
            Console.Write("IP-address: ");
            IPAddress ip = IPAddress.Parse(Console.ReadLine());

            proc.AnalyseNodeAsync(ip); 

        }
        
    }
}
