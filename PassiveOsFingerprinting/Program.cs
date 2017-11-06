using System;
using System.Net;
using System.Net.Sockets;

namespace PassiveOsFingerprinting
{
    public class Program
    {
        const string localIp = "192.168.0.14";
        const string targetIp = "192.168.0.172";
        const int targetPort = 22;

        public static void Main()
        {
            Program program = new Program();
            program.Intercept();
            program.Transmit();
            Console.Read();
        }

        public void Intercept()
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            socket.Bind(new IPEndPoint(IPAddress.Parse(localIp), 0));
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            socket.IOControl(IOControlCode.ReceiveAll, new byte[4] { 1, 0, 0, 0 }, new byte[4] { 1, 0, 0, 0 });

            Action<IAsyncResult> OnReceive = null;
            byte[] buffer = new byte[4096];

            OnReceive = (result) =>
            {
                if (buffer[9] == 6) // TCP packets
                {
                    IPHeader ipHeader = new IPHeader(buffer, socket.EndReceive(result));
                    TCPHeader tcpHeader = new TCPHeader(ipHeader.Data, ipHeader.MessageLength);
                    PacketHeader packet = new PacketHeader(ipHeader, tcpHeader);
                    if(localIp == ipHeader.DestinationAddress.ToString() && targetIp == ipHeader.SourceAddress.ToString() && tcpHeader.Flags.ToString().Contains("0x12"))
                        Console.WriteLine(packet.ToString());
                }

                buffer = new byte[4096];
                socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
            };

            socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
        }

        public bool Transmit()
        {
            using (var tcp = new TcpClient())
            {
                var ar = tcp.BeginConnect(targetIp, targetPort, null, null);
                using (ar.AsyncWaitHandle)
                {
                    if (ar.AsyncWaitHandle.WaitOne(200, false))
                    {
                        try
                        {
                            tcp.EndConnect(ar);
                            return true;
                        }
                        catch
                        {
                            return false;
                        }
                    }
                }
            }
            return false;
        }

    }
}