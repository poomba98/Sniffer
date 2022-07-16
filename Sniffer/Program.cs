using System;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace Sniffer
{
    class Program
    {
       static void Main(string[] args)
       {
            ipparsel obj = new ipparsel();
            IPAddress ip;
            string path;
            if (args.Length > 0)
            {
                ip = IPAddress.Parse(args[0]);
                path = args[1];
            }
            else
            {
                ip = IPAddress.Parse("127.0.0.1");
                path = "data.txt";
            }
            IPEndPoint lissenedip = new IPEndPoint(ip, 0);
            obj.path = path;
            obj.snifsock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            obj.snifsock.Bind(lissenedip);
            obj.snifsock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
            byte[] byOut = new byte[4];
            obj.snifsock.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);
            obj.snifsock.BeginReceive(obj.byteData, 0, obj.byteData.Length, SocketFlags.None, new AsyncCallback(obj.OnReceive), null);
            Console.WriteLine("Нажмите Enter для остановки программы");
            Console.ReadLine();
            obj.snifsock.Close();
       }
    }
}
