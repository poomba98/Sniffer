using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace Sniffer
{
    internal class ipparsel
    {
        public Socket snifsock;
        public byte[] byteData = new byte[4096];
        public string path;
        //IP Header fields
        private byte byVersionAndHeaderLength;   //Eight bits for version and header length
        private byte byDifferentiatedServices;    //Eight bits for differentiated services (TOS)
        private ushort usTotalLength;              //Sixteen bits for total length of the datagram (header + message)
        private ushort usIdentification;           //Sixteen bits for identification
        private ushort usFlagsAndOffset;           //Eight bits for flags and fragmentation offset
        private byte byTTL;                      //Eight bits for TTL (Time To Live)
        private byte byProtocol;                 //Eight bits for the underlying protocol
        private short sChecksum;                  //Sixteen bits containing the checksum of the header
                                                  //(checksum can be negative so taken as short)
        private uint uiSourceIPAddress;          //Thirty two bit source IP Address
        private uint uiDestinationIPAddress;     //Thirty two bit destination IP Address
                                                 //End IP Header fields

        private byte byHeaderLength;             //Header length
        private byte[] byIPData = new byte[4096];  //Data carried by the datagram


        public void IPHeader(byte[] byBuffer, int nReceived)
        {

            try
            {
                MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);
                BinaryReader binaryReader = new BinaryReader(memoryStream);
                byVersionAndHeaderLength = binaryReader.ReadByte();
                byDifferentiatedServices = binaryReader.ReadByte();
                usTotalLength = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usIdentification = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                usFlagsAndOffset = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                byTTL = binaryReader.ReadByte();
                byProtocol = binaryReader.ReadByte();
                sChecksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
                uiSourceIPAddress = (uint)(binaryReader.ReadInt32());
                uiDestinationIPAddress = (uint)(binaryReader.ReadInt32());
                byHeaderLength = byVersionAndHeaderLength;
                byHeaderLength <<= 4;
                byHeaderLength >>= 4;
                byHeaderLength *= 4;
 
                Array.Copy(byBuffer,
                           byHeaderLength,
                           byIPData, 0,
                           usTotalLength - byHeaderLength);
            }
            catch (Exception ex)
            {
            }
        }

        public string Version
        {
            get
            {
                if ((byVersionAndHeaderLength >> 4) == 4)
                {
                    return "IP v4";
                }
                else if ((byVersionAndHeaderLength >> 4) == 6)
                {
                    return "IP v6";
                }
                else
                {
                    return "Unknown";
                }
            }
        }

        public string HeaderLength
        {
            get
            {
                return byHeaderLength.ToString();
            }
        }

        public ushort MessageLength
        {
            get
            {
                return (ushort)(usTotalLength - byHeaderLength);
            }
        }

        public string DifferentiatedServices
        {
            get
            {
                return string.Format("0x{0:x2} ({1})", byDifferentiatedServices,
                    byDifferentiatedServices);
            }
        }

        public string Flags
        {
            get
            {
                int nFlags = usFlagsAndOffset >> 13;
                if (nFlags == 2)
                {
                    return "Don't fragment";
                }
                else if (nFlags == 1)
                {
                    return "More fragments to come";
                }
                else
                {
                    return nFlags.ToString();
                }
            }
        }

        public string FragmentationOffset
        {
            get
            {
                int nOffset = usFlagsAndOffset << 3;
                nOffset >>= 3;

                return nOffset.ToString();
            }
        }

        public string TTL
        {
            get
            {
                return byTTL.ToString();
            }
        }


        public string Checksum
        {
            get
            {
                return string.Format("0x{0:x2}", sChecksum);
            }
        }

        public IPAddress SourceAddress
        {
            get
            {
                return new IPAddress(uiSourceIPAddress);
            }
        }

        public IPAddress DestinationAddress
        {
            get
            {
                return new IPAddress(uiDestinationIPAddress);
            }
        }

        public string TotalLength
        {
            get
            {
                return usTotalLength.ToString();
            }
        }

        public string Identification
        {
            get
            {
                return usIdentification.ToString();
            }
        }

        public byte[] Data
        {
            get
            {
                return byIPData;
            }
        }
        public string gettype(byte byProtocol)
        {
            if (byProtocol == 6)
                return "tcp";
            if (byProtocol == 17)
                return "udp";
            else
                return "-1";
        }
        public void OnReceive(IAsyncResult ar)
        {
            int nReceived = snifsock.EndReceive(ar);
            IPHeader(byteData, nReceived);
            IPAddress sip = SourceAddress;
            StreamWriter log = new StreamWriter(path, append: true);
            log.WriteLine("IPv:" + Version.ToString() +" Длина заголовка:"+HeaderLength+ " Differentiated services:"+DifferentiatedServices +" Размер пакета:"+TotalLength+" Флаги:"+Flags+" Смещение фрагмента:"+FragmentationOffset+" TTl:"+TTL+ " Протокол:" + gettype(byProtocol) +" Контрольная сумма:"+Checksum+ ", IP отправителя:" + SourceAddress.ToString() + ", IP получателя:" + DestinationAddress.ToString()+".");
            switch (gettype(byProtocol))
            {
                case "tcp":
                    tcp tcphead=new tcp();
                    tcphead.tcphead(Data, MessageLength);
                    log.WriteLine("TCP заголовок [Передающий порт:"+tcphead.SourcePort+" Принимающий порт:"+tcphead.DestinationPort+" Порядковый номер:"+tcphead.SequenceNumber+" Номер подтверждения:"+tcphead.AcknowledgementNumber+" Длина заголовка:" + tcphead.HeaderLength+" Флаги:"+tcphead.Flags+" Размер окна:"+tcphead.WindowSize+" Контрольная сумма:"+tcphead.Checksum+" Указатель важности:"+tcphead.UrgentPointer);
                    break;
                case "udp":
                    udp udphead = new udp();
                    udphead.udphead(Data, MessageLength);
                    log.WriteLine("UDP заголовок [Передающий порт:" + udphead.SourcePort + " Принимающий порт:" + udphead.DestinationPort + " Длина датаграммы:" + udphead.Length + " Контрольная сумма:" + udphead.Checksum);
                    break;
                case "-1":
                    break;

            }
            log.Close();
            snifsock.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
        }
    }
}
