using System;

namespace PassiveOsFingerprinting
{
    public class PacketHeader
    {
        public IPHeader mIpHeader;
        public TCPHeader mTcpHeader;

        public PacketHeader(IPHeader ipHeader, TCPHeader tcpHeader)
        {
            mIpHeader = ipHeader;
            mTcpHeader = tcpHeader;

            String b = mTcpHeader.Options;
            Console.WriteLine(b);

        }

        public override string ToString()
        {
            return mIpHeader.SourceAddress + ":" + mTcpHeader.SourcePort + " > " +
                mIpHeader.DestinationAddress + ":" + mTcpHeader.DestinationPort + " (" +
                OSFingerprint.DetermineOS(this) + ")";
        }

    }
}
