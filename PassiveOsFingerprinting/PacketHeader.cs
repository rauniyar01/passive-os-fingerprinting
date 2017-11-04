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
        }

        public override string ToString()
        {
            return mIpHeader.SourceAddress + ":" + mTcpHeader.SourcePort + " > " +
                mIpHeader.DestinationAddress + ":" + mTcpHeader.DestinationPort + " ( " +
                mTcpHeader.Flags + " " + OSFingerprint.DetermineOS(this) + " ) ";
        }

    }
}
