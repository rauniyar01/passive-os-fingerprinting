using System;
using System.Collections.Generic;
using System.Linq;

namespace PassiveOsFingerprinting
{
    static class OSFingerprint
    {
        private static Dictionary<string, double> mGamma;

        public static string DetermineOS(PacketHeader packetHeader)
        {
            InitDictionary();
            TtlTest(packetHeader.mIpHeader.TTL);
            DfTest(packetHeader.mIpHeader.Flags);
            IpIdTest(packetHeader.mIpHeader.Identification);
            WindowSizeTest(packetHeader.mTcpHeader.WindowSize, packetHeader.mTcpHeader.MaxSegmentSize);
            WindowScaleTest(packetHeader.mTcpHeader.WindowScale);
            TcpOrderOptionsTest(packetHeader.mTcpHeader.Options);

            string max = mGamma.Aggregate((l, r) => l.Value > r.Value ? l : r).Key;
            return max;
        }

        private static void TtlTest(string packetTtl)
        {
            var ttl = Int32.Parse(packetTtl);
            var modifier = 0.5;

            if (ttl > 0 && ttl <= 32)
            {
                mGamma["Windows 3.11"] += modifier;
                mGamma["Windows 98"] += modifier;
                mGamma["Windows 2K3"] += modifier;
            }
            else if (ttl > 32 && ttl <= 64)
            {
                mGamma["Linux 1.2"] += modifier;
                mGamma["Linux 2.0"] += modifier;
                mGamma["Linux 2.0.3x"] += modifier;
                mGamma["Linux 2.2"] += modifier;
                mGamma["Linux 2.4"] += modifier;
                mGamma["Linux 2.6"] += modifier;

                mGamma["Windows 95"] += modifier;
                mGamma["Windows ME no SP"] += modifier;
                mGamma["Windows 2K3"] += modifier;

                mGamma["MacOS 10.2.6"] += modifier;
            }
            else if (ttl > 64 && ttl <= 128)
            {
                mGamma["Windows 95b"] += modifier;
                mGamma["Windows NT 4.0 SP6a"] += modifier;
                mGamma["Windows 2000 SP2+"] += modifier;
                mGamma["Windows 2000 SP3"] += modifier;
                mGamma["Windows 2000 SP4"] += modifier;
                mGamma["Windows XP SP1+"] += modifier;
                mGamma["Windows 2K3"] += modifier;
                mGamma["Windows Vista (beta)"] += modifier;
            }
            else if (ttl > 128 && ttl <= 255)
            {
                mGamma["MacOS 7.3-8.6"] += modifier;
                mGamma["MacOS 8.1-8.6"] += modifier;
                mGamma["MacOS 8.6"] += modifier;
                mGamma["MacOS 9.0-9.2"] += modifier;
                mGamma["MacOS 9.1"] += modifier;
            }
        }

        private static void DfTest(string packetDf)
        {
            var df = packetDf;
            var modifier = 1;

            if (df == "DF")
            {
                mGamma["Linux 2.2"] += modifier;
                mGamma["Linux 2.4"] += modifier;
                mGamma["Linux 2.6"] += modifier;

                mGamma["Windows 3.11"] += modifier;
                mGamma["Windows 95"] += modifier;
                mGamma["Windows 95b"] += modifier;
                mGamma["Windows 98"] += modifier;
                mGamma["Windows NT 4.0 SP6a"] += modifier;
                mGamma["Windows 2000 SP2+"] += modifier;
                mGamma["Windows 2000 SP3"] += modifier;
                mGamma["Windows 2000 SP4"] += modifier;
                mGamma["Windows XP SP1+"] += modifier;
                mGamma["Windows Vista (beta)"] += modifier;


                mGamma["MacOS 7.3-8.6"] += modifier;
                mGamma["MacOS 8.1-8.6"] += modifier;
                mGamma["MacOS 8.6"] += modifier;
                mGamma["MacOS 9.0-9.2"] += modifier;
                mGamma["MacOS 9.1"] += modifier;
                mGamma["MacOS 10.2.6"] += modifier;

            }
            else if (df == "NF")
            {
                mGamma["Linux 1.2"] += modifier;
                mGamma["Linux 2.0"] += modifier;
                mGamma["Linux 2.0.3x"] += modifier;

                mGamma["Windows ME no SP"] += modifier;
                mGamma["Windows 2K3"] += modifier;
            }
        }

        private static void IpIdTest(string packetId)
        {
            var id = Int32.Parse(packetId);
            var modifier = 1;

            if (id != 0)
            {
                mGamma["Linux 1.2"] += modifier;
                mGamma["Linux 2.0"] += modifier;
                mGamma["Linux 2.0.3x"] += modifier;
                mGamma["Linux 2.2"] += modifier;

                mGamma["Windows 3.11"] += modifier;
                mGamma["Windows 95"] += modifier;
                mGamma["Windows 95b"] += modifier;
                mGamma["Windows 98"] += modifier;
                mGamma["Windows ME no SP"] += modifier;
                mGamma["Windows NT 4.0 SP6a"] += modifier;
                mGamma["Windows 2000 SP2+"] += modifier;
                mGamma["Windows 2000 SP3"] += modifier;
                mGamma["Windows 2000 SP4"] += modifier;
                mGamma["Windows XP SP1+"] += modifier;
                mGamma["Windows 2K3"] += modifier;

                mGamma["MacOS 7.3-8.6"] += modifier;
                mGamma["MacOS 8.1-8.6"] += modifier;
                mGamma["MacOS 8.6"] += modifier;
                mGamma["MacOS 9.0-9.2"] += modifier;
                mGamma["MacOS 9.1"] += modifier;
                mGamma["MacOS 10.2.6"] += modifier;

            }
            else if (id == 0)
            {
                mGamma["Linux 2.4"] += modifier;
                mGamma["Linux 2.6"] += modifier;
            }
        }

        private static void WindowSizeTest(string packetWindowSize, uint packetMaxSegSize)
        {
            var ws = Int32.Parse(packetWindowSize);
            var mss = packetMaxSegSize;
            var modifier = 1;

            if (ws <= (mss + 50) && ws >= (mss - 50))
            {
                mGamma["Linux 1.2"] += modifier;
            }
            else if (ws <= (32736 + 70) && ws >= (32736 - 70))
            {
                mGamma["Linux 2.0"] += modifier;
            }
            else if ((ws <= (512 + 50) && ws >= 512 - 50) || 
                (ws <= (16384 + 70) && ws >= 16384 - 70))
            {
                mGamma["Linux 2.0.3x"] += modifier;
            }
            else if ((ws <= ((mss * 11) + 70) && ws >= ((mss * 11) - 70)) || 
                (ws <= ((mss * 20) + 70) && (ws >= (mss * 20) - 70)))
            {
                mGamma["Linux 2.2"] += modifier;
            }
            else if (((ws <= (mss * 2) + 70) && (ws >= (mss * 2) - 70)) ||
              ((ws <= (mss * 3) + 70) && (ws >= (mss * 3) - 70)) ||
              ((ws <= (mss * 4) + 70) && (ws >= (mss * 4) - 70)))
            {
                mGamma["Linux 2.4"] += modifier;
                mGamma["Linux 2.6"] += modifier;
            }
            else if ((ws <= (8192 + 70)) && (ws >= (8192 - 70)))
            {
                mGamma["Windows 3.11"] += modifier;
            }
            else if (((ws <= (mss * 44) + 70) && (ws >= (mss * 44) - 70)))
            {
                mGamma["Windows 95"] += modifier;
            }
            else if ((ws <= (8192 + 70)) && (ws >= (8192 - 70)))
            {
                mGamma["Windows 95b"] += modifier;
            }
            else if ((ws <= 65535) && (ws >= (65535 - 70)) ||
              (ws <= (8192 + 70)) && (ws >= (8192 - 70)) ||
              (ws <= (32767 + 70)) && (ws >= (32767 - 70)) ||
              (ws <= (37300 + 70)) && (ws >= (37300 - 70)) ||
              (ws <= (46080 + 70)) && (ws >= (46080 - 70)) ||
              (ws <= (60352 + 70)) && (ws >= (60352 - 70)) ||
              ((ws <= (mss * 44) + 70) && (ws >= (mss * 44) - 70)) ||
              ((ws <= (mss * 4) + 70) && (ws >= (mss * 4) - 70)) ||
              ((ws <= (mss * 6) + 70) && (ws >= (mss * 6) - 70)) ||
              ((ws <= (mss * 12) + 70) && (ws >= (mss * 12) - 70)) ||
              ((ws <= (mss * 16) + 70) && (ws >= (mss * 16) - 70)) ||
              ((ws <= (mss * 26) + 70) && (ws >= (mss * 26) - 70)))
            {
                mGamma["Windows 98"] += modifier;
            }
            else if ((ws <= (44620 + 70)) && (ws >= (44620 - 70)))
            {
                mGamma["Windows ME no SP"] += modifier;
            }
            else if ((ws <= (64512 + 70)) && (ws >= (64512 - 70)))
            {
                mGamma["Windows NT 4.0 SP6a"] += modifier;
            }
            else if ((ws <= (64512 + 70)) && (ws >= (64512 - 70)))
            {
                mGamma["Windows NT 4.0 SP6a"] += modifier;
            }
            else if ((ws <= (8192 + 70)) && (ws >= (8192 - 70)) ||
              ((ws <= (mss * 6) + 70) && (ws >= (mss * 6) - 70)))
            {
                mGamma["Windows 2000 SP2+"] += modifier;
            }
            else if ((ws <= (64512 + 70)) && (ws >= (64512 - 70)) ||
              ((ws <= (mss * 44) + 70) && (ws >= (mss * 44) - 70)))
            {
                mGamma["Windows 2000 SP3"] += modifier;
            }
            else if ((ws <= 65535) && (ws >= (65535 - 70)) ||
              (ws <= (40320 + 70)) && (ws >= (40320 - 70)) ||
              (ws <= (32767 + 70)) && (ws >= (32767 - 70)) ||
              ((ws <= (mss * 45) + 70) && (ws >= (mss * 45) - 70)))
            {
                mGamma["Windows 2000 SP4"] += modifier;
            }
            else if ((ws <= 65535) && (ws >= (65535 - 70)) ||
              (ws <= (8192 + 70)) && (ws >= (8192 - 70)) ||
              (ws <= (64512 + 70)) && (ws >= (64512 - 70)) ||
              (ws <= (32767 + 70)) && (ws >= (32767 - 70)) ||
              ((ws <= (mss * 45) + 70) && (ws >= (mss * 45) - 70)) ||
              ((ws <= (mss * 44) + 70) && (ws >= (mss * 44) - 70)) ||
              ((ws <= (mss * 12) + 70) && (ws >= (mss * 12) - 70)))
            {
                mGamma["Windows XP SP1+"] += modifier;
            }
            else if ((ws <= 65535) && (ws >= (65535 - 70)) ||
              (ws <= (32768 + 70)) && (ws >= (32768 - 70)) ||
              (ws <= (16384 + 70)) && (ws >= (16384 - 70)))
            {
                mGamma["Windows 2K3"] += modifier;
            }
            else if ((ws <= (8192 + 70)) && (ws >= (8192 - 70)))
            {
                mGamma["Windows Vista (beta)"] += modifier;
            }
            else if ((ws <= (16616 + 70)) && (ws >= (16616 - 70)))
            {
                mGamma["MacOS 7.3-8.6"] += modifier;
                mGamma["MacOS 8.1-8.6"] += modifier;
            }
            else if (((ws <= (mss * 2) + 70) && (ws >= (mss * 2) - 70)))
            {
                mGamma["MacOS 8.6"] += modifier;
            }
            else if ((ws <= (32768 + 70)) && (ws >= (32768 - 70)))
            {
                mGamma["MacOS 9.0-9.2"] += modifier;
            }
            else if (((ws <= (32768 + 70)) && (ws >= (32768 - 70))) ||
              ((ws <= 65535) && (ws >= (65535 - 70))))
            {
                mGamma["MacOS 9.1"] += modifier;
            }
            else if ((ws <= (33304 + 70)) && (ws >= (33304 - 70)))
            {
                mGamma["MacOS 10.2.6"] += modifier;
            }


        }

        private static void WindowScaleTest(byte packetWindowScale)
        {
            var ws = packetWindowScale;
            var modifier = 1;

            if (ws == 255) // no window scale set
            {
                mGamma["Linux 1.2"] += modifier;
                mGamma["Linux 2.0"] += modifier;
                mGamma["Linux 2.0.3x"] += modifier;

                mGamma["Windows 3.11"] += modifier;
                mGamma["Windows 95"] += modifier;
                mGamma["Windows 95b"] += modifier;
                mGamma["Windows 98"] += modifier;
                mGamma["Windows ME no SP"] += modifier;
                mGamma["Windows 2000 SP2+"] += modifier;
                mGamma["Windows 2000 SP3"] += modifier;
                mGamma["Windows 2000 SP4"] += modifier;
                mGamma["Windows XP SP1+"] += modifier;
                mGamma["Windows 2K3"] += modifier;

                mGamma["MacOS 8.1-8.6"] += modifier;
                mGamma["MacOS 9.1"] += modifier;
            }
            else if (ws == 0)
            {
                mGamma["Linux 2.2"] += modifier;
                mGamma["Linux 2.4"] += modifier;
                mGamma["Linux 2.6"] += modifier;

                mGamma["Windows XP SP1+"] += modifier;
                mGamma["Windows 2K3"] += modifier;

                mGamma["MacOS 7.3-8.6"] += modifier;
                mGamma["MacOS 8.6"] += modifier;
                mGamma["MacOS 9.0-9.2"] += modifier;
                mGamma["MacOS 10.2.6"] += modifier;
            }
            else if (ws == 1)
            {
                mGamma["Linux 2.4"] += modifier;
                mGamma["Linux 2.6"] += modifier;
            }
            else if (ws == 2)
            {
                mGamma["Linux 2.4"] += modifier;
                mGamma["Linux 2.6"] += modifier;

                mGamma["Windows 2K3"] += modifier;
            }
            else if (ws == 5 || ws == 6 || ws == 7)
            {
                mGamma["Linux 2.6"] += modifier;
            }
            else if (ws == 8)
            {
                mGamma["Windows Vista (beta)"] += modifier;
            }
        }

        private static void TcpOrderOptionsTest(string packetOptions)
        {
            var o = packetOptions;
            var modifier = 2.5;

            if (o == "2")
            {
                mGamma["Linux 1.2"] += modifier;
                mGamma["Linux 2.0"] += modifier;
                mGamma["Linux 2.0.3x"] += modifier;

                mGamma["Windows 3.11"] += modifier;
                mGamma["Windows NT 4.0 SP6a"] += modifier;
                mGamma["Windows 2K3"] += modifier;
            }
            else if (o == "24813")
            {
                mGamma["Linux 2.2"] += modifier;
                mGamma["Linux 2.4"] += modifier;
                mGamma["Linux 2.6"] += modifier;
            }
            else if (o == "213118114")
            {
                mGamma["Windows 95"] += modifier;
                mGamma["Windows 95b"] += modifier;
                mGamma["Windows 2000 SP4"] += modifier;
                mGamma["Windows XP SP1+"] += modifier;
                mGamma["Windows 2K3"] += modifier;
                mGamma["Windows 98"] += modifier;

            }
            else if (o == "213114")
            {
                mGamma["Windows 98"] += modifier;
                mGamma["Windows 2K3"] += modifier;
            }
            else if (o == "2114")
            {
                mGamma["Windows ME no SP"] += modifier;
                mGamma["Windows 2000 SP2+"] += modifier;
                mGamma["Windows 2000 SP3"] += modifier;
                mGamma["Windows 2000 SP4"] += modifier;
                mGamma["Windows XP SP1+"] += modifier;
                mGamma["Windows 98"] += modifier;
            }
            else if (o == "231114")
            {
                mGamma["Windows Vista (beta)"] += modifier;
            }
            else if (o == "23")
            {
                mGamma["MacOS 7.3-8.6"] += modifier;
                mGamma["MacOS 8.6"] += modifier;
            }
            else if (o == "2111")
            {
                mGamma["MacOS 8.1-8.6"] += modifier;
            }
            else if (o == "231")
            {
                mGamma["MacOS 9.0-9.2"] += modifier;
            }
            else if (o == "21111")
            {
                mGamma["MacOS 9.1"] += modifier;
            }
            else if (o == "213118")
            {
                mGamma["MacOS 10.2.6"] += modifier;
            }
        }

        private static void InitDictionary()
        {
            mGamma = new Dictionary<string, double>
            {
                { "Linux 1.2", 0 },
                { "Linux 2.0", 0 },
                { "Linux 2.0.3x", 0 },
                { "Linux 2.2", 0 },
                { "Linux 2.4", 0 },
                { "Linux 2.6", 0 },

                { "Windows 3.11", 0 },
                { "Windows 95", 0 },
                { "Windows 95b", 0 },
                { "Windows 98", 0 },
                { "Windows ME no SP", 0 },
                { "Windows NT 4.0 SP6a", 0 },
                { "Windows 2000 SP2+", 0 },
                { "Windows 2000 SP3", 0 },
                { "Windows 2000 SP4", 0 },
                { "Windows XP SP1+", 0 },
                { "Windows 2K3", 0 },
                { "Windows Vista (beta)", 0 },

                { "MacOS 7.3-8.6", 0 },
                { "MacOS 8.1-8.6", 0 },
                { "MacOS 8.6", 0 },
                { "MacOS 9.0-9.2", 0 },
                { "MacOS 9.1", 0 },
                { "MacOS 10.2.6", 0 }
            };
        }
    }
}
