using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.IO;
using SharpPcap;
using PacketDotNet;

namespace PortAuthority
{
    /// <summary>
    /// The PortAuthority class is used to perform various packet capturing functions and web queries associated with a specified network interface and Student Life's Netcenter's port_authority.php
    /// </summary>
    public class PortAuthority
    {
        #region Fields
        private NetworkInterface ni;
        private string url;
        private ICaptureDevice idev;
        #endregion

        #region Properties
        public string MACAddress
        {
            get;
            private set;
        }
        public string IPAddress
        {
            get;
            private set;
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes a new instance of the PortAuthority class that focuses on the NetworkInterface object that is passed to this constructor.
        /// </summary>
        /// <param name="n"></param>
        public PortAuthority(NetworkInterface n)
        {
            ni = n;
            url = "https://netcenter.studentaffairs.ohio-state.edu/portmapper/port_authority.php";
            MACAddress = BitConverter.ToString(n.GetPhysicalAddress().GetAddressBytes()).Replace('-', ':');
            IPAddress = GetIP();
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Gets the IPv4 Address associated with the network interface
        /// </summary>
        /// <returns>A string representing the IPv4 address in xxx.xxx.xxx.xxx format where xxx is an integer in the range of [0,256]</returns>
        private string GetIP()
        {
            foreach (UnicastIPAddressInformation ipi in ni.GetIPProperties().UnicastAddresses)
            {
                //if valid ipv4 address
                if (ipi.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    return ipi.Address.ToString();
                }
            }
            return "0.0.0.0";
        }

        /// <summary>
        /// Returns a query string using the parameters as the field values
        /// </summary>
        /// <param name="rm">Room number</param>
        /// <param name="jack">Jack name as stated in the room</param>
        /// <param name="nswitch">Switch name</param>
        /// <param name="port">The name of the port used on the switch</param>
        /// <param name="gb">True if the port supports Gigabit speeds. False otherwise</param>
        /// <param name="user">Student Affairs username for authentication</param>
        /// <param name="pass">Student Affairs password for authentication</param>
        /// <returns>A query string with the fields filled out by the values given in the parameters</returns>
        private string GenerateQueryString(string rm, string jack, string nswitch, string port, bool gb, string user, string pass)
        {
            var query = new StringBuilder();
            query.Append("roomnumber=");
            query.Append(rm);
            query.Append("&jack=");
            query.Append(jack);
            query.Append("&devideid=");
            query.Append(nswitch);
            query.Append("&portid=");
            query.Append(port);
            query.Append("&gigabit=");
            query.Append(gb ? "1" : "0");
            query.Append("&user=");
            query.Append(user);
            query.Append("&pass=");
            query.Append(pass);
            return query.ToString();
        }

        /// <summary>
        /// Converts a query string to an equivalent array of bytes
        /// </summary>
        /// <param name="query">The query string</param>
        /// <returns>A byte array representing the given query string</returns>
        private byte[] ConvertQueryStringToBytes(string query)
        {
            return Encoding.UTF8.GetBytes(query);
        }

        /// <summary>
        /// Sends a POST request to Netcenter with data given by the parameter postData
        /// Then calls the private method <c>ReadNetCenter</c> to obtain the response message and returns it as a string.
        /// </summary>
        /// <param name="postData">Data to be posted to Netcenter</param>
        /// <returns>A string representing the response from Netcenter</returns>
        private string WriteNetCenter(byte[] postData)
        {
            var req = WebRequest.Create(url);
            req.Method = "POST";
            req.ContentType = "application/x-www-form-urlencoded";
            req.ContentLength = postData.Length;
            var dstream = req.GetRequestStream();
            dstream.Write(postData, 0, postData.Length);
            dstream.Close();
            return GetWebRequestReponse(req);
        }

        /// <summary>
        /// Gets the response message from the WebRequest object passed in the parameter
        /// </summary>
        /// <param name="wr">The WebRequest object to be interrogated</param>
        /// <returns>A string with the reponse message from the given WebRequest</returns>
        private string GetWebRequestReponse(WebRequest wr)
        {
            string resp;
            var wresp = wr.GetResponse();
            var dstream = wresp.GetResponseStream();
            var reader = new StreamReader(dstream);
            resp = reader.ReadToEnd();
            reader.Close();
            dstream.Close();
            wresp.Close();
            return resp;
        }

        private bool SetupCaptureDevice()
        {
            bool success = false;
            foreach (ICaptureDevice icd in CaptureDeviceList.Instance)
            {
                icd.Open(DeviceMode.Promiscuous, 4000);
                if (BitConverter.ToString(icd.MacAddress.GetAddressBytes()).Replace('-', ':') == MACAddress)
                {
                    idev = icd;
                    success = true;
                }
                icd.Close();
            }
            return success;
        }

        private bool GetSwitchInformation(ref string sname, ref string port, ref bool gigabit)
        {
            var lldp = CaptureLLDPPacket();
            if (lldp == null)
                return false;
            sname = Encoding.UTF8.GetString(lldp[3].Bytes);
            sname = sname.Substring(2);
            port = Encoding.UTF8.GetString(lldp[6].Bytes);
            port = port.Substring(2);
            if (port[0] == 'g' || port[0] == 'G')
                gigabit = true;
            port = port.Split('/')[2];
            return true;
        }

        private LLDPPacket CaptureLLDPPacket()
        {
            idev.Filter = "ether dst 01:80:c2:00:00:0e";
            var rawpacket = idev.GetNextPacket();
            var packet = Packet.ParsePacket(rawpacket.LinkLayerType, rawpacket.Data);
            return (LLDPPacket)packet.Extract(typeof(LLDPPacket));
        }

        private void CloseCaptureDevice()
        {
            if (idev != null)
                idev.Close();
        }
        #endregion

        #region Public Methods
        public void RefeshIP()
        {
            IPAddress = GetIP();
        }
        public OperationalStatus GetOperationalStatus()
        {
            return ni.OperationalStatus;
        }
        public string PostNetCenter(string rm, string jack, string user, string pass)
        {
            if (!SetupCaptureDevice())
                return "Unable to match selected network adapter to ICaptureDevice";
            string nswitch = "";
            string port = "";
            bool gb = false;
            if (!GetSwitchInformation(ref nswitch, ref port, ref gb))
                return "Unable to capture packet: Check the connection and try again";
            CloseCaptureDevice();
            string query = GenerateQueryString(rm, jack, nswitch, port, gb, user, pass);
            var postData = ConvertQueryStringToBytes(query);
            return WriteNetCenter(postData);
        }
        #endregion
    }
}
