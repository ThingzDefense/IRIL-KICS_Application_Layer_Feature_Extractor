//Ghazanfar Abbas (topcoder2003@gmai.com)


using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text;
using System.Windows.Forms;

namespace PCAPToCSV
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                {
                    txtSelectPcapFile.Text = openFileDialog1.FileName;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                {
                    txtSelectTSharkFile.Text = openFileDialog1.FileName;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }
        Dictionary<string, string> dict =
                   new Dictionary<string, string>();
        private void button3_Click(object sender, EventArgs e)
        {
            try
            {
                if (textBox2.Text.Trim() == "" || txtSelectTSharkFile.Text == "" || txtFlowDuration.Text == "")
                {
                    MessageBox.Show("Please enter required fileds");
                    return;
                }
                DataTable table = new DataTable("output");
                table.Columns.Add("packetID", typeof(int));
                table.Columns.Add("time", typeof(DateTime));
                table.Columns.Add("srcIP");
                table.Columns.Add("dstIP");
                table.Columns.Add("srcPort");
                table.Columns.Add("dstPort");
                table.Columns.Add("proto", typeof(int));
                table.Columns.Add("frameLen", typeof(int));
                table.Columns.Add("tranLen", typeof(int));
                table.Columns.Add("appLen", typeof(int));
                table.Columns.Add("ethSrc");
                table.Columns.Add("ethDst");

                DataTable flowTable = new DataTable("flow");
                flowTable.Columns.Add("pcketID", typeof(int));
                flowTable.Columns.Add("srcIP");
                flowTable.Columns.Add("dstIP");
                flowTable.Columns.Add("srcPort");
                flowTable.Columns.Add("dstPort");
                flowTable.Columns.Add("ethSrc");
                flowTable.Columns.Add("ethDst");
                flowTable.Columns.Add("proto", typeof(int));
                flowTable.Columns.Add("startTime", typeof(DateTime));
                flowTable.Columns.Add("endTime", typeof(DateTime));
                flowTable.Columns.Add("hash1");
                flowTable.Columns.Add("hash2");
                flowTable.Columns.Add("totalPktCount", typeof(int));
                flowTable.Columns.Add("totalTransportPktCount", typeof(int));
                flowTable.Columns.Add("totalAppPktCount", typeof(int));
                flowTable.Columns.Add("totalFrameLen", typeof(int));
                flowTable.Columns.Add("totalTransportFrameLen", typeof(int));
                flowTable.Columns.Add("totalAppFrameLen", typeof(int));
                flowTable.Columns.Add("minPktLen", typeof(int));
                flowTable.Columns.Add("minTransportPktLen", typeof(int));
                flowTable.Columns.Add("minAppPktLen", typeof(int));
                flowTable.Columns.Add("maxPktLen", typeof(int));
                flowTable.Columns.Add("maxTransportPktLen", typeof(int));
                flowTable.Columns.Add("maxAppPktLen", typeof(int));
                flowTable.Columns.Add("label");
                string[] text = File.ReadAllText(textBox1.Text).Replace("\r", "").Split('\n');
                dict =
                  new Dictionary<string, string>();
                foreach (string s in text)
                    try
                    {
                        dict.Add(s.Split(',')[1].Trim(), s.Split(',')[2].Trim());
                    }
                    catch (Exception exxx)
                    { }

                string[] files = Directory.GetFiles(textBox2.Text, "*.pcap", SearchOption.AllDirectories);
                foreach(string file in files)
                {
                    txtSelectPcapFile.Text = file;
                string strCmdText = " -r \"" + txtSelectPcapFile.Text + "\" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e frame.len -e ip.len -e tcp.len -e udp.length -e data.len  -e eth.src  -e eth.dst";
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = txtSelectTSharkFile.Text;
                startInfo.Arguments = strCmdText;
                startInfo.RedirectStandardOutput = true;
                startInfo.UseShellExecute = false;
                List<string> lstStrings = new List<string>();
                string result;
                using (Process process = Process.Start(startInfo))
                {                    
                    using (StreamReader reader = process.StandardOutput)
                    {
                        result = reader.ReadToEnd();
                    }
                }


                result = result.Replace("\r", "");
                string[] resultArray = result.Split('\n');
                if (resultArray.Length == 0)
                {
                    MessageBox.Show("No Data Found!");
                        continue;
                }

              







                int counter = 0;
                foreach (string row in resultArray)
                {
                    counter++;
                    string[] rowArr = row.Split('\t');
                    if (rowArr[0] == "" || rowArr[1] == "")
                            continue;
                    if (rowArr[8].Contains(",")) //ip len is 0
                            continue;
                        string srcIP, dstIP, srcPort = "", dstPort = "";
                    int proto = 0;


                    DateTime dt = Convert.ToDateTime(rowArr[0].Replace(" Pakistan Standard Time", ""));
                    srcIP = rowArr[1];
                    dstIP = rowArr[2];
                    if (rowArr[3] != "") //tcp port
                    {
                        srcPort = rowArr[3];
                        dstPort = rowArr[4];
                        proto = 6;
                    }
                    if (rowArr[5] != "") //udp port
                    {
                        srcPort = rowArr[5];
                        dstPort = rowArr[6];
                        proto = 17;
                    }

                    int FrameLen = 0;
                    int IPLen = 0;
                    int TransLen = 0;
                    int appLen = 0;
                    FrameLen = Int32.Parse(rowArr[7]);

                    IPLen = Int32.Parse(rowArr[8]);
                    if (proto == 6)
                    {
                        TransLen = Int32.Parse(rowArr[9]);
                        appLen = TransLen - 20;
                    }
                    if (proto == 17)
                    {
                        TransLen = Int32.Parse(rowArr[10]);
                        appLen = TransLen - 8;
                    }
                    if (appLen < 0) appLen = 0;
                    TransLen = FrameLen - appLen;

                    DataRow dr = table.NewRow();
                    dr[0] = counter;
                    dr[1] = dt;
                    dr[2] = srcIP;
                    dr[3] = dstIP;
                    dr[4] = srcPort;
                    dr[5] = dstPort;
                    dr[6] = proto;
                    dr[7] = FrameLen;
                    dr[8] = TransLen;
                    dr[9] = appLen;
                    dr[10] = rowArr[12]; //eth src
                    dr[11] = rowArr[13]; //eth dst

                    table.Rows.Add(dr);

                    int hash1_1 = (srcIP + dstIP + srcPort + dstPort + proto.ToString()).GetHashCode();
                    int hash1_2 = (dstIP + srcIP + dstPort + srcPort + proto.ToString()).GetHashCode();
                    int hash2 = (srcIP + dstIP + srcPort + dstPort + proto.ToString() + dt.ToLongTimeString()).GetHashCode();
                    DataRow[] drFlow = flowTable.Select("hash1 = '" + hash1_1.ToString() + "' or hash1 = '" + hash1_2.ToString() + "'");
                    if (drFlow.Count() == 0)
                    {
                        DataRow drNewFlow = flowTable.NewRow();
                        drNewFlow["pcketID"] = counter;
                        drNewFlow["srcIP"] = srcIP;
                        drNewFlow["dstIP"] = dstIP;
                        drNewFlow["srcPort"] = srcPort;
                        drNewFlow["dstPort"] = dstPort;
                        drNewFlow["proto"] = proto;
                        drNewFlow["startTime"] = dt;
                        drNewFlow["endTime"] = dt.AddSeconds(Int32.Parse(txtFlowDuration.Text));
                        drNewFlow["hash1"] = hash1_1;
                        drNewFlow["hash2"] = hash2;
                        drNewFlow["totalPktCount"] = 1;
                        drNewFlow["totalTransportPktCount"] = 1;
                        drNewFlow["totalAppPktCount"] = appLen > 0? 1: 0;
                        drNewFlow["totalFrameLen"] = FrameLen;
                        drNewFlow["totalTransportFrameLen"] = TransLen;
                        drNewFlow["totalAppFrameLen"] = appLen;
                        drNewFlow["minPktLen"] = FrameLen;
                        drNewFlow["minTransportPktLen"] = TransLen;
                        drNewFlow["minAppPktLen"] = appLen;
                        drNewFlow["maxPktLen"] = FrameLen;
                        drNewFlow["maxTransportPktLen"] = TransLen;
                        drNewFlow["maxAppPktLen"] = appLen;
                        drNewFlow["ethSrc"] = rowArr[12]; //eth src
                        drNewFlow["ethDst"] = rowArr[13]; //eth dst
                        if (dict.ContainsKey(drNewFlow["ethSrc"].ToString()))
                            drNewFlow["label"] = dict[drNewFlow["ethSrc"].ToString()];
                        else if (dict.ContainsKey(drNewFlow["ethDst"].ToString()))
                            drNewFlow["label"] = dict[drNewFlow["ethDst"].ToString()];
                        else                           
                            drNewFlow["label"] = "";
                        flowTable.Rows.Add(drNewFlow);
                    }
                    else
                    {
                        foreach (DataRow drOldFlow in drFlow)
                        {
                            if (dt >= DateTime.Parse(drOldFlow["startTime"].ToString()) && dt <= DateTime.Parse(drOldFlow["endTime"].ToString()))
                            {
                                drOldFlow["totalPktCount"] = int.Parse(drOldFlow["totalPktCount"].ToString()) +  1;
                                drOldFlow["totalTransportPktCount"] = int.Parse(drOldFlow["totalTransportPktCount"].ToString()) + 1;
                                drOldFlow["totalAppPktCount"] = appLen > 0 ? (int.Parse(drOldFlow["totalAppPktCount"].ToString()) + 1) : drOldFlow["totalAppPktCount"];
                                drOldFlow["totalFrameLen"] = int.Parse(drOldFlow["totalFrameLen"].ToString()) +  FrameLen;
                                drOldFlow["totalTransportFrameLen"] = int.Parse(drOldFlow["totalTransportFrameLen"].ToString()) + TransLen;
                                drOldFlow["totalAppFrameLen"] = int.Parse(drOldFlow["totalAppFrameLen"].ToString()) +  appLen;
                                drOldFlow["minPktLen"] = FrameLen < int.Parse(drOldFlow["minPktLen"].ToString()) ? FrameLen : drOldFlow["minPktLen"];
                                drOldFlow["minTransportPktLen"] = TransLen < int.Parse(drOldFlow["minTransportPktLen"].ToString()) ? TransLen : drOldFlow["minTransportPktLen"];
                                drOldFlow["minAppPktLen"] = appLen < int.Parse(drOldFlow["minAppPktLen"].ToString()) ? appLen : drOldFlow["minAppPktLen"];
                                drOldFlow["maxPktLen"] = FrameLen > int.Parse(drOldFlow["maxPktLen"].ToString()) ? FrameLen : drOldFlow["maxPktLen"];
                                drOldFlow["maxTransportPktLen"] = TransLen > int.Parse(drOldFlow["maxTransportPktLen"].ToString()) ? TransLen : drOldFlow["maxTransportPktLen"];
                                drOldFlow["maxAppPktLen"] = appLen > int.Parse(drOldFlow["maxAppPktLen"].ToString()) ? appLen : drOldFlow["maxAppPktLen"];
                            }
                        }
                    }
                }
                }
                // lstStrings.Add(result);

                dataGridView1.DataSource = table;
                dataGridView1.Refresh();

                dataGridView2.DataSource = flowTable;
                dataGridView2.Refresh();

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {
                if (DateTime.Now.Year != 2020 && DateTime.Now.Month != 4)
                    this.Close();
            }
            catch (Exception ex)
            {
                this.Close();
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            try
            {
                //Build the CSV file data as a Comma separated string.
                string csv = string.Empty;

                //Add the Header row for CSV file.
                foreach (DataGridViewColumn column in dataGridView2.Columns)
                {
                    csv += column.HeaderText + ',';
                }

                //Add new line.
                csv += "\r\n";

                //Adding the Rows

                int rCount  = dataGridView2.Rows.Count;
                foreach (DataGridViewRow row in dataGridView2.Rows)
                {
                    if (rCount == 1)
                        break;
                    rCount--;
                    foreach (DataGridViewCell cell in row.Cells)
                    {
                        //Add the Data rows.
                        csv += cell.Value.ToString().Replace(",", ";") + ',';
                    }

                    //Add new line.
                    csv += "\r\n";
                }

                File.WriteAllText("output.csv", csv);

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        private void button5_Click(object sender, EventArgs e)
        {
            try
            {
                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                {
                    textBox1.Text = openFileDialog1.FileName;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        private void button6_Click(object sender, EventArgs e)
        {
            try
            {
                if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
                {
                    textBox2.Text = folderBrowserDialog1.SelectedPath;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }
    }
}
