using System;
using System.Diagnostics;

class Program
{
	static void Main()
	{
		System.Diagnostics.Process process = new System.Diagnostics.Process();
		System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
		startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
		startInfo.FileName = "cmd.exe";
		startInfo.Arguments = "/C mkdir C:\\ProgramData\\poc";
		process.StartInfo = startInfo;
		process.Start();
	}
}
